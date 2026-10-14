// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness

import (
	"bytes"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// InclusionProof is an RFC 6962-style proof that the entry with
// LeafHash at LeafIndex is the LeafIndex-th leaf of a tree with the
// given TreeSize whose root is the referenced STH's TreeHash.
//
// The proof is O(log TreeSize) audit-path siblings from the leaf up to
// the root. The verifier does NOT need access to the log — given
// {LeafHash, LeafIndex, TreeSize, Path, expected root}, it can
// reconstruct the root with pure hash math.
type InclusionProof struct {
	// LeafIndex is the 0-based position of the entry in the tree.
	// MUST be < TreeSize.
	LeafIndex uint64 `json:"leaf_index"`

	// TreeSize is the size of the tree this proof refers to. The STH
	// bundled with this proof MUST carry the same TreeSize.
	TreeSize uint64 `json:"tree_size"`

	// Path is the audit path: sibling hashes from the leaf level up to
	// (but not including) the root. Each element is exactly 32 bytes.
	// May be empty only when TreeSize == 1 AND LeafIndex == 0.
	Path [][]byte `json:"path"`
}

// Validate enforces field-shape invariants.
func (p *InclusionProof) Validate() error {
	if p == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"inclusion_proof: nil receiver",
			nil,
		)
	}
	if p.TreeSize == 0 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"inclusion_proof: tree_size must be > 0",
			nil,
		)
	}
	if p.LeafIndex >= p.TreeSize {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"inclusion_proof: leaf_index must be < tree_size",
			nil,
		)
	}
	for i := range p.Path {
		if len(p.Path[i]) != crypto.HashSize {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"inclusion_proof: path element not 32 bytes",
				nil,
			)
		}
	}
	// A tree of size 1 has no internal siblings; a non-trivial tree
	// must carry at least one.
	if p.TreeSize == 1 {
		if len(p.Path) != 0 {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"inclusion_proof: singleton tree must have empty path",
				nil,
			)
		}
	} else {
		if len(p.Path) == 0 {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"inclusion_proof: non-singleton tree must have non-empty path",
				nil,
			)
		}
	}
	return nil
}

// VerifyInclusion reconstructs the root from leafHash using the audit
// path and compares it to expectedRoot. Returns nil on match. A
// mismatch surfaces as Integrity (CodeSignatureInvalid reused here —
// the proof is the signature on the leaf's position in the tree).
//
// Implements the RFC 6962 §2.1.1 algorithm with the right-edge
// special case: on the last (right-most) index of a sub-tree, the
// algorithm bubbles upward through even-indexed levels before
// consuming the next sibling. This handles "ragged" trees where
// TreeSize is not a power of two and the right spine has lopsided
// subtrees.
func VerifyInclusion(leafHash []byte, proof *InclusionProof, expectedRoot []byte) error {
	if len(leafHash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"verify_inclusion: leaf_hash must be 32 bytes",
			nil,
		)
	}
	if len(expectedRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"verify_inclusion: expected_root must be 32 bytes",
			nil,
		)
	}
	if err := proof.Validate(); err != nil {
		return err
	}
	// Singleton tree — the leaf itself is the root.
	if proof.TreeSize == 1 {
		if !bytes.Equal(leafHash, expectedRoot) {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				"verify_inclusion: singleton tree leaf != root",
				nil,
			)
		}
		return nil
	}

	sn := proof.LeafIndex
	fn := proof.TreeSize - 1
	h := make([]byte, crypto.HashSize)
	copy(h, leafHash)
	for _, p := range proof.Path {
		if fn == 0 {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				"verify_inclusion: audit path too long",
				nil,
			)
		}
		if sn%2 == 1 || sn == fn {
			combined, err := CombineNodes(p, h)
			if err != nil {
				return err
			}
			h = combined
			// Right-edge bubble-up: when sn == fn and sn is even,
			// shift up until sn is odd (or zero). Skipping these
			// levels avoids inventing sibling slots that do not
			// exist in the ragged right spine.
			if sn%2 == 0 {
				for sn%2 == 0 && sn != 0 {
					sn >>= 1
					fn >>= 1
				}
			}
		} else {
			combined, err := CombineNodes(h, p)
			if err != nil {
				return err
			}
			h = combined
		}
		sn >>= 1
		fn >>= 1
	}
	if fn != 0 {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"verify_inclusion: audit path too short",
			nil,
		)
	}
	if !bytes.Equal(h, expectedRoot) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"verify_inclusion: reconstructed root mismatch",
			nil,
		)
	}
	return nil
}

// ConsistencyProof is an RFC 6962-style proof that a tree of size
// OldSize legitimately grew into a tree of size NewSize (OldSize <=
// NewSize). Given {oldRoot, newRoot, proof}, the verifier can check
// that newRoot is reachable from oldRoot by appending NewSize -
// OldSize entries — with no retroactive modifications to the first
// OldSize leaves.
//
// # Doctrinal role
//
// This is the primitive that detects FORKS. If an operator has issued
// two STHs {(N, rootA), (M, rootB)} with N <= M, a legitimate
// ConsistencyProof between them MUST exist. Absence of such a proof
// — or any proof that fails to verify both roots — is doctrinal
// evidence of a fork, surfaced by DetectFork as CategoryIncident.
type ConsistencyProof struct {
	// OldSize is the older tree size.
	OldSize uint64 `json:"old_size"`

	// NewSize is the newer tree size. MUST be >= OldSize.
	NewSize uint64 `json:"new_size"`

	// Path is the RFC 6962 PROOF(m, D[n]) audit path.
	// The path encodes the minimal set of hashes needed to reconstruct
	// BOTH oldRoot and newRoot. Each element is exactly 32 bytes.
	Path [][]byte `json:"path"`
}

// Validate enforces field-shape invariants.
func (c *ConsistencyProof) Validate() error {
	if c == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"consistency_proof: nil receiver",
			nil,
		)
	}
	if c.OldSize > c.NewSize {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"consistency_proof: old_size > new_size",
			nil,
		)
	}
	for i := range c.Path {
		if len(c.Path[i]) != crypto.HashSize {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"consistency_proof: path element not 32 bytes",
				nil,
			)
		}
	}
	// Trivial cases that require empty path:
	//   - OldSize == 0: empty tree is consistent with any tree; no proof.
	//   - OldSize == NewSize: same tree; no proof.
	// The converse — non-trivial must have non-empty path — is enforced
	// in VerifyConsistency because the detailed shape depends on whether
	// OldSize is a power of two.
	if (c.OldSize == 0 || c.OldSize == c.NewSize) && len(c.Path) != 0 {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"consistency_proof: trivial case must have empty path",
			nil,
		)
	}
	return nil
}

// VerifyConsistency checks that oldRoot and newRoot are consistent
// snapshots of the same log under proof. Returns nil on success.
//
// Implements the RFC 6962 §2.1.2 algorithm: reconstruct oldRoot and
// newRoot side-by-side from the shared proof path, walking the right
// spine of the old tree up into the new tree. When OldSize is a power
// of two, the old root itself is a sub-tree of the new tree and is
// NOT transmitted in the path — we seed with oldRoot directly;
// otherwise the first proof element is the first right-spine node.
func VerifyConsistency(oldRoot, newRoot []byte, proof *ConsistencyProof) error {
	if len(oldRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"verify_consistency: old_root must be 32 bytes",
			nil,
		)
	}
	if len(newRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"verify_consistency: new_root must be 32 bytes",
			nil,
		)
	}
	if err := proof.Validate(); err != nil {
		return err
	}

	// Trivial cases.
	if proof.OldSize == 0 {
		// An empty tree is consistent with anything — nothing to
		// verify. We do NOT check the newRoot here; that is the
		// caller's job to confirm via an STH signature.
		return nil
	}
	if proof.OldSize == proof.NewSize {
		if !bytes.Equal(oldRoot, newRoot) {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				"verify_consistency: same-size roots differ",
				nil,
			)
		}
		return nil
	}

	// Standard RFC 6962 algorithm. We work with the RIGHT-spine of the
	// old tree as it lived inside the new tree.
	node := proof.OldSize - 1
	lastNode := proof.NewSize - 1

	// Bubble up through any trailing even levels — these correspond to
	// positions that were left-children of an incomplete parent in the
	// old tree and thus have no sibling yet.
	for node%2 == 1 {
		node >>= 1
		lastNode >>= 1
	}

	path := proof.Path
	var seed []byte
	if node > 0 {
		// OldSize is NOT a power of two: the first right-spine sibling
		// is transmitted as the seed.
		if len(path) == 0 {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				"verify_consistency: proof unexpectedly empty",
				nil,
			)
		}
		seed = path[0]
		path = path[1:]
	} else {
		// OldSize IS a power of two: the old root is itself a left
		// sub-tree of the new tree; no seed is transmitted.
		seed = oldRoot
	}

	hash1 := make([]byte, crypto.HashSize)
	hash2 := make([]byte, crypto.HashSize)
	copy(hash1, seed)
	copy(hash2, seed)

	for _, p := range path {
		if lastNode == 0 {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				"verify_consistency: proof too long",
				nil,
			)
		}
		if node%2 == 1 || node == lastNode {
			// Sibling is on the left for BOTH trees at this level.
			combined1, err := CombineNodes(p, hash1)
			if err != nil {
				return err
			}
			hash1 = combined1
			combined2, err := CombineNodes(p, hash2)
			if err != nil {
				return err
			}
			hash2 = combined2
			// Right-edge bubble-up in the old tree only.
			for node%2 == 0 && node != 0 {
				node >>= 1
				lastNode >>= 1
			}
		} else {
			// Sibling is on the right for the NEW tree only; the OLD
			// tree has nothing at this position — its reconstruction
			// is already complete at this level.
			combined2, err := CombineNodes(hash2, p)
			if err != nil {
				return err
			}
			hash2 = combined2
		}
		node >>= 1
		lastNode >>= 1
	}

	if lastNode != 0 {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"verify_consistency: proof too short",
			nil,
		)
	}
	if !bytes.Equal(hash1, oldRoot) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"verify_consistency: reconstructed old_root mismatch",
			nil,
		)
	}
	if !bytes.Equal(hash2, newRoot) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"verify_consistency: reconstructed new_root mismatch",
			nil,
		)
	}
	return nil
}
