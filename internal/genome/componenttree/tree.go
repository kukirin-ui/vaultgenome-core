// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package componenttree

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Kind enumerates the admissible types of a genome Component. The set is
// closed; additions are doctrinal bumps.
type Kind string

const (
	// KindTensor — a single weight tensor or a shard of one. The dominant
	// kind by count and by bytes.
	KindTensor Kind = "tensor"

	// KindConfig — framework-parseable architecture descriptor
	// (e.g., a HuggingFace config.json).
	KindConfig Kind = "config"

	// KindTokenizer — vocabulary/encoder state.
	KindTokenizer Kind = "tokenizer"

	// KindTrainingMetadata — hyperparameters, seeds, schedules; recorded
	// for provenance rather than for reconstruction.
	KindTrainingMetadata Kind = "training-metadata"

	// KindBehavioralProbe — an (input, expected-output-space) pair used
	// by the behavioral fingerprint. Present as components so the tree
	// commits to them alongside weights.
	KindBehavioralProbe Kind = "behavioral-probe"
)

// validKinds is the closed set of allowed Component kinds.
var validKinds = map[Kind]struct{}{
	KindTensor:           {},
	KindConfig:           {},
	KindTokenizer:        {},
	KindTrainingMetadata: {},
	KindBehavioralProbe:  {},
}

// tags — the RFC 6962 leaf/node domain separators. NEVER change these;
// a change invalidates every signed AGD in existence.
const (
	leafTag byte = 0x00
	nodeTag byte = 0x01
)

// Component is one addressable unit of an AI Genome. The tree commits to
// the (Path, Kind, ByteSize, Hash) tuple only — the Component's content is
// addressed by its Hash; materializing bytes is a storage-layer concern.
type Component struct {
	// Path is the logical name of the component. Determines sort order at
	// tree-build time. Must be non-empty and unique within a tree.
	// Conventionally dot-separated, e.g.,
	// "decoder.block.12.attention.q_proj.weight".
	Path string

	// Kind is the component type. Must be one of the values in validKinds.
	Kind Kind

	// ByteSize is the content's size in bytes. Informational; not part of
	// the integrity check per se, but included in the leaf hash so a
	// caller who fabricates a tampered component with the right hash
	// would also have to match the reported byte-count.
	ByteSize uint64

	// Hash is the SHA-256 digest of the component's content. Exactly 32
	// bytes; any other length is a structural error.
	Hash []byte
}

// Tree is the built Merkle tree. Treat as read-only after BuildTree.
type Tree struct {
	// components holds the input components in sorted order (by Path).
	components []Component
	// leaves[i] is the leaf hash (tagged) of components[i].
	leaves [][]byte
	// root is the Merkle root over leaves.
	root [crypto.HashSize]byte
}

// BuildTree constructs a Merkle tree over components. The input slice is
// copied; callers may freely mutate their slice after the call.
//
// Build-time rejections:
//
//   - empty input
//   - empty Path
//   - duplicate Path (after sorting)
//   - Kind not in validKinds
//   - len(Hash) != crypto.HashSize
func BuildTree(components []Component) (*Tree, error) {
	if len(components) == 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"componenttree: at least one component required",
			nil,
		)
	}

	// Defensive copy with per-item validation.
	cp := make([]Component, len(components))
	for i, c := range components {
		if c.Path == "" {
			return nil, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"componenttree: component path required",
				nil,
			)
		}
		if _, ok := validKinds[c.Kind]; !ok {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"componenttree: unknown component kind: "+string(c.Kind),
				nil,
			)
		}
		if len(c.Hash) != crypto.HashSize {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"componenttree: component hash must be 32 bytes",
				nil,
			)
		}
		cp[i] = Component{
			Path:     c.Path,
			Kind:     c.Kind,
			ByteSize: c.ByteSize,
			Hash:     append([]byte(nil), c.Hash...),
		}
	}

	sort.Slice(cp, func(i, j int) bool { return cp[i].Path < cp[j].Path })

	// Post-sort duplicate-path check.
	for i := 1; i < len(cp); i++ {
		if cp[i].Path == cp[i-1].Path {
			return nil, shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"componenttree: duplicate component path: "+cp[i].Path,
				nil,
			)
		}
	}

	leaves := make([][]byte, len(cp))
	for i := range cp {
		leaves[i] = leafHash(cp[i])
	}

	root := computeRoot(leaves)

	return &Tree{
		components: cp,
		leaves:     leaves,
		root:       root,
	}, nil
}

// Root returns a copy of the tree's Merkle root.
func (t *Tree) Root() [crypto.HashSize]byte { return t.root }

// RootSlice returns a fresh-allocated copy of the tree's Merkle root. Use
// this when the value flows into a contract field typed as []byte.
func (t *Tree) RootSlice() []byte {
	out := make([]byte, crypto.HashSize)
	copy(out, t.root[:])
	return out
}

// Size returns the number of components in the tree.
func (t *Tree) Size() int { return len(t.components) }

// Components returns a defensive copy of the components in tree order
// (sorted by Path).
func (t *Tree) Components() []Component {
	out := make([]Component, len(t.components))
	for i, c := range t.components {
		out[i] = Component{
			Path:     c.Path,
			Kind:     c.Kind,
			ByteSize: c.ByteSize,
			Hash:     append([]byte(nil), c.Hash...),
		}
	}
	return out
}

// ComponentByPath returns the component with the given path, or false.
func (t *Tree) ComponentByPath(path string) (Component, bool) {
	// components is sorted; binary-search.
	i := sort.Search(len(t.components), func(i int) bool {
		return t.components[i].Path >= path
	})
	if i < len(t.components) && t.components[i].Path == path {
		c := t.components[i]
		return Component{
			Path:     c.Path,
			Kind:     c.Kind,
			ByteSize: c.ByteSize,
			Hash:     append([]byte(nil), c.Hash...),
		}, true
	}
	return Component{}, false
}

// InclusionProof is the evidence that a specific leaf (at LeafIndex) is part
// of a tree of size TreeSize with root Root. The proof verifies in
// O(log TreeSize) hash operations.
type InclusionProof struct {
	LeafIndex uint64
	TreeSize  uint64
	// Audit path: the sibling hashes bottom-up, in the order they are
	// combined into the root. Length is ceil(log2(TreeSize)) for leaves
	// not on the "right spine" of an unbalanced tree, and slightly less
	// for leaves that sit atop promoted levels (RFC 6962 §2.1.1).
	AuditPath [][]byte
}

// ProofFor returns an inclusion proof for the component at path. Returns an
// error if path is unknown to the tree.
func (t *Tree) ProofFor(path string) (InclusionProof, error) {
	i := sort.Search(len(t.components), func(i int) bool {
		return t.components[i].Path >= path
	})
	if i >= len(t.components) || t.components[i].Path != path {
		return InclusionProof{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"componenttree: unknown component path: "+path,
			nil,
		)
	}
	auditPath := proofPath(t.leaves, i)
	return InclusionProof{
		LeafIndex: uint64(i),
		TreeSize:  uint64(len(t.leaves)),
		AuditPath: auditPath,
	}, nil
}

// VerifyInclusion checks that c is the leaf at proof.LeafIndex of a tree of
// size proof.TreeSize whose root is root. Returns nil on success; an
// Integrity-classified error on any mismatch.
//
// The caller supplies c as the claimed component. VerifyInclusion re-hashes
// c with leafHash, then combines with proof.AuditPath bottom-up, and
// compares the result against root. This is the primitive a disclosure
// verifier runs against a signed AGD's ComponentTreeRoot.
func VerifyInclusion(c Component, proof InclusionProof, root []byte) error {
	if len(root) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"componenttree: verify: root must be 32 bytes",
			nil,
		)
	}
	if len(c.Hash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"componenttree: verify: component hash must be 32 bytes",
			nil,
		)
	}
	if _, ok := validKinds[c.Kind]; !ok {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"componenttree: verify: unknown component kind",
			nil,
		)
	}
	if proof.TreeSize == 0 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"componenttree: verify: empty tree has no inclusions",
			nil,
		)
	}
	if proof.LeafIndex >= proof.TreeSize {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"componenttree: verify: leaf_index >= tree_size",
			nil,
		)
	}

	h := leafHash(c)
	idx := proof.LeafIndex
	size := proof.TreeSize

	// Walk the RFC 6962 proof path. At each step, if idx is even and has
	// a right sibling within current level, hash(h || sibling). If idx is
	// odd, hash(sibling || h). When the level is promoted (no sibling
	// because idx == size-1 and size is odd), do not consume a proof
	// element — simply move up.
	ap := proof.AuditPath
	for size > 1 {
		levelLastIdx := size - 1
		var err error
		if idx == levelLastIdx && size%2 == 1 {
			// Promoted: no sibling at this level. No proof element consumed.
		} else {
			if len(ap) == 0 {
				return shared_errors.Integrity(
					shared_errors.CodeSignatureInvalid,
					"componenttree: verify: audit path too short",
					nil,
				)
			}
			sib := ap[0]
			ap = ap[1:]
			if len(sib) != crypto.HashSize {
				return shared_errors.Structural(
					shared_errors.CodeFieldValueInvalid,
					"componenttree: verify: audit-path element must be 32 bytes",
					nil,
				)
			}
			if idx%2 == 0 {
				h, err = combine(h, sib)
			} else {
				h, err = combine(sib, h)
			}
			if err != nil {
				return err
			}
		}
		idx /= 2
		size = (size + 1) / 2
	}

	if len(ap) != 0 {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"componenttree: verify: audit path longer than expected",
			nil,
		)
	}

	if !bytes.Equal(h, root) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"componenttree: verify: computed root does not match",
			nil,
		)
	}
	return nil
}

// ---- internals -------------------------------------------------------------

// encodeComponent produces the stable byte-form of c used as the pre-image
// of leafHash. Format (fixed, NEVER change):
//
//	 4-byte  big-endian  length of Kind string
//	 N-byte              Kind UTF-8
//	 4-byte  big-endian  length of Path string
//	 N-byte              Path UTF-8
//	 8-byte  big-endian  ByteSize
//	32-byte              Hash
//
// This specific layout is CHOSEN so it is trivially re-implementable in any
// language. CanonicalJSON is too loose a commitment for a tree that outside
// verifiers must reproduce byte-for-byte across decades.
func encodeComponent(c Component) []byte {
	kind := []byte(c.Kind)
	path := []byte(c.Path)
	out := make([]byte, 0, 4+len(kind)+4+len(path)+8+crypto.HashSize)
	var u32 [4]byte
	var u64 [8]byte

	binary.BigEndian.PutUint32(u32[:], uint32(len(kind)))
	out = append(out, u32[:]...)
	out = append(out, kind...)

	binary.BigEndian.PutUint32(u32[:], uint32(len(path)))
	out = append(out, u32[:]...)
	out = append(out, path...)

	binary.BigEndian.PutUint64(u64[:], c.ByteSize)
	out = append(out, u64[:]...)

	out = append(out, c.Hash...)
	return out
}

// leafHash computes SHA-256(0x00 || encodeComponent(c)). The leafTag is
// the RFC 6962 domain separator.
func leafHash(c Component) []byte {
	buf := make([]byte, 0, 1+4+len(c.Kind)+4+len(c.Path)+8+crypto.HashSize)
	buf = append(buf, leafTag)
	buf = append(buf, encodeComponent(c)...)
	h := crypto.SHA256(buf)
	out := make([]byte, crypto.HashSize)
	copy(out, h[:])
	return out
}

// combine computes SHA-256(0x01 || left || right). The nodeTag is the
// RFC 6962 domain separator for internal nodes.
func combine(left, right []byte) ([]byte, error) {
	if len(left) != crypto.HashSize || len(right) != crypto.HashSize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"componenttree: combine: inputs must be 32 bytes",
			nil,
		)
	}
	buf := make([]byte, 0, 1+2*crypto.HashSize)
	buf = append(buf, nodeTag)
	buf = append(buf, left...)
	buf = append(buf, right...)
	h := crypto.SHA256(buf)
	out := make([]byte, crypto.HashSize)
	copy(out, h[:])
	return out, nil
}

// computeRoot returns the RFC 6962 root over leaves. Promotes the last
// node at odd-sized levels instead of duplicating.
func computeRoot(leaves [][]byte) [crypto.HashSize]byte {
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		i := 0
		for ; i+1 < len(level); i += 2 {
			h, _ := combine(level[i], level[i+1])
			next = append(next, h)
		}
		if i < len(level) {
			// Promoted node: carries up unchanged.
			next = append(next, level[i])
		}
		level = next
	}
	var out [crypto.HashSize]byte
	if len(level) == 1 {
		copy(out[:], level[0])
	}
	return out
}

// proofPath returns the audit path for leaf at index i, bottom-up. It
// matches the semantics VerifyInclusion consumes: skip promoted levels
// (leaf_index == size-1 when size is odd).
func proofPath(leaves [][]byte, leafIdx int) [][]byte {
	// Copy current level so we can advance.
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	idx := leafIdx
	var audit [][]byte

	for len(level) > 1 {
		size := len(level)
		last := size - 1
		if idx == last && size%2 == 1 {
			// Promoted: no sibling.
		} else {
			var sib []byte
			if idx%2 == 0 {
				sib = level[idx+1]
			} else {
				sib = level[idx-1]
			}
			audit = append(audit, append([]byte(nil), sib...))
		}
		// Build next level.
		next := make([][]byte, 0, (size+1)/2)
		i := 0
		for ; i+1 < size; i += 2 {
			h, _ := combine(level[i], level[i+1])
			next = append(next, h)
		}
		if i < size {
			next = append(next, level[i])
		}
		level = next
		idx /= 2
	}
	return audit
}
