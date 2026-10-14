// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignedTreeHead (STH) is the log operator's periodic commitment to
// the log's entire state at a specific TreeSize.
//
// An STH binds together, under ONE signature:
//
//   - TreeSize  — the number of entries in the log at issuance time.
//   - TreeHash  — the RFC 6962 Merkle root over those TreeSize leaves
//     (an all-zero 32-byte slice when TreeSize == 0).
//   - TreeChainHead — the LeafHash of the last entry, equal to
//     TreeHash when TreeSize == 1 and equal to all-zero when
//     TreeSize == 0. Redundant with the tree commitment (a correct
//     tree always implies a specific chain head), but exposed so a
//     lightweight chain-walker can verify chain continuity without
//     running Merkle math.
//
// # Doctrinal role
//
// External observers RECORD STHs over time. Any attempt to silently
// rewrite the log's history manifests as a FORK: the same operator has
// signed TWO STHs claiming DIFFERENT TreeHash (or TreeChainHead) for
// the SAME TreeSize, OR has signed STHs whose relationship cannot be
// bridged by a ConsistencyProof.
//
// An STH is the atomic unit of "publish this history". Once issued, an
// STH is fact from the log operator's perspective — retraction is
// Incident-class.
type SignedTreeHead struct {
	// SchemaVersion gates the wire format. Readers MUST validate first.
	SchemaVersion uint16 `json:"schema_version"`

	// TreeSize is the number of entries covered by this STH. Zero is
	// legal — it represents the empty log.
	TreeSize uint64 `json:"tree_size"`

	// TreeHash is the RFC 6962 Merkle root over the log's leaves.
	// Exactly 32 bytes. All-zero when TreeSize == 0.
	TreeHash []byte `json:"tree_hash"`

	// TreeChainHead is the LeafHash of the entry at Index TreeSize-1.
	// Exactly 32 bytes. All-zero when TreeSize == 0. For TreeSize == 1,
	// this equals TreeHash.
	TreeChainHead []byte `json:"tree_chain_head"`

	// Timestamp is wall-clock of STH issuance (UTC). STHs issued by the
	// same operator MUST carry monotonically non-decreasing Timestamps
	// as TreeSize grows; a later STH with an older Timestamp is an
	// Incident-class signal.
	Timestamp time.Time `json:"timestamp"`

	// SigningKeyID identifies the log operator's witness key. Binds
	// under keys.PurposeSigningWitness — kept distinct from the
	// authority and audit signing purposes so that a compromise of one
	// cannot forge the others.
	SigningKeyID ids.KeyID `json:"signing_key_id"`

	// Signature is the Ed25519 signature over CanonicalBytes (which
	// excludes Signature itself).
	Signature []byte `json:"signature"`
}

// Validate enforces the structural contract. Does not touch the
// signature — signature verification is VerifySignature's job.
func (s *SignedTreeHead) Validate() error {
	if s == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"sth: nil receiver",
			nil,
		)
	}
	if s.SchemaVersion < SchemaVersionMin || s.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"sth: schema_version out of supported range",
			nil,
		)
	}
	if len(s.TreeHash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"sth: tree_hash must be 32 bytes",
			nil,
		)
	}
	if len(s.TreeChainHead) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"sth: tree_chain_head must be 32 bytes",
			nil,
		)
	}
	// Empty-tree rule: TreeHash and TreeChainHead are both all-zero.
	if s.TreeSize == 0 {
		if !isAllZero(s.TreeHash) {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"sth: tree_hash must be all-zero when tree_size == 0",
				nil,
			)
		}
		if !isAllZero(s.TreeChainHead) {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"sth: tree_chain_head must be all-zero when tree_size == 0",
				nil,
			)
		}
	} else {
		if isAllZero(s.TreeHash) {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"sth: tree_hash must be non-zero when tree_size > 0",
				nil,
			)
		}
		if isAllZero(s.TreeChainHead) {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"sth: tree_chain_head must be non-zero when tree_size > 0",
				nil,
			)
		}
		// Singleton-tree rule: when TreeSize == 1 the Merkle root is
		// defined to equal the single leaf, so TreeHash == TreeChainHead.
		if s.TreeSize == 1 && !bytes.Equal(s.TreeHash, s.TreeChainHead) {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"sth: for tree_size == 1, tree_hash must equal tree_chain_head",
				nil,
			)
		}
	}
	if s.Timestamp.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"sth: timestamp required",
			nil,
		)
	}
	if s.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"sth: signing_key_id required",
			nil,
		)
	}
	if len(s.Signature) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"sth: signature required",
			nil,
		)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature.
//
// STHs use a FIXED binary packing rather than JSON for the cover
// bytes. This keeps the pre-image reproducible across
// implementations that do not share the Go-specific JCS profile, and
// makes the STH cheaper to verify in resource-constrained
// environments (tiny observers, embedded watchdogs).
//
// Layout (fixed, NEVER change):
//
//	 2-byte  big-endian  SchemaVersion
//	 8-byte  big-endian  TreeSize
//	32-byte              TreeHash
//	32-byte              TreeChainHead
//	 8-byte  big-endian  Timestamp UnixNano (UTC)
//	 4-byte  big-endian  len(SigningKeyID)
//	 N-byte              SigningKeyID UTF-8
func (s *SignedTreeHead) CanonicalBytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return sthCoverBytes(s), nil
}

// sthCoverBytes builds the fixed cover bytes WITHOUT calling Validate
// — used by SignWith where the Signature is not yet populated.
func sthCoverBytes(s *SignedTreeHead) []byte {
	kid := []byte(s.SigningKeyID)
	size := 2 + 8 + crypto.HashSize + crypto.HashSize + 8 + 4 + len(kid)
	out := make([]byte, 0, size)

	var u16 [2]byte
	var u32 [4]byte
	var u64 [8]byte

	binary.BigEndian.PutUint16(u16[:], s.SchemaVersion)
	out = append(out, u16[:]...)

	binary.BigEndian.PutUint64(u64[:], s.TreeSize)
	out = append(out, u64[:]...)

	out = append(out, s.TreeHash...)
	out = append(out, s.TreeChainHead...)

	binary.BigEndian.PutUint64(u64[:], uint64(s.Timestamp.UTC().UnixNano()))
	out = append(out, u64[:]...)

	binary.BigEndian.PutUint32(u32[:], uint32(len(kid)))
	out = append(out, u32[:]...)
	out = append(out, kid...)

	return out
}

// SignWith signs the canonical cover bytes under s.SigningKeyID,
// binding to keys.PurposeSigningWitness. Does not call Validate — an
// STH mid-construction may still be populating fields.
func (s *SignedTreeHead) SignWith(signer keys.Signer) error {
	if s == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"sth: nil receiver",
			nil,
		)
	}
	if s.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"sth: signing_key_id required before sign",
			nil,
		)
	}
	if len(s.TreeHash) != crypto.HashSize || len(s.TreeChainHead) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"sth: tree_hash and tree_chain_head required before sign",
			nil,
		)
	}
	cb := sthCoverBytes(s)
	sig, err := signer.Sign(s.SigningKeyID, keys.PurposeSigningWitness, cb)
	if err != nil {
		return err
	}
	s.Signature = sig
	return nil
}

// VerifySignature resolves s.SigningKeyID under
// keys.PurposeSigningWitness and verifies Signature against cover
// bytes. Calls Validate first — cross-field inconsistencies surface
// before signature gate runs.
func (s *SignedTreeHead) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"sth: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := s.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(s.SigningKeyID, keys.PurposeSigningWitness)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, s.Signature)
}

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (s *SignedTreeHead) UnmarshalJSON(data []byte) error {
	type alias SignedTreeHead
	tmp := (*alias)(s)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"sth: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"sth: trailing content after JSON value",
			nil,
		)
	}
	if s.SchemaVersion < SchemaVersionMin || s.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"sth: schema_version out of supported range",
			nil,
		)
	}
	return nil
}

// isAllZero returns true iff b is entirely composed of 0x00 bytes.
// Small helper used by the empty-tree / non-empty-tree rules above.
func isAllZero(b []byte) bool {
	for i := range b {
		if b[i] != 0 {
			return false
		}
	}
	return true
}
