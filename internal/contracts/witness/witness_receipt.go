// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// WitnessReceipt is the self-contained bundle a disclosure embeds to
// prove that a specific attestation was publicly witnessed.
//
// Bundle contents:
//
//   - Entry — the LogEntry that committed to the attestation.
//   - InclusionProof — audit path from Entry's LeafHash to the STH's
//     TreeHash at a specific TreeSize.
//   - STH — the log operator's signed commitment at that TreeSize.
//
// # Stateless verification
//
// A consumer holding ONLY a WitnessReceipt (no log access, no
// network) can confirm that the receipt is internally consistent:
//
//  1. Entry.Validate() — re-derives LeafHash and EntryID from the
//     payload, catches tamper.
//  2. Entry.Index equals InclusionProof.LeafIndex, and the proof's
//     TreeSize equals the STH's TreeSize — cross-binds the three.
//  3. VerifyInclusion(Entry.LeafHash, InclusionProof, STH.TreeHash)
//     — the proof actually reconstructs the STH's committed root.
//  4. STH.VerifySignature(resolver) — the STH is genuinely from the
//     operator the consumer trusts.
//
// To detect forks the consumer additionally needs access to OTHER
// STHs from the same operator (future phase — or delegated to an
// observer network); but the receipt alone proves "this attestation
// is at this position of THIS operator's log AS OF this STH". That is
// the minimum viable public-witness evidence.
type WitnessReceipt struct {
	// SchemaVersion gates the wire format. Readers MUST validate first.
	SchemaVersion uint16 `json:"schema_version"`

	// Entry is the witnessed LogEntry — carries the attestation commit
	// plus Index/PrevLeafHash/Timestamp/derived LeafHash+EntryID.
	Entry LogEntry `json:"entry"`

	// InclusionProof binds Entry's LeafHash to STH.TreeHash.
	InclusionProof InclusionProof `json:"inclusion_proof"`

	// STH is the log operator's signed tree head that the
	// InclusionProof references.
	STH SignedTreeHead `json:"sth"`
}

// Validate runs the full internal-consistency check described in the
// package doctrine. Does NOT verify the STH signature — that is a
// separate step via VerifySignature, which requires a key resolver.
//
// The checks are in a specific order: cheap structural checks first,
// then cross-field binding, then the Merkle reconstruction. A failure
// at any step is returned immediately with a doctrinally correct
// classification:
//
//   - CategoryStructural for field-shape or cross-field mismatches.
//   - CategoryIntegrity for Merkle reconstruction failures.
func (r *WitnessReceipt) Validate() error {
	if r == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"witness_receipt: nil receiver",
			nil,
		)
	}
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"witness_receipt: schema_version out of supported range",
			nil,
		)
	}
	// Per-component validations — each one is a self-contained gate.
	if err := r.Entry.Validate(); err != nil {
		return err
	}
	if err := r.InclusionProof.Validate(); err != nil {
		return err
	}
	if err := r.STH.Validate(); err != nil {
		return err
	}
	// Cross-field binding: Entry's position MUST agree with the
	// proof's LeafIndex; the proof MUST be for the same tree size as
	// the STH; Entry.Index MUST be < STH.TreeSize (the entry cannot
	// be in a tree smaller than its own position + 1).
	if r.Entry.Index != r.InclusionProof.LeafIndex {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"witness_receipt: entry.index != inclusion_proof.leaf_index",
			nil,
		)
	}
	if r.InclusionProof.TreeSize != r.STH.TreeSize {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"witness_receipt: inclusion_proof.tree_size != sth.tree_size",
			nil,
		)
	}
	if r.Entry.Index >= r.STH.TreeSize {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"witness_receipt: entry.index >= sth.tree_size",
			nil,
		)
	}
	// Timestamp ordering: the STH cannot have been issued before the
	// entry it witnesses (an STH committing to a tree that contains
	// an entry timestamped after the STH itself is nonsensical).
	if r.STH.Timestamp.Before(r.Entry.Timestamp) {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"witness_receipt: sth.timestamp before entry.timestamp",
			nil,
		)
	}
	// If the receipt's STH is for TreeSize == Entry.Index + 1, then
	// the entry IS the last entry in the tree — the STH's
	// TreeChainHead must equal the entry's LeafHash. This is the
	// cheap chain-head sanity check that complements the Merkle
	// proof.
	if r.STH.TreeSize == r.Entry.Index+1 {
		if !bytes.Equal(r.STH.TreeChainHead, r.Entry.LeafHash) {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				"witness_receipt: sth.tree_chain_head != entry.leaf_hash at tail",
				nil,
			)
		}
	}
	// Full Merkle reconstruction — the core inclusion gate.
	if err := VerifyInclusion(r.Entry.LeafHash, &r.InclusionProof, r.STH.TreeHash); err != nil {
		return err
	}
	return nil
}

// VerifySignature verifies the STH signature under keys.PurposeSigningWitness.
// Does NOT re-run Validate — call Validate() first if you need a full
// end-to-end gate. This is deliberately decomposed so that a verifier
// that lacks a key resolver can still run the internal-consistency
// portion of the check.
func (r *WitnessReceipt) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"witness_receipt: key resolver required to verify the signature",
			nil,
		)
	}
	return r.STH.VerifySignature(resolver)
}

// Verify is the one-call-does-everything helper: Validate +
// VerifySignature. Returns the first error encountered. Preferred for
// consumers that have a key resolver and want a single "is this
// receipt trustworthy" answer.
func (r *WitnessReceipt) Verify(resolver keys.Resolver) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return r.VerifySignature(resolver)
}

// UnmarshalJSON rejects unknown fields and gates SchemaVersion. Each
// embedded struct's own UnmarshalJSON is also invoked by the decoder,
// so their unknown-field gates apply transitively.
func (r *WitnessReceipt) UnmarshalJSON(data []byte) error {
	type alias WitnessReceipt
	tmp := (*alias)(r)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"witness_receipt: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"witness_receipt: trailing content after JSON value",
			nil,
		)
	}
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"witness_receipt: schema_version out of supported range",
			nil,
		)
	}
	return nil
}

// Compile-time assertion: the receipt's LeafHash field shape MUST be
// crypto.HashSize bytes — enforced in Entry.Validate() but re-stated
// here as a constant for cross-reference readability.
const _ = crypto.HashSize
