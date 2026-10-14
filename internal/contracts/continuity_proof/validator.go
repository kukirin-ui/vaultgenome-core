// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof

import (
	"bytes"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Validate runs the full structural and cross-field gate over the
// bundle. It does NOT verify cryptographic signatures — see
// VerifySignature for the authority-signature check and Verify for the
// one-call composite gate that runs both plus the embedded per-AGD and
// witness-receipt verifications.
//
// Classification:
//   - Field-shape / schema / cross-field issues → Structural.
//   - Embedded content-address drift, Merkle reconstruction failures,
//     signature mismatches → Integrity (surfaced by the embedded
//     primitive's own Validate).
//   - Tamper signals (e.g. witness log fork indicators) → Incident,
//     also surfaced by the embedded primitive.
func (p ContinuityProof) Validate() error {
	if p.SchemaVersion < SchemaVersionMin || p.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"continuity_proof: schema_version out of supported range",
			nil,
		)
	}
	if p.ProofID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: proof_id required",
			nil,
		)
	}
	if p.Subject.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: subject required",
			nil,
		)
	}
	if p.IssuedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: issued_at required",
			nil,
		)
	}
	if p.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: signing_key_id required",
			nil,
		)
	}
	if len(p.Signature) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: signature required",
			nil,
		)
	}
	if err := p.validateAncestorChain(); err != nil {
		return err
	}
	if err := p.ProbeScorecard.Validate(); err != nil {
		return err
	}
	if err := p.WitnessReceipt.Validate(); err != nil {
		return err
	}
	if err := p.validateCrossBindings(); err != nil {
		return err
	}
	return nil
}

// validateAncestorChain enforces the DAG-linkage invariants over the
// flat pre-order DFS list of AGDs. The embedded per-AGD Validate()
// call picks up the R-14 content-address gate so a tamper on any
// descriptor's bytes is caught.
func (p *ContinuityProof) validateAncestorChain() error {
	if len(p.AncestorChain) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: ancestor_chain must be non-empty",
			nil,
		)
	}
	// Index 0 must be Subject's own AGD.
	if p.AncestorChain[0].GenomeID != p.Subject {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: ancestor_chain[0].genome_id != subject",
			nil,
		)
	}

	// Index AGDs by GenomeID for parent-reference resolution. Validate
	// each one along the way — this runs the R-14 content-address gate
	// (derive ID from canonical bytes, compare to stored).
	byID := make(map[ids.GenomeID]int, len(p.AncestorChain))
	for i := range p.AncestorChain {
		agd := &p.AncestorChain[i]
		if err := agd.Validate(); err != nil {
			return err
		}
		if _, dup := byID[agd.GenomeID]; dup {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"continuity_proof: ancestor_chain contains duplicate genome_id "+agd.GenomeID.String(),
				nil,
			)
		}
		byID[agd.GenomeID] = i
	}

	// Linkage: every non-root AGD's DerivedFrom parent MUST resolve
	// within the chain, and every edge must respect generation
	// monotonicity.
	hasGenesis := false
	for i := range p.AncestorChain {
		agd := &p.AncestorChain[i]
		if len(agd.Provenance.DerivedFrom) == 0 {
			if agd.Generation != 0 {
				return shared_errors.Structural(
					shared_errors.CodeCrossFieldInconsistent,
					"continuity_proof: ancestor_chain["+decStr(i)+"] has no parents but generation != 0",
					nil,
				)
			}
			hasGenesis = true
			continue
		}
		// Has parents: check every one resolves and respects
		// generation monotonicity.
		for _, edge := range agd.Provenance.DerivedFrom {
			pi, ok := byID[edge.ParentGenomeID]
			if !ok {
				return shared_errors.Structural(
					shared_errors.CodeCrossFieldInconsistent,
					"continuity_proof: ancestor_chain["+decStr(i)+"] cites unknown parent "+edge.ParentGenomeID.String(),
					nil,
				)
			}
			parent := &p.AncestorChain[pi]
			if parent.Generation >= agd.Generation {
				return shared_errors.Incident(
					shared_errors.CodeTamperSignal,
					"continuity_proof: generation monotonicity violated at "+agd.GenomeID.String(),
					nil,
				)
			}
			if !isKnownDerivation(edge.Method) {
				return shared_errors.Structural(
					shared_errors.CodeFieldValueInvalid,
					"continuity_proof: unknown derivation_method on edge into "+agd.GenomeID.String(),
					nil,
				)
			}
		}
	}
	if !hasGenesis {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: ancestor_chain must contain at least one generation-0 genesis",
			nil,
		)
	}
	return nil
}

// validateCrossBindings checks the cross-field invariants between
// Subject's AGD, the ProbeScorecard, and the WitnessReceipt. A tamper
// on any one of these three will cause a mismatch here and be
// reported as Structural cross-field.
func (p *ContinuityProof) validateCrossBindings() error {
	subj := &p.AncestorChain[0]

	// Scorecard ↔ Subject AGD
	if p.ProbeScorecard.GenomeID != p.Subject {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: probe_scorecard.genome_id != subject",
			nil,
		)
	}
	if !bytes.Equal(p.ProbeScorecard.BatteryMerkleRoot, subj.BehavioralFingerprint.BatteryMerkleRoot) {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: probe_scorecard.battery_merkle_root != subject.behavioral_fingerprint.battery_merkle_root",
			nil,
		)
	}
	if !bytes.Equal(p.ProbeScorecard.MerkleRoot, subj.BehavioralFingerprint.CanonicalScoresRoot) {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: probe_scorecard.merkle_root != subject.behavioral_fingerprint.canonical_scores_root",
			nil,
		)
	}

	// Witness entry ↔ Subject / scorecard
	entry := &p.WitnessReceipt.Entry
	if entry.GenomeID != p.Subject {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: witness_receipt.entry.genome_id != subject",
			nil,
		)
	}
	if !bytes.Equal(entry.BatteryMerkleRoot, p.ProbeScorecard.BatteryMerkleRoot) {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: witness_receipt.entry.battery_merkle_root != probe_scorecard.battery_merkle_root",
			nil,
		)
	}
	if !bytes.Equal(entry.ScorecardRoot, p.ProbeScorecard.MerkleRoot) {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: witness_receipt.entry.scorecard_root != probe_scorecard.merkle_root",
			nil,
		)
	}

	// Timing: the issuer cannot predate the witness STH it cites.
	if p.IssuedAt.Before(p.WitnessReceipt.STH.Timestamp) {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"continuity_proof: issued_at before witness_receipt.sth.timestamp",
			nil,
		)
	}
	return nil
}

// Verify is the full, one-call gate: structural Validate, then the
// embedded per-AGD signature checks, then the scorecard and witness
// signature checks, then this bundle's own authority signature.
//
// A single Resolver is sufficient iff it is authorized to return keys
// for PurposeSigningAuthority (AGDs, scorecard, this bundle) AND
// PurposeSigningWitness (STH). In the common case the platform's
// keystore satisfies both purposes under one object; nothing in this
// package requires the resolvers to be separate instances.
func (p *ContinuityProof) Verify(resolver keys.Resolver) error {
	// A verifier without keys is a malformed call, refused before any
	// work — never a nil dereference somewhere inside.
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: key resolver required",
			nil,
		)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	// Per-AGD signature re-check. Each AGD's VerifySignature also
	// re-runs its own Validate, which includes R-14 content-address
	// — defense in depth over the pass already done in Validate().
	for i := range p.AncestorChain {
		if err := p.AncestorChain[i].VerifySignature(resolver); err != nil {
			return err
		}
	}
	// Scorecard signature.
	if err := p.ProbeScorecard.VerifySignature(resolver); err != nil {
		return err
	}
	// Witness receipt — reruns internal-consistency Validate and
	// verifies the STH signature under PurposeSigningWitness.
	if err := p.WitnessReceipt.Verify(resolver); err != nil {
		return err
	}
	// Bundle's own authority signature — binds every cross-field
	// relation above to this issuer.
	return p.VerifySignature(resolver)
}

// isKnownDerivation gates edge.Method to the closed doctrinal set.
// Duplicates the membership test the embedded AGD's Validate already
// runs; kept here as defense in depth against a future refactor that
// relaxes the embedded gate.
func isKnownDerivation(m genome_descriptor.DerivationMethod) bool {
	switch m {
	case genome_descriptor.DerivationFineTune,
		genome_descriptor.DerivationDistill,
		genome_descriptor.DerivationMerge,
		genome_descriptor.DerivationQuantize,
		genome_descriptor.DerivationReconstruct:
		return true
	}
	return false
}

// decStr is a dependency-free small-integer→decimal helper for error
// messages. Mirrors the toDec helper in genome_descriptor/validator.go.
func decStr(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
