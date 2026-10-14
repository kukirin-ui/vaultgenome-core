// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure

import (
	"encoding/hex"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/continuity_proof"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/probe_battery"
	witness_contract "github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/genome/store"
	"github.com/vault-genome/vaultgenome-core/internal/genome/succession"
	witness_op "github.com/vault-genome/vaultgenome-core/internal/genome/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// DefaultIDPrefix is prepended to a monotonic counter when an Issuer
// generates a ContinuityProofID. Production deployments may override to
// embed a deployment tag (e.g. "proof-eu1-").
const DefaultIDPrefix = "proof-"

// Options configures an Issuer. Zero values fall back to package defaults.
type Options struct {
	// IDPrefix is prepended to the monotonic counter when generating
	// ContinuityProofIDs. Defaults to DefaultIDPrefix ("proof-").
	IDPrefix string
}

// Issuer composes, signs, and emits ContinuityProof bundles for a given
// Subject. It is the authority-side implementer of Staged Disclosure for
// continuity claims — receiver-side verification is implemented by
// ContinuityProof.Verify and does not depend on this package.
//
// # Doctrinal role
//
// The issuer is the ONLY object in the platform that (a) reads the AGD
// content-addressed store to extract a full DAG ancestor chain, (b)
// binds that chain to a signed scorecard and a signed probe
// attestation, and (c) appends a cross-binding entry to the witness
// transparency log. It performs these three steps atomically from the
// caller's perspective: either a fully self-consistent ContinuityProof
// is returned, or nothing is committed to the log and no proof is
// produced.
//
// The issuer does NOT materialize probe inputs, probe outputs, or
// genome weights. The proofs it emits carry only content commitments;
// the heavy bytes live elsewhere in the platform and are referenced
// by hash.
//
// # Concurrency
//
// All public methods hold a single mutex. Fine-grained locking is not
// bought at this layer — the witness log's own lock remains the hot
// path for append-heavy workloads.
type Issuer struct {
	mu sync.Mutex

	clock      shared_time.Clock
	signer     keys.Signer
	resolver   keys.Resolver
	signingKID ids.KeyID

	store store.Store
	log   witness_op.Log

	idPrefix string
	counter  uint64
}

// NewIssuer constructs an Issuer that reads ancestry from agdStore,
// commits cross-binding entries to log, and signs the outer bundle
// under signingKID bound to keys.PurposeSigningAuthority.
//
// clock, signer, resolver, agdStore, log are all required and must be
// non-nil; signingKID must be non-zero. Violating any of these is a
// programming bug, surfaced as a Structural error.
func NewIssuer(
	clock shared_time.Clock,
	signer keys.Signer,
	resolver keys.Resolver,
	signingKID ids.KeyID,
	agdStore store.Store,
	log witness_op.Log,
	opts Options,
) (*Issuer, error) {
	if clock == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure: clock is required",
			nil,
		)
	}
	if signer == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure: signer is required",
			nil,
		)
	}
	if resolver == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure: resolver is required",
			nil,
		)
	}
	if signingKID.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure: signing_key_id is required",
			nil,
		)
	}
	if agdStore == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure: agd store is required",
			nil,
		)
	}
	if log == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure: witness log is required",
			nil,
		)
	}
	prefix := opts.IDPrefix
	if prefix == "" {
		prefix = DefaultIDPrefix
	}
	return &Issuer{
		clock:      clock,
		signer:     signer,
		resolver:   resolver,
		signingKID: signingKID,
		store:      agdStore,
		log:        log,
		idPrefix:   prefix,
	}, nil
}

// IssueParams bundles the caller-supplied inputs for one ContinuityProof.
// Every field is required.
type IssueParams struct {
	// GenomeID names the Subject of the proof — the descendant whose
	// continuity is being attested.
	GenomeID ids.GenomeID

	// Scorecard is the signed behavioral commitment for the Subject.
	// MUST be self-validating (Scorecard.Validate passes) and bound
	// to the Subject's AGD via BatteryMerkleRoot/CanonicalScoresRoot.
	Scorecard probe_battery.Scorecard

	// Attestation is the signed, TEE-witnessed claim that the scorecard
	// was produced by a probe run against the Subject. MUST be
	// self-validating and cross-bound to the scorecard.
	Attestation probe_battery.ProbeAttestation
}

// Issue composes, signs, and returns one ContinuityProof for p.GenomeID.
//
// Side effect: one LogEntry is appended to the witness log, binding
// {Subject, AttestationRoot, BatteryMerkleRoot, ScorecardRoot}. If any
// step after the append fails, the log entry remains — the witness log
// is append-only by design. Callers that cannot tolerate an orphan
// entry should drive Issue only after having verified inputs out of
// band; every validation this method can do BEFORE the append is done
// BEFORE the append.
func (iss *Issuer) Issue(p IssueParams) (*continuity_proof.ContinuityProof, error) {
	if p.GenomeID.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure: genome_id required",
			nil,
		)
	}

	// ---- sanity: scorecard + attestation self-consistency first. ----------

	if err := p.Scorecard.Validate(); err != nil {
		return nil, err
	}
	if err := p.Attestation.Validate(); err != nil {
		return nil, err
	}

	// Signature gate — refuse to commit a witness entry for objects
	// whose outer authority signatures don't check out.
	if err := p.Scorecard.VerifySignature(iss.resolver); err != nil {
		return nil, err
	}
	if err := p.Attestation.VerifySignature(iss.resolver); err != nil {
		return nil, err
	}

	// Cross-binding: scorecard ↔ subject id.
	if p.Scorecard.GenomeID != p.GenomeID {
		return nil, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"disclosure: scorecard.genome_id != subject",
			nil,
		)
	}
	// Cross-binding: attestation ↔ subject id + scorecard roots.
	if p.Attestation.GenomeID != p.GenomeID {
		return nil, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"disclosure: attestation.genome_id != subject",
			nil,
		)
	}
	if !bytesEqual(p.Attestation.BatteryMerkleRoot, p.Scorecard.BatteryMerkleRoot) {
		return nil, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"disclosure: attestation.battery_merkle_root != scorecard.battery_merkle_root",
			nil,
		)
	}
	if !bytesEqual(p.Attestation.ScorecardRoot, p.Scorecard.MerkleRoot) {
		return nil, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"disclosure: attestation.scorecard_root != scorecard.merkle_root",
			nil,
		)
	}

	// ---- serialize state-mutation steps. -----------------------------------

	iss.mu.Lock()
	defer iss.mu.Unlock()

	// Load subject AGD — the content-address gate at store.Get catches a
	// tampered backing store. Unknown id surfaces as Authority.
	subjectAGD, err := iss.store.Get(p.GenomeID)
	if err != nil {
		return nil, err
	}

	// Cross-binding: scorecard ↔ subject AGD's behavioral fingerprint.
	if !bytesEqual(p.Scorecard.BatteryMerkleRoot, subjectAGD.BehavioralFingerprint.BatteryMerkleRoot) {
		return nil, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"disclosure: scorecard.battery_merkle_root != subject.behavioral_fingerprint.battery_merkle_root",
			nil,
		)
	}
	if !bytesEqual(p.Scorecard.MerkleRoot, subjectAGD.BehavioralFingerprint.CanonicalScoresRoot) {
		return nil, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"disclosure: scorecard.merkle_root != subject.behavioral_fingerprint.canonical_scores_root",
			nil,
		)
	}

	// Walk the full ancestor DAG under VerifySignatures — defense in
	// depth on top of the store's R-14 gate. Produces a flat pre-order
	// DFS list (deduplicated) starting with subject at index 0.
	chain, err := iss.loadAncestorChain(subjectAGD)
	if err != nil {
		return nil, err
	}

	// Derive AttestationRoot = SHA-256(canonical attestation bytes). This
	// is the commitment the witness log records alongside the battery
	// and scorecard roots.
	attCanon, err := p.Attestation.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	attestationRoot := crypto.SHA256Slice(attCanon)

	// ---- compose + append the witness entry. -------------------------------

	// Canonical-parent pick: if the subject is a genesis AGD, the
	// witness entry is a genesis witnessing (both ParentGenomeID and
	// DerivationMethod empty). Otherwise pick the first DerivedFrom
	// edge — for merge-parented children, a single log entry can only
	// witness one edge; the AncestorChain itself carries the full DAG.
	var parentID ids.GenomeID
	var method genome_descriptor.DerivationMethod
	if len(subjectAGD.Provenance.DerivedFrom) > 0 {
		parentID = subjectAGD.Provenance.DerivedFrom[0].ParentGenomeID
		method = subjectAGD.Provenance.DerivedFrom[0].Method
	}

	now := iss.clock.Now().UTC()

	entry := witness_contract.LogEntry{
		SchemaVersion:     witness_contract.SchemaVersionCurrent,
		Timestamp:         now,
		GenomeID:          p.GenomeID,
		AttestationRoot:   append([]byte(nil), attestationRoot...),
		BatteryMerkleRoot: append([]byte(nil), p.Scorecard.BatteryMerkleRoot...),
		ScorecardRoot:     append([]byte(nil), p.Scorecard.MerkleRoot...),
		ParentGenomeID:    parentID,
		DerivationMethod:  method,
	}
	committed, err := iss.log.Append(entry)
	if err != nil {
		return nil, err
	}

	// Receipt binds the committed entry to a fresh STH + inclusion path.
	// The STH timestamp is set by the log (its clock, not necessarily
	// this issuer's). A downstream IssuedAt-before-STH mismatch surfaces
	// as Structural in the final Validate() below.
	receipt, err := iss.log.Receipt(committed.Index)
	if err != nil {
		return nil, err
	}

	// ---- compose the outer bundle. ----------------------------------------

	iss.counter++
	proofID := ids.ContinuityProofID(iss.idPrefix + hex.EncodeToString(counterBytes(iss.counter)))

	// IssuedAt never predates the receipt's STH. In the shared-clock
	// case this is a trivial equality; under clock skew between log and
	// issuer we still satisfy the invariant. (Later Validate() would
	// reject the bundle otherwise.)
	issuedAt := now
	if issuedAt.Before(receipt.STH.Timestamp) {
		issuedAt = receipt.STH.Timestamp
	}

	proof := &continuity_proof.ContinuityProof{
		SchemaVersion:  continuity_proof.SchemaVersionCurrent,
		ProofID:        proofID,
		Subject:        p.GenomeID,
		AncestorChain:  chain,
		ProbeScorecard: p.Scorecard,
		WitnessReceipt: *receipt,
		IssuedAt:       issuedAt,
		SigningKeyID:   iss.signingKID,
	}
	if err := proof.SignWith(iss.signer); err != nil {
		return nil, err
	}
	// Post-condition: the bundle we emit MUST be self-consistent. This
	// catches a corner case where the log returned an STH in a clock
	// state inconsistent with the issuer's, or where the subject AGD
	// turned out to have a parent outside the store.
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	return proof, nil
}

// loadAncestorChain builds the flat pre-order DFS list of AGDs that
// forms ContinuityProof.AncestorChain. Index 0 is subject; every
// reachable ancestor appears exactly once; generation monotonicity and
// derivation-method closedness are enforced by the walker.
//
// The resulting slice owns fresh copies — the store's internal bytes
// are not aliased. Callers may mutate the slice freely.
func (iss *Issuer) loadAncestorChain(subject *genome_descriptor.GenomeDescriptor) ([]genome_descriptor.GenomeDescriptor, error) {
	seen := make(map[ids.GenomeID]struct{}, 4)
	chain := make([]genome_descriptor.GenomeDescriptor, 0, 4)
	// Prepopulate with the subject at index 0 — the walker's first
	// visit will be on the subject itself, and we dedup it against
	// this slot.
	chain = append(chain, *subject)
	seen[subject.GenomeID] = struct{}{}

	err := succession.Walk(subject.GenomeID, iss.store, succession.Options{
		VerifySignatures: true,
		Resolver:         iss.resolver,
	}, func(n *succession.Node) error {
		if _, dup := seen[n.GenomeID]; dup {
			return nil
		}
		seen[n.GenomeID] = struct{}{}
		chain = append(chain, *n.Descriptor)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return chain, nil
}

// bytesEqual is a local alias for bytes.Equal that avoids importing
// the "bytes" package for one call. The issuer's file-level import
// list is already heavy; this keeps it unambiguous.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// counterBytes renders a 64-bit counter in big-endian form. The result
// is hex-encoded into the ProofID. Fixed width so proofs sort
// lexicographically by issuance order within one Issuer instance.
func counterBytes(n uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(n & 0xFF)
		n >>= 8
	}
	return b[:]
}
