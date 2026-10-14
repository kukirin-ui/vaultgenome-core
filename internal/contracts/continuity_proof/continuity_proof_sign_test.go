// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/continuity_proof"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- sign / verify round-trip --------------------------------------------

func TestContinuityProof_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)
	require.NotEmpty(t, p.Signature)

	// VerifySignature alone — checks only the outer authority sig.
	require.NoError(t, p.VerifySignature(f.Store))

	// Verify — full composite gate.
	require.NoError(t, p.Verify(f.Store))
}

func TestContinuityProof_SignWith_RefusesMissingKeyID(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)
	p.SigningKeyID = ""
	p.Signature = nil
	err := p.SignWith(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestContinuityProof_SignWith_NilReceiver(t *testing.T) {
	t.Parallel()
	var p *continuity_proof.ContinuityProof
	err := p.SignWith(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// ---- tamper detection ----------------------------------------------------

// Tampering the outer bundle post-sign — e.g. shifting IssuedAt — must
// be caught by the outer Ed25519 signature check with Integrity.
func TestContinuityProof_Verify_TamperedOuterBundleRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)

	p.IssuedAt = p.IssuedAt.Add(time.Hour)
	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// Flipping one bit of the Signature itself — the body still validates
// and cross-binds, but crypto.Verify rejects.
func TestContinuityProof_Verify_FlippedSignatureBitRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)
	p.Signature[0] ^= 0x01
	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// Mutating an AGD covered field post-composition — the embedded AGD's
// own R-14 content-address gate fires first.
func TestContinuityProof_Verify_TamperedAncestorAGDRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)

	// Mutate the parent's FamilyName. The parent AGD's stored GenomeID
	// was content-addressed over the ORIGINAL body; the mutated body
	// derives a different ID ⇒ Integrity.
	p.AncestorChain[1].FamilyName = "adversary-renamed"
	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// Mutating a scorecard entry post-composition — the scorecard's
// MerkleRoot gate fires.
func TestContinuityProof_Verify_TamperedScorecardRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)

	p.ProbeScorecard.Entries[0].ResponseHash[0] ^= 0xFF
	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// Mutating a field inside the witnessed LogEntry — the entry's leaf-
// hash content-address gate fires.
func TestContinuityProof_Verify_TamperedWitnessEntryRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)

	// Flip the last byte of the entry's BatteryMerkleRoot — this drifts
	// canonicalLeafBytes, hence LeafHash, hence the stored-vs-derived
	// integrity gate.
	bb := p.WitnessReceipt.Entry.BatteryMerkleRoot
	bb[len(bb)-1] ^= 0xFF
	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// An STH that commits to another tree after signing — the fixture's
// witness tree has one leaf, so a well-formed forgery moves TreeHash and
// TreeChainHead together — no longer covers the witnessed entry: the
// receipt's chain-head and Merkle gates refuse it (Integrity), and the
// STH signature would fail too (Integrity). Either way, Integrity.
//
// A TreeHash that is all zeros for a non-empty tree, or that differs from
// the chain head of a one-leaf tree, is not a tampered value that fails to
// verify but a value the STH's shape rules exclude before anything is
// verified: that is refused as Structural, the same way a wrong-length
// hash is. Shape gates run before cryptographic ones throughout the
// contracts, on purpose — no verifier runs over input it has not first
// found well formed.
func TestContinuityProof_Verify_TamperedSTHRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)

	forged := repeat(0xAB, len(p.WitnessReceipt.STH.TreeHash))
	p.WitnessReceipt.STH.TreeHash = append([]byte(nil), forged...)
	p.WitnessReceipt.STH.TreeChainHead = append([]byte(nil), forged...)
	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	degenerate := buildProof(t, f)
	degenerate.WitnessReceipt.STH.TreeHash = repeat(0x00, len(degenerate.WitnessReceipt.STH.TreeHash))
	err = degenerate.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

// ---- resolver negatives ---------------------------------------------------

// Handing Verify a resolver that doesn't know the outer authority key
// must surface as Authority (unknown kid).
func TestContinuityProof_Verify_UnknownOuterKeyRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)

	// Build a fresh empty store — no keys at all.
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	empty := keys.NewInMemoryStore(fc)

	err := p.Verify(empty)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

// Verify rejects a nil resolver up front with Structural.
func TestContinuityProof_Verify_NilResolverRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)
	err := p.Verify(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// ---- deterministic signature ----------------------------------------------

// Two bundles built from the same fixture MUST produce the same outer
// signature bytes under a deterministic Ed25519 signer. This is the
// cross-machine reproducibility property that makes stateless
// verification trustworthy.
func TestContinuityProof_Signature_Deterministic(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p1 := buildProof(t, f)

	p2 := buildProof(t, f)
	require.Equal(t, p1.Signature, p2.Signature,
		"canonical encoding + deterministic Ed25519 ⇒ identical signatures across runs")
}

// ---- defensive sanity -----------------------------------------------------

// A bundle built with a ProofID that changes between SignWith and
// Verify must fail. (Same machinery as tampered outer, but exercised
// through a different field.)
func TestContinuityProof_Verify_ProofIDSwapRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)
	p.ProofID = ids.ContinuityProofID("proof-ADVERSARY")
	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}
