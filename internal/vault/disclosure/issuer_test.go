// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/disclosure"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- helper: construct an Issuer wired to f ---------------------------------

// newIssuer constructs a disclosure.Issuer driven by the fixture's
// clock, wired to f.AGDStore and f.Log, and signing under kidAuthority.
func newIssuer(t *testing.T, f fixture, opts disclosure.Options) *disclosure.Issuer {
	t.Helper()
	iss, err := disclosure.NewIssuer(
		f.Clock,
		f.Keystore,
		f.Keystore,
		kidAuthority,
		f.AGDStore,
		f.Log,
		opts,
	)
	require.NoError(t, err)
	return iss
}

// issueParamsFrom builds a fresh IssueParams pointing at f's subject.
// Tests clone this and mutate one field to exercise negative paths.
func issueParamsFrom(f fixture) disclosure.IssueParams {
	return disclosure.IssueParams{
		GenomeID:    f.Subject.GenomeID,
		Scorecard:   *f.Scorecard,
		Attestation: *f.Attestation,
	}
}

// ---- constructor validation ------------------------------------------------

func TestNewIssuer_RejectsNilClock(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := disclosure.NewIssuer(nil, f.Keystore, f.Keystore, kidAuthority, f.AGDStore, f.Log, disclosure.Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewIssuer_RejectsNilSigner(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := disclosure.NewIssuer(f.Clock, nil, f.Keystore, kidAuthority, f.AGDStore, f.Log, disclosure.Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewIssuer_RejectsNilResolver(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := disclosure.NewIssuer(f.Clock, f.Keystore, nil, kidAuthority, f.AGDStore, f.Log, disclosure.Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewIssuer_RejectsZeroSigningKID(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := disclosure.NewIssuer(f.Clock, f.Keystore, f.Keystore, ids.KeyID(""), f.AGDStore, f.Log, disclosure.Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewIssuer_RejectsNilAGDStore(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := disclosure.NewIssuer(f.Clock, f.Keystore, f.Keystore, kidAuthority, nil, f.Log, disclosure.Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewIssuer_RejectsNilLog(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, err := disclosure.NewIssuer(f.Clock, f.Keystore, f.Keystore, kidAuthority, f.AGDStore, nil, disclosure.Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// Empty options ⇒ DefaultIDPrefix applied.
func TestNewIssuer_DefaultPrefixApplied(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})
	proof, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(proof.ProofID.String(), disclosure.DefaultIDPrefix),
		"default prefix should be applied when opts.IDPrefix is empty; got %q", proof.ProofID)
}

// Custom prefix propagates.
func TestNewIssuer_CustomPrefixApplied(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{IDPrefix: "continuity-eu1-"})
	proof, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(proof.ProofID.String(), "continuity-eu1-"),
		"custom prefix should be applied; got %q", proof.ProofID)
}

// ---- happy path ------------------------------------------------------------

// Issue returns a bundle whose Verify passes and whose cross-field
// bindings are correct.
func TestIssuer_Issue_HappyPath(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})

	proof, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Full gate — validates structure + verifies every embedded
	// signature + checks outer authority sig.
	require.NoError(t, proof.Verify(f.Keystore))

	// Cross-checks we promised in the contract.
	require.Equal(t, f.Subject.GenomeID, proof.Subject)
	require.Len(t, proof.AncestorChain, 2)
	require.Equal(t, f.Subject.GenomeID, proof.AncestorChain[0].GenomeID)
	require.Equal(t, f.Parent.GenomeID, proof.AncestorChain[1].GenomeID)
	require.Equal(t, f.Subject.GenomeID, proof.WitnessReceipt.Entry.GenomeID)
	require.Equal(t, f.Parent.GenomeID, proof.WitnessReceipt.Entry.ParentGenomeID,
		"witness entry must cite subject's canonical parent")
	require.Equal(t, genome_descriptor.DerivationFineTune, proof.WitnessReceipt.Entry.DerivationMethod)
}

// Monotonic ProofIDs across a sequence of Issues from the same issuer.
func TestIssuer_Issue_ProofIDsMonotonic(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})

	p1, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)
	p2, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)
	p3, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)

	require.NotEqual(t, p1.ProofID, p2.ProofID)
	require.NotEqual(t, p2.ProofID, p3.ProofID)
	// Fixed-width hex counter ⇒ strict lexicographic order.
	require.True(t, p1.ProofID < p2.ProofID, "%q < %q", p1.ProofID, p2.ProofID)
	require.True(t, p2.ProofID < p3.ProofID, "%q < %q", p2.ProofID, p3.ProofID)

	// Each proof verifies independently.
	require.NoError(t, p1.Verify(f.Keystore))
	require.NoError(t, p2.Verify(f.Keystore))
	require.NoError(t, p3.Verify(f.Keystore))
}

// A genesis AGD (Generation=0, no DerivedFrom) issues a proof whose
// witness entry is a genesis witnessing — empty ParentGenomeID and
// DerivationMethod.
func TestIssuer_Issue_GenesisSubjectProducesGenesisWitnessEntry(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Build a fresh independent genesis AGD. Reuses the fixture's
	// battery/scorecard machinery so we don't rebuild the world.
	batteryRoot := append([]byte(nil), f.Battery.MerkleRoot...)
	entries := scoreEntriesFor(f.Battery)
	scoreRoot := deriveScoreRoot(t, entries)

	genesis := agdSkeleton("root-genome", 0, batteryRoot, scoreRoot)
	signAGD(t, f.Keystore, &genesis)
	putAGD(t, f.AGDStore, &genesis)

	scorecard := signedScorecard(t, f.Keystore, genesis.GenomeID, f.Battery.Name, batteryRoot, entries, issuerEpoch.Add(-30*time.Minute))
	attestation := signedAttestation(t, f.Keystore,
		genesis.GenomeID, f.Battery.Name, batteryRoot, scorecard.MerkleRoot,
		issuerEpoch.Add(-45*time.Minute),
		issuerEpoch.Add(-35*time.Minute),
		issuerEpoch.Add(-25*time.Minute),
	)

	iss := newIssuer(t, f, disclosure.Options{})
	proof, err := iss.Issue(disclosure.IssueParams{
		GenomeID:    genesis.GenomeID,
		Scorecard:   *scorecard,
		Attestation: *attestation,
	})
	require.NoError(t, err)
	require.NoError(t, proof.Verify(f.Keystore))

	require.Len(t, proof.AncestorChain, 1)
	require.Equal(t, genesis.GenomeID, proof.AncestorChain[0].GenomeID)
	require.True(t, proof.WitnessReceipt.Entry.ParentGenomeID.IsZero(),
		"genesis witnessing must leave parent empty")
	require.Equal(t, genome_descriptor.DerivationMethod(""), proof.WitnessReceipt.Entry.DerivationMethod)
}

// Three-generation chain: Grandparent → Parent → Subject.
// AncestorChain layout is flat pre-order DFS: [Subject, Parent, Grandparent].
func TestIssuer_Issue_MultiGenerationChain(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	batteryRoot := append([]byte(nil), f.Battery.MerkleRoot...)

	// Grandparent — genesis, distinct score root so its GenomeID is unique.
	gpScoreRoot := repeat(0xE2, 32)
	grandparent := agdSkeleton("ancient-family", 0, batteryRoot, gpScoreRoot)
	signAGD(t, f.Keystore, &grandparent)
	putAGD(t, f.AGDStore, &grandparent)

	// Parent — generation 1, DerivedFrom grandparent.
	parentScoreRoot := repeat(0xE3, 32)
	parent := agdSkeleton("mid-family", 1, batteryRoot, parentScoreRoot)
	parent.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: grandparent.GenomeID, Method: genome_descriptor.DerivationFineTune},
	}
	signAGD(t, f.Keystore, &parent)
	putAGD(t, f.AGDStore, &parent)

	// Subject — generation 2, DerivedFrom parent.
	entries := scoreEntriesFor(f.Battery)
	scoreRoot := deriveScoreRoot(t, entries)
	subject := agdSkeleton("descendant-llm", 2, batteryRoot, scoreRoot)
	subject.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: parent.GenomeID, Method: genome_descriptor.DerivationFineTune},
	}
	signAGD(t, f.Keystore, &subject)
	putAGD(t, f.AGDStore, &subject)

	scorecard := signedScorecard(t, f.Keystore, subject.GenomeID, f.Battery.Name, batteryRoot, entries, issuerEpoch.Add(-30*time.Minute))
	attestation := signedAttestation(t, f.Keystore,
		subject.GenomeID, f.Battery.Name, batteryRoot, scorecard.MerkleRoot,
		issuerEpoch.Add(-45*time.Minute),
		issuerEpoch.Add(-35*time.Minute),
		issuerEpoch.Add(-25*time.Minute),
	)

	iss := newIssuer(t, f, disclosure.Options{})
	proof, err := iss.Issue(disclosure.IssueParams{
		GenomeID:    subject.GenomeID,
		Scorecard:   *scorecard,
		Attestation: *attestation,
	})
	require.NoError(t, err)
	require.NoError(t, proof.Verify(f.Keystore))

	require.Len(t, proof.AncestorChain, 3)
	require.Equal(t, subject.GenomeID, proof.AncestorChain[0].GenomeID)
	require.Equal(t, parent.GenomeID, proof.AncestorChain[1].GenomeID)
	require.Equal(t, grandparent.GenomeID, proof.AncestorChain[2].GenomeID)
}

// ---- input validation on Issue --------------------------------------------

func TestIssuer_Issue_ZeroGenomeID(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})
	p := issueParamsFrom(f)
	p.GenomeID = ""
	_, err := iss.Issue(p)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// Drop the subject AGD (but keep the scorecard and attestation pointing
// at its id) and confirm the store-lookup surfaces as Authority.
func TestIssuer_Issue_SubjectMissingFromStore_SurfacesAuthority(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Build a brand new scorecard+attestation bound to an id that
	// deliberately has no AGD in the store.
	batteryRoot := append([]byte(nil), f.Battery.MerkleRoot...)
	entries := scoreEntriesFor(f.Battery)

	// Construct a plausible-looking AGD but DO NOT put it in the store.
	scoreRoot := deriveScoreRoot(t, entries)
	orphan := agdSkeleton("orphan-family", 0, batteryRoot, scoreRoot)
	signAGD(t, f.Keystore, &orphan)
	// Intentionally skip putAGD(orphan).

	scorecard := signedScorecard(t, f.Keystore, orphan.GenomeID, f.Battery.Name, batteryRoot, entries, issuerEpoch.Add(-30*time.Minute))
	attestation := signedAttestation(t, f.Keystore,
		orphan.GenomeID, f.Battery.Name, batteryRoot, scorecard.MerkleRoot,
		issuerEpoch.Add(-45*time.Minute),
		issuerEpoch.Add(-35*time.Minute),
		issuerEpoch.Add(-25*time.Minute),
	)

	iss := newIssuer(t, f, disclosure.Options{})
	_, err := iss.Issue(disclosure.IssueParams{
		GenomeID:    orphan.GenomeID,
		Scorecard:   *scorecard,
		Attestation: *attestation,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err),
		"absent subject in AGD CAS must surface as Authority")
}

func TestIssuer_Issue_ScorecardGenomeMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})
	p := issueParamsFrom(f)
	// Point scorecard at parent instead of subject; re-sign so the
	// scorecard itself remains self-valid. The issuer's cross-binding
	// check fires.
	p.Scorecard.GenomeID = f.Parent.GenomeID
	p.Scorecard.Signature = nil
	require.NoError(t, p.Scorecard.SignWith(f.Keystore))
	_, err := iss.Issue(p)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestIssuer_Issue_AttestationGenomeMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})
	p := issueParamsFrom(f)
	p.Attestation.GenomeID = f.Parent.GenomeID
	p.Attestation.Signature = nil
	require.NoError(t, p.Attestation.SignWith(f.Keystore))
	_, err := iss.Issue(p)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestIssuer_Issue_AttestationBatteryRootMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})
	p := issueParamsFrom(f)
	// Flip the attestation's battery root so it no longer matches the
	// scorecard's. Re-sign to isolate the issuer gate.
	bogus := repeat(0x77, 32)
	p.Attestation.BatteryMerkleRoot = bogus
	p.Attestation.Signature = nil
	require.NoError(t, p.Attestation.SignWith(f.Keystore))
	_, err := iss.Issue(p)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestIssuer_Issue_AttestationScorecardRootMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})
	p := issueParamsFrom(f)
	p.Attestation.ScorecardRoot = repeat(0x55, 32)
	p.Attestation.Signature = nil
	require.NoError(t, p.Attestation.SignWith(f.Keystore))
	_, err := iss.Issue(p)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// Tamper the scorecard's signature (flip a byte) — issuer's
// VerifySignature rejects before committing to the log.
func TestIssuer_Issue_ScorecardSignatureTampered(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})
	p := issueParamsFrom(f)
	p.Scorecard.Signature[0] ^= 0xFF
	_, err := iss.Issue(p)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestIssuer_Issue_AttestationSignatureTampered(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})
	p := issueParamsFrom(f)
	p.Attestation.Signature[0] ^= 0xFF
	_, err := iss.Issue(p)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// Scorecard's BatteryMerkleRoot disagrees with the subject AGD's
// BehavioralFingerprint.BatteryMerkleRoot — the issuer's subject-
// binding gate surfaces this as Structural cross-field.
func TestIssuer_Issue_ScorecardBatteryRootMismatchesSubjectAGD(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Rebuild the subject AGD + scorecard + attestation so the
	// scorecard's BatteryMerkleRoot is NOT the one baked into the
	// subject's behavioral fingerprint, but everything else cross-binds.
	batteryRoot := append([]byte(nil), f.Battery.MerkleRoot...)
	entries := scoreEntriesFor(f.Battery)
	scoreRoot := deriveScoreRoot(t, entries)

	// Subject AGD with a DIFFERENT battery root embedded. Its GenomeID
	// is content-addressed over this divergent root, so store.Get still
	// works — the cross-binding check in the issuer is what fails.
	bogusBattery := repeat(0x66, 32)
	subject := agdSkeleton("divergent-llm", 0, bogusBattery, scoreRoot)
	signAGD(t, f.Keystore, &subject)
	putAGD(t, f.AGDStore, &subject)

	// Scorecard + attestation cross-bind on batteryRoot (the real one,
	// different from the one the AGD embeds).
	scorecard := signedScorecard(t, f.Keystore, subject.GenomeID, f.Battery.Name, batteryRoot, entries, issuerEpoch.Add(-30*time.Minute))
	attestation := signedAttestation(t, f.Keystore,
		subject.GenomeID, f.Battery.Name, batteryRoot, scorecard.MerkleRoot,
		issuerEpoch.Add(-45*time.Minute),
		issuerEpoch.Add(-35*time.Minute),
		issuerEpoch.Add(-25*time.Minute),
	)

	iss := newIssuer(t, f, disclosure.Options{})
	_, err := iss.Issue(disclosure.IssueParams{
		GenomeID:    subject.GenomeID,
		Scorecard:   *scorecard,
		Attestation: *attestation,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

// ---- emitted proof is tamper-evident ---------------------------------------

// Mutating the emitted IssuedAt post-Issue breaks outer authority
// signature — Integrity, as documented in the contract's Verify.
func TestIssuer_EmittedProof_TamperedIssuedAtRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})

	proof, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)

	proof.IssuedAt = proof.IssuedAt.Add(time.Hour)
	err = proof.Verify(f.Keystore)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// Bob (receiver-side) verifies with an empty keystore — no keys — must
// surface as Authority on the first signature check.
func TestIssuer_EmittedProof_VerifyFailsWithUnknownKeys(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss := newIssuer(t, f, disclosure.Options{})

	proof, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)

	empty := keys.NewInMemoryStore(shared_time.NewFakeClock(issuerEpoch))
	err = proof.Verify(empty)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}
