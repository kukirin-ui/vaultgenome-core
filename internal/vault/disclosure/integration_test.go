// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_test

// End-to-end integration tests for the release-side continuity flow.
//
// These tests exercise the whole round-trip:
//
//	Alice (vault authority)
//	  ├─ runs disclosure.Issuer
//	  ├─ reads her AGD content-addressed store
//	  ├─ commits to her witness transparency log
//	  └─ emits a signed ContinuityProof
//
//	network / disk
//	  └─ JSON bytes — Alice never hands private state to Bob
//
//	Bob (external verifier)
//	  ├─ holds ONLY the public verifying keys Alice published
//	  ├─ has NO access to Alice's AGD store, signer, or witness log
//	  └─ runs ContinuityProof.Verify
//
// Stateless verification is the keystone property: Bob MUST be able to
// reach a verdict on the proof's integrity and authenticity from the
// bundle bytes plus the set of public keys alone. No side channels.
//
// The adversarial scenarios exercise the three tamper surfaces an MITM
// attacker has against a ContinuityProof in flight:
//
//  1. mutate an ancestor AGD field  → caught by R-14 content-address +
//     outer authority signature (Integrity).
//  2. swap the scorecard             → caught by cross-binding
//     (Structural) before the signature gate runs.
//  3. swap the witness receipt       → caught by cross-binding
//     (Structural) before the signature gate runs.
//
// A fourth scenario models a compromised witness operator running two
// divergent trees under one key — the only single-receipt fork signal
// a receiver cannot detect alone. This matches the doctrinal
// limitation documented on witness.WitnessReceipt: fork detection
// requires OTHER STHs (observer network / gossip). The test records
// the expected two-proof behavior: both proofs individually verify,
// but witness.DetectFork on the two STHs surfaces Incident.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/continuity_proof"
	witness_contract "github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	witness_op "github.com/vault-genome/vaultgenome-core/internal/genome/witness"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/disclosure"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- receiver-only resolver -------------------------------------------------

// receiverResolver is Bob's world: a purely read-side keys.Resolver
// holding the verifying halves of the signing keys Alice published —
// nothing more. No Signer method, no Sealer method, no private key
// material. This is the minimum capability stateless verification
// needs, and the minimum capability an external auditor can
// realistically be trusted with.
type receiverResolver struct {
	vks map[ids.KeyID]keys.VerifyingKey
}

// Resolve mirrors the classification InMemoryStore.Resolve uses so
// that negative paths in Bob's world surface identically — unknown
// kid → Authority, purpose mismatch → Integrity.
func (r *receiverResolver) Resolve(kid ids.KeyID, want keys.Purpose) (keys.VerifyingKey, error) {
	vk, ok := r.vks[kid]
	if !ok {
		return keys.VerifyingKey{}, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"receiver: unknown kid "+kid.String(),
			nil,
		)
	}
	if vk.Purpose != want {
		return keys.VerifyingKey{}, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"receiver: purpose mismatch on resolve",
			nil,
		)
	}
	return vk, nil
}

// publishVKs extracts the three verifying keys Alice would publish
// (authority + runner under PurposeSigningAuthority, witness under
// PurposeSigningWitness) from her keystore and returns them bundled
// for Bob.
func publishVKs(t *testing.T, alice *keys.InMemoryStore) *receiverResolver {
	t.Helper()
	authVK, err := alice.Resolve(kidAuthority, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	runnerVK, err := alice.Resolve(kidRunner, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	witnessVK, err := alice.Resolve(kidWitness, keys.PurposeSigningWitness)
	require.NoError(t, err)
	return &receiverResolver{
		vks: map[ids.KeyID]keys.VerifyingKey{
			kidAuthority: authVK,
			kidRunner:    runnerVK,
			kidWitness:   witnessVK,
		},
	}
}

// ---- happy path: stateless verification -----------------------------------

// Bob holds ONLY the public VKs Alice published. He has no AGD store,
// no witness log, no signer. Verify succeeds off bundle bytes alone.
// This is the keystone property — everything else in this file is
// negative-path stress on it.
func TestE2E_AliceIssues_BobVerifiesWithReceiverOnlyResolver(t *testing.T) {
	t.Parallel()
	alice := newFixture(t)
	iss := newIssuer(t, alice, disclosure.Options{})

	proof, err := iss.Issue(issueParamsFrom(alice))
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Bob's world: only verifying keys, nothing else.
	bob := publishVKs(t, alice.Keystore)
	require.NoError(t, proof.Verify(bob))

	// Sanity: Bob's resolver really is read-only by type — it
	// implements only the Resolver interface.
	var _ keys.Resolver = bob
}

// ---- wire round-trip -------------------------------------------------------

// The proof travels as JSON bytes — the most conservative assumption
// about the transport. After encode → decode, Bob still verifies.
// This validates that CanonicalJSON is stable across marshal/unmarshal
// (field ordering, byte-slice base64, time formatting).
func TestE2E_ProofSurvivesJSONWireRoundTrip(t *testing.T) {
	t.Parallel()
	alice := newFixture(t)
	iss := newIssuer(t, alice, disclosure.Options{})

	proof, err := iss.Issue(issueParamsFrom(alice))
	require.NoError(t, err)

	wire, err := json.Marshal(proof)
	require.NoError(t, err)
	require.NotEmpty(t, wire)

	var decoded continuity_proof.ContinuityProof
	require.NoError(t, json.Unmarshal(wire, &decoded))

	// Cross-field identity survives. (Full byte equality of
	// Signature is the strong check.)
	require.Equal(t, proof.ProofID, decoded.ProofID)
	require.Equal(t, proof.Subject, decoded.Subject)
	require.Equal(t, proof.Signature, decoded.Signature)

	// Canonical cover-bytes are stable — the decoded proof hashes
	// to the same bytes Alice signed.
	original, err := proof.CanonicalBytes()
	require.NoError(t, err)
	roundtrip, err := decoded.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, original, roundtrip,
		"canonical encoding must be stable across JSON round-trip")

	bob := publishVKs(t, alice.Keystore)
	require.NoError(t, decoded.Verify(bob))
}

// ---- adversary: tampered ancestor AGD --------------------------------------

// MITM flips a byte in AncestorChain[1].FamilyName after Alice signed.
// Two gates catch this:
//
//   - the AGD's own R-14 content-address gate (Validate re-derives
//     GenomeID from canonical bytes and compares to stored) — Integrity.
//   - the outer authority signature (if, hypothetically, R-14 missed
//     it) — also Integrity.
//
// Either way, category must be Integrity. Bob's verdict is
// independent of WHICH gate fires first.
func TestE2E_Adversary_TampersAncestorInFlight(t *testing.T) {
	t.Parallel()
	alice := newFixture(t)
	iss := newIssuer(t, alice, disclosure.Options{})

	proof, err := iss.Issue(issueParamsFrom(alice))
	require.NoError(t, err)
	bob := publishVKs(t, alice.Keystore)
	require.NoError(t, proof.Verify(bob), "pre-tamper sanity")

	// Flip a byte in the PARENT AGD (chain[1]) — subject is chain[0]
	// and we want to confirm mutation anywhere along ancestry is
	// caught, not just at index 0.
	proof.AncestorChain[1].FamilyName = "adversary-renamed-parent"

	err = proof.Verify(bob)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
		"mutation of AGD field in flight must surface as Integrity")
}

// Mutating a byte inside the ancestor's signature (as opposed to its
// covered body) — the AGD's own signature fails cryptographically.
// Still Integrity.
func TestE2E_Adversary_FlippedAncestorSignatureBit(t *testing.T) {
	t.Parallel()
	alice := newFixture(t)
	iss := newIssuer(t, alice, disclosure.Options{})

	proof, err := iss.Issue(issueParamsFrom(alice))
	require.NoError(t, err)
	bob := publishVKs(t, alice.Keystore)

	proof.AncestorChain[0].Signature[0] ^= 0x80

	err = proof.Verify(bob)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// ---- adversary: swapped scorecard -----------------------------------------

// Attacker swaps the proof's ProbeScorecard for a legitimately-signed
// scorecard of a DIFFERENT subject. The scorecard itself is
// internally valid — its signature verifies against kidRunner, its
// MerkleRoot derives correctly — but its GenomeID cross-binds to a
// different subject. The cross-binding gate in Validate() catches
// this as Structural BEFORE the signature gate runs.
//
// Doctrine: structural cross-binding is the primary line of defense.
// Signature checks are defense in depth, not the only wall. Bob MUST
// reject as Structural — if he ever saw Integrity here it would mean
// the structural gate had been weakened.
func TestE2E_Adversary_SwapsScorecardFromDifferentSubject(t *testing.T) {
	t.Parallel()
	alice := newFixture(t)
	iss := newIssuer(t, alice, disclosure.Options{})

	// Build an ENTIRELY SEPARATE subject+scorecard so its scorecard's
	// own cross-bindings all pass on their own.
	batteryRoot := append([]byte(nil), alice.Battery.MerkleRoot...)
	otherEntries := scoreEntriesFor(alice.Battery)
	// Divergent score root — different response hashes.
	for i := range otherEntries {
		otherEntries[i].ResponseHash[1] ^= 0x77
	}
	otherScoreRoot := deriveScoreRoot(t, otherEntries)
	otherSubject := agdSkeleton("other-subject-family", 0, batteryRoot, otherScoreRoot)
	signAGD(t, alice.Keystore, &otherSubject)
	// NOTE: we don't Put otherSubject in the store — we only need
	// its GenomeID for the scorecard binding.

	otherScorecard := signedScorecard(
		t, alice.Keystore,
		otherSubject.GenomeID,
		alice.Battery.Name,
		batteryRoot,
		otherEntries,
		issuerEpoch.Add(-30*time.Minute),
	)

	proof, err := iss.Issue(issueParamsFrom(alice))
	require.NoError(t, err)
	bob := publishVKs(t, alice.Keystore)
	require.NoError(t, proof.Verify(bob), "pre-swap sanity")

	// MITM substitutes the scorecard. Signature on the outer bundle
	// would also fail, but the cross-binding gate fires first.
	proof.ProbeScorecard = *otherScorecard

	err = proof.Verify(bob)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err),
		"cross-binding must fire before signature gate; category is Structural")
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

// ---- adversary: swapped witness receipt ------------------------------------

// Attacker swaps the proof's WitnessReceipt for a legitimate receipt
// from a DIFFERENT entry in the SAME log. The receipt's STH signature
// is genuine, its inclusion proof is valid, and its entry's LeafHash
// is correctly content-addressed — but the entry's GenomeID points
// at a different subject. Cross-binding (Entry.GenomeID != Subject)
// catches this as Structural.
//
// This scenario is the closest the attacker can get to "forging
// witnessing" without actually compromising the witness key: they
// can only quote receipts that already exist, and those receipts
// cross-bind to the wrong subject.
func TestE2E_Adversary_SwapsWitnessReceiptFromDifferentEntry(t *testing.T) {
	t.Parallel()
	alice := newFixture(t)
	iss := newIssuer(t, alice, disclosure.Options{})

	// Issue a proof for Alice's subject — this is the one the
	// attacker will tamper with.
	targetProof, err := iss.Issue(issueParamsFrom(alice))
	require.NoError(t, err)

	// Issue ANOTHER proof in the same session, binding a genuinely
	// different subject to the same log — this gives the attacker a
	// well-formed receipt to splice in. Second subject = another
	// independent genesis AGD, its own scorecard/attestation, etc.
	batteryRoot := append([]byte(nil), alice.Battery.MerkleRoot...)
	sideEntries := scoreEntriesFor(alice.Battery)
	for i := range sideEntries {
		sideEntries[i].ResponseHash[2] ^= 0x33
	}
	sideScoreRoot := deriveScoreRoot(t, sideEntries)
	sideSubject := agdSkeleton("side-subject-family", 0, batteryRoot, sideScoreRoot)
	signAGD(t, alice.Keystore, &sideSubject)
	putAGD(t, alice.AGDStore, &sideSubject)
	sideScorecard := signedScorecard(
		t, alice.Keystore,
		sideSubject.GenomeID,
		alice.Battery.Name,
		batteryRoot,
		sideEntries,
		issuerEpoch.Add(-30*time.Minute),
	)
	sideAttestation := signedAttestation(
		t, alice.Keystore,
		sideSubject.GenomeID, alice.Battery.Name,
		batteryRoot, sideScorecard.MerkleRoot,
		issuerEpoch.Add(-45*time.Minute),
		issuerEpoch.Add(-35*time.Minute),
		issuerEpoch.Add(-25*time.Minute),
	)
	sideProof, err := iss.Issue(disclosure.IssueParams{
		GenomeID:    sideSubject.GenomeID,
		Scorecard:   *sideScorecard,
		Attestation: *sideAttestation,
	})
	require.NoError(t, err)

	bob := publishVKs(t, alice.Keystore)
	require.NoError(t, targetProof.Verify(bob), "pre-splice target sanity")
	require.NoError(t, sideProof.Verify(bob), "pre-splice side sanity")

	// MITM splices the side proof's receipt into the target proof.
	targetProof.WitnessReceipt = sideProof.WitnessReceipt

	err = targetProof.Verify(bob)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err),
		"cross-binding witness_receipt.entry.genome_id != subject must be Structural")
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

// ---- adversary: forked witness log -----------------------------------------

// A compromised witness operator runs two divergent trees under one
// signing key. Each tree produces its own STH, each STH is validly
// signed, each inclusion proof against its own tree is correct.
//
// Bob CANNOT detect this given a single proof. That's a documented
// limitation of stateless verification — fork detection requires
// OTHER STHs from the same operator, delivered via gossip or an
// observer network.
//
// This test pins the expected two-proof behavior:
//
//  1. BOTH proofs verify individually under Bob's resolver.
//  2. witness.DetectFork on the two STHs DOES surface evidence,
//     categorized as Incident (same_size_different_root).
//
// In a deployed system this test's scenario would be an Incident
// raised by the observer network, routed to /internal/vault/incident
// for termination handling. The single-receipt path remains
// individually valid.
func TestE2E_ForkedWitnessLog_BothProofsVerify_ForkDetectableAcrossOperators(t *testing.T) {
	t.Parallel()
	// Shared keystore + AGD store + subject — the fork is entirely
	// on the witness side.
	alice := newFixture(t)

	// Two independent logs under the SAME witness kid, each driven
	// by its own clock. Both are honest-looking taken alone — they
	// just happen to commit different first entries, so their
	// Merkle roots at any common TreeSize will differ.
	logA, clkA := newWitnessLog(t, alice.Keystore, issuerEpoch)
	logB, clkB := newWitnessLog(t, alice.Keystore, issuerEpoch)

	// Seed each log with a different unrelated first entry so that
	// TreeHash(size=2) differs across the two logs for any
	// subsequent shared entry.
	seedA := witness_contract.LogEntry{
		SchemaVersion:     witness_contract.SchemaVersionCurrent,
		Timestamp:         issuerEpoch.Add(-5 * time.Minute),
		GenomeID:          alice.Parent.GenomeID, // valid-looking
		AttestationRoot:   repeat(0xAA, 32),
		BatteryMerkleRoot: append([]byte(nil), alice.Battery.MerkleRoot...),
		ScorecardRoot:     repeat(0xA1, 32),
	}
	seedB := witness_contract.LogEntry{
		SchemaVersion:     witness_contract.SchemaVersionCurrent,
		Timestamp:         issuerEpoch.Add(-5 * time.Minute),
		GenomeID:          alice.Parent.GenomeID,
		AttestationRoot:   repeat(0xBB, 32), // DIVERGES from seedA
		BatteryMerkleRoot: append([]byte(nil), alice.Battery.MerkleRoot...),
		ScorecardRoot:     repeat(0xB1, 32),
	}
	_, err := logA.Append(seedA)
	require.NoError(t, err)
	_, err = logB.Append(seedB)
	require.NoError(t, err)

	// Two issuers — one per log — share the AGD store, keystore,
	// and scorecard/attestation. The only difference is which
	// witness log they talk to.
	issA := newIssuerWithLog(t, alice, logA, clkA)
	issB := newIssuerWithLog(t, alice, logB, clkB)

	proofA, err := issA.Issue(issueParamsFrom(alice))
	require.NoError(t, err)
	proofB, err := issB.Issue(issueParamsFrom(alice))
	require.NoError(t, err)

	bob := publishVKs(t, alice.Keystore)

	// Property 1: individually valid. A receiver holding ONLY
	// proofA has no way to tell anything is wrong; same for proofB.
	require.NoError(t, proofA.Verify(bob), "proofA individually valid")
	require.NoError(t, proofB.Verify(bob), "proofB individually valid")

	// STHs must agree on TreeSize (each log has 2 entries) but
	// disagree on TreeHash (the first entries differed).
	require.Equal(t, proofA.WitnessReceipt.STH.TreeSize, proofB.WitnessReceipt.STH.TreeSize,
		"both logs at TreeSize=2 after one seed + one issuer append")
	require.NotEqual(t, proofA.WitnessReceipt.STH.TreeHash, proofB.WitnessReceipt.STH.TreeHash,
		"divergent first entries ⇒ divergent TreeHashes")

	// Property 2: an observer holding BOTH STHs detects the fork.
	// This is the gossip path the single-proof receiver is missing.
	ev, err := witness_contract.DetectFork(
		&proofA.WitnessReceipt.STH,
		&proofB.WitnessReceipt.STH,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, ev, "divergent STHs must surface as fork evidence")
	require.Equal(t, witness_contract.ForkKindSameSizeDifferentRoot, ev.Kind)
	require.True(t, ev.Kind.IsIncident(),
		"same_size_different_root is Incident-class")

	// The evidence renders as an Incident-classified error suitable
	// for incident routing.
	incidentErr := ev.AsError()
	require.Error(t, incidentErr)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(incidentErr),
		"ForkEvidence.AsError of incident-class evidence must classify as Incident")
	require.Equal(t, shared_errors.CodeTamperSignal, shared_errors.CodeOf(incidentErr))
}

// ---- adversary: unknown outer authority key --------------------------------

// Bob's resolver simply doesn't know the kid that signed the outer
// bundle — Alice used a key published only to a different circle.
// Integrity/Structural checks pass (the bundle IS internally
// consistent, and the AGD/scorecard/witness sigs verify under keys
// Bob DOES have), but the outer authority check surfaces Authority
// on the unknown kid.
//
// This is the production failure mode for a receiver not yet
// enrolled in the issuer's trust root.
func TestE2E_Adversary_UnknownOuterAuthorityKey_SurfacesAuthority(t *testing.T) {
	t.Parallel()
	alice := newFixture(t)
	iss := newIssuer(t, alice, disclosure.Options{})

	proof, err := iss.Issue(issueParamsFrom(alice))
	require.NoError(t, err)

	// Bob's world is missing kidAuthority but has kidRunner +
	// kidWitness. Per-AGD checks require kidAuthority (AGDs are
	// signed by the vault authority), so this also surfaces on the
	// AGD signature check. Either way, category is Authority.
	partial := &receiverResolver{
		vks: map[ids.KeyID]keys.VerifyingKey{},
	}
	runnerVK, err := alice.Keystore.Resolve(kidRunner, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	witnessVK, err := alice.Keystore.Resolve(kidWitness, keys.PurposeSigningWitness)
	require.NoError(t, err)
	partial.vks[kidRunner] = runnerVK
	partial.vks[kidWitness] = witnessVK

	err = proof.Verify(partial)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

// ---- helper: issuer bound to a specific witness log -----------------------

// newIssuerWithLog constructs an Issuer wired to a caller-supplied
// log + clock, but sharing Alice's keystore + AGD store. Used by the
// forked-witness-log scenario, where the only per-issuer variation
// is which log each issuer talks to.
func newIssuerWithLog(
	t *testing.T,
	alice fixture,
	log *witness_op.InMemoryLog,
	clock shared_time.Clock,
) *disclosure.Issuer {
	t.Helper()
	iss, err := disclosure.NewIssuer(
		clock,
		alice.Keystore,
		alice.Keystore,
		kidAuthority,
		alice.AGDStore,
		log,
		disclosure.Options{},
	)
	require.NoError(t, err)
	return iss
}
