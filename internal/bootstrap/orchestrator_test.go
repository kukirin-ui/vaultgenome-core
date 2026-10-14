// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- test fixtures -------------------------------------------------------

const (
	testSessionID     = ids.SessionID("sess-recv-0001")
	testManifestID    = ids.ManifestID("mani-recv-0001")
	testBootstrapID   = ids.BootstrapManifestID("boot-recv-0001")
	testGenomeID      = ids.GenomeID("agd-recv-0001")
	testPolicyVersion = ids.PolicyVersion("policy-v3")
	testRecipientKID  = ids.KeyID("recipient-1")
	testReleaseKID    = ids.KeyID("vault-auth-1")
	testRecvAuthKID   = ids.KeyID("recv-auth-1")
	testAuditKID      = ids.KeyID("recv-audit-1")
)

func testClock() shared_time.Clock {
	return shared_time.NewFakeClock(time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC))
}

// testKeyStores returns a single InMemoryStore registering the three
// keys the orchestrator needs: release-side authority (to sign the
// source-side DisclosureMessages in tests), receive-side authority
// (for BootstrapManifest and outgoing ReceivedDisclosure /
// ReconstitutionDecision), and receive-side audit.
func testKeyStore(t *testing.T) *keys.InMemoryStore {
	t.Helper()
	s := keys.NewInMemoryStore(testClock())

	_, err := s.GenerateSigning(testReleaseKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = s.GenerateSigning(testRecvAuthKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = s.GenerateSigning(testAuditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	return s
}

// testDisclosures builds a parallel pair: N DisclosureMessages signed
// under the release-side authority + their canonical-cover SHA-256
// hashes (which the receive-side orchestrator will verify against).
//
// The sealed payload is intentionally non-empty but not decrypted
// here — the orchestrator does not open the seal; it only verifies
// the wire envelope.
func testDisclosures(t *testing.T, store keys.Signer, count int) ([]disclosure_message.DisclosureMessage, [][]byte) {
	t.Helper()
	msgs := make([]disclosure_message.DisclosureMessage, count)
	hashes := make([][]byte, count)
	issued := time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC)
	for i := 0; i < count; i++ {
		did := ids.DisclosureID("disc-" + positionLabel(i))
		cid := ids.ComponentID("comp-" + positionLabel(i))
		msgs[i] = disclosure_message.DisclosureMessage{
			SchemaVersion:  disclosure_message.SchemaVersionCurrent,
			DisclosureID:   did,
			SessionID:      testSessionID,
			ComponentID:    cid,
			PolicyVersion:  testPolicyVersion,
			SequenceIndex:  uint32(i),
			SealedPayload:  []byte("sealed-" + positionLabel(i)),
			Nonce:          bytes.Repeat([]byte{byte(i + 1)}, disclosure_message.GCMNonceSize),
			RecipientKeyID: testRecipientKID,
			AuthorizedAt:   issued.Add(time.Duration(i) * time.Second),
			SigningKeyID:   testReleaseKID,
		}
		require.NoError(t, msgs[i].SignWith(store))
		cb, err := msgs[i].CanonicalBytes()
		require.NoError(t, err)
		h := crypto.SHA256Slice(cb)
		hashes[i] = h
	}
	return msgs, hashes
}

// testManifests builds a matched pair: a receive-side BootstrapManifest
// + a release-side ReconstructionJobManifest that agree on every
// field, covering `count` disclosures.
func testManifests(t *testing.T, store keys.Signer, disclosureIDs []ids.DisclosureID, componentIDs []ids.ComponentID) (*bootstrap_manifest.BootstrapManifest, *reconstruction_job_manifest.ReconstructionJobManifest) {
	t.Helper()
	issued := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	deadline := issued.Add(2 * time.Hour)

	b := &bootstrap_manifest.BootstrapManifest{
		SchemaVersion:         bootstrap_manifest.SchemaVersionCurrent,
		BootstrapID:           testBootstrapID,
		SessionID:             testSessionID,
		ManifestID:            testManifestID,
		GenomeID:              testGenomeID,
		PolicyVersion:         testPolicyVersion,
		ExpectedDisclosureIDs: append([]ids.DisclosureID(nil), disclosureIDs...),
		ExpectedComponentIDs:  append([]ids.ComponentID(nil), componentIDs...),
		Deadline:              deadline,
		IssuedAt:              issued,
		SigningKeyID:          testRecvAuthKID,
	}
	require.NoError(t, b.SignWith(store))

	r := &reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             testManifestID,
		SessionID:              testSessionID,
		GenomeID:               testGenomeID,
		PolicyVersion:          testPolicyVersion,
		DisclosureIDs:          append([]ids.DisclosureID(nil), disclosureIDs...),
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 1 << 20,
		RecipientKeyID:         testRecipientKID,
		Deadline:               deadline,
		IssuedAt:               issued,
		SigningKeyID:           testReleaseKID,
		Signature:              []byte{0x01}, // signed on the release side; not verified here
	}
	return b, r
}

// newTestOrchestrator builds a fully wired orchestrator + fixtures
// ready for Start(). N controls the number of disclosures.
func newTestOrchestrator(t *testing.T, count int) (*Orchestrator, []disclosure_message.DisclosureMessage, *bootstrap_manifest.BootstrapManifest, *reconstruction_job_manifest.ReconstructionJobManifest, chain.Chain) {
	t.Helper()
	store := testKeyStore(t)

	msgs, hashes := testDisclosures(t, store, count)

	disclosureIDs := make([]ids.DisclosureID, count)
	componentIDs := make([]ids.ComponentID, count)
	for i := 0; i < count; i++ {
		disclosureIDs[i] = msgs[i].DisclosureID
		componentIDs[i] = msgs[i].ComponentID
	}
	bm, rjm := testManifests(t, store, disclosureIDs, componentIDs)

	ch := chain.NewInMemoryChain()
	o, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            bm,
		JobManifest:         rjm,
		ExpectedWireHashes:  hashes,
		AuditChain:          ch,
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.NoError(t, err)
	return o, msgs, bm, rjm, ch
}

// ---- constructor refusals ------------------------------------------------

func TestNewOrchestrator_MissingManifest(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	_, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            nil,
		JobManifest:         &reconstruction_job_manifest.ReconstructionJobManifest{},
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestNewOrchestrator_MissingJobManifest(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	_, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            &bootstrap_manifest.BootstrapManifest{},
		JobManifest:         nil,
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestNewOrchestrator_MissingAuditChain(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	_, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            &bootstrap_manifest.BootstrapManifest{},
		JobManifest:         &reconstruction_job_manifest.ReconstructionJobManifest{},
		AuditChain:          nil,
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestNewOrchestrator_MissingAuditSigner(t *testing.T) {
	t.Parallel()
	_, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            &bootstrap_manifest.BootstrapManifest{},
		JobManifest:         &reconstruction_job_manifest.ReconstructionJobManifest{},
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         nil,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: testKeyStore(t),
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestNewOrchestrator_MissingRecvAuthSigner(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	_, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            &bootstrap_manifest.BootstrapManifest{},
		JobManifest:         &reconstruction_job_manifest.ReconstructionJobManifest{},
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: nil,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestNewOrchestrator_MissingClock(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	_, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            &bootstrap_manifest.BootstrapManifest{},
		JobManifest:         &reconstruction_job_manifest.ReconstructionJobManifest{},
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               nil,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestNewOrchestrator_WireHashesLenMismatch(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	msgs, hashes := testDisclosures(t, store, 3)
	disclosureIDs := []ids.DisclosureID{msgs[0].DisclosureID, msgs[1].DisclosureID, msgs[2].DisclosureID}
	componentIDs := []ids.ComponentID{msgs[0].ComponentID, msgs[1].ComponentID, msgs[2].ComponentID}
	bm, rjm := testManifests(t, store, disclosureIDs, componentIDs)

	_, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            bm,
		JobManifest:         rjm,
		ExpectedWireHashes:  hashes[:2], // short
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestNewOrchestrator_WireHashWrongLength(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	msgs, _ := testDisclosures(t, store, 1)
	disclosureIDs := []ids.DisclosureID{msgs[0].DisclosureID}
	componentIDs := []ids.ComponentID{msgs[0].ComponentID}
	bm, rjm := testManifests(t, store, disclosureIDs, componentIDs)

	_, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            bm,
		JobManifest:         rjm,
		ExpectedWireHashes:  [][]byte{[]byte("too-short")},
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

// ---- start / happy path ---------------------------------------------------

func TestOrchestrator_Start_OK(t *testing.T) {
	t.Parallel()
	o, _, _, _, _ := newTestOrchestrator(t, 3)
	require.Equal(t, StateUnstarted, o.State())
	require.NoError(t, o.Start())
	require.Equal(t, StateIngress, o.State())
}

func TestOrchestrator_Start_Twice(t *testing.T) {
	t.Parallel()
	o, _, _, _, _ := newTestOrchestrator(t, 3)
	require.NoError(t, o.Start())
	err := o.Start()
	require.Error(t, err)
	require.Equal(t, CodeAlreadyStarted, shared_errors.CodeOf(err))
}

// TestOrchestrator_Start_AgreementFail verifies that a mismatched
// cross-manifest pair is refused at Start — no session leak into the
// ingress phase.
func TestOrchestrator_Start_AgreementFail(t *testing.T) {
	t.Parallel()
	o, _, _, rjm, _ := newTestOrchestrator(t, 3)
	// Mutate the release-side manifest after construction to break
	// agreement. The orchestrator holds the pointer, so the mutation
	// is visible.
	rjm.SessionID = ids.SessionID("sess-xxxx")
	err := o.Start()
	require.Error(t, err)
	require.Equal(t, CodeAgreementSessionMismatch, shared_errors.CodeOf(err))
	require.Equal(t, StateUnstarted, o.State(), "refusal must not advance state")
}

// TestOrchestrator_HappyPath_FullAcceptance runs the complete accepted
// flow end-to-end: Start → 3× Accept → MarkReassembled → MarkValidated
// → Decide. Asserts every ReceivedDisclosure is audit-bound, the
// terminal decision is accepted, and the audit chain verifies.
func TestOrchestrator_HappyPath_FullAcceptance(t *testing.T) {
	t.Parallel()
	o, msgs, bm, _, ch := newTestOrchestrator(t, 3)

	require.NoError(t, o.Start())

	for i, msg := range msgs {
		rd, err := o.Accept(&msg)
		require.NoErrorf(t, err, "Accept #%d", i)
		require.NotNil(t, rd)
		require.Equal(t, bm.BootstrapID, rd.BootstrapID)
		require.Equal(t, bm.SessionID, rd.SessionID)
		require.Equal(t, msg.DisclosureID, rd.DisclosureID)
		require.Equal(t, msg.ComponentID, rd.ComponentID)
		require.Equal(t, uint32(i), rd.SequenceIndex)
		require.Len(t, rd.WireHash, crypto.HashSize)
		require.NotEmpty(t, rd.Signature)
		require.NotEmpty(t, rd.AuditEventID, "every accepted disclosure must be audit-bound")
	}

	require.Equal(t, StateReassemble, o.State())
	require.Len(t, o.Received(), 3)

	require.NoError(t, o.MarkReassembled())
	require.Equal(t, StateValidate, o.State())

	vrid := ids.ValidationResultID("vr-recv-0001")
	require.NoError(t, o.MarkValidated(vrid))
	require.Equal(t, StateReady, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.NotNil(t, dec)
	require.True(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReconstructedOK, dec.Reason)
	require.Equal(t, vrid, dec.ValidationResultID)
	require.NotEmpty(t, dec.AuditEventID)
	require.NotEmpty(t, dec.Signature)
	require.Equal(t, StateReconstituted, o.State())

	// Receive-side audit chain sanity: 3 DISCLOSURE_RECEIVED + 1
	// RECONSTITUTION_DECIDED = 4 events. Every accepted event is
	// chained and verifies under the audit resolver.
	require.Equal(t, 4, ch.Len())
	resolver, ok := o.auditSigner.(keys.Resolver)
	require.True(t, ok, "InMemoryStore must implement keys.Resolver")
	require.NoError(t, ch.Verify(resolver))
}

// TestOrchestrator_AuditChainVerifies runs the happy path and verifies
// the full audit chain under a resolver that has the audit key
// registered.
func TestOrchestrator_AuditChainVerifies(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, ch := newTestOrchestrator(t, 2)
	// Re-fetch the store the orchestrator is using — in these fixtures
	// NewTestOrchestrator shares it. Get it indirectly via a fresh
	// store is wrong; we can't verify through a different store
	// because the audit keys are process-local. So we reuse the same
	// store via a closure over o.auditSigner (which is a *InMemoryStore).
	require.NoError(t, o.Start())
	for _, msg := range msgs {
		_, err := o.Accept(&msg)
		require.NoError(t, err)
	}
	require.NoError(t, o.MarkReassembled())
	require.NoError(t, o.MarkValidated(ids.ValidationResultID("vr-0001")))
	_, err := o.Decide()
	require.NoError(t, err)

	// The audit signer also satisfies Resolver in the InMemoryStore case.
	resolver, ok := o.auditSigner.(keys.Resolver)
	require.True(t, ok, "InMemoryStore must implement keys.Resolver")
	require.NoError(t, ch.Verify(resolver))
}

// ---- accept refusal paths -------------------------------------------------

func TestOrchestrator_Accept_BeforeStartRefused(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	_, err := o.Accept(&msgs[0])
	require.Error(t, err)
	require.Equal(t, CodeAcceptWrongState, shared_errors.CodeOf(err))
}

func TestOrchestrator_Accept_NilMessage(t *testing.T) {
	t.Parallel()
	o, _, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	_, err := o.Accept(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestOrchestrator_Accept_SessionMismatch(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	msg := msgs[0]
	msg.SessionID = ids.SessionID("sess-other")
	// We don't re-sign: the canonical-bytes hash now diverges from
	// the expected wire-hash, which is itself a structural refusal —
	// either path latches rejection. The orchestrator's per-field
	// session check would also catch it; what matters here is that the
	// state machine correctly transitions to Rejected on ANY refusal.
	_, err := o.Accept(&msg)
	require.Error(t, err)
	require.Equal(t, StateRejected, o.State())
}

func TestOrchestrator_Accept_PolicyMismatch(t *testing.T) {
	t.Parallel()
	// Build an orchestrator with a specific policy, then submit a
	// disclosure that validates fine but carries a different policy
	// version.
	store := testKeyStore(t)
	msgs, hashes := testDisclosures(t, store, 1)
	// Mutate the message to use a different policy then re-sign.
	msgs[0].PolicyVersion = ids.PolicyVersion("policy-other")
	msgs[0].Signature = nil
	require.NoError(t, msgs[0].SignWith(store))
	// Recompute hash so it matches the new signed payload.
	cb, err := msgs[0].CanonicalBytes()
	require.NoError(t, err)
	hashes[0] = crypto.SHA256Slice(cb)

	bm, rjm := testManifests(t, store, []ids.DisclosureID{msgs[0].DisclosureID}, []ids.ComponentID{msgs[0].ComponentID})
	o, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            bm,
		JobManifest:         rjm,
		ExpectedWireHashes:  hashes,
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.NoError(t, err)
	require.NoError(t, o.Start())

	_, err = o.Accept(&msgs[0])
	require.Error(t, err)
	require.Equal(t, CodeAcceptPolicyMismatch, shared_errors.CodeOf(err))
	require.Equal(t, StateRejected, o.State())
}

func TestOrchestrator_Accept_UnknownDisclosureID(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	msgs, hashes := testDisclosures(t, store, 1)
	// Build a manifest with a different expected DisclosureID.
	bm, rjm := testManifests(t, store,
		[]ids.DisclosureID{ids.DisclosureID("disc-expected")},
		[]ids.ComponentID{msgs[0].ComponentID})
	o, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            bm,
		JobManifest:         rjm,
		ExpectedWireHashes:  hashes,
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.NoError(t, err)
	require.NoError(t, o.Start())

	_, err = o.Accept(&msgs[0])
	require.Error(t, err)
	require.Equal(t, CodeAcceptDisclosureNotExpected, shared_errors.CodeOf(err))
	require.Equal(t, StateRejected, o.State())
}

// TestOrchestrator_Accept_OutOfOrder swaps two disclosures' arrival
// order. The second disclosure (by manifest position) shows up first —
// the orchestrator MUST refuse because order is semantically
// significant (doctrine §3).
func TestOrchestrator_Accept_OutOfOrder(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 2)
	require.NoError(t, o.Start())

	// Present msg[1] where msg[0] is expected.
	_, err := o.Accept(&msgs[1])
	require.Error(t, err)
	require.Equal(t, CodeAcceptOutOfOrder, shared_errors.CodeOf(err))
	require.Equal(t, StateRejected, o.State())
}

// TestOrchestrator_Accept_WireHashMismatch simulates an in-flight
// message tampering: the receive-side's expected hash doesn't match
// what actually arrives. This is the CRITICAL doctrine test — without
// it, identity preservation cannot be asserted.
func TestOrchestrator_Accept_WireHashMismatch(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	msgs, hashes := testDisclosures(t, store, 1)
	// Poison the expected hash — the orchestrator now "expects" a
	// different message than what arrives. This is the structural
	// stand-in for "an observer holding both ledgers detects a wire
	// mismatch."
	hashes[0][0] ^= 0xFF

	bm, rjm := testManifests(t, store,
		[]ids.DisclosureID{msgs[0].DisclosureID},
		[]ids.ComponentID{msgs[0].ComponentID})
	o, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            bm,
		JobManifest:         rjm,
		ExpectedWireHashes:  hashes,
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.NoError(t, err)
	require.NoError(t, o.Start())

	_, err = o.Accept(&msgs[0])
	require.Error(t, err)
	require.Equal(t, CodeAcceptWireHashMismatch, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
		"wire-hash mismatch is an integrity signal, not a structural one")
	require.Equal(t, StateRejected, o.State())
}

// TestOrchestrator_Accept_ComponentMismatch verifies the parallel
// ExpectedComponentIDs list is enforced.
func TestOrchestrator_Accept_ComponentMismatch(t *testing.T) {
	t.Parallel()
	store := testKeyStore(t)
	msgs, hashes := testDisclosures(t, store, 1)
	bm, rjm := testManifests(t, store,
		[]ids.DisclosureID{msgs[0].DisclosureID},
		[]ids.ComponentID{ids.ComponentID("comp-other")})
	o, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            bm,
		JobManifest:         rjm,
		ExpectedWireHashes:  hashes,
		AuditChain:          chain.NewInMemoryChain(),
		AuditSigner:         store,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: store,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.NoError(t, err)
	require.NoError(t, o.Start())

	_, err = o.Accept(&msgs[0])
	require.Error(t, err)
	require.Equal(t, CodeAcceptComponentMismatch, shared_errors.CodeOf(err))
	require.Equal(t, StateRejected, o.State())
}

// ---- mark* state-machine refusals ----------------------------------------

func TestOrchestrator_MarkReassembled_WrongState(t *testing.T) {
	t.Parallel()
	o, _, _, _, _ := newTestOrchestrator(t, 1)
	// Call before Start.
	err := o.MarkReassembled()
	require.Error(t, err)
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
}

func TestOrchestrator_MarkValidated_WrongState(t *testing.T) {
	t.Parallel()
	o, _, _, _, _ := newTestOrchestrator(t, 1)
	err := o.MarkValidated(ids.ValidationResultID("vr-0001"))
	require.Error(t, err)
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
}

func TestOrchestrator_MarkValidated_EmptyVRID(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.NoError(t, o.MarkReassembled())
	err = o.MarkValidated("")
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// ---- rejection paths -----------------------------------------------------

// TestOrchestrator_MarkReassemblyFailed_DecideEmitsRejection runs the
// reassembly-failed rejection path end-to-end.
func TestOrchestrator_MarkReassemblyFailed_DecideEmitsRejection(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, ch := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.Equal(t, StateReassemble, o.State())

	require.NoError(t, o.MarkReassemblyFailed())
	require.Equal(t, StateRejected, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReassemblyFailed, dec.Reason)
	require.NotEmpty(t, dec.AuditEventID)
	require.NotEmpty(t, dec.ValidationResultID,
		"contract validator requires ValidationResultID even for reassembly_failed — we mint a sentinel")

	// Audit chain still verifies despite the rejection path:
	// DISCLOSURE_RECEIVED × 1 + RECONSTITUTION_DECIDED × 1 = 2 events.
	require.Equal(t, 2, ch.Len())
	resolver, ok := o.auditSigner.(keys.Resolver)
	require.True(t, ok)
	require.NoError(t, ch.Verify(resolver))
}

// TestOrchestrator_MarkValidationFailed_DecideEmitsRejection runs the
// validation-failed rejection path end-to-end.
func TestOrchestrator_MarkValidationFailed_DecideEmitsRejection(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.NoError(t, o.MarkReassembled())

	vrid := ids.ValidationResultID("vr-recv-failed-001")
	require.NoError(t, o.MarkValidationFailed(vrid))
	require.Equal(t, StateRejected, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonValidationFailed, dec.Reason)
	require.Equal(t, vrid, dec.ValidationResultID,
		"validation_failed decisions preserve the VRID that refused them")
}

// TestOrchestrator_AcceptRefusal_DecideEmitsRejection runs the
// accept-refusal rejection path — an out-of-order disclosure
// latches reassembly_failed, and the caller must still call Decide
// to obtain the signed rejection artifact.
func TestOrchestrator_AcceptRefusal_DecideEmitsRejection(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 2)
	require.NoError(t, o.Start())

	_, err := o.Accept(&msgs[1])
	require.Error(t, err)
	require.Equal(t, StateRejected, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReassemblyFailed, dec.Reason)
}

// ---- decide refusals -----------------------------------------------------

func TestOrchestrator_Decide_WrongState(t *testing.T) {
	t.Parallel()
	o, _, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	_, err := o.Decide()
	require.Error(t, err)
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
}

func TestOrchestrator_Decide_Twice(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.NoError(t, o.MarkReassembled())
	require.NoError(t, o.MarkValidated(ids.ValidationResultID("vr-0001")))
	_, err = o.Decide()
	require.NoError(t, err)
	_, err = o.Decide()
	require.Error(t, err)
	require.Equal(t, CodeAlreadyDecided, shared_errors.CodeOf(err))
}

// ---- invariants ---------------------------------------------------------

// TestOrchestrator_InvariantMirror_ValidationPrecedesDecide asserts
// the receive-side mirror of release-side invariant #5: validation
// precedes release. A ReconstitutionDecision's ValidationResultID is
// always populated after Decide, either as the caller-supplied VRID
// (happy path, validation-failed path) or a bootstrap-bound sentinel
// (reassembly-failed path).
func TestOrchestrator_InvariantMirror_ValidationPrecedesDecide(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.NoError(t, o.MarkReassembled())
	require.NoError(t, o.MarkValidated(ids.ValidationResultID("vr-0001")))
	dec, err := o.Decide()
	require.NoError(t, err)
	require.NotEmpty(t, dec.ValidationResultID)
}

// TestOrchestrator_InvariantMirror_AuditFirstClass asserts the
// receive-side mirror of release-side invariant #8: every authority
// decision has an audit event appended BEFORE the decision becomes
// visible. The ReceivedDisclosure returned by Accept and the
// ReconstitutionDecision returned by Decide both carry a
// non-empty AuditEventID.
func TestOrchestrator_InvariantMirror_AuditFirstClass(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, ch := newTestOrchestrator(t, 2)
	require.NoError(t, o.Start())

	for _, msg := range msgs {
		rd, err := o.Accept(&msg)
		require.NoError(t, err)
		require.NotEmpty(t, rd.AuditEventID,
			"every ReceivedDisclosure must be bound to a DISCLOSURE_RECEIVED audit event")
	}
	require.NoError(t, o.MarkReassembled())
	require.NoError(t, o.MarkValidated(ids.ValidationResultID("vr-0001")))
	dec, err := o.Decide()
	require.NoError(t, err)
	require.NotEmpty(t, dec.AuditEventID,
		"the ReconstitutionDecision must be bound to a RECONSTITUTION_DECIDED audit event")

	// The audit chain must contain the three events in canonical
	// order: two DISCLOSURE_RECEIVED (one per Accept) followed by one
	// RECONSTITUTION_DECIDED. The audit-first-class discipline
	// requires that each audit append is committed BEFORE the
	// corresponding artifact is returned to the caller, which is why
	// the chain length is fully deterministic at this point.
	require.Equal(t, 3, ch.Len(),
		"expected 2 DISCLOSURE_RECEIVED + 1 RECONSTITUTION_DECIDED = 3 audit events")
	events := ch.Events()
	require.Equal(t, audit_event.KindDisclosureReceived, events[0].Kind)
	require.Equal(t, audit_event.KindDisclosureReceived, events[1].Kind)
	require.Equal(t, audit_event.KindReconstitutionDecided, events[2].Kind)

	// Audit chain must verify under the shared in-memory store.
	resolver, ok := o.auditSigner.(keys.Resolver)
	require.True(t, ok)
	require.NoError(t, ch.Verify(resolver),
		"audit-first-class means the chain is always internally consistent — "+
			"if verification fails here, some path bypassed the audit append")
}
