// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// errSignerUnavailable is the sentinel a scripted signer returns when it
// is told to fail. Tests assert it surfaces unchanged through the
// orchestrator so operators see the real cause.
var errSignerUnavailable = errors.New("signer unavailable")

// scriptedSigner wraps a real signer and misbehaves on exactly one Sign
// call (1-based failAt): it either returns errSignerUnavailable or, with
// empty set, a zero-length signature that signs "successfully" but can
// never pass a contract validator. Every other call is delegated.
//
// It deliberately does not implement keys.Resolver, so Start skips the
// manifest signature verification just as it does for any signer-only
// double.
type scriptedSigner struct {
	inner  keys.Signer
	failAt int
	empty  bool
	calls  int
}

func (s *scriptedSigner) Sign(kid ids.KeyID, purpose keys.Purpose, msg []byte) ([]byte, error) {
	s.calls++
	if s.calls == s.failAt {
		if s.empty {
			return []byte{}, nil
		}
		return nil, errSignerUnavailable
	}
	return s.inner.Sign(kid, purpose, msg)
}

// newOrchestratorWithSigners mirrors newTestOrchestrator but lets the
// test substitute the audit and receive-side signers. Both substitutes
// receive the same backing store so the fixtures stay valid.
func newOrchestratorWithSigners(t *testing.T, count int, wrap func(store *keys.InMemoryStore) (audit, recv keys.Signer)) (*Orchestrator, []disclosure_message.DisclosureMessage, chain.Chain) {
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
	audit, recv := wrap(store)
	ch := chain.NewInMemoryChain()
	o, err := NewOrchestrator(OrchestratorOptions{
		Manifest:            bm,
		JobManifest:         rjm,
		ExpectedWireHashes:  hashes,
		AuditChain:          ch,
		AuditSigner:         audit,
		AuditKeyID:          testAuditKID,
		RecvAuthoritySigner: recv,
		RecvAuthorityKeyID:  testRecvAuthKID,
		Clock:               testClock(),
	})
	require.NoError(t, err)
	return o, msgs, ch
}

// forceState moves the orchestrator into a state the public API would
// never produce on its own, so the defensive branches that guard
// against such corruption can be exercised.
func forceState(o *Orchestrator, s State) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.state = s
}

// ---- constructor refusals -------------------------------------------------

// TestNewOrchestrator_MissingKeyIDs proves both signer key identifiers
// are mandatory: a signer without the ID it was registered under could
// never produce a verifiable artifact.
func TestNewOrchestrator_MissingKeyIDs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*OrchestratorOptions)
		wantMsg string
	}{
		{
			name:    "audit key id zero",
			mutate:  func(o *OrchestratorOptions) { o.AuditKeyID = "" },
			wantMsg: "audit_key_id is required",
		},
		{
			name:    "recv authority key id zero",
			mutate:  func(o *OrchestratorOptions) { o.RecvAuthorityKeyID = "" },
			wantMsg: "recv_authority_key_id is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := testKeyStore(t)
			opts := OrchestratorOptions{
				Manifest:            &bootstrap_manifest.BootstrapManifest{},
				JobManifest:         &reconstruction_job_manifest.ReconstructionJobManifest{},
				AuditChain:          chain.NewInMemoryChain(),
				AuditSigner:         store,
				AuditKeyID:          testAuditKID,
				RecvAuthoritySigner: store,
				RecvAuthorityKeyID:  testRecvAuthKID,
				Clock:               testClock(),
			}
			tc.mutate(&opts)
			o, err := NewOrchestrator(opts)
			require.Nil(t, o)
			require.Error(t, err)
			require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// ---- accessors ------------------------------------------------------------

// TestOrchestrator_ReceivedCount_TracksAccepts proves the counter
// follows successful Accept calls exactly and ignores refused ones.
func TestOrchestrator_ReceivedCount_TracksAccepts(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 2)
	require.Equal(t, 0, o.ReceivedCount())
	require.NoError(t, o.Start())
	require.Equal(t, 0, o.ReceivedCount())

	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.Equal(t, 1, o.ReceivedCount())

	_, err = o.Accept(&msgs[1])
	require.NoError(t, err)
	require.Equal(t, 2, o.ReceivedCount())
	require.Len(t, o.Received(), o.ReceivedCount())
}

// TestOrchestrator_Decision_NilUntilDecidedThenCopy proves Decision is
// nil before Decide, equals the artifact Decide returned afterwards,
// and hands out an independent copy each time.
func TestOrchestrator_Decision_NilUntilDecidedThenCopy(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	require.Nil(t, o.Decision())
	require.NoError(t, o.Start())
	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.Nil(t, o.Decision(), "no decision before Decide")
	require.NoError(t, o.MarkReassembled())
	require.NoError(t, o.MarkValidated(ids.ValidationResultID("vr-0001")))

	dec, err := o.Decide()
	require.NoError(t, err)

	got := o.Decision()
	require.NotNil(t, got)
	require.Equal(t, *dec, *got)

	got.Accepted = false
	got.Reason = reconstitution_decision.ReasonValidationFailed
	again := o.Decision()
	require.True(t, again.Accepted, "mutating the returned copy must not touch the stored decision")
	require.Equal(t, reconstitution_decision.ReasonReconstructedOK, again.Reason)
}

// ---- start refusals -------------------------------------------------------

// TestOrchestrator_Start_ManifestValidateRefused proves Start runs the
// BootstrapManifest validator and refuses a malformed manifest without
// leaving StateUnstarted.
func TestOrchestrator_Start_ManifestValidateRefused(t *testing.T) {
	t.Parallel()
	o, _, bm, _, _ := newTestOrchestrator(t, 1)
	bm.GenomeID = ""
	err := o.Start()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), "genome_id required")
	require.Equal(t, StateUnstarted, o.State())
}

// TestOrchestrator_Start_ManifestSignatureRefused proves Start verifies
// the manifest signature under the receive-side authority when the
// signer also resolves keys: a single flipped signature byte is an
// integrity refusal and the state does not advance.
func TestOrchestrator_Start_ManifestSignatureRefused(t *testing.T) {
	t.Parallel()
	o, _, bm, _, _ := newTestOrchestrator(t, 1)
	bm.Signature[0] ^= 0xFF
	err := o.Start()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, StateUnstarted, o.State())
}

// ---- accept refusals ------------------------------------------------------

// TestOrchestrator_Accept_MalformedMessageLatches proves a disclosure
// that fails its own validator is refused with the validator's error,
// latches reassembly_failed, and still yields a signed rejection.
func TestOrchestrator_Accept_MalformedMessageLatches(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, ch := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())

	msg := msgs[0]
	msg.Signature = nil
	rd, err := o.Accept(&msg)
	require.Nil(t, rd)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), "disclosure_message: signature required")
	require.Equal(t, StateRejected, o.State())
	require.Equal(t, 0, o.ReceivedCount())
	require.Equal(t, 0, ch.Len(), "no audit event for a refused disclosure")

	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReassemblyFailed, dec.Reason)
	require.Equal(t, ids.ValidationResultID("vr-recv-noop-"+testBootstrapID.String()), dec.ValidationResultID)
}

// TestOrchestrator_Accept_SequenceMismatch proves a disclosure whose
// SequenceIndex disagrees with its arrival slot is refused even when
// its identifiers are the expected ones.
func TestOrchestrator_Accept_SequenceMismatch(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())

	msg := msgs[0]
	msg.SequenceIndex = 7
	_, err := o.Accept(&msg)
	require.Error(t, err)
	require.Equal(t, CodeAcceptSequenceMismatch, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, StateRejected, o.State())
}

// TestOrchestrator_Accept_MoreThanExpected proves the defensive guard
// against an ingress window that is somehow still open after every
// slot is filled: the extra disclosure is refused as out of order.
func TestOrchestrator_Accept_MoreThanExpected(t *testing.T) {
	t.Parallel()
	o, msgs, _, _, _ := newTestOrchestrator(t, 1)
	require.NoError(t, o.Start())
	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.Equal(t, StateReassemble, o.State())

	forceState(o, StateIngress)
	_, err = o.Accept(&msgs[0])
	require.Error(t, err)
	require.Equal(t, CodeAcceptOutOfOrder, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), "more disclosures than expected")
	require.Equal(t, StateRejected, o.State())
	require.Equal(t, 1, o.ReceivedCount(), "the accepted set must not widen")
}

// TestOrchestrator_Accept_AuditAppendFailure proves an audit-chain
// append failure is terminal: the signer's error surfaces, nothing is
// recorded, and the orchestrator latches rejection.
func TestOrchestrator_Accept_AuditAppendFailure(t *testing.T) {
	t.Parallel()
	o, msgs, ch := newOrchestratorWithSigners(t, 1, func(store *keys.InMemoryStore) (keys.Signer, keys.Signer) {
		return &scriptedSigner{inner: store, failAt: 1}, store
	})
	require.NoError(t, o.Start())

	rd, err := o.Accept(&msgs[0])
	require.Nil(t, rd)
	require.ErrorIs(t, err, errSignerUnavailable)
	require.Equal(t, StateRejected, o.State())
	require.Equal(t, 0, o.ReceivedCount())
	require.Equal(t, 0, ch.Len())
}

// TestOrchestrator_Accept_RecordSignFailure proves that when the
// ReceivedDisclosure cannot be signed after the audit event was
// appended, the event stays in the chain, no record is issued, and the
// orchestrator latches rejection.
func TestOrchestrator_Accept_RecordSignFailure(t *testing.T) {
	t.Parallel()
	o, msgs, ch := newOrchestratorWithSigners(t, 1, func(store *keys.InMemoryStore) (keys.Signer, keys.Signer) {
		return store, &scriptedSigner{inner: store, failAt: 1}
	})
	require.NoError(t, o.Start())

	rd, err := o.Accept(&msgs[0])
	require.Nil(t, rd)
	require.ErrorIs(t, err, errSignerUnavailable)
	require.Equal(t, StateRejected, o.State())
	require.Equal(t, 0, o.ReceivedCount())
	require.Equal(t, 1, ch.Len(), "the DISCLOSURE_RECEIVED event is already committed")
}

// TestOrchestrator_Accept_RecordValidateFailure proves the signed
// record is re-validated before it is surfaced: a signer that returns
// an empty signature is caught by the contract validator.
func TestOrchestrator_Accept_RecordValidateFailure(t *testing.T) {
	t.Parallel()
	o, msgs, ch := newOrchestratorWithSigners(t, 1, func(store *keys.InMemoryStore) (keys.Signer, keys.Signer) {
		return store, &scriptedSigner{inner: store, failAt: 1, empty: true}
	})
	require.NoError(t, o.Start())

	rd, err := o.Accept(&msgs[0])
	require.Nil(t, rd)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), "received_disclosure: signature required")
	require.Equal(t, StateRejected, o.State())
	require.Equal(t, 0, o.ReceivedCount())
	require.Equal(t, 1, ch.Len())
}

// ---- mark* refusals -------------------------------------------------------

// TestOrchestrator_MarkReassemblyFailed_WrongState proves the
// transition is only legal from StateReassemble.
func TestOrchestrator_MarkReassemblyFailed_WrongState(t *testing.T) {
	t.Parallel()
	o, _, _, _, _ := newTestOrchestrator(t, 1)
	err := o.MarkReassemblyFailed()
	require.Error(t, err)
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), StateUnstarted.String())
	require.Equal(t, StateUnstarted, o.State())
}

// TestOrchestrator_MarkValidationFailed_Refusals proves the transition
// is only legal from StateValidate and that the refusing
// ValidationResultID is mandatory.
func TestOrchestrator_MarkValidationFailed_Refusals(t *testing.T) {
	t.Parallel()

	t.Run("wrong state", func(t *testing.T) {
		t.Parallel()
		o, _, _, _, _ := newTestOrchestrator(t, 1)
		require.NoError(t, o.Start())
		err := o.MarkValidationFailed(ids.ValidationResultID("vr-0001"))
		require.Error(t, err)
		require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
		require.Equal(t, StateIngress, o.State())
	})

	t.Run("empty vrid", func(t *testing.T) {
		t.Parallel()
		o, msgs, _, _, _ := newTestOrchestrator(t, 1)
		require.NoError(t, o.Start())
		_, err := o.Accept(&msgs[0])
		require.NoError(t, err)
		require.NoError(t, o.MarkReassembled())
		err = o.MarkValidationFailed("")
		require.Error(t, err)
		require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
		require.Equal(t, StateValidate, o.State(), "a refused call must not latch rejection")
	})
}

// ---- decide refusals ------------------------------------------------------

// TestOrchestrator_Decide_DefensiveStateChecks proves Decide refuses
// to sign a decision whose preconditions were bypassed: StateReady
// without a validated result, or StateRejected without a latched
// reason.
func TestOrchestrator_Decide_DefensiveStateChecks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		state   State
		wantMsg string
	}{
		{name: "ready without vrid", state: StateReady, wantMsg: "without validated ValidationResultID"},
		{name: "rejected without reason", state: StateRejected, wantMsg: "without latched reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o, _, _, _, ch := newTestOrchestrator(t, 1)
			require.NoError(t, o.Start())
			forceState(o, tc.state)
			dec, err := o.Decide()
			require.Nil(t, dec)
			require.Error(t, err)
			require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), tc.wantMsg)
			require.Nil(t, o.Decision())
			require.Equal(t, 0, ch.Len(), "no audit event for a refused decision")
		})
	}
}

// readyOrchestrator drives an orchestrator built with the given signer
// substitutes to StateReady with one accepted disclosure.
func readyOrchestrator(t *testing.T, wrap func(store *keys.InMemoryStore) (audit, recv keys.Signer)) (*Orchestrator, chain.Chain) {
	t.Helper()
	o, msgs, ch := newOrchestratorWithSigners(t, 1, wrap)
	require.NoError(t, o.Start())
	_, err := o.Accept(&msgs[0])
	require.NoError(t, err)
	require.NoError(t, o.MarkReassembled())
	require.NoError(t, o.MarkValidated(ids.ValidationResultID("vr-0001")))
	require.Equal(t, 1, ch.Len())
	return o, ch
}

// TestOrchestrator_Decide_AuditAppendFailure proves a failed
// RECONSTITUTION_DECIDED append leaves no decision behind and keeps
// the orchestrator in StateReady.
func TestOrchestrator_Decide_AuditAppendFailure(t *testing.T) {
	t.Parallel()
	o, ch := readyOrchestrator(t, func(store *keys.InMemoryStore) (keys.Signer, keys.Signer) {
		// The first audit Sign call is the DISCLOSURE_RECEIVED event.
		return &scriptedSigner{inner: store, failAt: 2}, store
	})
	dec, err := o.Decide()
	require.Nil(t, dec)
	require.ErrorIs(t, err, errSignerUnavailable)
	require.Nil(t, o.Decision())
	require.Equal(t, StateReady, o.State())
	require.Equal(t, 1, ch.Len())
}

// TestOrchestrator_Decide_SignFailure proves a decision that cannot be
// signed is not surfaced, although its audit event is already
// committed.
func TestOrchestrator_Decide_SignFailure(t *testing.T) {
	t.Parallel()
	o, ch := readyOrchestrator(t, func(store *keys.InMemoryStore) (keys.Signer, keys.Signer) {
		// The first receive-side Sign call is the ReceivedDisclosure.
		return store, &scriptedSigner{inner: store, failAt: 2}
	})
	dec, err := o.Decide()
	require.Nil(t, dec)
	require.ErrorIs(t, err, errSignerUnavailable)
	require.Nil(t, o.Decision())
	require.Equal(t, StateReady, o.State())
	require.Equal(t, 2, ch.Len(), "the RECONSTITUTION_DECIDED event is already committed")
}

// TestOrchestrator_Decide_ValidateFailure proves the signed decision is
// re-validated before it is surfaced: an empty signature is refused
// by the contract validator.
func TestOrchestrator_Decide_ValidateFailure(t *testing.T) {
	t.Parallel()
	o, _ := readyOrchestrator(t, func(store *keys.InMemoryStore) (keys.Signer, keys.Signer) {
		return store, &scriptedSigner{inner: store, failAt: 2, empty: true}
	})
	dec, err := o.Decide()
	require.Nil(t, dec)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), "reconstitution_decision: signature required")
	require.Nil(t, o.Decision())
	require.Equal(t, StateReady, o.State())
}
