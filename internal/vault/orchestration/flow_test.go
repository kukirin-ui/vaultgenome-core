// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package orchestration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/release_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	valservice "github.com/vault-genome/vaultgenome-core/internal/validation/service"
	"github.com/vault-genome/vaultgenome-core/internal/vault/incident"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/trust"
)

type harness struct {
	clock     *shared_time.FakeClock
	store     *keys.InMemoryStore
	audit     *keys.InMemoryStore
	chain     chain.Chain
	authority *Authority
	zeroized  int
	peer      trust.Peer
}

const (
	hAuthKID  = ids.KeyID("vault-auth")
	hSealKID  = ids.KeyID("session-sealing")
	hAuditKID = ids.KeyID("vault-audit")
	hPolicy   = ids.PolicyVersion("gate-policy/v1;atol=0.01")
)

func newHarness(t *testing.T, c chain.Chain) *harness {
	t.Helper()
	clock := shared_time.NewFakeClock(time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(clock)
	_, err := store.GenerateSigning(hAuthKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	require.NoError(t, store.GenerateSealing(hSealKID))
	audit := keys.NewInMemoryStore(clock)
	_, err = audit.GenerateSigning(hAuditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)
	if c == nil {
		c = chain.NewInMemoryChain()
	}
	h := &harness{clock: clock, store: store, audit: audit, chain: c}
	h.authority, err = NewAuthority(AuthorityOptions{
		Clock: clock, Signer: store, Sealer: store, Resolver: store, AuthorityKeyID: hAuthKID, RecipientKeyID: hSealKID,
		Audit: c, AuditSigner: audit, AuditKeyID: hAuditKID, PolicyVersion: hPolicy, Profiles: []string{"gate"},
		Zeroizer: incident.ZeroizerFunc(func() { h.zeroized++ }), IDNonce: "t1",
	})
	require.NoError(t, err)
	h.peer = trust.Peer{Provider: tee.ProviderSimulated, Measurement: make([]byte, 32), RemoteAddr: "127.0.0.1:9", EvidenceAt: clock.Now()}
	return h
}

func (h *harness) request(id, profile string) recovery_request.RecoveryRequest {
	return recovery_request.RecoveryRequest{
		SchemaVersion: recovery_request.SchemaVersionCurrent, RequestID: ids.RequestID(id), GenomeID: "genome-abc",
		PolicyProfile: profile, RequesterIdentity: "operator:test", Contour: map[string]string{"bundle": "gen-0.genome"},
		CreatedAt: h.clock.Now(),
	}
}

func kinds(c chain.Chain) []string {
	out := make([]string, 0, c.Len())
	for i := 0; i < c.Len(); i++ {
		e, _ := c.EventAt(i)
		out = append(out, string(e.Kind))
	}
	return out
}

func passDims() map[validation_result.Dimension]valservice.EvaluatedDimension {
	return map[validation_result.Dimension]valservice.EvaluatedDimension{
		validation_result.DimensionSemantic:   {Evaluator: "top1-agreement", Verdict: validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: 1, Threshold: 1}, Detail: []byte(`{"agreed":3,"total":3}`)},
		validation_result.DimensionBehavioral: {Evaluator: "equivalence-ladder", Verdict: validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: 1, Threshold: 1}, Detail: []byte(`{"level":"EXACT"}`)},
	}
}

// The whole flow, stage by stage: every artifact signed under the
// authority key, every decision on the chain before it took effect, the
// chain verifying under the audit key at the end.
func TestFlow_NineStagesOnTheRecord(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	a := h.authority

	f, err := a.Intake(h.request("req-1", "gate"), []byte(`{"job_id":"j1"}`))
	require.NoError(t, err)
	require.Equal(t, StateTrust, f.State())
	require.Equal(t, []string{"REQUEST_RECEIVED"}, kinds(h.chain))

	// Stages must come in order: no session before trust.
	_, err = f.IssueSession(time.Minute)
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))

	dec, err := f.Admit(h.peer, 10*time.Minute)
	require.NoError(t, err)
	require.True(t, dec.Allowed)
	require.NoError(t, dec.Result.VerifySignature(h.store))
	require.Equal(t, StateSession, f.State())

	sess, err := f.IssueSession(10 * time.Minute)
	require.NoError(t, err)
	require.NoError(t, sess.VerifySignature(h.store))
	require.Equal(t, hPolicy, sess.PolicyVersion)
	require.True(t, strings.HasPrefix(sess.SessionID.String(), "ses-t1-"))
	require.Equal(t, StateDisclosure, f.State())

	comps := []Component{
		{ID: "descriptor", Plaintext: []byte(`{"schema":"vault-genome/gate-job/v1"}`)},
		{ID: "adapter/adapter_model.safetensors", Plaintext: []byte("weights")},
	}
	msgs, err := f.Disclose(comps)
	require.NoError(t, err)
	require.Len(t, msgs, 2)
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0}, comps[1].Plaintext, "plaintext is zeroized after sealing")
	for i, m := range msgs {
		require.EqualValues(t, i, m.SequenceIndex)
		require.NoError(t, m.VerifySignature(h.store))
		aad, err := disclosure_message.BuildRecipientAADForMessage(&m)
		require.NoError(t, err)
		pt, err := h.store.Open(hSealKID, m.Nonce, m.SealedPayload, aad)
		require.NoError(t, err, "the recipient key opens the disclosure under its AAD")
		require.NotEmpty(t, pt)
	}
	require.Equal(t, StateDisclosure, f.State())

	deadline := h.clock.Now().Add(5 * time.Minute)
	man, err := f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 666, Deadline: deadline, Detail: []byte(`{"fixtures":3}`)})
	require.NoError(t, err)
	require.NoError(t, man.VerifySignature(h.store))
	require.Equal(t, []ids.DisclosureID{msgs[0].DisclosureID, msgs[1].DisclosureID}, man.DisclosureIDs)
	require.Equal(t, sess.SessionID, man.SessionID)
	require.Equal(t, StateExternalCompute, f.State())

	require.NoError(t, f.CandidateReceived(CandidateRecord{OutputKind: "bytes/fixed-length", Bytes: 666, SHA256: strings.Repeat("a", 64), ProducedAt: h.clock.Now(), WorkerSigningKeyID: "worker-1"}))
	require.Equal(t, StateValidation, f.State())

	vr, err := f.Validate(ValidateParams{Evaluated: passDims()})
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict)
	require.Equal(t, 1.0, vr.Dimensions[validation_result.DimensionOperational].Score, "six operational sub-checks pass on the flow's own artifacts: %+v", vr.Dimensions[validation_result.DimensionOperational].Details)
	require.Equal(t, StateRelease, f.State())

	d, err := f.Decide()
	require.NoError(t, err)
	require.True(t, d.Release)
	require.Equal(t, release_decision.ReasonValidationPass, d.Reason)
	require.Equal(t, vr.ValidationResultID, d.ValidationResultID)
	require.Equal(t, dec.Result.AttestationID, d.AttestationID)
	require.NoError(t, d.VerifySignature(h.store))
	require.Equal(t, StateAudit, f.State())

	final, err := f.Seal()
	require.NoError(t, err)
	require.Equal(t, StateReleaseAuthorized, final)
	require.True(t, f.Ended())

	want := []string{"REQUEST_RECEIVED", "TRUST_EVALUATED", "SESSION_ISSUED", "DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED",
		"MANIFEST_ISSUED", "CANDIDATE_RECEIVED", "VALIDATION_STARTED", "VALIDATION_DIMENSION_EVALUATED", "VALIDATION_DIMENSION_EVALUATED",
		"VALIDATION_DIMENSION_EVALUATED", "VALIDATION_COMPLETED", "RELEASE_DECIDED"}
	require.Equal(t, want, kinds(h.chain))
	require.NoError(t, h.chain.Verify(h.audit))

	// The decision cites the RELEASE_DECIDED event that precedes it.
	last, _ := h.chain.EventAt(h.chain.Len() - 1)
	require.Equal(t, last.EventID, d.AuditEventID)
	require.Equal(t, f.Request().RequestID, last.RequestID)

	v := f.Snapshot()
	require.Equal(t, StateReleaseAuthorized, v.State)
	require.Len(t, v.Steps, 10)
	require.Len(t, v.Disclosures, 2)
	require.NotEmpty(t, v.Disclosures[0].AuditEventID)
	require.NotNil(t, v.Decision)
	require.NotEmpty(t, v.AuditTip)
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"state":"release_authorized"`)
	require.NotContains(t, string(raw), "sealed_payload", "the view never carries ciphertext")

	// Nothing more is taken from a sealed flow.
	_, err = f.Decide()
	require.Equal(t, CodeFlowEnded, shared_errors.CodeOf(err))
	require.Equal(t, 0, h.zeroized)
}

// Trust denied: a release decision without a session, citing the
// attestation, and the flow terminates without touching the genome.
func TestFlow_TrustDenyIsARecordedRefusal(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	f, err := h.authority.Intake(h.request("req-2", "unknown-profile"), nil)
	require.NoError(t, err)

	dec, err := f.Admit(h.peer, 0)
	require.NoError(t, err)
	require.False(t, dec.Allowed)
	require.Equal(t, trust.ReasonProfileNotServed, dec.Reason)
	require.Equal(t, StateRelease, f.State())

	_, err = f.IssueSession(time.Minute)
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err), "no session after a deny")

	d, err := f.Decide()
	require.NoError(t, err)
	require.False(t, d.Release)
	require.Equal(t, release_decision.ReasonTrustDenied, d.Reason)
	require.Equal(t, dec.Result.AttestationID, d.AttestationID)
	require.Empty(t, d.SessionID)
	require.NoError(t, d.VerifySignature(h.store))

	final, err := f.Seal()
	require.NoError(t, err)
	require.Equal(t, StateIncidentTerminated, final)
	require.Equal(t, []string{"REQUEST_RECEIVED", "TRUST_EVALUATED", "RELEASE_DECIDED"}, kinds(h.chain))
	require.NoError(t, h.chain.Verify(h.audit))
	e, _ := h.chain.EventAt(1)
	require.Contains(t, string(e.Payload), `"outcome":"deny"`)
	require.Contains(t, string(e.Payload), `"reason":"trust.policy_profile_not_served"`)
}

// A failing gate: the refusal is decided, then the R-15 incident closes
// the session on the record.
func TestFlow_RefusedReleaseTerminatesAsAnIncident(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	f := h.driveToValidation(t, "req-3")

	dims := passDims()
	dims[validation_result.DimensionBehavioral] = valservice.EvaluatedDimension{
		Evaluator: "equivalence-ladder",
		Verdict: validation_result.DimensionVerdict{Verdict: validation_result.VerdictFail, Score: 0, Threshold: 1, Details: []validation_result.Finding{
			{Code: "reconstruction_no_door_opened", Severity: validation_result.SeverityError, Message: "no door opened"},
		}},
	}
	vr, err := f.Validate(ValidateParams{Evaluated: dims})
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict)

	d, err := f.Decide()
	require.NoError(t, err)
	require.False(t, d.Release)
	require.Equal(t, release_decision.ReasonValidationFail, d.Reason)

	final, err := f.Seal()
	require.NoError(t, err)
	require.Equal(t, StateIncidentTerminated, final)

	got := kinds(h.chain)
	require.Equal(t, []string{"VALIDATION_FINDING", "VALIDATION_COMPLETED", "RELEASE_DECIDED", "INCIDENT_DETECTED", "SESSION_INVALIDATED", "INCIDENT_TERMINATED"}, got[len(got)-6:])
	require.NoError(t, h.chain.Verify(h.audit))

	v := f.Snapshot()
	require.NotNil(t, v.Incident)
	require.Equal(t, "validation_hard_fail", v.Incident.Scenario)
	require.Equal(t, "error", v.Incident.Severity)
	require.True(t, v.Incident.SessionInvalidated)
	require.Equal(t, session_object.StateInvalidated, v.Session.State)
	require.Equal(t, 0, h.zeroized, "an Error incident wipes no keys")

	// The invalidation is correlated to the flow's request and manifest.
	inv, _ := h.chain.EventAt(h.chain.Len() - 2)
	require.Equal(t, f.Request().RequestID, inv.RequestID)
	require.Equal(t, f.ManifestID(), inv.ManifestID)
}

// A flow that cannot reach its decision is aborted: an incident for an
// integrity failure, the session invalidated, the machine terminated.
func TestFlow_AbortRecordsAndTerminates(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	f := h.driveToValidation(t, "req-4")

	require.NoError(t, f.Abort("judge", shared_errors.Integrity("gate_output_invalid", "not an answer", nil)))
	require.Equal(t, StateIncidentTerminated, f.State())
	got := kinds(h.chain)
	require.Equal(t, []string{"CANDIDATE_RECEIVED", "INCIDENT_DETECTED", "SESSION_INVALIDATED"}, got[len(got)-3:])
	require.NoError(t, h.chain.Verify(h.audit))
	v := f.Snapshot()
	require.NotNil(t, v.Abort)
	require.True(t, v.Abort.Incident)
	require.Equal(t, "gate_output_invalid", v.Abort.Code)
	require.Equal(t, session_object.StateInvalidated, v.Session.State)
	require.NoError(t, f.Abort("again", errors.New("x")), "a second abort is a no-op")

	// An operational failure before any session records nothing but the
	// termination.
	g, err := h.authority.Intake(h.request("req-5", "gate"), nil)
	require.NoError(t, err)
	n := h.chain.Len()
	require.NoError(t, g.Abort("dispatch", shared_errors.Operational("worker_gone", "no worker", nil)))
	require.Equal(t, n, h.chain.Len())
	require.Equal(t, StateIncidentTerminated, g.State())
}

// A chain that refuses a record stops the stage: nothing moves.
func TestFlow_AuditFailureStopsTheStage(t *testing.T) {
	t.Parallel()
	fc := &flakyChain{Chain: chain.NewInMemoryChain()}
	h := newHarness(t, fc)
	f, err := h.authority.Intake(h.request("req-6", "gate"), nil)
	require.NoError(t, err)

	fc.fail = true
	_, err = f.Admit(h.peer, 0)
	require.Error(t, err)
	require.Equal(t, CodeAuditUnavailable, shared_errors.CodeOf(err))
	require.Equal(t, StateTrust, f.State(), "the machine did not move")
	require.Equal(t, 1, fc.Len())

	fc.fail = false
	_, err = f.Admit(h.peer, 0)
	require.NoError(t, err)
	require.Equal(t, StateSession, f.State())

	fc.fail = true
	_, err = h.authority.Intake(h.request("req-7", "gate"), nil)
	require.Equal(t, CodeAuditUnavailable, shared_errors.CodeOf(err))
}

func TestNewAuthority_RefusesMissingWiring(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	base := AuthorityOptions{
		Clock: h.clock, Signer: h.store, Sealer: h.store, Resolver: h.store, AuthorityKeyID: hAuthKID, RecipientKeyID: hSealKID,
		Audit: h.chain, AuditSigner: h.audit, AuditKeyID: hAuditKID, PolicyVersion: hPolicy, Profiles: []string{"gate"},
		Zeroizer: incident.ZeroizerFunc(func() {}),
	}
	_, err := NewAuthority(base)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*AuthorityOptions){
		"clock":      func(o *AuthorityOptions) { o.Clock = nil },
		"audit":      func(o *AuthorityOptions) { o.Audit = nil },
		"policy":     func(o *AuthorityOptions) { o.PolicyVersion = "" },
		"zeroizer":   func(o *AuthorityOptions) { o.Zeroizer = nil },
		"profiles":   func(o *AuthorityOptions) { o.Profiles = nil },
		"recipient":  func(o *AuthorityOptions) { o.RecipientKeyID = "" },
		"auditkey":   func(o *AuthorityOptions) { o.AuditKeyID = "" },
		"authorizer": func(o *AuthorityOptions) { o.AuthorityKeyID = "" },
	} {
		o := base
		mutate(&o)
		_, err := NewAuthority(o)
		require.Error(t, err, name)
	}
	id, err := MintRequestID()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(id.String(), "req-"))
}

// driveToValidation runs stages 1–6 for a fresh request.
func (h *harness) driveToValidation(t *testing.T, reqID string) *Flow {
	t.Helper()
	f, err := h.authority.Intake(h.request(reqID, "gate"), nil)
	require.NoError(t, err)
	_, err = f.Admit(h.peer, 0)
	require.NoError(t, err)
	_, err = f.IssueSession(10 * time.Minute)
	require.NoError(t, err)
	_, err = f.Disclose([]Component{{ID: "descriptor", Plaintext: []byte("d")}})
	require.NoError(t, err)
	_, err = f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 16, Deadline: h.clock.Now().Add(time.Minute)})
	require.NoError(t, err)
	require.NoError(t, f.CandidateReceived(CandidateRecord{OutputKind: "bytes/fixed-length", Bytes: 16, SHA256: strings.Repeat("b", 64), ProducedAt: h.clock.Now(), WorkerSigningKeyID: "worker-1"}))
	return f
}

// flakyChain refuses appends while fail is set.
type flakyChain struct {
	chain.Chain
	fail bool
}

func (c *flakyChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	if c.fail {
		return audit_event.AuditEvent{}, errors.New("disk full")
	}
	return c.Chain.Append(evt, signer)
}

// The small surfaces: accessors before anything exists, details that are
// not JSON, stages asked out of order, a second disclosure.
func TestFlow_EdgesAndAccessors(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	require.Equal(t, hPolicy, h.authority.PolicyVersion())

	_, err := h.authority.Intake(h.request("req-e1", "gate"), []byte("{not json"))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))

	f, err := h.authority.Intake(h.request("req-e2", "gate"), nil)
	require.NoError(t, err)
	require.Empty(t, f.SessionID())
	require.Empty(t, f.ManifestID())
	require.Nil(t, f.Decision())
	require.False(t, f.Ended())

	// Stages asked out of order are refused without moving the machine.
	_, err = f.Disclose([]Component{{ID: "d", Plaintext: []byte("x")}})
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	_, err = f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 1, Deadline: h.clock.Now().Add(time.Minute)})
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(f.CandidateReceived(CandidateRecord{})))
	_, err = f.Validate(ValidateParams{})
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	_, err = f.Decide()
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	_, err = f.Seal()
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	require.Equal(t, StateTrust, f.State())

	_, err = f.Admit(h.peer, 0)
	require.NoError(t, err)
	_, err = f.IssueSession(time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, f.SessionID())

	// A manifest needs disclosures; disclosures happen once.
	_, err = f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 1, Deadline: h.clock.Now().Add(time.Minute)})
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	_, err = f.Disclose([]Component{{ID: "d", Plaintext: []byte("x")}})
	require.NoError(t, err)
	_, err = f.Disclose([]Component{{ID: "d2", Plaintext: []byte("y")}})
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	_, err = f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 1, Deadline: h.clock.Now().Add(time.Minute), Detail: []byte("nope")})
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	man, err := f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 1, Deadline: h.clock.Now().Add(time.Minute)})
	require.NoError(t, err)
	require.Equal(t, man.ManifestID, f.ManifestID())
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(f.CandidateReceived(CandidateRecord{Detail: []byte("nope")})))
	require.NoError(t, f.CandidateReceived(CandidateRecord{OutputKind: "bytes/fixed-length", Bytes: 1, SHA256: strings.Repeat("c", 64), ProducedAt: h.clock.Now(), WorkerSigningKeyID: "w"}))

	// Only semantic and behavioral can be evaluated outside.
	_, err = f.Validate(ValidateParams{Evaluated: map[validation_result.Dimension]valservice.EvaluatedDimension{
		validation_result.DimensionOperational: {Verdict: validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: 1, Threshold: 1}},
	}})
	require.Error(t, err)
	require.Equal(t, StateValidation, f.State())

	// Empty dims fail closed through the service; the refusal seals.
	vr, err := f.Validate(ValidateParams{})
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict)
	d, err := f.Decide()
	require.NoError(t, err)
	require.False(t, d.Release)
	require.Equal(t, d.DecisionID, f.Decision().DecisionID)
	_, err = f.Seal()
	require.NoError(t, err)
	require.True(t, f.Ended())
	require.Equal(t, "invalid", State(200).String())
}

// What the peer's verifier said beyond the measurement is on the
// TRUST_EVALUATED record: for a confidential GPU worker, the GPUs and the
// verifier's own evaluation of their reports.
func TestFlow_TrustRecordCarriesThePeersDetail(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	f, err := h.authority.Intake(h.request("req-1", "gate"), []byte(`{"job_id":"j1"}`))
	require.NoError(t, err)
	peer := h.peer
	peer.Provider = tee.ProviderAzureCGPU
	peer.Detail = &tee.AttestationDetail{Provider: tee.ProviderAzureCGPU, Product: "Genoa",
		GPUs: []tee.GPUVerdict{{Key: "GPU-0", HWModel: "GH100", DriverVersion: "580.95.05", Issuer: "own evaluation"}}}

	dec, err := f.Admit(peer, 10*time.Minute)
	require.NoError(t, err)
	require.True(t, dec.Allowed)
	e, _ := h.chain.EventAt(1)
	require.Equal(t, "TRUST_EVALUATED", string(e.Kind))
	require.Contains(t, string(e.Payload), `"peer_provider":"azure-cgpu"`)
	// The payload is canonical JSON: keys sorted, the detail's own keys too.
	require.Contains(t, string(e.Payload), `"peer_detail":{"gpus":[{"driver_version":"580.95.05","hw_model":"GH100","issuer":"own evaluation","key":"GPU-0"}],"product":"Genoa","provider":"azure-cgpu"}`)
	var p trustEvaluatedPayload
	require.NoError(t, json.Unmarshal(e.Payload, &p))
	require.Equal(t, peer.Detail, p.PeerDetail)

	// Without more than a measurement, the field is off the record.
	f2, err := h.authority.Intake(h.request("req-2", "gate"), []byte(`{"job_id":"j2"}`))
	require.NoError(t, err)
	_, err = f2.Admit(h.peer, 10*time.Minute)
	require.NoError(t, err)
	e, _ = h.chain.EventAt(3)
	require.Equal(t, "TRUST_EVALUATED", string(e.Kind))
	require.NotContains(t, string(e.Payload), "peer_detail")
}
