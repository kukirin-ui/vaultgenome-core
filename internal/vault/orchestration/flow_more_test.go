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
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/release_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	valservice "github.com/vault-genome/vaultgenome-core/internal/validation/service"
	"github.com/vault-genome/vaultgenome-core/internal/vault/incident"
	"github.com/vault-genome/vaultgenome-core/internal/vault/intake"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Every required dependency is named in the refusal, and intake options
// are checked through the Authority rather than silently defaulted.
func TestNewAuthority_NamesEachMissingDependency(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	base := AuthorityOptions{
		Clock: h.clock, Signer: h.store, Sealer: h.store, Resolver: h.store, AuthorityKeyID: hAuthKID, RecipientKeyID: hSealKID,
		Audit: h.chain, AuditSigner: h.audit, AuditKeyID: hAuditKID, PolicyVersion: hPolicy, Profiles: []string{"gate"},
		Zeroizer: incident.ZeroizerFunc(func() {}),
	}
	cases := []struct {
		name    string
		mutate  func(*AuthorityOptions)
		code    string
		message string
	}{
		{"signer", func(o *AuthorityOptions) { o.Signer = nil }, shared_errors.CodeRequiredFieldMissing, "signer is required"},
		{"sealer", func(o *AuthorityOptions) { o.Sealer = nil }, shared_errors.CodeRequiredFieldMissing, "sealer is required"},
		{"resolver", func(o *AuthorityOptions) { o.Resolver = nil }, shared_errors.CodeRequiredFieldMissing, "resolver is required"},
		{"audit signer", func(o *AuthorityOptions) { o.AuditSigner = nil }, shared_errors.CodeRequiredFieldMissing, "audit signer is required"},
		{"intake capacity", func(o *AuthorityOptions) { o.Intake = intake.Options{Capacity: -1} }, shared_errors.CodeFieldValueInvalid, "vault/intake"},
		{"intake window", func(o *AuthorityOptions) { o.Intake = intake.Options{Window: -time.Second} }, shared_errors.CodeFieldValueInvalid, "vault/intake"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mutate(&o)
			a, err := NewAuthority(o)
			require.Nil(t, a)
			require.Error(t, err)
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Contains(t, err.Error(), tc.message)
		})
	}

	// A caller-chosen nonce is used verbatim; a random one is eight hex digits.
	a, err := NewAuthority(base)
	require.NoError(t, err)
	require.Len(t, a.nonce, 8)
	for _, c := range a.nonce {
		require.Contains(t, "0123456789abcdef", string(c))
	}
}

// Intake refuses what intake refuses: a request it already admitted and a
// request that is not well-formed. Neither leaves a record.
func TestFlow_IntakeRefusalsLeaveNoRecord(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	first, err := h.authority.Intake(h.request("req-dup", "gate"), nil)
	require.NoError(t, err)
	require.Equal(t, StateTrust, first.State())
	n := h.chain.Len()

	cases := []struct {
		name   string
		mutate func(*recovery_request.RecoveryRequest)
		code   string
	}{
		{"duplicate request id", func(r *recovery_request.RecoveryRequest) { r.RequestID = "req-dup" }, intake.CodeDuplicateRequest},
		{"missing genome", func(r *recovery_request.RecoveryRequest) { r.GenomeID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"missing policy profile", func(r *recovery_request.RecoveryRequest) { r.PolicyProfile = "" }, shared_errors.CodeRequiredFieldMissing},
		{"missing request id", func(r *recovery_request.RecoveryRequest) { r.RequestID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"unsupported schema", func(r *recovery_request.RecoveryRequest) { r.SchemaVersion = recovery_request.SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
	}
	for _, tc := range cases {
		req := h.request("req-"+strings.ReplaceAll(tc.name, " ", "-"), "gate")
		tc.mutate(&req)
		f, err := h.authority.Intake(req, nil)
		require.Nil(t, f, tc.name)
		require.Equal(t, tc.code, shared_errors.CodeOf(err), tc.name)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), tc.name)
	}
	require.Equal(t, n, h.chain.Len(), "a refused request is not on the record")
}

// Each stage checks its own inputs before it touches the record: a
// repeated stage, a bad ttl, a manifest that would not validate.
func TestFlow_StageInputRefusals(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	f, err := h.authority.Intake(h.request("req-in", "gate"), nil)
	require.NoError(t, err)

	// Trust cannot decide on a negative ttl; the machine stays at trust.
	_, err = f.Admit(h.peer, -time.Second)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.Equal(t, StateTrust, f.State())
	require.Equal(t, 1, h.chain.Len())

	_, err = f.Admit(h.peer, 0)
	require.NoError(t, err)
	// Trust is decided once.
	_, err = f.Admit(h.peer, 0)
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	require.Equal(t, StateSession, f.State())

	// The issuer refuses a negative session ttl; the machine stays at session.
	_, err = f.IssueSession(-time.Minute)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.Equal(t, StateSession, f.State())
	require.Equal(t, 2, h.chain.Len())

	_, err = f.IssueSession(10 * time.Minute)
	require.NoError(t, err)

	// Nothing to disclose is refused before any issuer is built.
	_, err = f.Disclose(nil)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	_, err = f.Disclose([]Component{})
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	// A component the issuer refuses (no plaintext) is a coded refusal
	// with a partial result; the flow keeps no disclosures from it.
	_, err = f.Disclose([]Component{{ID: "empty"}})
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Equal(t, 3, h.chain.Len(), "no DISCLOSURE_AUTHORIZED for a refused component")
	require.Empty(t, f.Snapshot().Disclosures)

	_, err = f.Disclose([]Component{{ID: "descriptor", Plaintext: []byte("d")}})
	require.NoError(t, err)
	before := h.chain.Len()

	deadline := h.clock.Now().Add(time.Minute)
	cases := []struct {
		name   string
		params ManifestParams
		code   string
	}{
		{"unknown output kind", ManifestParams{OutputKind: "bytes/what", MaxBytes: 1, Deadline: deadline}, shared_errors.CodeFieldValueInvalid},
		{"empty output kind", ManifestParams{MaxBytes: 1, Deadline: deadline}, shared_errors.CodeFieldValueInvalid},
		{"zero budget", ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, Deadline: deadline}, shared_errors.CodeFieldValueInvalid},
		{"missing deadline", ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 1}, shared_errors.CodeRequiredFieldMissing},
		{"deadline already passed", ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 1, Deadline: h.clock.Now().Add(-time.Second)}, shared_errors.CodeCrossFieldInconsistent},
		{"deadline equals issuance", ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 1, Deadline: h.clock.Now()}, shared_errors.CodeCrossFieldInconsistent},
	}
	for _, tc := range cases {
		m, err := f.IssueManifest(tc.params)
		require.Equal(t, tc.code, shared_errors.CodeOf(err), tc.name)
		require.Empty(t, m.ManifestID, tc.name)
		require.Equal(t, StateDisclosure, f.State(), tc.name)
		require.Empty(t, f.ManifestID(), tc.name)
	}
	require.Equal(t, before, h.chain.Len(), "a manifest that does not validate is not on the record")

	m, err := f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 1, Deadline: deadline})
	require.NoError(t, err)
	require.Equal(t, m.ManifestID, f.ManifestID())
}

// A session that can no longer be continued stops disclosure with the
// issuer's own coded refusal: one that expired, or one pinned to a policy
// the vault has since rotated away from. Nothing is sealed and nothing is
// recorded. The plaintext is wiped only when the sequencer ran: a
// refusal from the issuer's constructor leaves the caller's buffers as
// they were.
func TestFlow_DiscloseRefusesASessionThatCannotContinue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		arrange  func(h *harness)
		code     string
		category shared_errors.Category
		wiped    bool
	}{
		{"expired", func(h *harness) { h.clock.Step(2 * time.Minute) }, shared_errors.CodeSessionExpired, shared_errors.CategoryAuthority, true},
		{"policy rotated", func(h *harness) { h.authority.policy = hPolicy + ";rotated" }, shared_errors.CodePolicyDrifted, shared_errors.CategoryAuthority, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, nil)
			f, err := h.authority.Intake(h.request("req-exp", "gate"), nil)
			require.NoError(t, err)
			_, err = f.Admit(h.peer, 0)
			require.NoError(t, err)
			_, err = f.IssueSession(time.Minute)
			require.NoError(t, err)
			n := h.chain.Len()

			tc.arrange(h)
			comps := []Component{{ID: "descriptor", Plaintext: []byte("secret")}}
			msgs, err := f.Disclose(comps)
			require.Nil(t, msgs)
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.Equal(t, tc.category, shared_errors.CategoryOf(err))
			if tc.wiped {
				require.Equal(t, []byte{0, 0, 0, 0, 0, 0}, comps[0].Plaintext, "the sequencer wipes the plaintext even when nothing was sealed")
			} else {
				require.Equal(t, []byte("secret"), comps[0].Plaintext, "a constructor refusal runs no sequencer and wipes nothing")
			}
			require.Equal(t, n, h.chain.Len())
			require.Equal(t, StateDisclosure, f.State())
			require.Empty(t, f.Snapshot().Disclosures)
		})
	}
}

// A chain that refuses a record stops every stage where it is asked,
// leaves the machine where it was, and the stage succeeds once the chain
// takes records again.
func TestFlow_AuditFailureStopsEachStage(t *testing.T) {
	t.Parallel()
	fc := &flakyChain{Chain: chain.NewInMemoryChain()}
	h := newHarness(t, fc)
	f, err := h.authority.Intake(h.request("req-af", "gate"), nil)
	require.NoError(t, err)
	_, err = f.Admit(h.peer, 0)
	require.NoError(t, err)

	// The Authority's own stages classify the refusal as audit_unavailable;
	// the sequencer and the validation service surface the chain's own
	// error unchanged.
	type stage struct {
		name  string
		state State
		code  string
		run   func() error
	}
	stages := []stage{
		{"session", StateSession, CodeAuditUnavailable, func() error { _, err := f.IssueSession(10 * time.Minute); return err }},
		{"disclosure", StateDisclosure, "", func() error {
			_, err := f.Disclose([]Component{{ID: "descriptor", Plaintext: []byte("d")}})
			return err
		}},
		{"manifest", StateDisclosure, CodeAuditUnavailable, func() error {
			_, err := f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 16, Deadline: h.clock.Now().Add(time.Minute)})
			return err
		}},
		{"candidate", StateExternalCompute, CodeAuditUnavailable, func() error {
			return f.CandidateReceived(CandidateRecord{OutputKind: "bytes/fixed-length", Bytes: 16, SHA256: strings.Repeat("d", 64), ProducedAt: h.clock.Now(), WorkerSigningKeyID: "w"})
		}},
		{"validation", StateValidation, "", func() error {
			dims := passDims()
			dims[validation_result.DimensionBehavioral] = valservice.EvaluatedDimension{
				Evaluator: "equivalence-ladder",
				Verdict:   validation_result.DimensionVerdict{Verdict: validation_result.VerdictFail, Score: 0, Threshold: 1},
			}
			_, err := f.Validate(ValidateParams{Evaluated: dims})
			return err
		}},
		{"decision", StateRelease, CodeAuditUnavailable, func() error { _, err := f.Decide(); return err }},
		{"seal", StateAudit, CodeAuditUnavailable, func() error { _, err := f.Seal(); return err }},
	}
	for _, s := range stages {
		require.Equal(t, s.state, f.State(), s.name)
		n := fc.Len()
		fc.fail = true
		err := s.run()
		require.Error(t, err, s.name)
		require.Contains(t, err.Error(), "disk full", s.name)
		require.Equal(t, s.code, shared_errors.CodeOf(err), s.name)
		require.Equal(t, s.state, f.State(), "%s: the machine did not move", s.name)
		require.False(t, f.Ended(), s.name)
		require.Equal(t, n, fc.Len(), "%s: nothing was recorded", s.name)
		if s.name == "disclosure" {
			require.Empty(t, f.Snapshot().Disclosures, "a message without a record is not kept")
		}
		fc.fail = false
		require.NoError(t, s.run(), s.name)
	}
	require.Equal(t, StateIncidentTerminated, f.State())
	require.True(t, f.Ended())
	require.NoError(t, fc.Verify(h.audit))
	v := f.Snapshot()
	require.NotNil(t, v.Incident)
	require.Equal(t, session_object.StateInvalidated, v.Session.State)
}

// codedChain refuses appends with a classified error, the way a store
// that reports its own failures does.
type codedChain struct {
	chain.Chain
	fail bool
}

func (c *codedChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	if c.fail {
		return audit_event.AuditEvent{}, shared_errors.Operational("store_offline", "store offline", nil)
	}
	return c.Chain.Append(evt, signer)
}

// The sequencer's partial result is dropped and the chain's classified
// error is surfaced as it was; the disclosure can be redone once the
// chain is back.
func TestFlow_DiscloseSurfacesAClassifiedChainError(t *testing.T) {
	t.Parallel()
	cc := &codedChain{Chain: chain.NewInMemoryChain()}
	h := newHarness(t, cc)
	f, err := h.authority.Intake(h.request("req-cc", "gate"), nil)
	require.NoError(t, err)
	_, err = f.Admit(h.peer, 0)
	require.NoError(t, err)
	_, err = f.IssueSession(10 * time.Minute)
	require.NoError(t, err)

	cc.fail = true
	msgs, err := f.Disclose([]Component{{ID: "descriptor", Plaintext: []byte("d")}})
	require.Nil(t, msgs)
	require.Equal(t, "store_offline", shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Empty(t, f.Snapshot().Disclosures)

	cc.fail = false
	msgs, err = f.Disclose([]Component{{ID: "descriptor", Plaintext: []byte("d")}})
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Len(t, f.Snapshot().Disclosures, 1)
}

// flakySigner is a keystore whose signing can be switched off, the way an
// HSM that went away would refuse.
type flakySigner struct {
	*keys.InMemoryStore
	fail bool
}

const codeSignerOffline = "signer_offline"

func (s *flakySigner) Sign(kid ids.KeyID, purpose keys.Purpose, msg []byte) ([]byte, error) {
	if s.fail {
		return nil, shared_errors.Operational(codeSignerOffline, "signer offline", nil)
	}
	return s.InMemoryStore.Sign(kid, purpose, msg)
}

func newSignerHarness(t *testing.T) (*harness, *flakySigner) {
	t.Helper()
	h := newHarness(t, nil)
	fs := &flakySigner{InMemoryStore: h.store}
	a, err := NewAuthority(AuthorityOptions{
		Clock: h.clock, Signer: fs, Sealer: h.store, Resolver: h.store, AuthorityKeyID: hAuthKID, RecipientKeyID: hSealKID,
		Audit: h.chain, AuditSigner: h.audit, AuditKeyID: hAuditKID, PolicyVersion: hPolicy, Profiles: []string{"gate"},
		Zeroizer: incident.ZeroizerFunc(func() { h.zeroized++ }), IDNonce: "s1",
	})
	require.NoError(t, err)
	h.authority = a
	return h, fs
}

// An authority key that will not sign stops the manifest and the
// decision; the stage is retried when the key is back.
func TestFlow_SignerFailureStopsTheStage(t *testing.T) {
	t.Parallel()
	h, fs := newSignerHarness(t)
	f, err := h.authority.Intake(h.request("req-sg", "gate"), nil)
	require.NoError(t, err)
	_, err = f.Admit(h.peer, 0)
	require.NoError(t, err)
	_, err = f.IssueSession(10 * time.Minute)
	require.NoError(t, err)
	_, err = f.Disclose([]Component{{ID: "descriptor", Plaintext: []byte("d")}})
	require.NoError(t, err)

	n := h.chain.Len()
	fs.fail = true
	_, err = f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 16, Deadline: h.clock.Now().Add(time.Minute)})
	require.Equal(t, codeSignerOffline, shared_errors.CodeOf(err))
	require.Equal(t, StateDisclosure, f.State())
	require.Empty(t, f.ManifestID())
	require.Equal(t, n, h.chain.Len(), "an unsigned manifest is not on the record")
	fs.fail = false
	_, err = f.IssueManifest(ManifestParams{OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: 16, Deadline: h.clock.Now().Add(time.Minute)})
	require.NoError(t, err)

	require.NoError(t, f.CandidateReceived(CandidateRecord{OutputKind: "bytes/fixed-length", Bytes: 16, SHA256: strings.Repeat("e", 64), ProducedAt: h.clock.Now(), WorkerSigningKeyID: "w"}))
	_, err = f.Validate(ValidateParams{Evaluated: passDims()})
	require.NoError(t, err)

	fs.fail = true
	_, err = f.Decide()
	require.Equal(t, codeSignerOffline, shared_errors.CodeOf(err))
	require.Equal(t, StateRelease, f.State())
	require.Nil(t, f.Decision())
	fs.fail = false
	d, err := f.Decide()
	require.NoError(t, err)
	require.True(t, d.Release)
	require.NoError(t, d.VerifySignature(h.store))
	last, _ := h.chain.EventAt(h.chain.Len() - 1)
	require.Equal(t, last.EventID, d.AuditEventID, "the decision cites the record that preceded its signature")
	_, err = f.Seal()
	require.NoError(t, err)
	require.Equal(t, StateReleaseAuthorized, f.State())
}

// An abort whose session cannot be re-signed as invalidated still ends
// the flow; the caller learns that the invalidation did not happen.
func TestFlow_AbortReportsAnInvalidationThatFailed(t *testing.T) {
	t.Parallel()
	h, fs := newSignerHarness(t)
	f, err := h.authority.Intake(h.request("req-ab", "gate"), nil)
	require.NoError(t, err)
	_, err = f.Admit(h.peer, 0)
	require.NoError(t, err)
	_, err = f.IssueSession(10 * time.Minute)
	require.NoError(t, err)
	n := h.chain.Len()

	fs.fail = true
	err = f.Abort("dispatch", shared_errors.Operational("worker_gone", "no worker", nil))
	require.Equal(t, codeSignerOffline, shared_errors.CodeOf(err))
	require.True(t, f.Ended())
	require.Equal(t, StateIncidentTerminated, f.State())
	require.Equal(t, n, h.chain.Len(), "no SESSION_INVALIDATED without an invalidated session")
	v := f.Snapshot()
	require.NotNil(t, v.Abort)
	require.Equal(t, "worker_gone", v.Abort.Code)
	require.False(t, v.Abort.Incident)
	require.Equal(t, session_object.StateActive, v.Session.State, "the issuer still holds the session active")
}

// When the chain is down during an abort, the abort still ends the flow
// and the first audit failure is what the caller gets: for an integrity
// failure the missing INCIDENT_DETECTED, for an operational one the
// missing SESSION_INVALIDATED.
func TestFlow_AbortSurfacesTheFirstAuditFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		id       string
		err      error
		incident bool
	}{
		{"integrity failure", "req-int", shared_errors.Integrity("gate_output_invalid", "not an answer", nil), true},
		{"incident failure", "req-inc", shared_errors.Incident("tamper_signal", "tamper", nil), true},
		{"operational failure", "req-op", shared_errors.Operational("worker_gone", "no worker", nil), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fc := &flakyChain{Chain: chain.NewInMemoryChain()}
			h := newHarness(t, fc)
			f := h.driveToValidation(t, tc.id)
			n := fc.Len()

			fc.fail = true
			err := f.Abort("judge", tc.err)
			require.Equal(t, CodeAuditUnavailable, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), "disk full")
			require.True(t, f.Ended())
			require.Equal(t, StateIncidentTerminated, f.State())
			require.Equal(t, n, fc.Len())

			v := f.Snapshot()
			require.NotNil(t, v.Abort)
			require.Equal(t, tc.incident, v.Abort.Incident)
			require.Equal(t, shared_errors.CodeOf(tc.err), v.Abort.Code)
			require.Equal(t, shared_errors.CategoryOf(tc.err).String(), v.Abort.Category)
			require.Equal(t, session_object.StateInvalidated, v.Session.State, "the session is closed even when the record failed")
			require.Nil(t, f.Abort("again", errors.New("x")), "the flow is over")
		})
	}
}

// A conditional behavioral verdict is refused for review: the decision
// says so, and the incident that closes the session carries the
// decision's reason when no finding names a code.
func TestFlow_ConditionalFailIsRefusedForReview(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	f := h.driveToValidation(t, "req-cf")
	dims := passDims()
	dims[validation_result.DimensionBehavioral] = valservice.EvaluatedDimension{
		Evaluator: "equivalence-ladder",
		Verdict:   validation_result.DimensionVerdict{Verdict: validation_result.VerdictConditionalFail, Score: 0.5, Threshold: 1},
	}
	vr, err := f.Validate(ValidateParams{Evaluated: dims})
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictConditionalFail, vr.OverallVerdict)
	for _, dv := range vr.Dimensions {
		require.Empty(t, dv.Details)
	}

	d, err := f.Decide()
	require.NoError(t, err)
	require.False(t, d.Release)
	require.Equal(t, release_decision.ReasonConditionalFailRequiresReview, d.Reason)
	require.Equal(t, vr.ValidationResultID, d.ValidationResultID)
	require.NoError(t, d.VerifySignature(h.store))

	final, err := f.Seal()
	require.NoError(t, err)
	require.Equal(t, StateIncidentTerminated, final)
	got := kinds(h.chain)
	require.Equal(t, []string{"RELEASE_DECIDED", "INCIDENT_DETECTED", "SESSION_INVALIDATED", "INCIDENT_TERMINATED"}, got[len(got)-4:])
	det, _ := h.chain.EventAt(h.chain.Len() - 3)
	var p struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(det.Payload, &p))
	require.Equal(t, string(release_decision.ReasonConditionalFailRequiresReview), p.Code)
	require.NoError(t, h.chain.Verify(h.audit))
}

// A refusal that carries a finding names it to the incident; the first
// finding of the first dimension that has one wins, operational first.
func TestFirstFinding_PicksOperationalThenSemanticThenBehavioral(t *testing.T) {
	t.Parallel()
	finding := func(code string) validation_result.DimensionVerdict {
		return validation_result.DimensionVerdict{Verdict: validation_result.VerdictFail, Details: []validation_result.Finding{{Code: code, Severity: validation_result.SeverityError}}}
	}
	pass := validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass}
	cases := []struct {
		name string
		dims map[validation_result.Dimension]validation_result.DimensionVerdict
		want string
	}{
		{"no findings", map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: pass, validation_result.DimensionSemantic: pass, validation_result.DimensionBehavioral: pass}, ""},
		{"operational first", map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: finding("op"), validation_result.DimensionSemantic: finding("sem"), validation_result.DimensionBehavioral: finding("beh")}, "op"},
		{"semantic before behavioral", map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: pass, validation_result.DimensionSemantic: finding("sem"), validation_result.DimensionBehavioral: finding("beh")}, "sem"},
		{"behavioral alone", map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: pass, validation_result.DimensionBehavioral: finding("beh")}, "beh"},
	}
	for _, tc := range cases {
		fd := firstFinding(&validation_result.ValidationResult{Dimensions: tc.dims})
		if tc.want == "" {
			require.Nil(t, fd, tc.name)
			continue
		}
		require.NotNil(t, fd, tc.name)
		require.Equal(t, tc.want, fd.Code, tc.name)
	}
}

// The decision guard: a flow that reached release with neither a trust
// decision nor a validation result has nothing to decide on, and says so
// without touching the record.
func TestFlow_DecideRefusesAFlowWithNothingToDecide(t *testing.T) {
	t.Parallel()
	h := newHarness(t, nil)
	f := &Flow{a: h.authority, machine: NewMachine(), request: h.request("req-nd", "gate")}
	for _, trigger := range []string{TriggerRequestReceived, TriggerRequestValidated, TriggerAttestationDeny} {
		_, err := f.machine.Advance(trigger, h.clock.Now())
		require.NoError(t, err)
	}
	require.Equal(t, StateRelease, f.State())
	d, err := f.Decide()
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), "nothing to decide on")
	require.Empty(t, d.DecisionID)
	require.Equal(t, 0, h.chain.Len())
	require.Equal(t, StateRelease, f.State())
}

// A step reads back only from well-formed JSON naming known states.
func TestStep_UnmarshalJSONRefusesMalformedInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"not json", `{"from":`, "unexpected end"},
		{"unknown from", `{"from":"nowhere","to":"trust","trigger":"x","at":"2026-09-16T00:00:00Z"}`, `unknown state "nowhere"`},
		{"unknown to", `{"from":"request","to":"elsewhere","trigger":"x","at":"2026-09-16T00:00:00Z"}`, `unknown state "elsewhere"`},
		{"state not a string", `{"from":3}`, "cannot unmarshal"},
	}
	for _, tc := range cases {
		var s Step
		err := json.Unmarshal([]byte(tc.input), &s)
		require.Error(t, err, tc.name)
		require.Contains(t, err.Error(), tc.want, tc.name)
	}

	var s Step
	require.NoError(t, json.Unmarshal([]byte(`{"from":"audit","to":"incident_terminated","trigger":"audit.sealed.release_false","at":"2026-09-16T00:00:00Z"}`), &s))
	require.Equal(t, Step{From: StateAudit, To: StateIncidentTerminated, Trigger: TriggerAuditSealedRefusal, At: time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)}, s)
	raw, err := marshalJSON(s)
	require.NoError(t, err)
	require.JSONEq(t, `{"from":"audit","to":"incident_terminated","trigger":"audit.sealed.release_false","at":"2026-09-16T00:00:00Z"}`, string(raw))
}
