// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// refusingChain takes records until its n-th append, which it refuses.
type refusingChain struct {
	chain.Chain
	refuseAt int
	appends  int
	err      error
}

func (c *refusingChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	c.appends++
	if c.appends == c.refuseAt {
		return audit_event.AuditEvent{}, c.err
	}
	return c.Chain.Append(evt, signer)
}

// withChain rebuilds the fixture's service over c.
func (f *serviceFixtures) withChain(t *testing.T, c chain.Chain) *ValidationService {
	t.Helper()
	svc, err := NewValidationService(ServiceOptions{AuditChain: c, AuditSigner: f.store, AuditKeyID: f.auditKID, Clock: f.clock})
	require.NoError(t, err)
	return svc
}

// Every record the service writes is written before the work it
// describes is surfaced: whichever append the chain refuses — the start,
// a dimension, a finding of any dimension, the completion — the chain's
// own error comes back, no result is surfaced, and the chain holds
// exactly the records that preceded the refusal.
func TestValidate_ChainRefusalStopsAtThatRecord(t *testing.T) {
	t.Parallel()
	semanticFail := func(f *serviceFixtures) {
		bad := append([]byte(nil), f.candidateOK...)
		bad[2] ^= 0xff
		f.inputs.Semantic.Candidate = bad
	}
	behavioralFail := func(f *serviceFixtures) { f.inputs.Behavioral.Probes[1].Evaluate = alwaysFail }
	operationalFail := func(f *serviceFixtures) {
		f.inputs.Operational.Now = f.inputs.Operational.Session.ExpiresAt.Add(time.Second)
	}
	cases := []struct {
		name     string
		arrange  func(*serviceFixtures)
		refuseAt int
		before   []audit_event.Kind
	}{
		{"start", nil, 1, []audit_event.Kind{}},
		{"operational dimension", nil, 2, []audit_event.Kind{audit_event.KindValidationStarted}},
		{"semantic dimension", nil, 3, []audit_event.Kind{audit_event.KindValidationStarted, audit_event.KindValidationDimension}},
		{"behavioral dimension", nil, 4, []audit_event.Kind{audit_event.KindValidationStarted, audit_event.KindValidationDimension, audit_event.KindValidationDimension}},
		{"completion", nil, 5, []audit_event.Kind{audit_event.KindValidationStarted, audit_event.KindValidationDimension, audit_event.KindValidationDimension, audit_event.KindValidationDimension}},
		{"operational finding", operationalFail, 3, []audit_event.Kind{audit_event.KindValidationStarted, audit_event.KindValidationDimension}},
		{"semantic finding", semanticFail, 5, []audit_event.Kind{audit_event.KindValidationStarted, audit_event.KindValidationDimension, audit_event.KindValidationDimension, audit_event.KindValidationDimension}},
		{"behavioral finding", behavioralFail, 5, []audit_event.Kind{audit_event.KindValidationStarted, audit_event.KindValidationDimension, audit_event.KindValidationDimension, audit_event.KindValidationDimension}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newServiceFixtures(t)
			if tc.arrange != nil {
				tc.arrange(f)
			}
			refused := errors.New("audit store refused the record")
			rc := &refusingChain{Chain: f.chain, refuseAt: tc.refuseAt, err: refused}
			svc := f.withChain(t, rc)

			vr, err := svc.Validate(f.inputs)
			require.Nil(t, vr)
			require.ErrorIs(t, err, refused, "the chain's own error is surfaced")
			require.Equal(t, tc.refuseAt, rc.appends, "nothing is attempted past the refusal")
			require.Equal(t, tc.before, kindsInChain(f.chain))
			require.NoError(t, f.chain.Verify(f.store))

			// The same inputs validate once the chain takes records again.
			rc.refuseAt = 0
			vr, err = svc.Validate(f.inputs)
			require.NoError(t, err)
			require.NotNil(t, vr)
			require.NoError(t, vr.Validate())
			require.Equal(t, audit_event.KindValidationCompleted, kindsInChain(f.chain)[f.chain.Len()-1])
		})
	}
}

// rewindingClock answers each call a second earlier than the last, as a
// clock that was stepped back between two readings would.
type rewindingClock struct {
	at    time.Time
	calls int
}

func (c *rewindingClock) Now() time.Time {
	c.calls++
	return c.at.Add(-time.Duration(c.calls) * time.Second)
}

func (c *rewindingClock) Since(t time.Time) time.Duration { return c.Now().Sub(t) }

// A result is never dated before the validation it concludes: when the
// clock reads earlier at completion than at the start, the start time is
// used and the completion record carries it.
func TestValidate_CompletionNeverPredatesTheStart(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	clk := &rewindingClock{at: f.clock.Now()}
	svc, err := NewValidationService(ServiceOptions{AuditChain: f.chain, AuditSigner: f.store, AuditKeyID: f.auditKID, Clock: clk})
	require.NoError(t, err)

	vr, err := svc.Validate(f.inputs)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict)
	started, ok := f.chain.EventAt(0)
	require.True(t, ok)
	require.Equal(t, audit_event.KindValidationStarted, started.Kind)
	require.Equal(t, started.OccurredAt, vr.ValidatedAt, "the completion takes the start's time rather than an earlier one")
	completed, ok := f.chain.EventAt(f.chain.Len() - 1)
	require.True(t, ok)
	require.Equal(t, audit_event.KindValidationCompleted, completed.Kind)
	require.Equal(t, started.OccurredAt, completed.OccurredAt)
	require.Greater(t, clk.calls, 1, "the clock was read again at completion")
	require.NoError(t, f.chain.Verify(f.store))
}

// An outside evaluator's verdict is recorded as given, and a verdict the
// result contract refuses — a score outside [0,1], a finding without a
// code — is refused at the post-condition: no result is surfaced.
func TestValidate_RefusesAnEvaluatedVerdictTheContractRefuses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		verdict validation_result.DimensionVerdict
		code    string
		want    string
	}{
		{"score above one", validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: 1.5, Threshold: 1}, shared_errors.CodeFieldValueInvalid, "score out of [0,1]"},
		{"negative threshold", validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: 1, Threshold: -0.1}, shared_errors.CodeFieldValueInvalid, "threshold out of [0,1]"},
		{"finding without a code", validation_result.DimensionVerdict{Verdict: validation_result.VerdictFail, Score: 0, Threshold: 1,
			Details: []validation_result.Finding{{Severity: validation_result.SeverityError, Message: "no code"}}}, shared_errors.CodeRequiredFieldMissing, "finding.code required"},
		{"unknown severity", validation_result.DimensionVerdict{Verdict: validation_result.VerdictFail, Score: 0, Threshold: 1,
			Details: []validation_result.Finding{{Code: "x", Severity: "catastrophic"}}}, shared_errors.CodeFieldValueInvalid, "finding.severity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newServiceFixtures(t)
			f.inputs.Evaluated = map[validation_result.Dimension]EvaluatedDimension{
				validation_result.DimensionSemantic:   {Evaluator: "top1-agreement", Verdict: tc.verdict},
				validation_result.DimensionBehavioral: {Evaluator: "equivalence-ladder", Verdict: validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: 1, Threshold: 1}},
			}
			vr, err := f.service.Validate(f.inputs)
			require.Nil(t, vr)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, audit_event.KindValidationCompleted, kindsInChain(f.chain)[f.chain.Len()-1],
				"the record of the attempt stays on the chain")
		})
	}
}
