// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package orchestration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

func TestMachine_WalksTheHappyPathAndRefusesWhatTheTableLacks(t *testing.T) {
	t.Parallel()
	m := NewMachine()
	require.Equal(t, StateUnstarted, m.State())
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)

	// A stage cannot be skipped: no session before trust.
	_, err := m.Advance(TriggerSessionIssued, at)
	require.Error(t, err)
	require.Equal(t, CodeIllegalTransition, shared_errors.CodeOf(err))
	require.Equal(t, StateUnstarted, m.State(), "a refused transition does not move the machine")

	for _, trigger := range []string{
		TriggerRequestReceived, TriggerRequestValidated, TriggerAttestationAllow, TriggerSessionIssued,
		TriggerManifestDispatched, TriggerCandidateReceived, TriggerReturnAccepted, TriggerValidationCompleted,
		TriggerDecisionSigned, TriggerAuditSealedRelease,
	} {
		_, err := m.Advance(trigger, at)
		require.NoError(t, err, trigger)
	}
	require.Equal(t, StateReleaseAuthorized, m.State())
	require.True(t, m.State().IsTerminal())
	_, err = m.Advance(TriggerIncidentDetected, at)
	require.Error(t, err, "nothing leaves a terminal state")

	steps := m.Steps()
	require.Len(t, steps, 10)
	require.Equal(t, StateUnstarted, steps[0].From)
	require.Equal(t, StateRequest, steps[0].To)
	require.Equal(t, StateReleaseAuthorized, steps[9].To)

	raw, err := json.Marshal(steps[2])
	require.NoError(t, err)
	require.JSONEq(t, `{"from":"trust","to":"session","trigger":"attestation.allow","at":"2026-09-16T00:00:00Z"}`, string(raw))
	var back Step
	require.NoError(t, json.Unmarshal(raw, &back))
	require.Equal(t, steps[2], back)
	var bad State
	require.Error(t, bad.UnmarshalText([]byte("nowhere")))
}

func TestMachine_DenyAndIncidentArcs(t *testing.T) {
	t.Parallel()
	at := time.Now()
	m := NewMachine()
	for _, trigger := range []string{TriggerRequestReceived, TriggerRequestValidated, TriggerAttestationDeny} {
		_, err := m.Advance(trigger, at)
		require.NoError(t, err)
	}
	require.Equal(t, StateRelease, m.State(), "a deny is a release decision without a session")
	for _, trigger := range []string{TriggerDecisionSigned, TriggerAuditSealedRefusal} {
		_, err := m.Advance(trigger, at)
		require.NoError(t, err)
	}
	require.Equal(t, StateIncidentTerminated, m.State())

	m = NewMachine()
	for _, trigger := range []string{TriggerRequestReceived, TriggerRequestValidated, TriggerAttestationAllow, TriggerSessionIssued, TriggerManifestDispatched} {
		_, err := m.Advance(trigger, at)
		require.NoError(t, err)
	}
	_, err := m.Advance(TriggerIncidentDetected, at)
	require.NoError(t, err)
	require.Equal(t, StateIncidentTerminated, m.State())
}
