// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package intake

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

func request(id string, at time.Time) recovery_request.RecoveryRequest {
	return recovery_request.RecoveryRequest{
		SchemaVersion:     recovery_request.SchemaVersionCurrent,
		RequestID:         ids.RequestID(id),
		GenomeID:          ids.GenomeID("genome-1"),
		PolicyProfile:     "gate",
		RequesterIdentity: "operator:test",
		CreatedAt:         at,
	}
}

func TestIntake_AdmitsWellFormedOnceAndRefusesDuplicates(t *testing.T) {
	t.Parallel()
	clock := shared_time.NewFakeClock(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	in, err := New(clock, Options{})
	require.NoError(t, err)

	require.NoError(t, in.Admit(request("req-1", clock.Now())))
	err = in.Admit(request("req-1", clock.Now()))
	require.Error(t, err)
	require.Equal(t, CodeDuplicateRequest, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, 1, in.Remembered())

	// A malformed request is the contract's refusal, and is not remembered.
	bad := request("", clock.Now())
	err = in.Admit(bad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Equal(t, 1, in.Remembered())
}

func TestIntake_ForgetsPastTheWindowAndBeyondCapacity(t *testing.T) {
	t.Parallel()
	clock := shared_time.NewFakeClock(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	in, err := New(clock, Options{Capacity: 2, Window: time.Hour})
	require.NoError(t, err)

	require.NoError(t, in.Admit(request("a", clock.Now())))
	require.NoError(t, in.Admit(request("b", clock.Now())))
	require.NoError(t, in.Admit(request("c", clock.Now()))) // evicts a
	require.Equal(t, 2, in.Remembered())
	require.NoError(t, in.Admit(request("a", clock.Now())), "a was forgotten past capacity")
	require.Error(t, in.Admit(request("c", clock.Now())))

	clock.Step(2 * time.Hour)
	require.NoError(t, in.Admit(request("c", clock.Now())), "c was forgotten past the window")
}

func TestNew_RefusesMissingClockAndNegatives(t *testing.T) {
	t.Parallel()
	_, err := New(nil, Options{})
	require.Error(t, err)
	_, err = New(shared_time.NewSystemClock(), Options{Capacity: -1})
	require.Error(t, err)
}
