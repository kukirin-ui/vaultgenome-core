// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// TestHandle_ClockRewindDoesNotPredateTermination proves that a clock
// stepping backwards between detection and termination — here rewound by
// the invalidator while the side effects run — cannot produce a
// TERMINATED record earlier than its DETECTED one: the termination time
// is clamped to the detection time on the result and on the chain.
func TestHandle_ClockRewindDoesNotPredateTermination(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	fc := shared_time.NewFakeClock(start)
	store := keys.NewInMemoryStore(fc)
	auditKID := ids.KeyID("incident-audit-g1")
	_, err := store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)
	ch := chain.NewInMemoryChain()

	svc, err := NewService(ServiceOptions{
		AuditChain:  ch,
		AuditSigner: store,
		AuditKeyID:  auditKID,
		Clock:       fc,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error {
			fc.SetNow(start.Add(-time.Hour))
			return nil
		}),
		Zeroizer: ZeroizerFunc(func() {}),
	})
	require.NoError(t, err)

	res, err := svc.HandleValidationHardFail(goodTrigger())
	require.NoError(t, err)
	require.Equal(t, start, res.DetectedAt)
	require.Equal(t, res.DetectedAt, res.TerminatedAt, "termination is clamped to detection")
	require.True(t, res.SessionInvalidated)

	require.Equal(t, 2, ch.Len())
	detected, ok := ch.EventAt(0)
	require.True(t, ok)
	terminated, ok := ch.EventAt(1)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentDetected, detected.Kind)
	require.Equal(t, audit_event.KindIncidentTerminated, terminated.Kind)
	require.Equal(t, detected.OccurredAt, terminated.OccurredAt)
	require.False(t, terminated.OccurredAt.Before(detected.OccurredAt))
	require.NoError(t, ch.Verify(store))
}

// TestErrIncidentV2Deferred_IsAClassifiedLeaf pins the deferred-handler
// error as callers see it: a stable message carrying its code, the
// incident category, no wrapped cause, and recognised by IsV2Deferred
// only when it is actually present.
func TestErrIncidentV2Deferred_IsAClassifiedLeaf(t *testing.T) {
	t.Parallel()
	require.Equal(t, "incident["+CodeIncidentV2Deferred+"]: v2+ scenario handler not implemented in MVP", ErrIncidentV2Deferred.Error())
	require.Nil(t, errors.Unwrap(ErrIncidentV2Deferred))
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(ErrIncidentV2Deferred))
	require.Equal(t, CodeIncidentV2Deferred, shared_errors.CodeOf(ErrIncidentV2Deferred))
	require.False(t, IsV2Deferred(nil))
	require.True(t, IsV2Deferred(ErrIncidentV2Deferred))
}
