// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// The Return Path log is not opened on a key the daemon cannot read, nor
// in a place it cannot write; and a payload that cannot be encoded never
// reaches the chain.
func TestReturnPathAudit_OpenRefusalsAndUnencodablePayload(t *testing.T) {
	_, cfg := newTestAudit(t)

	noSeed := cfg
	noSeed.Keys.AuditSigning.SeedPath = filepath.Join(t.TempDir(), "absent.seed")
	_, err := openReturnPathAudit(noSeed, shared_time.NewSystemClock(), nil)
	require.ErrorContains(t, err, "keys.audit_signing.seed_path")

	noDir := cfg
	noDir.Audit.LogPath = filepath.Join(t.TempDir(), "missing", "rp.db")
	_, err = openReturnPathAudit(noDir, shared_time.NewSystemClock(), nil)
	require.ErrorContains(t, err, "open audit.log_path")

	a, _ := newTestAudit(t)
	err = a.emit(audit_event.KindTrustEvaluated, map[string]any{"bad": make(chan int)})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.Equal(t, 0, a.Len(), "nothing was appended")
}
