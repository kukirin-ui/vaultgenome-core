// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// newTestAudit opens a Return Path audit log in a temp dir under a fresh
// audit key and returns it with the config that names it.
func newTestAudit(t *testing.T) (*returnPathAudit, Config) {
	t.Helper()
	return newTestAuditWith(t, metrics.NewRegistry())
}

func newTestAuditWith(t *testing.T, registry *metrics.Registry) (*returnPathAudit, Config) {
	t.Helper()
	dir := t.TempDir()
	seed := bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize)
	seedPath := filepath.Join(dir, "audit.seed")
	require.NoError(t, os.WriteFile(seedPath, seed, 0o600))
	cfg := DefaultConfig()
	cfg.Audit.LogPath = filepath.Join(dir, "returnpath.db")
	cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-test-1", SeedPath: seedPath}
	a, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), registry)
	require.NoError(t, err)
	require.NotNil(t, a)
	t.Cleanup(func() { _ = a.Close() })
	return a, cfg
}

// The daemon's own two decisions — a peer refused, a peer told to attest
// again — and every flow event share one log, counted by kind, verified
// under the published key after the daemon lets go of it, continued on
// reopen.
func TestReturnPathAudit_RefusalsAndFlowEventsShareOneVerifiedLog(t *testing.T) {
	registry := metrics.NewRegistry()
	a, cfg := newTestAuditWith(t, registry)

	require.NoError(t, a.TrustRefused("handshake", "127.0.0.1:5", tee.ProviderSimulated,
		shared_errors.Authority("handshake_failure", "client TEE evidence verification failed", nil)))
	evidenceAt := time.Now().Add(-10 * time.Minute)
	require.NoError(t, a.TrustStale("127.0.0.1:6", tee.ProviderGCPSEVSNP, bytes.Repeat([]byte{0xab}, 48), evidenceAt, 10*time.Minute, 5*time.Minute))

	// A flow driven over the same log to a trust deny.
	ta := newTestAuthority(t, a)
	f := ta.flow(t, "req-audit-1", "genome-0123456789ab-g0-0123456789ab")
	_, err := f.Admit(trustPeer(), 0)
	require.NoError(t, err)

	events := a.chain.Events()
	var kinds []audit_event.Kind
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	require.Equal(t, []audit_event.Kind{
		audit_event.KindTrustEvaluated, audit_event.KindTrustEvaluated,
		audit_event.KindRequestReceived, audit_event.KindTrustEvaluated,
	}, kinds)
	require.Equal(t, 4, a.Len())
	require.Len(t, a.Tip(), 64)

	var refused, stale trustPayload
	require.NoError(t, json.Unmarshal(events[0].Payload, &refused))
	require.Equal(t, auditPayloadSchema, refused.Schema)
	require.Equal(t, "deny", refused.Outcome)
	require.Equal(t, "handshake_failure", refused.Code)
	require.Empty(t, string(events[0].SessionID), "a refused peer has no job")
	require.NoError(t, json.Unmarshal(events[1].Payload, &stale))
	require.Equal(t, "session", stale.Phase)
	require.Equal(t, CodeEvidenceStale, stale.Code)
	require.Equal(t, "gcp-sev-snp", stale.PeerProvider)
	require.Len(t, stale.PeerMeasurementHex, 96)
	require.InDelta(t, 600, stale.EvidenceAgeSeconds, 0.001)
	require.NotNil(t, stale.EvidenceAt)
	require.Equal(t, "req-audit-1", string(events[2].RequestID))
	require.Contains(t, string(events[3].Payload), `"outcome":"allow"`)
	require.True(t, strings.HasPrefix(string(events[3].EventID), "rp-flow-"), "flow events carry their own ids: %s", events[3].EventID)

	// Every writer is counted.
	var rendered bytes.Buffer
	require.NoError(t, registry.WriteMetricsTo(&rendered))
	require.Contains(t, rendered.String(), `sagvd_audit_events_total{kind="TRUST_EVALUATED"} 3`)
	require.Contains(t, rendered.String(), `sagvd_audit_events_total{kind="REQUEST_RECEIVED"} 1`)

	// The log verifies under the published audit key, as acpctl does,
	// after the daemon let go of it.
	require.NoError(t, a.Close())
	logStore, err := store.Open(cfg.Audit.LogPath)
	require.NoError(t, err)
	stored, err := logStore.Load()
	require.NoError(t, err)
	require.NoError(t, logStore.Close())
	require.Len(t, stored, 4)
	resolver := keys.NewInMemoryStore(shared_time.NewSystemClock())
	_, err = resolver.RegisterSigningFromSeed("audit-test-1", keys.PurposeSigningAudit, bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	for i, e := range stored {
		require.NoError(t, e.VerifySignature(resolver), "event %d", i)
		if i > 0 {
			require.Equal(t, stored[i-1].Hash, e.PrevHash, "event %d links to its predecessor", i)
		}
	}

	// Reopened, the log continues where it stopped.
	again, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil)
	require.NoError(t, err)
	defer func() { _ = again.Close() }()
	require.Equal(t, 4, again.Len())
	require.NoError(t, again.TrustRefused("tls", "127.0.0.1:7", tee.ProviderSimulated, shared_errors.Operational("x", "y", nil)))
	require.Equal(t, 5, again.Len())
}

func TestReturnPathAudit_ClosedLogStopsTheDecision(t *testing.T) {
	a, _ := newTestAudit(t)
	ta := newTestAuthority(t, a)
	require.NoError(t, a.Close())

	err := a.TrustRefused("tls", "", tee.ProviderSimulated, shared_errors.Operational("x", "y", nil))
	require.Error(t, err)
	require.Equal(t, CodeAuditUnavailable, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))

	// The flow stops the same way: nothing is admitted off the record.
	_, err = ta.authority.Intake(ta.request("never", "genome-x"), nil)
	require.Error(t, err)
	require.Equal(t, CodeAuditUnavailable, shared_errors.CodeOf(err))

	// No log configured: nothing is recorded, nothing fails.
	var none *returnPathAudit
	require.NoError(t, none.TrustRefused("tls", "", tee.ProviderSimulated, shared_errors.Operational("x", "y", nil)))
	require.NoError(t, none.TrustStale("", tee.ProviderSimulated, nil, time.Time{}, 0, 0))
	require.NoError(t, none.Close())
	require.Equal(t, 0, none.Len())
	require.Equal(t, "", none.Tip())
	require.Nil(t, none.Chain())
	require.Nil(t, none.Signer())
	require.Empty(t, none.KeyID())
}

func TestReturnPathAudit_RefusesAnEditedLogAndNeedsItsKey(t *testing.T) {
	a, cfg := newTestAudit(t)
	require.NoError(t, a.TrustRefused("tls", "", tee.ProviderSimulated, shared_errors.Operational("x", "y", nil)))
	require.NoError(t, a.Close())

	// Another key: the stored events do not verify, the log is refused.
	other := filepath.Join(t.TempDir(), "other.seed")
	require.NoError(t, os.WriteFile(other, bytes.Repeat([]byte{0x43}, crypto.Ed25519SeedSize), 0o600))
	wrong := cfg
	wrong.Keys.AuditSigning.SeedPath = other
	_, err := openReturnPathAudit(wrong, shared_time.NewSystemClock(), nil)
	require.ErrorContains(t, err, "does not verify")

	// No key configured with a log path.
	nokey := cfg
	nokey.Keys.AuditSigning = SigningKeyConfig{}
	_, err = openReturnPathAudit(nokey, shared_time.NewSystemClock(), nil)
	require.ErrorContains(t, err, "keys.audit_signing")

	// No log path: no audit, no error.
	none := cfg
	none.Audit.LogPath = ""
	got, err := openReturnPathAudit(none, shared_time.NewSystemClock(), nil)
	require.NoError(t, err)
	require.Nil(t, got)
}
