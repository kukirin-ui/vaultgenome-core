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
	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// --- shared helpers --------------------------------------------------------

// buildAuditFixture writes a temp bbolt audit file containing N
// chain-linked, signed events. Returns (auditPath, auditPubKey, auditKID, events).
func buildAuditFixture(t *testing.T, count int) (string, []byte, ids.KeyID, []audit_event.AuditEvent) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.bbolt")

	clock := shared_time.NewSystemClock()
	store0 := keys.NewInMemoryStore(clock)
	auditKID := ids.KeyID("test-audit-signing")
	seed := bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize)
	vk, err := store0.RegisterSigningFromSeed(auditKID, keys.PurposeSigningAudit, seed)
	require.NoError(t, err)

	bs, err := store.Open(auditPath)
	require.NoError(t, err)

	c := chain.NewInMemoryChain()
	t0 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	written := make([]audit_event.AuditEvent, 0, count)
	for i := 0; i < count; i++ {
		// Alternate kinds and session IDs so query/lineage tests have
		// meaningful filtering surfaces.
		kind := audit_event.KindRequestReceived
		if i%3 == 0 {
			kind = audit_event.KindReleaseDecided
		} else if i%3 == 1 {
			kind = audit_event.KindValidationCompleted
		}
		sess := ids.SessionID("sess-A")
		if i%2 == 1 {
			sess = ids.SessionID("sess-B")
		}
		evt := audit_event.AuditEvent{
			SchemaVersion: audit_event.SchemaVersionCurrent,
			EventID:       ids.AuditEventID("evt-" + string(rune('A'+i))),
			Kind:          kind,
			OccurredAt:    t0.Add(time.Duration(i) * time.Minute),
			SessionID:     sess,
			ManifestID:    ids.ManifestID("m-1"),
			Payload:       []byte(`{"i":` + string(rune('0'+i)) + `}`),
			SigningKeyID:  auditKID,
		}
		signed, err := c.Append(evt, store0)
		require.NoError(t, err)
		require.NoError(t, bs.Append(signed))
		written = append(written, signed)
	}
	require.NoError(t, bs.Close())

	pub := make([]byte, len(vk.PublicKey))
	copy(pub, vk.PublicKey)
	return auditPath, pub, auditKID, written
}

// --- status ---------------------------------------------------------------

func TestStatusCmd_PrintsSummary(t *testing.T) {
	t.Parallel()
	auditPath, _, _, events := buildAuditFixture(t, 6)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	rc := statusCmd([]string{"--audit", auditPath}, stdout, stderr)
	require.Equal(t, 0, rc, "stderr=%q", stderr.String())

	out := stdout.String()
	require.Contains(t, out, "audit events:    6")
	require.Contains(t, out, "RELEASE_DECIDED")
	require.Contains(t, out, "VALIDATION_COMPLETED")
	require.Contains(t, out, "REQUEST_RECEIVED")
	require.Contains(t, out, string(events[len(events)-1].EventID))
}

func TestStatusCmd_JSONOutput(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 4)

	stdout := &bytes.Buffer{}
	rc := statusCmd([]string{"--audit", auditPath, "--json"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)

	var s statusSummary
	require.NoError(t, json.NewDecoder(stdout).Decode(&s))
	require.Equal(t, 4, s.AuditEventCount)
	require.Equal(t, 2, s.UniqueSessions)
	require.Equal(t, 1, s.UniqueManifests)
	require.NotNil(t, s.LastEvent)
}

func TestStatusCmd_EmptyAuditFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "empty.bbolt")
	bs, err := store.Open(auditPath)
	require.NoError(t, err)
	require.NoError(t, bs.Close())

	stdout := &bytes.Buffer{}
	rc := statusCmd([]string{"--audit", auditPath, "--json"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	var s statusSummary
	require.NoError(t, json.NewDecoder(stdout).Decode(&s))
	require.Equal(t, 0, s.AuditEventCount)
}

func TestStatusCmd_RejectsMissingAuditFlag(t *testing.T) {
	t.Parallel()
	stderr := &bytes.Buffer{}
	rc := statusCmd([]string{}, &bytes.Buffer{}, stderr)
	require.Equal(t, 2, rc)
	require.Contains(t, stderr.String(), "--audit is required")
}

func TestStatusCmd_NonexistentAuditFile(t *testing.T) {
	t.Parallel()
	stderr := &bytes.Buffer{}
	rc := statusCmd([]string{"--audit", "/nonexistent/path"}, &bytes.Buffer{}, stderr)
	require.NotEqual(t, 0, rc)
}

// --- audit query ----------------------------------------------------------

func TestAuditQueryCmd_FilterByKind(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 9)

	stdout := &bytes.Buffer{}
	rc := auditCmd([]string{"query", "--audit", auditPath, "--kind", "RELEASE_DECIDED"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	out := stdout.String()
	require.Contains(t, out, "RELEASE_DECIDED")
	require.NotContains(t, out, "REQUEST_RECEIVED")
}

func TestAuditQueryCmd_FilterBySession(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 6)

	stdout := &bytes.Buffer{}
	rc := auditCmd([]string{"query", "--audit", auditPath, "--session", "sess-A"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	out := stdout.String()
	require.Contains(t, out, "session=sess-A")
	require.NotContains(t, out, "session=sess-B")
}

func TestAuditQueryCmd_TimeRange(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 6)

	since := "2026-04-01T12:02:00Z"
	until := "2026-04-01T12:04:00Z"
	stdout := &bytes.Buffer{}
	rc := auditCmd([]string{"query", "--audit", auditPath, "--since", since, "--until", until, "--json"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	// Each line is a JSON event; count them.
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if line == "" {
			continue
		}
		var evt map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &evt))
		count++
	}
	// Events occur at minutes 0,1,2,3,4,5; window 12:02..12:04 includes 2,3,4 → 3.
	require.Equal(t, 3, count)
}

func TestAuditQueryCmd_LimitsApplied(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 10)
	stdout := &bytes.Buffer{}
	rc := auditCmd([]string{"query", "--audit", auditPath, "--limit", "3"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	require.Contains(t, stdout.String(), "matched: 3 of 10")
}

// --- audit verify ---------------------------------------------------------

func TestAuditVerifyCmd_HappyPath(t *testing.T) {
	t.Parallel()
	auditPath, pub, kid, _ := buildAuditFixture(t, 5)
	pubPath := filepath.Join(t.TempDir(), "audit.pub")
	require.NoError(t, os.WriteFile(pubPath, pub, 0o600))

	stdout := &bytes.Buffer{}
	rc := auditCmd([]string{"verify",
		"--audit", auditPath,
		"--audit-pubkey", pubPath,
		"--audit-kid", string(kid),
	}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	require.Contains(t, stdout.String(), "audit chain ok")
	require.Contains(t, stdout.String(), "5 events verified")
}

func TestAuditVerifyCmd_DetectsTamperedEvent(t *testing.T) {
	t.Parallel()
	auditPath, pub, kid, _ := buildAuditFixture(t, 4)

	// Tamper the audit file: open, alter the last event's payload via
	// a second store handle, append a corrupted blob. The simplest way
	// to simulate corruption is to write a hand-built event whose hash
	// chain is broken.
	bs, err := store.Open(auditPath)
	require.NoError(t, err)
	rogue := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID("rogue-1"),
		Kind:          audit_event.KindReleaseDecided,
		OccurredAt:    time.Now(),
		SigningKeyID:  kid,
		// Deliberately wrong PrevHash — would correctly link to a
		// different event, breaking the chain.
		PrevHash:  bytes.Repeat([]byte{0xFF}, audit_event.HashSize),
		Hash:      bytes.Repeat([]byte{0xAA}, audit_event.HashSize),
		Signature: bytes.Repeat([]byte{0xBB}, crypto.Ed25519SignatureSize),
		Payload:   []byte(`{}`),
	}
	require.NoError(t, bs.Append(rogue))
	require.NoError(t, bs.Close())

	pubPath := filepath.Join(t.TempDir(), "audit.pub")
	require.NoError(t, os.WriteFile(pubPath, pub, 0o600))

	stderr := &bytes.Buffer{}
	rc := auditCmd([]string{"verify",
		"--audit", auditPath,
		"--audit-pubkey", pubPath,
		"--audit-kid", string(kid),
	}, &bytes.Buffer{}, stderr)
	require.NotEqual(t, 0, rc)
	require.Contains(t, stderr.String(), "BROKEN")
}

func TestAuditVerifyCmd_RejectsWrongPubkey(t *testing.T) {
	t.Parallel()
	auditPath, _, kid, _ := buildAuditFixture(t, 3)
	wrongPub := bytes.Repeat([]byte{0x99}, crypto.Ed25519PublicKeySize)
	pubPath := filepath.Join(t.TempDir(), "wrong.pub")
	require.NoError(t, os.WriteFile(pubPath, wrongPub, 0o600))

	rc := auditCmd([]string{"verify",
		"--audit", auditPath,
		"--audit-pubkey", pubPath,
		"--audit-kid", string(kid),
	}, &bytes.Buffer{}, &bytes.Buffer{})
	require.NotEqual(t, 0, rc)
}

// --- lineage --------------------------------------------------------------

func TestLineageCmd_BySession(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 8)
	stdout := &bytes.Buffer{}
	rc := lineageCmd([]string{"--audit", auditPath, "--session-id", "sess-A", "--json"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	var r lineageResult
	require.NoError(t, json.NewDecoder(stdout).Decode(&r))
	require.Equal(t, "sess-A", r.QuerySession)
	// indices 0,2,4,6 — even-numbered events have session=sess-A.
	require.Equal(t, 4, r.Matched)
	for _, e := range r.Events {
		require.Equal(t, "sess-A", e.SessionID)
	}
}

func TestLineageCmd_ByManifest(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 5)
	stdout := &bytes.Buffer{}
	rc := lineageCmd([]string{"--audit", auditPath, "--manifest-id", "m-1", "--json"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	var r lineageResult
	require.NoError(t, json.NewDecoder(stdout).Decode(&r))
	require.Equal(t, 5, r.Matched)
}

func TestLineageCmd_NoMatches(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 3)
	stdout := &bytes.Buffer{}
	rc := lineageCmd([]string{"--audit", auditPath, "--session-id", "nonexistent", "--json"}, stdout, &bytes.Buffer{})
	require.Equal(t, 0, rc)
	var r lineageResult
	require.NoError(t, json.NewDecoder(stdout).Decode(&r))
	require.Equal(t, 0, r.Matched)
}

func TestLineageCmd_RejectsBothFlags(t *testing.T) {
	t.Parallel()
	stderr := &bytes.Buffer{}
	rc := lineageCmd([]string{"--audit", "x.bbolt", "--session-id", "a", "--manifest-id", "b"}, &bytes.Buffer{}, stderr)
	require.Equal(t, 2, rc)
	require.Contains(t, stderr.String(), "exactly one")
}

func TestLineageCmd_RejectsNeitherFlag(t *testing.T) {
	t.Parallel()
	stderr := &bytes.Buffer{}
	rc := lineageCmd([]string{"--audit", "x.bbolt"}, &bytes.Buffer{}, stderr)
	require.Equal(t, 2, rc)
}

// --- audit sub-dispatch ---------------------------------------------------

func TestAuditCmd_RejectsUnknownSubcommand(t *testing.T) {
	t.Parallel()
	stderr := &bytes.Buffer{}
	rc := auditCmd([]string{"explode"}, &bytes.Buffer{}, stderr)
	require.Equal(t, 2, rc)
	require.Contains(t, stderr.String(), "unknown subcommand")
}

func TestAuditCmd_ZeroArgsShowsUsage(t *testing.T) {
	t.Parallel()
	stderr := &bytes.Buffer{}
	rc := auditCmd([]string{}, &bytes.Buffer{}, stderr)
	require.Equal(t, 2, rc)
	require.Contains(t, stderr.String(), "usage:")
}
