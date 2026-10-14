// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// signedAuditFixture writes a bbolt audit file holding the given events,
// chain-linked and signed in order. The caller sets the correlators; the
// schema version and signing key are filled in here.
func signedAuditFixture(t *testing.T, events []audit_event.AuditEvent) (string, []byte, ids.KeyID) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.bbolt")
	ks := keys.NewInMemoryStore(shared_time.NewSystemClock())
	kid := ids.KeyID("test-audit-signing")
	vk, err := ks.RegisterSigningFromSeed(kid, keys.PurposeSigningAudit, bytes.Repeat([]byte{0x24}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	bs, err := store.Open(path)
	require.NoError(t, err)
	c := chain.NewInMemoryChain()
	for _, evt := range events {
		evt.SchemaVersion = audit_event.SchemaVersionCurrent
		evt.SigningKeyID = kid
		signed, err := c.Append(evt, ks)
		require.NoError(t, err)
		require.NoError(t, bs.Append(signed))
	}
	require.NoError(t, bs.Close())
	return path, append([]byte(nil), vk.PublicKey...), kid
}

// corruptAuditStore writes a bbolt audit file whose one record is not an
// event, so the store opens but its events do not load.
func corruptAuditStore(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corrupt.bbolt")
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("audit_events"))
		if err != nil {
			return err
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], 1)
		return b.Put(key[:], []byte("this is not an audit event"))
	}))
	require.NoError(t, db.Close())
	return path
}

// absentDirPath is a path whose parent directory does not exist, so the
// store cannot be created there.
func absentDirPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent", "audit.bbolt")
}

// kindColumn is an event kind padded to the 30-character column the text
// forms print it in.
func kindColumn(kind string) string { return kind + strings.Repeat(" ", 30-len(kind)) }

// --- audit dispatch -------------------------------------------------------

func TestAuditCmd_Help(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"help", "--help", "-h"} {
		var stdout, stderr bytes.Buffer
		require.Equal(t, 0, auditCmd([]string{arg}, &stdout, &stderr))
		require.Contains(t, stdout.String(), "query")
		require.Contains(t, stdout.String(), "verify")
		require.Empty(t, stderr.String())
	}
}

// --- audit query ----------------------------------------------------------

func TestAuditQueryCmd_Refusals(t *testing.T) {
	t.Parallel()
	auditPath, _, _, _ := buildAuditFixture(t, 2)
	corrupt := corruptAuditStore(t)
	absent := absentDirPath(t)
	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"no audit":      {[]string{}, 2, "--audit is required"},
		"unknown flag":  {[]string{"--audit", auditPath, "--nope"}, 2, "flag provided but not defined"},
		"bad since":     {[]string{"--audit", auditPath, "--since", "yesterday"}, 2, "--since: must be RFC3339"},
		"bad until":     {[]string{"--audit", auditPath, "--until", "2026-04-01"}, 2, "--until: must be RFC3339"},
		"cannot open":   {[]string{"--audit", absent}, 1, "open audit store"},
		"corrupt event": {[]string{"--audit", corrupt}, 1, "load: integrity[field_value_invalid]: audit/store: unmarshal seq=1 failed"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			rc := auditCmd(append([]string{"query"}, tc.args...), &stdout, &stderr)
			require.Equal(t, tc.code, rc, stderr.String())
			require.Contains(t, stderr.String(), tc.want)
			require.Empty(t, stdout.String())
		})
	}
}

// --manifest narrows to one manifest, --limit 0 means every match, and the
// text form names the manifest of every event.
func TestAuditQueryCmd_ManifestFilterAndUnlimited(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	var events []audit_event.AuditEvent
	for i := 0; i < 5; i++ {
		man := ids.ManifestID("m-odd")
		if i%2 == 0 {
			man = "m-even"
		}
		events = append(events, audit_event.AuditEvent{
			EventID:    ids.AuditEventID("evt-" + string(rune('a'+i))),
			Kind:       audit_event.KindReleaseDecided,
			OccurredAt: t0.Add(time.Duration(i) * time.Minute),
			SessionID:  "sess-1",
			ManifestID: man,
			Payload:    []byte(`{}`),
		})
	}
	auditPath, _, _ := signedAuditFixture(t, events)

	var stdout, stderr bytes.Buffer
	rc := auditCmd([]string{"query", "--audit", auditPath, "--manifest", "m-even", "--limit", "0"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	out := stdout.String()
	require.Contains(t, out, "matched: 3 of 5 events")
	require.Equal(t, 3, strings.Count(out, "manifest=m-even"))
	require.NotContains(t, out, "m-odd")
	require.Contains(t, out, "session=sess-1")

	stdout.Reset()
	rc = auditCmd([]string{"query", "--audit", auditPath, "--manifest", "m-none"}, &stdout, &stderr)
	require.Equal(t, 0, rc)
	require.Contains(t, stdout.String(), "matched: 0 of 5 events")
}

// parseOptionalTime accepts nothing or RFC 3339 and names the flag it
// refuses.
func TestParseOptionalTime(t *testing.T) {
	t.Parallel()
	got, err := parseOptionalTime("", "--since")
	require.NoError(t, err)
	require.True(t, got.IsZero())

	got, err = parseOptionalTime("2026-04-01T12:34:56Z", "--until")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 4, 1, 12, 34, 56, 0, time.UTC), got)

	_, err = parseOptionalTime("2026-04-01 12:34", "--until")
	require.ErrorContains(t, err, `--until: must be RFC3339, got "2026-04-01 12:34"`)
}

// Every filter dimension excludes on its own; an unset one matches all.
func TestMatchesFilters(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	evt := &audit_event.AuditEvent{Kind: audit_event.KindReleaseDecided, SessionID: "s", ManifestID: "m", OccurredAt: at}
	for name, tc := range map[string]struct {
		kind, sess, man string
		since, until    time.Time
		want            bool
	}{
		"no filter":      {want: true},
		"all match":      {kind: "RELEASE_DECIDED", sess: "s", man: "m", since: at, until: at, want: true},
		"other kind":     {kind: "REQUEST_RECEIVED"},
		"other session":  {sess: "t"},
		"other manifest": {man: "n"},
		"before since":   {since: at.Add(time.Second)},
		"after until":    {until: at.Add(-time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, matchesFilters(evt, tc.kind, tc.sess, tc.man, tc.since, tc.until))
		})
	}
}

// The JSON form embeds a JSON payload as JSON and carries any other
// payload base64-encoded; the text form names the session and manifest.
func TestEmitEvent_Forms(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 4, 1, 12, 0, 0, 500, time.UTC)
	evt := &audit_event.AuditEvent{EventID: "evt-1", Kind: audit_event.KindReleaseDecided, OccurredAt: at, SessionID: "sess-1", ManifestID: "m-1", RequestID: "req-1", Payload: []byte(`{"decision":"allow"}`)}

	var buf bytes.Buffer
	emitEvent(&buf, true, evt)
	var rec map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	require.JSONEq(t, `{"decision":"allow"}`, string(rec["payload"]))
	require.NotContains(t, rec, "payload_base64")
	require.JSONEq(t, `"2026-04-01T12:00:00.0000005Z"`, string(rec["occurred_at"]))
	require.JSONEq(t, `"req-1"`, string(rec["request_id"]))

	buf.Reset()
	raw := &audit_event.AuditEvent{EventID: "evt-2", Kind: audit_event.KindRequestReceived, OccurredAt: at, Payload: []byte{0xff, 0x00, 'x'}}
	emitEvent(&buf, true, raw)
	rec = nil
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	require.NotContains(t, rec, "payload")
	require.JSONEq(t, `"/wB4"`, string(rec["payload_base64"]))

	buf.Reset()
	emitEvent(&buf, false, evt)
	require.Equal(t, "2026-04-01T12:00:00Z  "+kindColumn("RELEASE_DECIDED")+"  evt-1  session=sess-1  manifest=m-1\n", buf.String())

	buf.Reset()
	emitEvent(&buf, false, raw)
	require.Equal(t, "2026-04-01T12:00:00Z  "+kindColumn("REQUEST_RECEIVED")+"  evt-2\n", buf.String())
}

// --- audit verify ---------------------------------------------------------

func TestAuditVerifyCmd_Refusals(t *testing.T) {
	t.Parallel()
	auditPath, pub, kid, _ := buildAuditFixture(t, 2)
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "audit.pub")
	require.NoError(t, os.WriteFile(pubPath, pub, 0o600))
	shortPub := filepath.Join(dir, "short.pub")
	require.NoError(t, os.WriteFile(shortPub, []byte("short"), 0o600))
	corrupt := corruptAuditStore(t)
	absent := absentDirPath(t)

	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"no flags":     {[]string{}, 2, "all required"},
		"no kid":       {[]string{"--audit", auditPath, "--audit-pubkey", pubPath}, 2, "all required"},
		"unknown flag": {[]string{"--nope"}, 2, "flag provided but not defined"},
		"bad pubkey":   {[]string{"--audit", auditPath, "--audit-pubkey", shortPub, "--audit-kid", string(kid)}, 1, "pubkey must be PEM or exactly 32 raw bytes"},
		"cannot open":  {[]string{"--audit", absent, "--audit-pubkey", pubPath, "--audit-kid", string(kid)}, 1, "open audit store"},
		"cannot load":  {[]string{"--audit", corrupt, "--audit-pubkey", pubPath, "--audit-kid", string(kid)}, 1, "load:"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			rc := auditCmd(append([]string{"verify"}, tc.args...), &stdout, &stderr)
			require.Equal(t, tc.code, rc, stderr.String())
			require.Contains(t, stderr.String(), tc.want)
			require.Empty(t, stdout.String())
		})
	}
}

// --json reports the verdict, the event count and the tip of a sound
// chain, and the error of a broken one (exit 4 either way it is broken).
func TestAuditVerifyCmd_JSON(t *testing.T) {
	t.Parallel()
	auditPath, pub, kid, events := buildAuditFixture(t, 3)
	pubPath := filepath.Join(t.TempDir(), "audit.pub")
	require.NoError(t, os.WriteFile(pubPath, pub, 0o600))

	var stdout, stderr bytes.Buffer
	rc := auditCmd([]string{"verify", "--audit", auditPath, "--audit-pubkey", pubPath, "--audit-kid", string(kid), "--json"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	var res auditVerifyResult
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &res))
	require.True(t, res.OK)
	require.Equal(t, 3, res.EventCount)
	require.Equal(t, auditPath, res.AuditPath)
	require.Equal(t, hex.EncodeToString(events[2].Hash), res.Tip)
	require.Empty(t, res.Error)

	// The same chain checked against another registered key ID: every
	// signature then resolves to nothing, which is a broken chain.
	stdout.Reset()
	stderr.Reset()
	rc = auditCmd([]string{"verify", "--audit", auditPath, "--audit-pubkey", pubPath, "--audit-kid", "other-kid", "--json"}, &stdout, &stderr)
	require.Equal(t, 4, rc)
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &res))
	require.False(t, res.OK)
	require.Contains(t, res.Error, "event #0")
	require.Contains(t, res.Error, "not registered")
	require.Contains(t, stderr.String(), "chain BROKEN")
}

func TestEmitAuditVerify_Forms(t *testing.T) {
	t.Parallel()
	ok := auditVerifyResult{OK: true, AuditPath: "/a", EventCount: 4, Tip: "abcd"}
	broken := auditVerifyResult{OK: false, AuditPath: "/a", EventCount: 4, Error: "event #2: bad"}

	var buf bytes.Buffer
	emitAuditVerify(&buf, false, ok)
	require.Equal(t, "audit chain ok — 4 events verified, tip abcd\n", buf.String())

	buf.Reset()
	emitAuditVerify(&buf, false, broken)
	require.Equal(t, "audit chain BROKEN: event #2: bad\n", buf.String())

	buf.Reset()
	emitAuditVerify(&buf, true, broken)
	var back auditVerifyResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &back))
	require.Equal(t, broken, back)
}

// The verify resolver answers for one key ID and the audit-signing
// purpose only, refusing anything else with a classified error.
func TestSinglePubkeyResolver(t *testing.T) {
	t.Parallel()
	pub := bytes.Repeat([]byte{0x11}, crypto.Ed25519PublicKeySize)
	r := newSinglePubkeyResolver("audit-1", pub)

	vk, err := r.Resolve("audit-1", keys.PurposeSigningAudit)
	require.NoError(t, err)
	require.Equal(t, ids.KeyID("audit-1"), vk.KeyID)
	require.Equal(t, keys.PurposeSigningAudit, vk.Purpose)
	require.Equal(t, crypto.PublicKey(pub), vk.PublicKey)
	pub[0] = 0xEE
	require.Equal(t, byte(0x11), vk.PublicKey[0], "the resolver keeps its own copy of the key")

	_, err = r.Resolve("audit-2", keys.PurposeSigningAudit)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, `kid "audit-2" not registered (expected "audit-1")`)

	_, err = r.Resolve("audit-1", keys.PurposeSigningAuthority)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "only signing_audit")
}

// A chain whose link is cut is an integrity error naming the event.
func TestVerifyEventsInOrder_BrokenLink(t *testing.T) {
	t.Parallel()
	_, pub, kid, events := buildAuditFixture(t, 3)
	resolver := newSinglePubkeyResolver(kid, pub)
	require.NoError(t, verifyEventsInOrder(events, resolver))
	require.NoError(t, verifyEventsInOrder(nil, resolver), "an empty log is sound")

	cut := append([]audit_event.AuditEvent(nil), events...)
	cut[2].PrevHash = bytes.Repeat([]byte{0xFF}, audit_event.HashSize)
	err := verifyEventsInOrder(cut, resolver)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "event #2: prev_hash does not link to event #1")
}

// readEd25519PublicKey takes a PKIX PEM or the raw 32 bytes and nothing else.
func TestReadEd25519PublicKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, data, 0o600))
		return p
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edPEM, err := crypto.PublicKeyPEM(crypto.PublicKey(edPub))
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})
	junkPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not DER")})

	got, err := readEd25519PublicKey(write("raw", edPub))
	require.NoError(t, err)
	require.Equal(t, []byte(edPub), got)

	got, err = readEd25519PublicKey(write("pem", edPEM))
	require.NoError(t, err)
	require.Equal(t, []byte(edPub), got)

	for name, tc := range map[string]struct {
		path string
		want string
	}{
		"absent":        {filepath.Join(dir, "absent"), "read pubkey"},
		"wrong length":  {write("short", []byte("too short")), "exactly 32 raw bytes"},
		"not ed25519":   {write("ec.pem", ecPEM), "want an Ed25519 key"},
		"pem not pkix":  {write("junk.pem", junkPEM), "parse pubkey PEM"},
		"seed sized":    {write("seed", bytes.Repeat([]byte{1}, 33)), "exactly 32 raw bytes"},
		"empty file":    {write("empty", nil), "exactly 32 raw bytes"},
		"pem of 32 raw": {write("raw32.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edPub})), "parse pubkey PEM"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := readEd25519PublicKey(tc.path)
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, got)
		})
	}
}

// --- lineage --------------------------------------------------------------

func TestLineageCmd_Refusals(t *testing.T) {
	t.Parallel()
	corrupt := corruptAuditStore(t)
	absent := absentDirPath(t)
	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"no audit":     {[]string{"--session-id", "s"}, 2, "--audit is required"},
		"unknown flag": {[]string{"--audit", "x", "--nope"}, 2, "flag provided but not defined"},
		"cannot open":  {[]string{"--audit", absent, "--session-id", "s"}, 1, "open audit store"},
		"cannot load":  {[]string{"--audit", corrupt, "--manifest-id", "m"}, 1, "load:"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			rc := lineageCmd(tc.args, &stdout, &stderr)
			require.Equal(t, tc.code, rc, stderr.String())
			require.Contains(t, stderr.String(), tc.want)
			require.Empty(t, stdout.String())
		})
	}
}

// The text form lists every event of the lineage in time order with the
// correlators the query did not fix: the manifest for a session query,
// the session for a manifest query, and the request either way.
func TestLineageCmd_Text(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	auditPath, _, _ := signedAuditFixture(t, []audit_event.AuditEvent{
		{EventID: "evt-1", Kind: audit_event.KindRequestReceived, OccurredAt: t0, SessionID: "sess-A", ManifestID: "m-1", RequestID: "req-9", Payload: []byte(`{}`)},
		{EventID: "evt-2", Kind: audit_event.KindReleaseDecided, OccurredAt: t0.Add(2 * time.Minute), SessionID: "sess-B", ManifestID: "m-1", Payload: []byte(`{}`)},
		// Written last but it happened first: the lineage is in time order.
		{EventID: "evt-3", Kind: audit_event.KindSessionIssued, OccurredAt: t0.Add(-time.Minute), SessionID: "sess-A", Payload: []byte(`{}`)},
	})

	var stdout, stderr bytes.Buffer
	rc := lineageCmd([]string{"--audit", auditPath, "--session-id", "sess-A"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	out := stdout.String()
	require.Contains(t, out, "lineage for session sess-A:\n")
	require.Contains(t, out, "2 events in lineage")
	require.Less(t, strings.Index(out, "evt-3"), strings.Index(out, "evt-1"), "time order, not storage order")
	require.Contains(t, out, "  [   2] 2026-04-01T11:59:00Z  "+kindColumn("SESSION_ISSUED")+"  evt-3\n")
	require.Contains(t, out, "  [   0] 2026-04-01T12:00:00Z  "+kindColumn("REQUEST_RECEIVED")+"  evt-1  manifest=m-1  request=req-9\n")
	require.NotContains(t, out, "session=", "the session is the query, not a column")
	require.NotContains(t, out, "evt-2")

	stdout.Reset()
	rc = lineageCmd([]string{"--audit", auditPath, "--manifest-id", "m-1"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	out = stdout.String()
	require.Contains(t, out, "lineage for manifest m-1:\n")
	require.Contains(t, out, "evt-1  session=sess-A  request=req-9\n")
	require.Contains(t, out, "evt-2  session=sess-B\n")
	require.NotContains(t, out, "manifest=")
	require.Contains(t, out, "2 events in lineage")

	stdout.Reset()
	rc = lineageCmd([]string{"--audit", auditPath, "--manifest-id", "m-none"}, &stdout, &stderr)
	require.Equal(t, 0, rc)
	require.Equal(t, "no events found for the requested ID\n", stdout.String())
}

func TestEmitLineage_JSON(t *testing.T) {
	t.Parallel()
	r := lineageResult{QueryManifest: "m-1", Matched: 1, Events: []lineageEvent{{EventID: "e", Kind: "K", OccurredAt: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC), Index: 3}}}
	var buf bytes.Buffer
	emitLineage(&buf, true, r)
	var back lineageResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &back))
	require.Equal(t, r, back)
}

// --- status ---------------------------------------------------------------

func TestStatusCmd_CannotLoad(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	rc := statusCmd([]string{"--audit", corruptAuditStore(t)}, &stdout, &stderr)
	require.Equal(t, 1, rc)
	require.Contains(t, stderr.String(), "load events")
	require.Empty(t, stdout.String())

	stderr.Reset()
	rc = statusCmd([]string{"--audit", "x", "--nope"}, &stdout, &stderr)
	require.Equal(t, 2, rc)
	require.Contains(t, stderr.String(), "flag provided but not defined")
	require.Empty(t, stdout.String())
}

// The time range is the earliest and latest event, whatever the storage
// order; the most recent event is the last stored.
func TestBuildStatusSummary_OutOfOrderEvents(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	events := []audit_event.AuditEvent{
		{EventID: "mid", Kind: audit_event.KindRequestReceived, OccurredAt: t0, SessionID: "s1"},
		{EventID: "late", Kind: audit_event.KindReleaseDecided, OccurredAt: t0.Add(time.Hour), SessionID: "s2", ManifestID: "m1"},
		{EventID: "early", Kind: audit_event.KindReleaseDecided, OccurredAt: t0.Add(-time.Hour), SessionID: "s1", ManifestID: "m1"},
	}
	s := buildStatusSummary(events)
	require.Equal(t, 3, s.AuditEventCount)
	require.Equal(t, t0.Add(-time.Hour), *s.FirstEventAt)
	require.Equal(t, t0.Add(time.Hour), *s.LastEventAt)
	require.Equal(t, 2, s.UniqueSessions)
	require.Equal(t, 1, s.UniqueManifests)
	require.Equal(t, map[string]int{"REQUEST_RECEIVED": 1, "RELEASE_DECIDED": 2}, s.KindHistogram)
	require.Equal(t, "early", s.LastEvent.EventID)
	require.Equal(t, "m1", s.LastEvent.ManifestID)

	var buf bytes.Buffer
	emitStatus(&buf, false, s)
	out := buf.String()
	require.Contains(t, out, "first event at:  2026-04-01T11:00:00Z")
	require.Contains(t, out, "last event at:   2026-04-01T13:00:00Z")
	require.Contains(t, out, "  RELEASE_DECIDED                  2\n")
	require.Contains(t, out, "  event_id:    early\n")
	require.Contains(t, out, "  manifest_id: m1\n")

	buf.Reset()
	emitStatus(&buf, false, buildStatusSummary(nil))
	require.Equal(t, "audit events:    0\nunique sessions: 0\nunique manifests:0\n", buf.String())
}
