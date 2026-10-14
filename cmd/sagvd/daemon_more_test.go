// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// NewDaemon refuses to wire a daemon that is missing any of its parts,
// and names the missing one; a TLS listener whose files are not there is
// refused before anything is bound.
func TestNewDaemon_RefusesMissingWiring(t *testing.T) {
	clock := shared_time.NewSystemClock()
	store := keys.NewInMemoryStore(clock)
	mat := &materials{Store: store}
	queue := NewJobQueue(clock, 0)
	registry := metrics.NewRegistry()
	cfg := DefaultConfig()
	cfg.Vault.ListenAddress = "127.0.0.1:0"

	for name, tc := range map[string]struct {
		cfg      func() Config
		mat      *materials
		queue    *JobQueue
		clock    shared_time.Clock
		registry *metrics.Registry
		want     string
	}{
		"no listen address": {func() Config { c := cfg; c.Vault.ListenAddress = ""; return c }, mat, queue, clock, registry, "vault.listen_address"},
		"no materials":      {func() Config { return cfg }, nil, queue, clock, registry, "non-nil materials"},
		"no queue":          {func() Config { return cfg }, mat, nil, clock, registry, "non-nil JobQueue"},
		"no clock":          {func() Config { return cfg }, mat, queue, nil, registry, "non-nil clock"},
		"no registry":       {func() Config { return cfg }, mat, queue, clock, nil, "non-nil metrics.Registry"},
		"tls files missing": {func() Config {
			c := cfg
			c.Vault.TLS = TLSConfig{Enabled: true, ServerCert: filepath.Join(t.TempDir(), "absent.crt"), ServerKey: "k", ClientCAs: "c"}
			return c
		}, mat, queue, clock, registry, "load server keypair"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewDaemon(tc.cfg(), tc.mat, tc.queue, nil, nil, tc.clock, nil, tc.registry)
			require.ErrorContains(t, err, tc.want)
		})
	}

	// Without a logger the daemon makes its own; Health starts live and
	// not ready; Metrics is the registered bundle with the start time set;
	// Zeroize empties the keystore so nothing signs after shutdown.
	kid := ids.KeyID("auth-z")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	d, err := NewDaemon(cfg, mat, queue, nil, nil, clock, nil, registry)
	require.NoError(t, err)
	require.True(t, d.Health().IsLive())
	require.False(t, d.Health().IsReady())
	require.Same(t, d.metrics, d.Metrics())
	var rendered bytes.Buffer
	require.NoError(t, registry.WriteMetricsTo(&rendered))
	require.Contains(t, rendered.String(), "sagvd_start_unix ")
	require.Equal(t, cfg.Vault.ListenAddress, d.Addr(), "the configured address until Run binds")
	_, err = store.Sign(kid, keys.PurposeSigningAuthority, []byte("before"))
	require.NoError(t, err)
	d.Zeroize()
	_, err = store.Sign(kid, keys.PurposeSigningAuthority, []byte("after"))
	require.Error(t, err, "the key is gone")
	d.Shutdown()
	require.False(t, d.Health().IsLive())
	(&Daemon{}).Zeroize() // no materials: nothing to wipe, nothing to fail
}

// A listener address that is taken is a bind failure Run reports as such,
// without marking the daemon ready.
func TestDaemon_RunRefusesAnOccupiedAddress(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()
	cfg := DefaultConfig()
	cfg.Vault.ListenAddress = taken.Addr().String()
	d, err := NewDaemon(cfg, &materials{}, NewJobQueue(shared_time.NewSystemClock(), 0), nil, nil, shared_time.NewSystemClock(), slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.NewRegistry())
	require.NoError(t, err)
	err = d.Run(context.Background())
	require.ErrorContains(t, err, "sagvd: listen")
	require.False(t, d.Health().IsReady())
}

func TestSleepContext(t *testing.T) {
	live, cancel := context.WithCancel(context.Background())
	require.True(t, sleepContext(live, 0), "nothing to wait for on a live context")
	require.True(t, sleepContext(live, time.Millisecond), "the sleep ran out")
	cancel()
	require.False(t, sleepContext(live, 0), "a cancelled context, even with nothing to wait for")
	require.False(t, sleepContext(live, time.Hour), "the cancellation wins over the timer")
}

func TestFirstFindingText(t *testing.T) {
	finding := func(code, msg string) validation_result.DimensionVerdict {
		return validation_result.DimensionVerdict{Verdict: validation_result.VerdictFail, Details: []validation_result.Finding{{Code: code, Message: msg}}}
	}
	require.Equal(t, "no finding", firstFindingText(validation_result.ValidationResult{}))
	require.Equal(t, "no finding", firstFindingText(validation_result.ValidationResult{Dimensions: map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionSemantic: {Verdict: validation_result.VerdictFail},
	}}), "a failed dimension without details names nothing")
	vr := validation_result.ValidationResult{Dimensions: map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionBehavioral: finding("beh.x", "behavioral first?"),
		validation_result.DimensionSemantic:   finding("sem.top1_disagreement", "fixture fx-002"),
	}}
	require.Equal(t, "semantic: sem.top1_disagreement: fixture fx-002", firstFindingText(vr), "the semantic dimension comes before the behavioral one")
	vr.Dimensions[validation_result.DimensionOperational] = finding("op.tamper", "tamper signalled")
	require.Equal(t, "operational: op.tamper: tamper signalled", firstFindingText(vr), "the operational dimension comes first")
}

func TestOutcomeFromError(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"operational":  {shared_errors.Operational("x", "m", nil), "reject"},
		"structural":   {shared_errors.Structural("x", "m", nil), "reject"},
		"authority":    {shared_errors.Authority("x", "m", nil), "fail"},
		"integrity":    {shared_errors.Integrity("x", "m", nil), "fail"},
		"incident":     {shared_errors.Incident("x", "m", nil), "fail"},
		"unclassified": {errors.New("plain"), "fail"},
		"nil":          {nil, "fail"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, outcomeFromError(tc.err))
		})
	}
}

// jobRequestFrom puts a signed manifest and its disclosures on the wire
// as one JobRequest — one SealedMaterialRef per disclosure, each under
// the AAD the disclosure was sealed with — and refuses what the wire
// contract refuses.
func TestJobRequestFrom(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	man := rjm.ReconstructionJobManifest{
		ManifestID: "rjm-1", SessionID: "ses-1", ExpectedOutputKind: rjm.OutputKindBytesFixedLength, ExpectedOutputMaxBytes: 64,
		Deadline: now.Add(time.Minute), IssuedAt: now,
	}
	msg := func(kid string, seq uint32) disclosure_message.DisclosureMessage {
		return disclosure_message.DisclosureMessage{
			SessionID: "ses-1", ComponentID: ids.ComponentID("c" + string(rune('0'+seq))), SequenceIndex: seq, PolicyVersion: "gate-policy/v1",
			RecipientKeyID: ids.KeyID(kid), Nonce: bytes.Repeat([]byte{1}, 12), SealedPayload: []byte("ciphertext"),
		}
	}

	req, err := jobRequestFrom(man, []disclosure_message.DisclosureMessage{msg("seal-1", 0), msg("seal-1", 1)})
	require.NoError(t, err)
	require.Equal(t, transport.FrameTypeJobRequest, req.Type)
	require.Equal(t, "rjm-1", req.ManifestID)
	require.Equal(t, "ses-1", req.SessionID)
	require.Equal(t, uint64(64), req.ExpectedOutputMaxBytes)
	require.Equal(t, man.Deadline, req.Deadline)
	require.Len(t, req.SealedMaterial, 2)
	wantAAD, err := disclosure_message.BuildRecipientAAD("ses-1", "c1", 1, "gate-policy/v1", "seal-1")
	require.NoError(t, err)
	require.Equal(t, wantAAD, req.SealedMaterial[1].AAD, "the AAD the disclosure was sealed under")
	require.Equal(t, "seal-1", req.SealedMaterial[1].RecipientKeyID)
	require.Equal(t, []byte("ciphertext"), req.SealedMaterial[1].Ciphertext)

	_, err = jobRequestFrom(rjm.ReconstructionJobManifest{}, []disclosure_message.DisclosureMessage{msg("seal-1", 0)})
	require.Error(t, err, "a manifest without an id is not a JobRequest")
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	_, err = jobRequestFrom(man, nil)
	require.Error(t, err, "a job with nothing to disclose")
	_, err = jobRequestFrom(man, []disclosure_message.DisclosureMessage{msg("", 0)})
	require.Error(t, err, "a disclosure sealed to no key")
}

// The mTLS listener's material is read when the daemon is wired: every
// missing or mismatched piece is named.
func TestLoadServerTLS_Refusals(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSignedPair(t, dir, "vault")
	_, otherKey := selfSignedPair(t, dir, "other")
	noPEM := filepath.Join(dir, "not-pem")
	require.NoError(t, os.WriteFile(noPEM, []byte("nothing here"), 0o600))
	for name, tc := range map[string]struct {
		cfg  TLSConfig
		want string
	}{
		"missing cert":   {TLSConfig{ServerCert: filepath.Join(dir, "absent.crt"), ServerKey: key, ClientCAs: cert}, "load server keypair"},
		"missing key":    {TLSConfig{ServerCert: cert, ServerKey: filepath.Join(dir, "absent.key"), ClientCAs: cert}, "vault.tls.server_key"},
		"mismatched key": {TLSConfig{ServerCert: cert, ServerKey: otherKey, ClientCAs: cert}, "load server keypair"},
		"missing CAs":    {TLSConfig{ServerCert: cert, ServerKey: key, ClientCAs: filepath.Join(dir, "absent.pem")}, "client CA bundle"},
		"CAs not PEM":    {TLSConfig{ServerCert: cert, ServerKey: key, ClientCAs: noPEM}, "no valid PEM certificates"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadServerTLS(TEEConfig{}, tc.cfg)
			require.ErrorContains(t, err, tc.want)
		})
	}
	tc, err := loadServerTLS(TEEConfig{}, TLSConfig{ServerCert: cert, ServerKey: key, ClientCAs: cert})
	require.NoError(t, err)
	require.Equal(t, tls.RequireAndVerifyClientCert, tc.ClientAuth, "a worker without a certificate cannot begin")
	require.Equal(t, uint16(tls.VersionTLS13), tc.MinVersion)
}

// A refused peer goes on the record when there is a record to put it on;
// without an audit log nothing is recorded and nothing fails, and a log
// that cannot take it is logged, not fatal.
func TestDaemon_RecordRefusal(t *testing.T) {
	audit, _ := newTestAudit(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &Daemon{mat: &materials{PeerProvider: tee.ProviderSimulated}, log: logger}
	d.recordRefusal("tls", "127.0.0.1:1", shared_errors.Authority("tls_handshake_failed", "x", nil))
	require.Equal(t, 0, d.audit.Len(), "no log configured: nothing recorded")

	d.audit = audit
	d.recordRefusal("handshake", "127.0.0.1:2", shared_errors.Authority("handshake_failure", "y", nil))
	require.Equal(t, 1, audit.Len())
	require.Contains(t, string(audit.chain.Events()[0].Payload), `"phase":"handshake"`)

	require.NoError(t, audit.Close())
	d.recordRefusal("handshake", "127.0.0.1:3", shared_errors.Authority("handshake_failure", "z", nil))
	require.Equal(t, 1, audit.Len(), "a closed log takes nothing")
}

// tlsFixture is a daemon fixture whose Return Path listener requires
// mTLS: the vault's pair, the worker's pair, each pinned by the other.
func tlsFixture(t *testing.T) (*daemonFixture, tls.Certificate) {
	t.Helper()
	dir := t.TempDir()
	serverCert, serverKey := selfSignedPair(t, dir, "vault")
	clientCert, clientKey := selfSignedPair(t, dir, "worker")
	f := newDaemonFixture(t, func(c *Config) {
		c.Vault.TLS = TLSConfig{Enabled: true, ServerCert: serverCert, ServerKey: serverKey, ClientCAs: clientCert}
	})
	pair, err := tls.LoadX509KeyPair(clientCert, clientKey)
	require.NoError(t, err)
	return f, pair
}

func (f *daemonFixture) auditTrustPhases() []string {
	var phases []string
	for _, e := range f.audit.chain.Events() {
		var p trustPayload
		if e.Kind == "TRUST_EVALUATED" && len(e.Payload) > 0 {
			_ = json.Unmarshal(e.Payload, &p)
			phases = append(phases, p.Phase)
		}
	}
	return phases
}

// Over mTLS a worker without a certificate is refused at the TLS
// handshake — counted, on the record as a denial with no request behind
// it — and a worker with one is taken through the whole flow.
func TestDaemon_MTLSRefusesTheUncertifiedAndServesTheCertified(t *testing.T) {
	f, pair := tlsFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// No client certificate: the server ends the handshake.
	raw, err := net.Dial("tcp", f.daemon.Addr())
	require.NoError(t, err)
	bare := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	err = bare.HandshakeContext(ctx)
	if err == nil {
		// TLS 1.3 lets the client finish before the server has judged its
		// (absent) certificate: the refusal arrives with the first read.
		_, err = bare.Read(make([]byte, 1))
	}
	require.Error(t, err, "a worker without a certificate gets no session")
	_ = bare.Close()
	require.Eventually(t, func() bool { return len(f.auditTrustPhases()) == 1 }, 5*time.Second, 10*time.Millisecond, "the refusal goes on the record")
	require.Equal(t, []string{"tls"}, f.auditTrustPhases())
	require.Equal(t, `sagvd_handshake_failures_total{phase="tls"} 1`, f.metric(`sagvd_handshake_failures_total{phase="tls"}`))

	// The certified worker is served.
	id := f.submit(PolicyProfileGate)
	raw, err = net.Dial("tcp", f.daemon.Addr())
	require.NoError(t, err)
	conn := tls.Client(raw, &tls.Config{Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	require.NoError(t, conn.HandshakeContext(ctx))
	require.NoError(t, f.workerConn(ctx, conn, func(string) ([]byte, error) { return f.sealed.rightOutput(t, nil), nil }))
	view := f.waitJob(id, "succeeded")
	require.Equal(t, "release_authorized", view.State)
	require.Equal(t, `sagvd_sessions_opened_total 1`, f.metric("sagvd_sessions_opened_total"))
}

// Bytes that are not a Return Path handshake are refused at the handshake,
// counted and on the record; the daemon goes on to serve the next worker.
func TestDaemon_GarbageHandshakeIsRefusedOnTheRecord(t *testing.T) {
	f := newDaemonFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := net.Dial("tcp", f.daemon.Addr())
	require.NoError(t, err)
	_, err = conn.Write(bytes.Repeat([]byte("not a frame "), 8))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return len(f.auditTrustPhases()) == 1 }, 5*time.Second, 10*time.Millisecond, "the refusal goes on the record")
	require.Equal(t, []string{"handshake"}, f.auditTrustPhases())
	require.Equal(t, `sagvd_handshake_failures_total{phase="handshake"} 1`, f.metric(`sagvd_handshake_failures_total{phase="handshake"}`))

	id := f.submit(PolicyProfileGate)
	require.NoError(t, f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, nil) }))
	require.Equal(t, "release_authorized", f.waitJob(id, "succeeded").State)
}

// A worker that attested and finds no job within runtime.job_timeout is
// sent away normally: nothing was decided, nothing is on the record.
func TestDaemon_NoWorkPendingEndsTheSessionNormally(t *testing.T) {
	f := newDaemonFixture(t, func(c *Config) { c.Runtime.JobTimeoutSeconds = 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := f.worker(ctx, func(string) []byte { return nil })
	require.ErrorContains(t, err, "Shutdown before any JobRequest")
	require.Equal(t, `sagvd_sessions_opened_total 1`, f.metric("sagvd_sessions_opened_total"))
	require.Empty(t, f.kinds(), "no decision was taken")

	// Shutting the daemon down while a worker waits closes its session too.
	waiting := make(chan error, 1)
	go func() { waiting <- f.worker(ctx, func(string) []byte { return nil }) }()
	require.Eventually(t, func() bool { return f.metric("sagvd_sessions_opened_total") == "sagvd_sessions_opened_total 2" }, 5*time.Second, 10*time.Millisecond)
	f.stop()
	select {
	case err := <-waiting:
		require.Error(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting worker was not released at shutdown")
	}
}

// A worker that accepts the job and then gives up on it aborts the flow
// at serve: the vault, awaiting the candidate, records a protocol
// violation and the job fails on it, on the record.
func TestDaemon_WorkerRefusalAbortsAtServe(t *testing.T) {
	f := newDaemonFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	id := f.submit(PolicyProfileGate)
	conn, err := net.Dial("tcp", f.daemon.Addr())
	require.NoError(t, err)
	err = f.workerConn(ctx, conn, func(string) ([]byte, error) { return nil, errors.New("no GPU today") })
	require.ErrorContains(t, err, "no GPU today")
	view := f.waitJob(id, "failed")
	require.NotNil(t, view.Flow.Abort)
	require.Equal(t, "serve", view.Flow.Abort.Stage)
	require.Equal(t, transport.CodeProtocolViolation, view.Error.Code)
	require.Equal(t, "structural", view.Error.Category)
	require.Nil(t, view.Result)
	require.Equal(t, `sagvd_jobs_completed_total{outcome="reject"} 1`, f.metric(`sagvd_jobs_completed_total{outcome="reject"}`))
	require.NoError(t, f.audit.chain.Verify(f.audit.keys))
}

// With the audit log gone, trust admission cannot be recorded, so it is
// not taken: the job fails at trust and the worker is sent away.
func TestDaemon_ClosedAuditLogStopsTrustAdmission(t *testing.T) {
	f := newDaemonFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	id := f.submit(PolicyProfileGate)
	require.NoError(t, f.audit.Close())
	require.Error(t, f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, nil) }))
	view := f.waitJob(id, "failed")
	require.Equal(t, "failed", string(view.Status))
	require.Contains(t, view.Error.Code, "audit")
	require.Nil(t, view.Result)
	require.Nil(t, view.Flow.Session, "no session was issued off the record")
}

// A model whose numbers pass within the operator's outlier allowance but
// whose top-1 answer differs on that fixture is refused by validation,
// not by the gate: the verdict is EQUIVALENT, the release is refused.
func TestDaemon_ValidationRefusesWhatTheGatePassed(t *testing.T) {
	f := newDaemonFixture(t, func(c *Config) { c.Genome.Gate.MaxNonCriticalOutliers = 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	id := f.submit(PolicyProfileGate)
	// fx-002 is not critical; +5 at its third position makes it the top-1.
	require.NoError(t, f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, map[[2]int]float32{{2, 2}: 5}) }))
	view := f.waitJob(id, "failed")
	require.Equal(t, CodeReleaseRefused, view.Error.Code)
	require.Contains(t, view.Error.Message, "sem.top1_disagreement")
	require.Equal(t, "EQUIVALENT", view.Gate.Level)
	require.Equal(t, 2, view.Top1.Agreed)
	require.Nil(t, view.Result, "the answer is withheld")
	require.False(t, view.Flow.Decision.Release)
	require.Equal(t, `sagvd_release_decisions_total{decision="refuse"} 1`, f.metric(`sagvd_release_decisions_total{decision="refuse"}`))
	require.Equal(t, `sagvd_jobs_completed_total{outcome="reject"} 1`, f.metric(`sagvd_jobs_completed_total{outcome="reject"}`))
}
