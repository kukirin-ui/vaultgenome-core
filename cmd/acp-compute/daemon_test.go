// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/server"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

const daemonTestTimeout = 5 * time.Second

// testFixture holds every piece of state both the daemon and its stub
// sagvd need. Files on disk for the daemon, in-memory state for the
// server.
type testFixture struct {
	t     *testing.T
	dir   string
	cfg   Config
	clock shared_time.Clock

	// Raw seeds/keys we wrote to disk — the server-side stub needs the
	// same bytes to construct matching verifiers / resolvers.
	teeSeed    []byte
	workerSeed []byte
	sealingKey []byte
	serverSeed []byte

	// Server-side TEE + keystore (built from the above).
	serverSim          *tee.Simulated
	serverVerifier     *tee.SimulatedVerifier
	resolver           *server.PublicKeyResolver
	serverSealingStore *keys.InMemoryStore

	// Workload descriptor used on both sides — must match what the
	// daemon writes into Config.TEE.WorkloadDescriptor.
	workloadDescriptor string
}

// newTestFixture generates key material, writes it to disk, and returns
// a ready-to-use fixture. The daemon will LoadMaterials(cfg) and see
// exactly what the fixture wrote; the server side uses parallel copies.
func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	dir := t.TempDir()
	f := &testFixture{
		t:                  t,
		dir:                dir,
		clock:              shared_time.NewSystemClock(),
		workloadDescriptor: "acp-compute-daemon-test-worker-v1",
		// Deterministic bytes so a flaky test yields a reproducible
		// failure report.
		teeSeed:    bytes.Repeat([]byte{0xAA}, crypto.Ed25519SeedSize),
		workerSeed: bytes.Repeat([]byte{0xBB}, crypto.Ed25519SeedSize),
		sealingKey: bytes.Repeat([]byte{0xCC}, crypto.AES256KeySize),
		serverSeed: bytes.Repeat([]byte{0xDD}, crypto.Ed25519SeedSize),
	}

	// Server-side Simulated + Verifier (pinned to the daemon's identity).
	serverSim, err := tee.NewSimulated([]byte("sagvd-daemon-test-authority-v1"), f.serverSeed)
	require.NoError(t, err)
	f.serverSim = serverSim

	daemonSim, err := tee.NewSimulated([]byte(f.workloadDescriptor), f.teeSeed)
	require.NoError(t, err)
	f.serverVerifier = tee.NewSimulatedVerifier(daemonSim.PublicKey(), daemonSim.Measurement())

	// Server-side worker pubkey resolver.
	workerPub, _, err := crypto.Ed25519FromSeed(f.workerSeed)
	require.NoError(t, err)
	f.resolver = server.NewPublicKeyResolver(map[ids.KeyID]keys.VerifyingKey{
		ids.KeyID("worker-sign-1"): {
			KeyID:     ids.KeyID("worker-sign-1"),
			Purpose:   keys.PurposeSigningAuthority,
			PublicKey: workerPub,
		},
	})

	// Server-side sealing store — registers the SAME material the daemon
	// loads, so jobs the server seals can be opened by the daemon.
	f.serverSealingStore = keys.NewInMemoryStore(f.clock)
	require.NoError(t, f.serverSealingStore.RegisterSealing(
		ids.KeyID("session-seal-1"), f.sealingKey))

	// Write the files on disk for the daemon.
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, b, 0o600))
		return path
	}
	f.cfg = DefaultConfig()
	f.cfg.TEE.WorkloadDescriptor = f.workloadDescriptor
	f.cfg.TEE.SeedPath = write("tee.seed", f.teeSeed)
	f.cfg.TEE.InsecureSimulation = true
	f.cfg.TEE.Peer.PublicKeyPath = write("peer.pub", []byte(f.serverSim.PublicKey()))
	meas := f.serverSim.Measurement()
	f.cfg.TEE.Peer.MeasurementPath = write("peer.meas", meas[:])
	f.cfg.Keys.WorkerSigning.KeyID = "worker-sign-1"
	f.cfg.Keys.WorkerSigning.SeedPath = write("worker.seed", f.workerSeed)
	f.cfg.Keys.SessionSealing.KeyID = "session-seal-1"
	f.cfg.Keys.SessionSealing.MaterialPath = write("session.key", f.sealingKey)
	// The daemon under test is driven with the deterministic reference
	// backend (see NewDaemon); the config still has to name a door.
	f.cfg.Genome.Door.Command = []string{"/nonexistent/vg-door"}

	// Test defaults: disable HTTP; very short backoff so the cancel
	// path doesn't have to wait a second.
	f.cfg.Health.ListenAddress = ""
	f.cfg.Runtime.DialBackoffInitialMs = 10
	f.cfg.Runtime.DialBackoffMaxMs = 50
	f.cfg.Runtime.IdleBetweenJobsMs = 0
	f.cfg.Runtime.HandshakeTimeoutSeconds = 3
	f.cfg.Runtime.JobTimeoutSeconds = 5

	require.NoError(t, f.cfg.Validate())
	return f
}

// buildJobRequest seals each plaintext under the session sealing key
// and returns a JobRequest the server can hand to ServeOneJob.
func (f *testFixture) buildJobRequest(plaintexts [][]byte) transport.JobRequest {
	const manifestID = "manifest-daemon-test"
	const sessionID = "session-daemon-test"

	sealed := make([]transport.SealedMaterialRef, 0, len(plaintexts))
	for i, pt := range plaintexts {
		aad := append([]byte("rp-daemon-aad|"), []byte(manifestID)...)
		aad = append(aad, byte(i))
		nonce, ct, err := f.serverSealingStore.Seal(ids.KeyID("session-seal-1"), pt, aad)
		require.NoError(f.t, err)
		sealed = append(sealed, transport.SealedMaterialRef{
			RecipientKeyID: "session-seal-1",
			Nonce:          nonce,
			Ciphertext:     ct,
			AAD:            aad,
		})
	}
	now := f.clock.Now().UTC()
	req := transport.JobRequest{
		Type:                   transport.FrameTypeJobRequest,
		SchemaVersion:          1,
		ManifestID:             manifestID,
		SessionID:              sessionID,
		ExpectedOutputKind:     string(rjm.OutputKindBytesFixedLength),
		ExpectedOutputMaxBytes: 512,
		Deadline:               now.Add(30 * time.Second),
		IssuedAt:               now,
		SealedMaterial:         sealed,
	}
	require.NoError(f.t, req.Validate())
	return req
}

// stubServer accepts exactly one connection on lis and drives a full
// server-side Return Path cycle with the given JobRequest. The
// completed CandidateOutput (or any error) is sent on the returned
// channel. The goroutine closes the channel after writing exactly once.
func (f *testFixture) stubServer(lis net.Listener, req transport.JobRequest) <-chan serverResult {
	out := make(chan serverResult, 1)
	go func() {
		defer close(out)
		c, err := lis.Accept()
		if err != nil {
			out <- serverResult{err: err}
			return
		}
		sess, err := server.Accept(server.SessionConfig{
			Conn:              c,
			Producer:          f.serverSim,
			Verifier:          f.serverVerifier,
			Clock:             f.clock,
			WorkerKeyResolver: f.resolver,
			HandshakeTimeout:  daemonTestTimeout,
		})
		if err != nil {
			_ = c.Close()
			out <- serverResult{err: err}
			return
		}
		defer sess.Close()
		ctx, cancel := context.WithTimeout(context.Background(), daemonTestTimeout)
		defer cancel()
		cand, err := sess.ServeOneJob(ctx, req)
		if err == nil {
			_ = sess.WriteShutdown(transport.CodeShutdownNormal, "daemon test done")
		}
		out <- serverResult{cand: cand, err: err}
	}()
	return out
}

type serverResult struct {
	cand returnpath.CandidateOutput
	err  error
}

// silentLogger returns a logger that swallows all output. Used in tests
// so `go test -v` stays readable.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// ---- happy-path end-to-end ----------------------------------------------

func TestDaemon_RunOneJob_EndToEnd(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	f.cfg.Vault.Address = lis.Addr().String()

	plaintexts := [][]byte{
		[]byte("alpha-bytes"),
		[]byte("beta-bytes"),
		[]byte("gamma-bytes"),
	}
	req := f.buildJobRequest(plaintexts)
	srvCh := f.stubServer(lis, req)

	// Build the daemon.
	mat, err := LoadMaterials(f.cfg, f.clock)
	require.NoError(t, err)
	recon, err := worker.NewDeterministicReconstructor(f.clock)
	require.NoError(t, err)
	registry := NewRegistry()
	daemon, err := NewDaemon(f.cfg, mat, f.clock, silentLogger(), recon, registry)
	require.NoError(t, err)

	// Run the daemon in the background; cancel once the server has
	// produced its CandidateOutput.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- daemon.Run(ctx) }()

	// Wait for the server to complete its side.
	sr := <-srvCh
	require.NoError(t, sr.err, "stub server failed")
	require.NotEmpty(t, sr.cand.Bytes, "vault received empty CandidateOutput")
	require.Equal(t, ids.ManifestID("manifest-daemon-test"), sr.cand.ManifestID)

	// Wait for the daemon to reach ready (post-first-success) before
	// cancelling. Without this the metric increment might race the
	// cancel path.
	require.Eventually(t, daemon.health.IsReady,
		daemonTestTimeout, 10*time.Millisecond,
		"daemon never flipped to ready")

	require.EqualValues(t, 1, daemon.metrics.jobsTotal.Value(
		Label{Name: "outcome", Value: "success"}))
	require.EqualValues(t, 1, daemon.metrics.sessionsOpened.Value())
	require.True(t, daemon.metrics.lastSuccessUnix.Value() > 0,
		"last_success_unix gauge must be set")

	// Graceful shutdown.
	cancel()
	select {
	case err := <-runErrCh:
		require.NoError(t, err, "daemon.Run must return cleanly on ctx cancel")
	case <-time.After(daemonTestTimeout):
		t.Fatal("daemon did not return within timeout after cancel")
	}
	daemon.Shutdown()
	require.False(t, daemon.health.IsLive(), "Shutdown must clear live flag")
	require.False(t, daemon.health.IsReady(), "Shutdown must clear ready flag")

	// Zeroize should be safe; after it, the signing key must be unreachable.
	daemon.Zeroize()
	_, err = mat.Store.Sign(mat.SigningKeyID, keys.PurposeSigningAuthority, []byte("x"))
	require.Error(t, err, "post-zeroize signing must fail")
}

// ---- dial failure backoff -----------------------------------------------

func TestDaemon_DialFailure_BackoffAndMetric(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)

	// Bind-and-close so the address is almost guaranteed to refuse
	// connections — more robust than an unused port probe.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := lis.Addr().String()
	_ = lis.Close()
	f.cfg.Vault.Address = addr

	mat, err := LoadMaterials(f.cfg, f.clock)
	require.NoError(t, err)
	recon, err := worker.NewDeterministicReconstructor(f.clock)
	require.NoError(t, err)
	registry := NewRegistry()
	daemon, err := NewDaemon(f.cfg, mat, f.clock, silentLogger(), recon, registry)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- daemon.Run(ctx) }()

	// Wait for ctx to fire, then for Run to return.
	select {
	case err := <-runErrCh:
		// We expect nil: ctx cancellation is graceful.
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("daemon.Run did not return after ctx cancellation")
	}

	// At least one dial failure must have been recorded; no successful
	// sessions could have occurred.
	require.Greater(t, daemon.metrics.dialFail.Value(), uint64(0),
		"dial failure counter must have incremented")
	require.EqualValues(t, 0, daemon.metrics.sessionsOpened.Value())
	require.False(t, daemon.health.IsReady(), "ready must not flip on dial failure")
	require.True(t, daemon.health.IsLive(), "live stays true during dial failures")
}

// ---- NewDaemon argument validation --------------------------------------

func TestNewDaemon_RejectsMissingDependencies(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)
	mat, err := LoadMaterials(f.cfg, f.clock)
	require.NoError(t, err)
	recon, err := worker.NewDeterministicReconstructor(f.clock)
	require.NoError(t, err)

	// Missing Reconstructor.
	_, err = NewDaemon(f.cfg, mat, f.clock, silentLogger(), nil, NewRegistry())
	require.Error(t, err)

	// Missing Registry.
	_, err = NewDaemon(f.cfg, mat, f.clock, silentLogger(), recon, nil)
	require.Error(t, err)

	// Missing materials.
	_, err = NewDaemon(f.cfg, nil, f.clock, silentLogger(), recon, NewRegistry())
	require.Error(t, err)

	// Missing clock.
	_, err = NewDaemon(f.cfg, mat, nil, silentLogger(), recon, NewRegistry())
	require.Error(t, err)

	// Empty Vault.Address is a cfg bug, rejected here too.
	bad := f.cfg
	bad.Vault.Address = ""
	_, err = NewDaemon(bad, mat, f.clock, silentLogger(), recon, NewRegistry())
	require.Error(t, err)
}

// ---- health server wiring -----------------------------------------------

func TestHealthServer_RoutesAndStates(t *testing.T) {
	t.Parallel()
	// Exercises healthz/readyz/metrics without a full daemon run, so
	// this test is fast even under -race.
	h := newHealthState()
	reg := NewRegistry()
	c := reg.NewCounter("rp_hs_smoke", "smoke counter")
	c.Inc()

	srv := NewHealthServer("127.0.0.1:0", h, reg, silentLogger())
	require.NoError(t, srv.Start())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Close(ctx)
	})

	addr := srv.Addr()
	require.NotEmpty(t, addr)

	// healthz 200
	body, status := httpGet(t, "http://"+addr+"/healthz")
	require.Equal(t, 200, status)
	require.Contains(t, body, "ok")

	// readyz 503 before ready
	_, status = httpGet(t, "http://"+addr+"/readyz")
	require.Equal(t, 503, status)

	h.MarkReady()
	body, status = httpGet(t, "http://"+addr+"/readyz")
	require.Equal(t, 200, status)
	require.Contains(t, body, "ready")

	// metrics 200 with our counter visible
	body, status = httpGet(t, "http://"+addr+"/metrics")
	require.Equal(t, 200, status)
	require.Contains(t, body, "rp_hs_smoke 1")

	// After MarkDown, both probes report 503.
	h.MarkDown()
	_, status = httpGet(t, "http://"+addr+"/healthz")
	require.Equal(t, 503, status)
	_, status = httpGet(t, "http://"+addr+"/readyz")
	require.Equal(t, 503, status)
}

func TestHealthServer_EmptyAddrIsNoOp(t *testing.T) {
	t.Parallel()
	srv := NewHealthServer("", newHealthState(), NewRegistry(), silentLogger())
	require.NoError(t, srv.Start())
	require.Equal(t, "", srv.Addr())
	// Close on a non-started server is a no-op.
	require.NoError(t, srv.Close(context.Background()))
}

// ---- small helpers ------------------------------------------------------

// httpGet issues a time-bounded GET to url and returns (body, status).
// Test-local; the daemon's production path does not issue HTTP
// requests, so this helper does not mirror anything in health.go.
func httpGet(t *testing.T, url string) (string, int) {
	t.Helper()
	cli := &http.Client{Timeout: 2 * time.Second}
	resp, err := cli.Get(url)
	require.NoError(t, err, "GET %s", url)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b), resp.StatusCode
}
