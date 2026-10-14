// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
)

// A job the worker cannot serve — here its sealed material names a key
// the worker does not hold — is rejected to the vault and counted as a
// failure, and does not make the worker ready; the loop goes on to the
// next dial and stops when told.
func TestDaemon_JobFailure_IsRejectedAndCounted(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	f.cfg.Vault.Address = lis.Addr().String()

	req := f.buildJobRequest([][]byte{[]byte("alpha-bytes")})
	req.SealedMaterial[0].RecipientKeyID = "session-seal-unknown"
	require.NoError(t, req.Validate())
	srvCh := f.stubServer(lis, req)
	daemon := tlsDaemon(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- daemon.Run(ctx) }()

	sr := <-srvCh
	require.Error(t, sr.err, "the vault hears the rejection")
	require.Empty(t, sr.cand.Bytes)
	failed := func() bool { return daemon.metrics.jobsTotal.Value(Label{Name: "outcome", Value: "fail"}) == 1 }
	require.Eventually(t, failed, daemonTestTimeout, 10*time.Millisecond, "the failed job is counted")
	require.EqualValues(t, 1, daemon.metrics.sessionsOpened.Value(), "the handshake itself completed")
	require.EqualValues(t, 0, daemon.metrics.jobsTotal.Value(Label{Name: "outcome", Value: "success"}))
	require.False(t, daemon.health.IsReady(), "a failed job does not make the worker ready")

	cancel()
	select {
	case err := <-runErrCh:
		require.NoError(t, err, "a shutdown is a clean stop")
	case <-time.After(daemonTestTimeout):
		t.Fatal("daemon did not return within timeout after cancel")
	}
}

// After a job the worker pauses before its next dial; a shutdown during
// the pause ends it at once, with no further dial attempted.
func TestDaemon_IdlePauseEndsOnShutdown(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)
	f.cfg.Runtime.IdleBetweenJobsMs = 60_000
	require.NoError(t, f.cfg.Validate())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	f.cfg.Vault.Address = lis.Addr().String()
	srvCh := f.stubServer(lis, f.buildJobRequest([][]byte{[]byte("alpha-bytes")}))
	daemon := tlsDaemon(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- daemon.Run(ctx) }()

	sr := <-srvCh
	require.NoError(t, sr.err)
	require.Eventually(t, daemon.health.IsReady, daemonTestTimeout, 10*time.Millisecond, "the job completed")
	cancel()
	select {
	case err := <-runErrCh:
		require.NoError(t, err, "a shutdown during the pause is a clean stop")
	case <-time.After(daemonTestTimeout):
		t.Fatal("the idle pause outlived the shutdown")
	}
	require.EqualValues(t, 1, daemon.metrics.sessionsOpened.Value())
	require.EqualValues(t, 0, daemon.metrics.dialFail.Value(), "no dial was attempted during the pause")
}

// signallingDialer dials like net.Dialer and closes connected once the
// first connection is up, so a test knows the daemon is inside a session
// waiting on the vault.
type signallingDialer struct {
	net.Dialer
	connected chan struct{}
	once      sync.Once
}

func (d *signallingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, address)
	if err == nil {
		d.once.Do(func() { close(d.connected) })
	}
	return c, err
}

// A shutdown while the vault holds the connection open and says nothing
// closes the connection and ends the cycle at once: the worker does not
// outlive its stop signal inside a session, and the cut-short handshake
// is counted as one. The dialer installed with WithDialer is the one the
// daemon dials with; a Run that starts after the stop dials nothing.
func TestDaemon_ShutdownClosesASilentSession(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	f.cfg.Vault.Address = lis.Addr().String()
	f.cfg.Runtime.HandshakeTimeoutSeconds = 60
	f.cfg.Runtime.JobTimeoutSeconds = 120
	require.NoError(t, f.cfg.Validate())
	dialer := &signallingDialer{connected: make(chan struct{})}
	daemon := tlsDaemon(t, f)
	require.Same(t, daemon, daemon.WithDialer(dialer))
	require.Same(t, dialer, daemon.dialer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- daemon.Run(ctx) }()
	select {
	case <-dialer.connected:
	case <-time.After(daemonTestTimeout):
		t.Fatal("the daemon never dialed the vault")
	}
	cancel()
	select {
	case err := <-runErrCh:
		require.NoError(t, err, "a shutdown inside a session is a clean stop")
	case <-time.After(daemonTestTimeout):
		t.Fatal("the silent session outlived the shutdown")
	}
	require.EqualValues(t, 1, daemon.metrics.handshakeFail.Value(Label{Name: "phase", Value: "handshake"}))
	require.EqualValues(t, 0, daemon.metrics.sessionsOpened.Value())
	require.EqualValues(t, 0, daemon.metrics.dialFail.Value())

	require.NoError(t, daemon.Run(ctx), "a Run after the stop returns at once")
	require.EqualValues(t, 0, daemon.metrics.dialFail.Value(), "and dials nothing")
}

// sleepContext waits out its duration unless the context ends first; a
// context already done ends even a long sleep at once, and a zero sleep
// reports only whether the context is still live.
func TestSleepContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	require.True(t, sleepContext(ctx, 0))
	require.True(t, sleepContext(ctx, time.Millisecond))
	cancel()
	require.False(t, sleepContext(ctx, 0))
	require.False(t, sleepContext(ctx, time.Hour))
}

// Without a logger the daemon makes its own; TLS material it cannot load
// stops construction.
func TestNewDaemon_DefaultLoggerAndTLSMaterial(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)
	mat, err := LoadMaterials(f.cfg, f.clock)
	require.NoError(t, err)
	recon, err := worker.NewDeterministicReconstructor(f.clock)
	require.NoError(t, err)
	d, err := NewDaemon(f.cfg, mat, f.clock, nil, recon, NewRegistry())
	require.NoError(t, err)
	require.NotNil(t, d.log)
	require.Nil(t, d.tlsConfig, "TLS off: plain TCP")

	bad := f.cfg
	bad.Vault.TLS = TLSConfig{Enabled: true, ClientCert: filepath.Join(f.dir, "absent.crt"), ClientKey: filepath.Join(f.dir, "absent.key"),
		CABundle: filepath.Join(f.dir, "absent.pem"), ServerName: "127.0.0.1"}
	_, err = NewDaemon(bad, mat, f.clock, silentLogger(), recon, NewRegistry())
	require.ErrorContains(t, err, "load client keypair")
}

// A client key that is not there is reported under its config field; a
// key that is not the certificate's is refused as the pair.
func TestLoadClientTLS_KeyRefusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := newTLSMaterial(t, dir)
	_, err := loadClientTLS(TEEConfig{}, TLSConfig{ClientCert: m.clientCert, ClientKey: filepath.Join(dir, "absent.key"), CABundle: m.caPEM})
	require.ErrorContains(t, err, "vault.tls.client_key")

	other := newTLSMaterial(t, t.TempDir())
	_, err = loadClientTLS(TEEConfig{}, TLSConfig{ClientCert: m.clientCert, ClientKey: other.clientKey, CABundle: m.caPEM})
	require.ErrorContains(t, err, "load client keypair")
}

// runDaemon stops before the first dial when its key material or its TLS
// material does not load, or when its health address is already taken.
func TestRunDaemon_StopsOnStartupFaults(t *testing.T) {
	f := newTestFixture(t)
	f.cfg.Log = LogConfig{Level: "error", Format: "json"}
	n := 0
	writeConfig := func(c Config) string {
		raw, err := json.Marshal(c)
		require.NoError(t, err)
		n++
		p := filepath.Join(f.dir, fmt.Sprintf("acp-compute-%d.json", n))
		require.NoError(t, os.WriteFile(p, raw, 0o600))
		return p
	}
	noSeed := f.cfg
	noSeed.Keys.WorkerSigning.SeedPath = filepath.Join(f.dir, "absent.seed")
	badTLS := f.cfg
	badTLS.Vault.TLS = TLSConfig{Enabled: true, ClientCert: filepath.Join(f.dir, "absent.crt"), ClientKey: filepath.Join(f.dir, "absent.key"),
		CABundle: filepath.Join(f.dir, "absent.pem"), ServerName: "127.0.0.1"}
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = taken.Close() })
	busyHealth := f.cfg
	busyHealth.Health.ListenAddress = taken.Addr().String()

	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"material that does not load":     {noSeed, "read keys.worker_signing.seed_path"},
		"TLS material that does not load": {badTLS, "load client keypair"},
		"health address already taken":    {busyHealth, "acp-compute: health server"},
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, tc.cfg.Validate())
			require.ErrorContains(t, runDaemon([]string{"-config", writeConfig(tc.cfg)}), tc.want)
		})
	}
}
