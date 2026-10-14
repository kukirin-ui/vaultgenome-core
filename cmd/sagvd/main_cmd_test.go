// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// captureStdout runs fn with os.Stdout redirected into a pipe and returns
// what fn printed. The commands print their JSON result to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	func() {
		defer func() { os.Stdout = old; _ = w.Close() }()
		fn()
	}()
	out := <-done
	_ = r.Close()
	return out
}

// daemonConfig is a config runDaemon starts under: the material fixture's
// keys and pins, a sealed genome with its audit log, the operator's stop
// list, and every listener on a loopback port of the OS's choosing.
func daemonConfig(t *testing.T) (*materialFixture, Config) {
	t.Helper()
	f := newMaterialFixture(t)
	cfg := f.cfg
	cfg.Vault.ListenAddress = "127.0.0.1:0"
	cfg.HTTPAPI.ListenAddress = "127.0.0.1:0"
	cfg.Health.ListenAddress = ""
	cfg.Log = LogConfig{Level: "error", Format: "json"}
	cfg.Runtime.QueuePollMs = 10
	cfg.Genome.BundleDir = f.dir
	sealTestGenome(t, f.dir, genomeOptions{})
	cfg.Audit.LogPath = filepath.Join(f.dir, "returnpath.db")
	auditSeed := filepath.Join(f.dir, "audit.seed")
	require.NoError(t, os.WriteFile(auditSeed, bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize), 0o600))
	cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: auditSeed}
	opPub, opPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cfg.OperatorStop = OperatorStopConfig{KeyID: "operator-test", PublicKeyPath: writeFile(t, f.dir, "operator.pub", opPub), ListPath: filepath.Join(f.dir, "stop.json")}
	writeStopList(t, cfg.OperatorStop.ListPath, opPriv, revocation.List{Serial: 1})
	// A plaintext escrow key, accepted under the simulated TEE only.
	escrowPriv, err := escrow.GenerateKey()
	require.NoError(t, err)
	cfg.Genome.KeyEscrowPath = writeFile(t, f.dir, "escrow.key", escrowPriv.Bytes())
	require.NoError(t, os.Chmod(cfg.Genome.KeyEscrowPath, 0o600))
	require.NoError(t, cfg.Validate())
	return f, cfg
}

// runUntilSignalled starts runDaemon on cfgPath, waits until ready says
// so, sends SIGTERM until the daemon has taken it, and returns what
// runDaemon returned. The test holds SIGTERM itself for the duration, so a
// signal that lands before the daemon registers for it cannot end the
// test binary.
func runUntilSignalled(t *testing.T, cfgPath string, ready func() bool) error {
	t.Helper()
	guard := make(chan os.Signal, 8)
	signal.Notify(guard, syscall.SIGTERM)
	defer signal.Stop(guard)

	done := make(chan error, 1)
	go func() { done <- runDaemon([]string{"-config", cfgPath}) }()
	var early error
	var stoppedEarly bool
	require.Eventually(t, func() bool {
		select {
		case early = <-done:
			stoppedEarly = true
			return true
		default:
		}
		return ready()
	}, 15*time.Second, 20*time.Millisecond, "the daemon did not report ready")
	require.False(t, stoppedEarly, "the daemon stopped before it was ready: %v", early)

	pid := os.Getpid()
	var runErr error
	require.Eventually(t, func() bool {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			return false
		}
		select {
		case runErr = <-done:
			return true
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}, 15*time.Second, time.Millisecond, "the daemon did not stop on SIGTERM")
	return runErr
}

func writeConfig(t *testing.T, dir, name string, cfg Config) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	return writeFile(t, dir, name, raw)
}

// freePort returns a loopback address with a port the OS just handed out
// and released, for a listener whose bound address the test must know
// before the daemon reports it.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// The daemon refuses to start on every input it cannot stand behind, in
// the order it reads them: flags, the config file, its validation, the
// secrets it names, the key material, the audit log, the operator's stop
// list, and the listeners it binds.
func TestRunDaemon_RefusesBeforeServing(t *testing.T) {
	f, cfg := daemonConfig(t)
	absent := filepath.Join(f.dir, "absent")
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()

	invalid := cfg
	invalid.Vault.ListenAddress = ""
	noToken := cfg
	noToken.HTTPAPI.BearerTokenFile = absent
	noPeer := cfg
	noPeer.TEE.Peer.MeasurementPath = absent
	noAuditDir := cfg
	noAuditDir.Audit.LogPath = filepath.Join(absent, "rp.db")
	noStopList := cfg
	noStopList.OperatorStop.ListPath = absent
	apiTaken := cfg
	apiTaken.HTTPAPI.ListenAddress = taken.Addr().String()
	healthTaken := cfg
	healthTaken.Health.ListenAddress = taken.Addr().String()

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no flags":             {nil, "-config is required"},
		"undefined flag":       {[]string{"-nope"}, "flag provided but not defined"},
		"missing config":       {[]string{"-config", absent}, "open config"},
		"invalid config":       {[]string{"-config", writeConfig(t, f.dir, "invalid.json", invalid)}, "sagvd: config validation"},
		"token file missing":   {[]string{"-config", writeConfig(t, f.dir, "notoken.json", noToken)}, "http_api.bearer_token_file"},
		"materials missing":    {[]string{"-config", writeConfig(t, f.dir, "nopeer.json", noPeer)}, "tee.peer.measurement_path"},
		"audit log unopenable": {[]string{"-config", writeConfig(t, f.dir, "noaudit.json", noAuditDir)}, "open audit.log_path"},
		"stop list missing":    {[]string{"-config", writeConfig(t, f.dir, "nostop.json", noStopList)}, "sagvd: operator_stop"},
		"api address taken":    {[]string{"-config", writeConfig(t, f.dir, "apitaken.json", apiTaken)}, "HTTP API listen"},
		"health address taken": {[]string{"-config", writeConfig(t, f.dir, "healthtaken.json", healthTaken)}, "sagvd: health server"},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, runDaemon(tc.args), tc.want)
		})
	}
}

// The daemon starts whole — keys, TEE, audit log, operator stop, gate
// jobs, the Return Path listener, the REST API and the health server —
// answers probes, and stops cleanly on SIGTERM: every listener closed,
// nothing left running.
func TestRunDaemon_ServesUntilSignalled(t *testing.T) {
	f, cfg := daemonConfig(t)
	cfg.Health.ListenAddress = freePort(t)
	cfg.HTTPAPI.ListenAddress = freePort(t)
	cfgPath := writeConfig(t, f.dir, "daemon.json", cfg)
	client := &http.Client{Timeout: 2 * time.Second}
	probe := func(url string) (int, bool) {
		resp, err := client.Get(url)
		if err != nil {
			return 0, false
		}
		_ = resp.Body.Close()
		return resp.StatusCode, true
	}
	health := "http://" + cfg.Health.ListenAddress
	api := "http://" + cfg.HTTPAPI.ListenAddress
	var metricsBody []byte
	runErr := runUntilSignalled(t, cfgPath, func() bool {
		if code, ok := probe(health + "/readyz"); !ok || code != http.StatusOK {
			return false
		}
		code, ok := probe(health + "/healthz")
		require.True(t, ok)
		require.Equal(t, http.StatusOK, code)
		code, ok = probe(api + "/v1/jobs/no-such-job")
		require.True(t, ok, "the REST API is up")
		require.Equal(t, http.StatusNotFound, code)
		resp, err := client.Get(health + "/metrics")
		require.NoError(t, err)
		metricsBody, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		return true
	})
	require.NoError(t, runErr)
	require.Contains(t, string(metricsBody), "sagvd_start_unix")
	require.Contains(t, string(metricsBody), `vg_tee_capability_total{available="true",provider="simulated"} 1`)
	_, ok := probe(health + "/healthz")
	require.False(t, ok, "the health server is closed")
	_, ok = probe(api + "/v1/jobs/no-such-job")
	require.False(t, ok, "the REST API is closed")
	st, err := os.Stat(cfg.Audit.LogPath)
	require.NoError(t, err)
	require.Positive(t, st.Size(), "the audit log was created")

	// Without gate jobs there is no audit log and the REST API accepts no
	// jobs; the daemon says so at start and still serves its listeners.
	bare := cfg
	bare.Genome = GenomeConfig{Gate: cfg.Genome.Gate}
	bare.Audit.LogPath = ""
	bare.OperatorStop = OperatorStopConfig{}
	bare.Health.ListenAddress = freePort(t)
	bare.HTTPAPI.ListenAddress = freePort(t)
	require.NoError(t, bare.Validate())
	bareAPI := "http://" + bare.HTTPAPI.ListenAddress
	var submitCode int
	runErr = runUntilSignalled(t, writeConfig(t, f.dir, "bare.json", bare), func() bool {
		code, ok := probe("http://" + bare.Health.ListenAddress + "/readyz")
		if !ok || code != http.StatusOK {
			return false
		}
		resp, err := client.Post(bareAPI+"/v1/jobs", "application/json", strings.NewReader(`{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"}}`))
		require.NoError(t, err)
		_ = resp.Body.Close()
		submitCode = resp.StatusCode
		return true
	})
	require.NoError(t, runErr)
	require.Equal(t, http.StatusServiceUnavailable, submitCode, "gate jobs are not configured")
}

// The logger follows log.level and log.format: the level gates what is
// written, the format picks the handler.
func TestBuildLogger(t *testing.T) {
	ctx := t.Context()
	for level, want := range map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError, "anything-else": slog.LevelInfo} {
		l := buildLogger(LogConfig{Level: level, Format: "json"})
		require.True(t, l.Enabled(ctx, want), level)
		require.False(t, l.Enabled(ctx, want-1), level)
		require.IsType(t, &slog.JSONHandler{}, l.Handler())
	}
	require.IsType(t, &slog.TextHandler{}, buildLogger(LogConfig{Level: "info", Format: "text"}).Handler())
}

// help names every subcommand and its flags.
func TestPrintUsage(t *testing.T) {
	out := captureStdout(t, printUsage)
	for _, want := range []string{"Usage:", "sagvd -config PATH", "sagvd identity", "sagvd crosscloud-restore", "sagvd crosscloud-confirm",
		"sagvd failover", "sagvd escrow-provision", "sagvd seal-keys", "sagvd version", "sagvd help", "-config PATH"} {
		require.Contains(t, out, want)
	}
}

// main dispatches on the first argument: version and help print and
// return; identity runs the subcommand against its config.
func TestMain_Dispatch(t *testing.T) {
	f := newMaterialFixture(t)
	cfgPath := writeConfig(t, f.dir, "sagvd.json", f.cfg)
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"sagvd", "version"}
	require.True(t, strings.HasPrefix(captureStdout(t, main), "sagvd "+version+" (commit "))
	os.Args = []string{"sagvd", "--help"}
	require.Contains(t, captureStdout(t, main), "Usage:")
	os.Args = []string{"sagvd", "identity", "-config", cfgPath}
	var id authorityIdentity
	require.NoError(t, json.Unmarshal([]byte(captureStdout(t, main)), &id))
	require.Equal(t, "authority-1", id.AuthorityKID)

	os.Args = []string{"sagvd", "escrow-provision", "-config", cfgPath, "-out", filepath.Join(f.dir, "escrow.sealed"), "-pub", filepath.Join(f.dir, "escrow.pem")}
	var provisioned escrowProvisionOutput
	require.NoError(t, json.Unmarshal([]byte(captureStdout(t, main)), &provisioned))
	require.Equal(t, "generated", provisioned.Source)
	os.Args = []string{"sagvd", "seal-keys", "-config", cfgPath}
	var sealed sealKeysOutput
	require.NoError(t, json.Unmarshal([]byte(captureStdout(t, main)), &sealed))
	require.Len(t, sealed.Sealed, 2)
}
