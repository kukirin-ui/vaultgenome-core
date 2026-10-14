// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunDaemon_RefusesWhatItCannotStartFrom(t *testing.T) {
	require.ErrorContains(t, runDaemon(nil), "-config is required")
	require.Error(t, runDaemon([]string{"-no-such-flag"}))
	require.Error(t, runDaemon([]string{"-config", filepath.Join(t.TempDir(), "missing.json")}))
	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{"vault":{"address":""}}`), 0o600))
	require.ErrorContains(t, runDaemon([]string{"-config", bad}), "config validation")
}

// The daemon as the operator runs it: a config file, TLS to the vault, the
// health surface up, and SIGTERM to stop. The vault here accepts the TLS
// connection and hangs up, so every Return Path session fails and the
// loop backs off until it is told to stop — which is exactly what a worker
// waiting for its vault does.
func TestRunDaemon_ServesHealthAndStopsOnSIGTERM(t *testing.T) {
	f := newTestFixture(t)
	m := newTLSMaterial(t, f.dir)
	f.cfg.Vault.Address = hangUpTLSVault(t, m)
	f.cfg.Vault.TLS = TLSConfig{Enabled: true, ClientCert: m.clientCert, ClientKey: m.clientKey, CABundle: m.caPEM, ServerName: "127.0.0.1"}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	healthAddr := probe.Addr().String()
	require.NoError(t, probe.Close())
	f.cfg.Health.ListenAddress = healthAddr
	f.cfg.Log = LogConfig{Level: "error", Format: "text"}
	require.NoError(t, f.cfg.Validate())
	raw, err := json.Marshal(f.cfg)
	require.NoError(t, err)
	cfgPath := filepath.Join(f.dir, "acp-compute.json")
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))

	// The test process keeps SIGTERM non-fatal for the whole test: the
	// daemon arms its own handler after the health surface is up.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	defer signal.Stop(sigs)

	done := make(chan error, 1)
	go func() { done <- runDaemon([]string{"-config", cfgPath}) }()

	client := &http.Client{Timeout: time.Second}
	require.Eventually(t, func() bool {
		resp, err := client.Get("http://" + healthAddr + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 20*time.Millisecond, "the health surface never came up")

	// Stop it as the service manager would; repeat until it is heard.
	deadline := time.Now().Add(10 * time.Second)
	for {
		require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
		select {
		case err := <-done:
			require.NoError(t, err, "a signalled stop is a clean stop")
			resp, err := client.Get("http://" + healthAddr + "/healthz")
			if err == nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err, "the health surface is down after the stop")
			return
		case <-time.After(100 * time.Millisecond):
		}
		require.True(t, time.Now().Before(deadline), "the daemon did not stop on SIGTERM")
	}
}

func TestBuildLogger_LevelsAndFormats(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		cfg      LogConfig
		enabled  slog.Level
		disabled slog.Level
	}{
		{LogConfig{Level: "debug", Format: "json"}, slog.LevelDebug, slog.LevelDebug - 4},
		{LogConfig{Level: "info", Format: "json"}, slog.LevelInfo, slog.LevelDebug},
		{LogConfig{Level: "warn", Format: "text"}, slog.LevelWarn, slog.LevelInfo},
		{LogConfig{Level: "error", Format: "text"}, slog.LevelError, slog.LevelWarn},
	} {
		l := buildLogger(tc.cfg)
		require.True(t, l.Enabled(ctx, tc.enabled), "%+v", tc.cfg)
		require.False(t, l.Enabled(ctx, tc.disabled), "%+v", tc.cfg)
	}
}

func TestPrintUsage_NamesEveryCommand(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	stdout := os.Stdout
	os.Stdout = w
	printUsage()
	os.Stdout = stdout
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	for _, want := range []string{"acp-compute -config PATH", "acp-compute identity -config PATH", "acp-compute version", "acp-compute help"} {
		require.Contains(t, string(out), want)
	}
}
