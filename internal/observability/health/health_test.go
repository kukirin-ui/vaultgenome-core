// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package health

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
)

// silentLogger returns a logger that discards everything — keeps test
// output readable under -v.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestState_LifecycleTransitions(t *testing.T) {
	t.Parallel()
	s := NewState()
	require.True(t, s.IsLive(), "fresh State should be live")
	require.False(t, s.IsReady(), "fresh State should not be ready")

	s.MarkReady()
	require.True(t, s.IsReady())
	require.True(t, s.IsLive())

	s.MarkDown()
	require.False(t, s.IsLive())
	require.False(t, s.IsReady())
}

func TestServer_RoutesAndStates(t *testing.T) {
	t.Parallel()
	// Exercises healthz/readyz/metrics without a full daemon run, so
	// this test is fast even under -race.
	h := NewState()
	reg := metrics.NewRegistry()
	c := reg.NewCounter("rp_hs_smoke", "smoke counter")
	c.Inc()

	srv := NewServer("127.0.0.1:0", h, reg, silentLogger())
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

func TestServer_EmptyAddrIsNoOp(t *testing.T) {
	t.Parallel()
	srv := NewServer("", NewState(), metrics.NewRegistry(), silentLogger())
	require.NoError(t, srv.Start())
	require.Equal(t, "", srv.Addr())
	// Close on a non-started server is a no-op.
	require.NoError(t, srv.Close(context.Background()))
}

func TestServer_NilLoggerReplacedWithDefault(t *testing.T) {
	t.Parallel()
	// Construction with a nil logger should not panic; the package
	// replaces nil with slog.Default so the handlers can log errors.
	srv := NewServer("", NewState(), metrics.NewRegistry(), nil)
	require.NoError(t, srv.Start())
	require.NoError(t, srv.Close(context.Background()))
}

// ---- small helpers ------------------------------------------------------

// httpGet issues a time-bounded GET to url and returns (body, status).
// Test-local; the production path does not issue HTTP requests, so
// this helper does not mirror anything in health.go.
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
