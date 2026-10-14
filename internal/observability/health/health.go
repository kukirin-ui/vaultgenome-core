// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package health

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
)

// State is a small atomic latch shared between a daemon's main loop
// and the HTTP server. ready flips to true after the first successful
// end-to-end cycle (so orchestrators can wait for readiness before
// routing traffic); live is always true while the process is up.
//
// We keep this struct rather than raw atomics so that the daemon's
// hot path makes a single field access (via a pointer) instead of
// chasing two unrelated globals.
type State struct {
	// live is set to 1 at startup and to 0 only during shutdown. The
	// /healthz probe reports liveness; a cluster orchestrator that
	// sees /healthz=503 will restart the pod.
	live atomic.Bool
	// ready flips to 1 after the first successful cycle, and back to 0
	// during shutdown. /readyz uses it as the gating signal; before
	// the first success we report 503 so that an orchestrator holds
	// traffic off a daemon still coming up.
	ready atomic.Bool
}

// NewState returns a State with live=true, ready=false. Callers call
// MarkReady() once a successful end-to-end cycle has occurred;
// MarkDown() during graceful shutdown.
func NewState() *State {
	s := &State{}
	s.live.Store(true)
	return s
}

// MarkReady sets ready=true.
func (s *State) MarkReady() { s.ready.Store(true) }

// MarkDown sets live=false and ready=false. Called during graceful
// shutdown. The order (ready first, then live) is intentional: an
// orchestrator that polls both endpoints on a short interval will
// observe readyz=503 one tick before healthz=503, giving it time to
// route traffic away before initiating pod restart.
func (s *State) MarkDown() {
	s.ready.Store(false)
	s.live.Store(false)
}

// IsReady reports whether ready is set. Used by the /readyz handler.
func (s *State) IsReady() bool { return s.ready.Load() }

// IsLive reports whether live is set. Used by the /healthz handler.
func (s *State) IsLive() bool { return s.live.Load() }

// ---- HTTP server ---------------------------------------------------------

// Server wires /healthz, /readyz, and /metrics onto a local HTTP
// listener. Pure stdlib plus /internal/observability/metrics.
type Server struct {
	listenAddr string
	state      *State
	registry   *metrics.Registry
	logger     *slog.Logger

	srv *http.Server
	lsn net.Listener
}

// NewServer constructs the server. Start() binds the listener;
// Close() drains it. A nil logger is replaced with a no-op JSON
// handler so the caller never has to guard against nil.
func NewServer(listenAddr string, state *State, registry *metrics.Registry, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		listenAddr: listenAddr,
		state:      state,
		registry:   registry,
		logger:     logger,
	}
}

// Start binds to the configured address and begins serving. Safe to
// call once per instance. If listenAddr is empty the server is a no-op
// (tests use this to skip HTTP wiring entirely).
//
// Start returns after the listener is bound so that readiness
// signalling from outside the process (e.g. a docker-compose
// healthcheck against /healthz) is never a race.
func (s *Server) Start() error {
	if s.listenAddr == "" {
		s.logger.Info("health server disabled (empty listen address)")
		return nil
	}
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.lsn = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.HandleFunc("/metrics", s.metrics)

	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.logger.Info("health server listening", "addr", ln.Addr().String())
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("health server terminated", "err", err)
		}
	}()
	return nil
}

// Addr returns the actually-bound address (useful when listenAddr was
// "127.0.0.1:0" in tests). Empty string if Start was never called or
// the server was constructed with an empty listen address.
func (s *Server) Addr() string {
	if s.lsn == nil {
		return ""
	}
	return s.lsn.Addr().String()
}

// Close gracefully shuts down the server with a bounded deadline.
// Safe to call on a Server whose Start was a no-op.
func (s *Server) Close(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	if !s.state.IsLive() {
		http.Error(w, "unhealthy", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if !s.state.IsReady() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ready\n"))
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := s.registry.WriteMetricsTo(w); err != nil {
		s.logger.Error("metrics write failed", "err", err)
	}
}
