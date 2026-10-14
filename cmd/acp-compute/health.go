// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// This file is a thin compatibility shim over the shared health
// surface in /internal/observability/health. The implementation used
// to live here; it moved when cmd/sagvd (task #75) needed the same
// /healthz /readyz /metrics wiring. Keeping the local names
// (healthState, HealthServer, newHealthState, NewHealthServer) as
// aliases means the daemon's call-sites in daemon.go, main.go, and
// daemon_test.go compile unchanged.

import (
	"log/slog"

	"github.com/vault-genome/vaultgenome-core/internal/observability/health"
)

// Type aliases keep the in-package names the daemon has always used
// while pointing them at the shared implementation.
type (
	healthState  = health.State
	HealthServer = health.Server
)

// newHealthState forwards to health.NewState so the daemon keeps
// calling the unexported constructor it has always called.
func newHealthState() *healthState { return health.NewState() }

// NewHealthServer forwards to health.NewServer. Registry flows through
// as *Registry (aliased to *metrics.Registry) without conversion.
func NewHealthServer(listenAddr string, state *healthState, registry *Registry, logger *slog.Logger) *HealthServer {
	return health.NewServer(listenAddr, state, registry, logger)
}
