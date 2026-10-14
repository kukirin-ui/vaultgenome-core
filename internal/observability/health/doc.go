// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package health provides the liveness / readiness latch and the
// HTTP surface that every AI Continuity Platform daemon exposes on
// its operational port.
//
// # Doctrine
//
// The three endpoints are the contract:
//
//   - GET /healthz — 200 "ok\n" while the process is alive, 503
//     otherwise. Used by cluster orchestrators to decide whether to
//     restart a pod.
//   - GET /readyz  — 200 "ready\n" once the daemon has completed its
//     first healthy end-to-end cycle (acp-compute: one Return-Path
//     job; sagvd: listener bound + first worker handshake). 503 until
//     then and after MarkDown. Used to hold traffic off a daemon still
//     coming up.
//   - GET /metrics — Prometheus text-format exposition, backed by
//     /internal/observability/metrics.Registry.
//
// State is a two-bit atomic latch (live, ready). Transitions are
// driven by the daemon's main loop; the HTTP handlers are pure
// readers. Invariants:
//
//   - live starts true and goes false only in MarkDown().
//   - ready starts false and goes true only in MarkReady().
//   - MarkDown clears both (the readyz probe flips to 503 first, so an
//     orchestrator stops routing traffic before healthz starts failing).
//
// # Surface
//
// The package is intentionally placed under /internal/observability so
// non-binary packages cannot import it accidentally. Only cmd/* is
// expected to instantiate a Server.
//
// # Dependencies
//
// Pure stdlib (net, net/http, log/slog, sync/atomic) plus the sister
// metrics package in /internal/observability/metrics. No external
// libraries.
package health
