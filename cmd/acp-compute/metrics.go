// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// This file is now a thin compatibility shim over the shared metrics
// registry in /internal/observability/metrics. The implementation used
// to live here; it was lifted to /internal/observability/metrics when
// cmd/sagvd (task #75) needed the same exposition surface. Keeping the
// local names (Registry, Counter, Gauge, Label, NewRegistry) as
// type/function aliases means the daemon's call-sites in daemon.go,
// main.go, and daemon_test.go did not have to change.
//
// Any future work on the metrics format belongs in
// /internal/observability/metrics — this file should stay a near-empty
// shim, not grow package-local helpers.

import "github.com/vault-genome/vaultgenome-core/internal/observability/metrics"

// Type aliases preserve identity: *main.Registry and
// *metrics.Registry are the same type, so values flow between the
// two halves without conversions.
type (
	Registry = metrics.Registry
	Counter  = metrics.Counter
	Gauge    = metrics.Gauge
	Label    = metrics.Label
)

// NewRegistry forwards to metrics.NewRegistry so existing call-sites
// continue to compile unmodified.
func NewRegistry() *Registry { return metrics.NewRegistry() }
