// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The exhaustive metrics test suite moved to
// /internal/observability/metrics/metrics_test.go when the registry
// was lifted out of cmd/acp-compute for task #75. Keeping only a
// compile-check here confirms the alias shim in metrics.go still
// exposes the names daemon.go and daemon_test.go depend on; running
// the full semantic coverage twice would just be redundant work on
// every CI run.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
)

// TestMetricsAliases_Identity asserts that the aliases in metrics.go
// are identity aliases (not wrappers), so values produced by
// /internal/observability/metrics flow through the daemon's types
// without conversions.
func TestMetricsAliases_Identity(t *testing.T) {
	t.Parallel()
	// Construct via the alias's NewRegistry, exercise it via both the
	// alias types and the underlying package types.
	var r *Registry = NewRegistry()
	require.NotNil(t, r)

	// Counter emitted through the alias; labels via both spellings.
	var c *Counter = r.NewCounter("rp_alias_smoke", "alias-identity smoke")
	c.Inc(Label{Name: "outcome", Value: "success"})
	c.Inc(metrics.Label{Name: "outcome", Value: "success"})
	require.Equal(t, uint64(2), c.Value(Label{Name: "outcome", Value: "success"}))

	// Gauge through the alias.
	var g *Gauge = r.NewGauge("rp_alias_gauge", "alias-identity gauge")
	g.Set(42)
	require.Equal(t, float64(42), g.Value())

	// WriteTo still emits valid Prometheus text format.
	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	require.Contains(t, buf.String(), "rp_alias_smoke{outcome=\"success\"} 2")
	require.Contains(t, buf.String(), "rp_alias_gauge 42")
}
