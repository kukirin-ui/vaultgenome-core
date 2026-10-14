// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics provides a minimal Prometheus-text-format metrics
// registry shared between the AI Continuity Platform daemons
// (cmd/acp-compute, cmd/sagvd, and future binaries).
//
// # Doctrine
//
// The registry is stdlib-only on purpose. Adding
// github.com/prometheus/client_golang would push every daemon past the
// dependency-policy allowlist (doc #8 §2), and the exposition format
// we actually need is ~200 lines of code: counters and gauges, single
// low-cardinality label key, deterministic ordering, strict HELP/TYPE
// emission. Histograms / Summaries are deliberately out of scope — if
// a daemon grows a need for them, that is the signal to revisit the
// dependency question.
//
// The text format emitted here matches what `promtool check metrics`
// accepts and what Grafana Agent / Prometheus scrape:
//
//	# HELP acp_compute_jobs_total Total jobs processed by outcome.
//	# TYPE acp_compute_jobs_total counter
//	acp_compute_jobs_total{outcome="success"} 42
//
// See https://prometheus.io/docs/instrumenting/exposition_formats/.
//
// # Contract
//
//   - Registration order is preserved by Registry.WriteTo so that tests
//     can assert deterministic output.
//   - Counter cells are addressed by an ordered serialisation of their
//     labels; Inc/Add with labels in any order write to the same cell.
//   - Label values are escaped per the exposition format: backslash,
//     double-quote, and newline are each prefixed with a backslash;
//     everything else passes through verbatim.
//   - Duplicate metric names panic at registration — a programmer
//     error caught at startup, never at runtime.
//   - Counter and Gauge are safe for concurrent use.
//
// # Usage
//
//	reg := metrics.NewRegistry()
//	jobs := reg.NewCounter("acp_compute_jobs_total",
//	    "Total Return Path jobs processed, labelled by outcome.")
//	jobs.Inc(metrics.Label{Name: "outcome", Value: "success"})
//	_ = reg.WriteMetricsTo(os.Stdout)
//
// # Naming
//
// The package is intentionally placed under /internal/observability so
// non-binary packages cannot import it accidentally; only cmd/* should
// wire metrics registries — library packages emit information via
// callbacks and let the binary decide how to surface it.
package metrics
