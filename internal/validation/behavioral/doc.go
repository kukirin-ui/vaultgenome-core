// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package behavioral implements the Behavioral dimension of validation:
// "does the reconstructed output behave the way the Genome profile
// claims it should?"
//
// # Doctrinal role
//
// MVP: probe suite in /test/fixtures/validation/behavioral. Two
// categories: critical and non-critical. Pass = all critical probes pass
// AND non-critical pass-rate >= 95%. Conditional-fail = [85%, 95%).
// Fail below 85% or on any critical probe failure
// (docs/doctrine/validation-thresholds.md §3).
//
// Minimum probe set for Phase 6 sign-off: 10 probes total, at least 3
// critical, covering deterministic reproducibility, manifest-bounded
// output shape, absence of out-of-policy side effects, session-scoped
// boundedness.
//
// Surface in this package
//
//   - Probe                — one suite entry (ID, Name, Critical, Evaluate)
//   - Inputs               — candidate bytes + probe suite
//   - Run(Inputs)          — pure function producing a DimensionVerdict
//   - Code* constants      — stable Finding codes exported to auditors
//   - PassThreshold,
//     ConditionalThreshold — public threshold constants (§3.3)
//
// Deterministic-by-construction: Details are sorted by code then message.
// No clocks, no randomness, no I/O.
package behavioral
