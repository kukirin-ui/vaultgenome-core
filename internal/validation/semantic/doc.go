// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package semantic implements the Semantic dimension of validation:
// "does the reconstructed output preserve the semantic content the
// Genome claims to encode?"
//
// # Doctrinal role
//
// MVP: fixture-based byte-equality against a pre-computed expected
// output. Score == 1.0 to pass; any byte difference fails. Fixtures live
// in /test/fixtures/genome and regenerate deterministically from their
// seeds (docs/doctrine/validation-thresholds.md §2).
//
// Production: swaps the implementation of the SemanticEvaluator interface
// with a real model-evaluation suite. The interface shape does not
// change.
//
// Surface in this package
//
//   - Inputs              — the candidate/expected bytes tuple
//   - Run(Inputs)         — pure function producing a DimensionVerdict
//   - Code* constants     — stable Finding codes exported to auditors
//
// The implementation has no state and no dependencies on clocks,
// randomness, or I/O — all of those belong in the Service layer
// (/internal/validation/service) that composes the three dimensions and
// writes audit events.
package semantic
