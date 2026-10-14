// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package service is the Validation Service entry point. It composes the
// three dimension evaluators (semantic, behavioral, operational), applies
// the aggregation rule, and emits the ValidationResult.
//
// # Doctrinal role
//
// The aggregation rule in docs/doctrine/validation-thresholds.md §5 is
// authoritative and short-circuits on operational fail. This package
// implements that exact rule. The six negative-test scenarios in §8 of
// that document are integration-test obligations of /test/integration and
// are referenced from this package's test files.
//
// Validation is always evaluated before release. The doctrine test suite
// asserts no code path constructs a ReleaseDecision without a preceding
// ValidationResult from this package.
//
// Surface in this package
//
//   - ValidationService          — composing entry point
//   - NewValidationService       — constructor (Structural refusals)
//   - ServiceOptions             — construction-time dependencies
//   - ValidateInputs             — per-request bundle of the three
//     dimensions' inputs
//   - (*ValidationService).Validate — runs STARTED → op → (sem → beh) →
//     FINDINGs → COMPLETED, returning a
//     ValidationResult whose Evidence cites
//     every sealed audit event.
//   - Aggregate                  — pure §5 aggregation rule.
//
// Contract:
//
//   - STARTED is appended BEFORE any sub-check runs.
//   - Operational runs first; on fail, semantic and behavioral are NOT
//     evaluated (doctrine §8(3)–(5) negative tests).
//   - COMPLETED is appended AFTER the result is fully constructed and
//     BEFORE it is surfaced to the caller (§9(4)).
//   - result.Validate() runs as a post-condition so malformed verdicts
//     cannot escape the Service.
package service
