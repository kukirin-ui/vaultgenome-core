// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package integration hosts the cross-package integration tests that exercise
// real flows end-to-end. Unit tests belong to their respective packages;
// this package is for tests that would otherwise create import cycles or
// that exist only to prove the packages compose correctly.
//
// Two canonical inhabitants:
//
//   - vertical_slice_test.go — a single execution of the full nine-stage
//     release-side ACP flow with every authority artifact signed and every
//     transition hash-chained under the audit log. Covers invariants #2, #3,
//     #4, #5, #8 end-to-end.
//
//   - roundtrip_slice_test.go — the receive-side six-stage round trip
//     (BootstrapManifest → Orchestrator → Reassembler → ReconstitutionDecision)
//     composed against genuinely signed and AES-256-GCM-sealed artifacts.
//     Three tests: happy path (narrated via t.Logf so `go test -v` reads as a
//     demo trace); tier-1 wire tamper (Orchestrator's wire-hash refusal);
//     tier-2 payload fraud (Reassembler's plaintext-hash refusal — doctrine
//     §8.4 acid test). Covers the two-tier integrity split and invariant #1
//     on the receive side.
//
// The scripts/demo.sh harness runs both files back-to-back under a two-act
// narration to produce an operator-facing walkthrough from a single
// `make demo` invocation.
//
// A failure in either test is always a regression: either a contract shape
// drifted, an authority boundary leaked, the audit chain broke, or one of
// the two integrity tiers regressed.
package integration
