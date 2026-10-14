// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package doctrine contains architectural-invariant tests. Each test in
// this package asserts one of the eleven doctrinal invariants enumerated
// in docs/internal/stage-a-summary.md §2. Failure of any doctrine test blocks merge
// via the vault-gate CI workflow (sub-check 15).
//
// These are NOT unit tests of a specific package. They are whole-module
// assertions: import-graph rules, existence of required artifacts, and
// structural guarantees that must hold regardless of which implementation
// detail is present. A doctrine test that begins passing because of an
// accidental coincidence is a risk — tests here must assert the
// underlying structural property, not a lexical accident.
//
// Stage B: the tests are intentional placeholders, each t.Skipf with a
// message naming the invariant. Stage C populates them with real
// assertions as the packages they test come into existence.
package doctrine
