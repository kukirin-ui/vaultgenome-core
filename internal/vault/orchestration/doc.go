// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package orchestration is the state-machine that executes the nine-stage
// orchestrated reconstruction flow: request → trust → session → disclosure
// → delegated external compute → return → validation → release → audit.
//
// # Doctrinal role
//
// This package IS the vault's authority at the control-flow level. It
// decides which stage runs next, enforces transition preconditions, and
// short-circuits on operational failures. Every transition emits an
// AuditEvent.
//
// The "Gated Self-Bootstrapping" umbrella process in the patent family
// (P1 / P3) is implemented, at the software level, by this state machine.
// The canonical code-layer name is "Orchestrated Reconstruction," per
// docs/doctrine/terminology.md §1.2.
//
// Stage B: empty package, doctrinal purpose only.
package orchestration
