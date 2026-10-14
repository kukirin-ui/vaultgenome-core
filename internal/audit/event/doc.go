// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package event constructs AuditEvent records for the vault's authority
// decisions. It is the only legitimate constructor of AuditEvent values
// within the running process — callers outside /internal/audit/* never
// instantiate AuditEvent directly. This is enforced by the doctrine test
// suite's import-graph rule.
//
// # Doctrinal role
//
// Audit is first-class. Every authority decision emits an AuditEvent
// BEFORE the decision becomes visible to its caller. VALIDATION_FINDING
// events in particular must be persisted before a fail or
// conditional_fail verdict is returned — un-evidenced decisions are not
// governed decisions (docs/doctrine/validation-thresholds.md §9).
//
// Stage B: empty package, doctrinal purpose only.
package event
