// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package policy holds the active policy document and resolves PolicyProfile
// references into effective Policy objects consulted by trust, disclosure,
// and validation.
//
// # Doctrinal role
//
// Policy is versioned. The PolicyVersion pinned at session issuance is
// what operational validation's op.policy_alignment sub-check compares
// against at release time (docs/doctrine/validation-thresholds.md §4.2). A
// silent policy swap mid-flow is an operational fail.
//
// Policy is NOT a configuration file consumed ad hoc. It is a first-class
// versioned object; changes are audit-bound via AuditEvent.
//
// Stage B: empty package, doctrinal purpose only.
package policy
