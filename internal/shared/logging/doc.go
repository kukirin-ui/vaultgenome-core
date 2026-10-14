// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package logging provides the structured logger used by non-authority
// code paths for diagnostic output.
//
// # Doctrinal role
//
// Logging is NOT audit. Log lines are diagnostics; AuditEvent records are
// evidence. A code path that needs to record an authority decision must
// NOT substitute a log line for an AuditEvent — that is a doctrinal
// defect caught by /test/doctrine.
//
// Logs must never emit genome material, sealed or unsealed, session
// secrets, keys, or signatures. The structured logger enforces this via
// typed field helpers (Stage C); string interpolation of contract fields
// is discouraged.
//
// Stage B: empty package, doctrinal purpose only.
package logging
