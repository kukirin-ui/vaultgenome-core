// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package errors defines the structured error types used across the
// platform. Errors are classified by doctrinal category:
//
//   - StructuralError — malformed contract, wrong schema version
//   - AuthorityError  — authority denied a request (trust/policy/session)
//   - OperationalError — an operational sub-check failed
//   - IntegrityError  — cryptographic or chain integrity violation
//   - IncidentError   — tamper or adversarial-condition signal
//
// # Doctrinal role
//
// Errors are not just diagnostics. Classification drives what AuditEvent
// kind is emitted and whether IncidentTermination must run. A caller that
// misclassifies an IntegrityError as a StructuralError is downgrading a
// critical signal — that is itself a reviewable doctrinal defect.
//
// Stage B: empty package, doctrinal purpose only.
package errors
