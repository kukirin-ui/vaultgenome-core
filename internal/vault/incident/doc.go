// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package incident implements the IncidentCoordinationService — the
// authoritative handler for R-15 incident scenarios inside the Vault.
//
// # Doctrinal role
//
// Incident Termination is a governed workflow termination with session
// invalidation and (for critical severities) key material zeroization
// (docs/doctrine/terminology.md §2). Detection of an event of severity
// >= error short-circuits whatever stage is running, invalidates bound
// sessions, and — if severity warrants it — triggers Zeroization
// through /internal/vault/keys.
//
// Incident state is itself audit-bound: INCIDENT_DETECTED and
// INCIDENT_TERMINATED events are first-class members of the AuditEvent
// Kind enum (release-side, SchemaVersion 1). Per invariant #8 the
// events are appended to the release-side audit chain BEFORE the
// Service returns, so a crashed-mid-flight incident is still
// evidenced by the DETECTED record.
//
// R-15 scope (docs/doctrine/open-decisions-resolved.md):
//
//   - MVP-covered: AttestationFailure, ValidationHardFail, and (as of
//     Stage G Iteration 3) AuditAppendFailure. Each runs the full
//     termination flow — DETECTED event, session invalidation, optional
//     zeroization, TERMINATED event — and returns a Result whose
//     AuditEventIDs an auditor can chain-verify.
//   - V2+: PhysicalTamperSignal and SideChannelAnomaly. Per patent
//     P3 §[0017] the full incident taxonomy belongs to the Secure
//     Execution Layer, out of MVP budget. MVP stubs these scenarios
//     with explicit code ErrIncidentV2Deferred (CategoryIncident,
//     Code=incident.v2_deferred). The V2 handlers do NOT emit audit
//     events — doing so would misrepresent the module as having
//     handled the incident. The caller must initiate the manual
//     escalation runbook /docs/operator/03_incident_response.md
//     §4 / §5.
//
// Surface in this package
//
//   - Service — the IncidentCoordinationService shape.
//   - NewService — Structural-refusal constructor.
//   - ServiceOptions — construction-time dependencies.
//   - Trigger — per-call context (SessionID, ManifestID, Code, Detail,
//     CauseError) consumed by every Handle* method.
//   - Result — the per-incident record returned to the caller
//     (scenario, severity, both audit-event IDs, side-effect flags).
//   - Scenario — enum of R-15 scenario kinds (3 MVP + 2 V2+).
//   - Severity — enum {Info, Warn, Error, Critical} mapped from
//     Scenario in severityFor().
//   - SessionInvalidator — the seam the caller wires to the Session
//     Registry (or equivalent); InvalidateSession(session, reason).
//   - Zeroizer — the seam the caller wires to the Vault keystore
//     (keys.InMemoryStore satisfies it via Zeroize()).
//   - (*Service).HandleAttestationFailure — MVP scenario 1.
//   - (*Service).HandleValidationHardFail — MVP scenario 2.
//   - (*Service).HandleAuditAppendFailure — MVP scenario 3 (new in
//     Stage G Iteration 3 — formalises the "audit-append failure is
//     terminal" rule that /internal/vault/disclosure.StagedSequencer
//     enforces in practice; makes the scenario auditable as a
//     first-class incident rather than an opaque Finalize() call).
//   - (*Service).HandlePhysicalTamperSignal — V2+ stub.
//   - (*Service).HandleSideChannelAnomaly — V2+ stub.
//   - ErrIncidentV2Deferred — the classified error value V2+ handlers
//     return. Also predicate IsV2Deferred(err).
//   - Stable code constants under the Code* prefix (see incident.go).
//
// Contract:
//
//   - DETECTED is appended BEFORE session invalidation or zeroization.
//     If the chain refuses, the incident never became visible; the
//     caller can retry or escalate. The Service leaves no half-written
//     state when the first append fails.
//   - Zeroization runs only on Critical severity (AttestationFailure).
//     This preserves the session registry's ability to emit its own
//     follow-up events under the audit signing key, which survives
//     zeroization because audit keys are a separate Purpose in
//     /internal/vault/keys.
//   - TERMINATED is appended AFTER session invalidation + zeroization
//     and BEFORE the Service returns. If TERMINATED append fails, the
//     side effects have already executed; the caller surfaces the
//     error, and the DETECTED event remains on the chain as the
//     authoritative record that something went wrong.
//   - SessionInvalidator errors are logged into the TERMINATED
//     payload (as invalidation_failed_code) but do NOT abort the
//     flow — a registry that can't invalidate the session is itself
//     an incident signal; the operator sees it in the TERMINATED
//     payload and follows up.
//   - V2+ handlers have zero side effects: no audit events, no
//     invalidation, no zeroization. They return ErrIncidentV2Deferred
//     immediately so callers get a loud, classified failure.
//
// Invariants this package depends on
//
//   - #1 Vault is authority — this package is under /internal/vault;
//     non-vault callers that need to declare an incident do so via
//     the session-scoped error channels defined in
//     /internal/shared/errors (CategoryIncident), which the vault
//     driver routes into HandleAttestationFailure /
//     HandleValidationHardFail / HandleAuditAppendFailure.
//   - #8 Audit is first-class — DETECTED precedes side effects;
//     TERMINATED precedes return. No silent handling.
//   - R-15 — MVP covers three scenarios by real execution; V2+
//     scenarios return the explicit ErrIncidentV2Deferred rather
//     than the legacy NotImplementedInMVP sentinel, so a caller
//     accidentally depending on them gets a classified,
//     code-diagnosable failure.
package incident
