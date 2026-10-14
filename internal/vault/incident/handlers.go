// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// ---- MVP handlers ---------------------------------------------------------

// HandleAttestationFailure is the R-15 MVP scenario 1 entry point.
// TEE attestation failed during an active session — the binding
// between the enclave and the keys can no longer be trusted, so the
// Service invalidates the session AND zeroizes key material
// (Critical severity).
//
// The full side-effect sequence is:
//
//  1. Append INCIDENT_DETECTED with scenario=attestation_failure,
//     severity=critical.
//  2. Call SessionInvalidator.InvalidateSession.
//  3. Call Zeroizer.Zeroize().
//  4. Append INCIDENT_TERMINATED citing the DETECTED event.
//
// Steps 2 and 3 are non-short-circuiting: a SessionInvalidator
// failure is recorded in the TERMINATED payload but does not abort
// zeroization or the TERMINATED append, because a failed invalidator
// is itself an incident signal and the audit tape must reflect it.
func (s *Service) HandleAttestationFailure(trig Trigger) (*Result, error) {
	return s.runMVP(ScenarioAttestationFailure, trig)
}

// HandleValidationHardFail is the R-15 MVP scenario 2 entry point.
// Validation produced OverallVerdict=fail on a release candidate;
// the workflow terminates with session invalidation but no
// zeroization (the keys were not compromised, just the candidate
// failed policy).
//
// Per operator doc §2 the specific failing operational sub-check
// should be cited in Trigger.Code. The release-side StagedSequencer
// already refuses to emit a disclosure when validation is not
// green; this handler formalises the refusal as a first-class
// incident.
func (s *Service) HandleValidationHardFail(trig Trigger) (*Result, error) {
	return s.runMVP(ScenarioValidationHardFail, trig)
}

// HandleAuditAppendFailure is the R-15 MVP scenario 3 entry point
// (Stage G Iteration 3 / task #68 addition). A prior audit-chain
// Append succeeded within the session; a subsequent Append refused
// — per invariant #8 ("audit is first-class") the session must
// refuse to continue.
//
// The handler does NOT attempt to append the TERMINATED event
// through the same chain that just rejected an Append. Instead it
// uses the same chain interface: the caller's detection path
// guarantees the failure was for a reason that does not affect the
// incident tape (e.g. Append-side signer or state-machine refusal
// at a later stage); if the chain itself is broken at the byte
// level, the TERMINATED Append will also fail and the Service will
// surface that error — operator doc §3 point 2 covers this case
// explicitly ("If the terminating append itself succeeded …
// escalate immediately").
//
// Error severity (invalidation, no zeroization).
func (s *Service) HandleAuditAppendFailure(trig Trigger) (*Result, error) {
	return s.runMVP(ScenarioAuditAppendFailure, trig)
}

// ---- V2+ handlers ---------------------------------------------------------

// HandlePhysicalTamperSignal is the R-15 V2+ stub for the physical
// tamper scenario (patent P3 §[0017]). MVP does not implement
// detection logic for physical tamper, so the handler returns
// ErrIncidentV2Deferred without side effects.
//
// The caller receives a classified error with
// Category=CategoryIncident, Code=incident.v2_deferred. Per
// operator doc §4 the correct response is manual escalation: do
// not restart the vault, capture state to an external medium,
// terminate the in-flight session through the normal flow, take
// the vault offline.
//
// The Service intentionally emits no audit events here: doing so
// would misrepresent the module as having handled the incident,
// undermining the guarantee that DETECTED + TERMINATED records
// always accompany real side effects.
func (s *Service) HandlePhysicalTamperSignal(trig Trigger) (*Result, error) {
	return nil, ErrIncidentV2Deferred
}

// HandleSideChannelAnomaly is the R-15 V2+ stub for the
// side-channel / pattern-anomaly scenario (patent P3 §[0017]). MVP
// does not implement detection logic; the handler returns
// ErrIncidentV2Deferred without side effects. Per operator doc §5
// manual escalation is the correct response.
func (s *Service) HandleSideChannelAnomaly(trig Trigger) (*Result, error) {
	return nil, ErrIncidentV2Deferred
}

// ---- common MVP flow ------------------------------------------------------

// runMVP is the shared termination engine for every MVP-covered
// scenario. It is not exported — the only entry points are the
// per-scenario Handle* methods above.
//
// Flow invariants (see doc.go "Contract" section):
//
//   - DETECTED appended BEFORE side effects.
//   - SessionInvalidator errors are recorded but not short-circuiting.
//   - Zeroization runs only on Critical severity.
//   - TERMINATED appended AFTER side effects, BEFORE return.
func (s *Service) runMVP(scenario Scenario, trig Trigger) (*Result, error) {
	if trig.SessionID.IsZero() {
		return nil, shared_errors.Structural(
			CodeMissingSessionID,
			"incident: trigger.session_id is required",
			nil,
		)
	}
	if trig.Code == "" {
		return nil, shared_errors.Structural(
			CodeMissingCode,
			"incident: trigger.code is required",
			nil,
		)
	}

	severity := severityFor(scenario)

	s.mu.Lock()
	defer s.mu.Unlock()

	detectedAt := s.clock.Now().UTC()

	// ---- audit-event-before-side-effect: INCIDENT_DETECTED ----
	detectedPayload, err := buildIncidentDetectedPayload(scenario, severity, trig)
	if err != nil {
		return nil, err
	}
	detectedSkel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       s.mintAuditEventID("detected"),
		Kind:          audit_event.KindIncidentDetected,
		OccurredAt:    detectedAt,
		SessionID:     trig.SessionID,
		ManifestID:    trig.ManifestID,
		Payload:       detectedPayload,
		SigningKeyID:  s.auditKID,
	}
	detectedSealed, err := s.chain.Append(detectedSkel, s.auditSigner)
	if err != nil {
		// Chain refused BEFORE any side effects. The Service leaves
		// no half-written state; caller retries or escalates.
		return nil, err
	}

	// ---- side effects: session invalidation, zeroization ----
	result := Result{
		Scenario:        scenario,
		Severity:        severity,
		SessionID:       trig.SessionID,
		ManifestID:      trig.ManifestID,
		DetectedAt:      detectedAt,
		DetectedEventID: detectedSealed.EventID,
	}

	invErr := s.invalidator.InvalidateSession(trig.SessionID, scenario.String())
	if invErr == nil {
		result.SessionInvalidated = true
	} else {
		result.SessionInvalidated = false
		if code := shared_errors.CodeOf(invErr); code != "" {
			result.InvalidationFailedCode = code
		} else {
			// Uncategorised invalidator failure — still record a
			// stable code so the audit payload is deterministic.
			result.InvalidationFailedCode = "incident.invalidator_failed"
		}
	}

	if severity >= SeverityCritical {
		s.zeroizer.Zeroize()
		result.Zeroized = true
	}

	// ---- audit-event-before-surface: INCIDENT_TERMINATED ----
	terminatedAt := s.clock.Now().UTC()
	if terminatedAt.Before(detectedAt) {
		terminatedAt = detectedAt
	}
	result.TerminatedAt = terminatedAt

	terminatedPayload, err := buildIncidentTerminatedPayload(result)
	if err != nil {
		// Side effects already executed; DETECTED remains on the
		// chain. Surface the payload-encode error — an operator
		// will see one DETECTED with no matching TERMINATED, which
		// is itself an operator signal (matches the "DETECTED
		// survives partial failure" contract in doc.go).
		return nil, err
	}
	terminatedSkel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       s.mintAuditEventID("terminated"),
		Kind:          audit_event.KindIncidentTerminated,
		OccurredAt:    terminatedAt,
		SessionID:     trig.SessionID,
		ManifestID:    trig.ManifestID,
		Payload:       terminatedPayload,
		SigningKeyID:  s.auditKID,
	}
	terminatedSealed, err := s.chain.Append(terminatedSkel, s.auditSigner)
	if err != nil {
		// Same survivorship rule: DETECTED + side effects happened,
		// TERMINATED refused. docs/operator/03_incident_response.md §3
		// (audit-append failure) covers this.
		return nil, err
	}
	result.TerminatedEventID = terminatedSealed.EventID
	return &result, nil
}
