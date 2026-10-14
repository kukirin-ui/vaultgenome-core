// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// incidentDetectedPayload is the canonical-JSON body of an
// INCIDENT_DETECTED AuditEvent. It commits to the scenario, the
// severity, the session/manifest correlators, the stable trigger
// code, a short detail string, and (if available) the classified
// cause error's category + code.
//
// Invariant #7 ("no raw export"): the Detail field is short operator
// text only; it MUST NOT carry plaintext candidate bytes. Callers
// are responsible for that cleanliness at the call site — this
// package does not attempt to sanitize.
type incidentDetectedPayload struct {
	Scenario      string         `json:"scenario"`
	Severity      string         `json:"severity"`
	SessionID     ids.SessionID  `json:"session_id"`
	ManifestID    ids.ManifestID `json:"manifest_id,omitempty"`
	Code          string         `json:"code"`
	Detail        string         `json:"detail,omitempty"`
	CauseCategory string         `json:"cause_category,omitempty"`
	CauseCode     string         `json:"cause_code,omitempty"`
}

func buildIncidentDetectedPayload(scenario Scenario, severity Severity, trig Trigger) ([]byte, error) {
	p := incidentDetectedPayload{
		Scenario:   scenario.String(),
		Severity:   severity.String(),
		SessionID:  trig.SessionID,
		ManifestID: trig.ManifestID,
		Code:       trig.Code,
		Detail:     trig.Detail,
	}
	if trig.CauseError != nil {
		if cat := shared_errors.CategoryOf(trig.CauseError); cat != shared_errors.CategoryUnknown {
			p.CauseCategory = cat.String()
		}
		if code := shared_errors.CodeOf(trig.CauseError); code != "" {
			p.CauseCode = code
		}
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			CodePayloadEncodeFailed,
			"incident: audit payload encode failed (detected)",
			err,
		)
	}
	return out, nil
}

// incidentTerminatedPayload is the canonical-JSON body of an
// INCIDENT_TERMINATED AuditEvent. It commits to the scenario and
// severity, cites the preceding DETECTED event, and records the
// actual side-effect outcomes: whether session invalidation
// succeeded (and if not, the failure code), and whether zeroization
// ran.
//
// The DetectedEventID field binds the TERMINATED record to its
// DETECTED counterpart without requiring an auditor to rebuild the
// chain index — a linear scan for TERMINATED records is sufficient
// to recover the full incident history.
type incidentTerminatedPayload struct {
	Scenario               string           `json:"scenario"`
	Severity               string           `json:"severity"`
	SessionID              ids.SessionID    `json:"session_id"`
	ManifestID             ids.ManifestID   `json:"manifest_id,omitempty"`
	DetectedEventID        ids.AuditEventID `json:"detected_event_id"`
	SessionInvalidated     bool             `json:"session_invalidated"`
	InvalidationFailedCode string           `json:"invalidation_failed_code,omitempty"`
	Zeroized               bool             `json:"zeroized"`
}

func buildIncidentTerminatedPayload(result Result) ([]byte, error) {
	p := incidentTerminatedPayload{
		Scenario:               result.Scenario.String(),
		Severity:               result.Severity.String(),
		SessionID:              result.SessionID,
		ManifestID:             result.ManifestID,
		DetectedEventID:        result.DetectedEventID,
		SessionInvalidated:     result.SessionInvalidated,
		InvalidationFailedCode: result.InvalidationFailedCode,
		Zeroized:               result.Zeroized,
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			CodePayloadEncodeFailed,
			"incident: audit payload encode failed (terminated)",
			err,
		)
	}
	return out, nil
}
