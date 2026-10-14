// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package release_decision defines the ReleaseDecision canonical contract —
// the explicit, governed authority decision artifact that ends the flow.
//
// # Doctrinal role
//
// A ReleaseDecision is NOT a consequence of a passing validation alone. It
// is a separate authority decision made by the vault that consumes the
// ValidationResult and applies the coupling table in
// docs/doctrine/validation-thresholds.md §6:
//
//	pass             → Release=true,  Reason="validation_pass"
//	conditional_fail → Release=false (MVP), "conditional_fail_requires_review"
//	fail             → Release=false, Reason="validation_fail"
//
// and, since schema v2 (ADR 0015), the decision Trust Admission's deny
// short-circuits to — a release decision without a session:
//
//	trust deny       → Release=false, Reason="trust_denied", AttestationID set
//
// The ReleaseDecision is signed, audit-bound, and immutable once issued. It
// is the terminal artifact of the nine-stage flow.
//
// Canonical term: "Release Decision" — docs/doctrine/terminology.md §2, §3.
package release_decision

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	// SchemaVersionMin stays at 1: a v1 decision (the three validation
	// reasons, every id set) is a valid v2 decision.
	SchemaVersionMin uint16 = 1
	// v1 → v2 (ADR 0015): ReasonTrustDenied, and the AttestationID it
	// cites; session_id, manifest_id and validation_result_id are then
	// empty, because the flow never reached them.
	SchemaVersionMax     uint16 = 2
	SchemaVersionCurrent uint16 = 2
)

// Reason enumerates the admissible reason codes. The set is closed; any
// addition is a schema bump.
type Reason string

const (
	ReasonValidationPass                Reason = "validation_pass"
	ReasonValidationFail                Reason = "validation_fail"
	ReasonConditionalFailRequiresReview Reason = "conditional_fail_requires_review"
	// ReasonTrustDenied (schema v2): Trust Admission denied the request;
	// no session was issued and nothing was validated. Release is false.
	ReasonTrustDenied Reason = "trust_denied"
)

// ReleaseDecision is the terminal authority artifact.
type ReleaseDecision struct {
	SchemaVersion uint16         `json:"schema_version"`
	DecisionID    ids.DecisionID `json:"decision_id"`

	SessionID          ids.SessionID          `json:"session_id"`
	ManifestID         ids.ManifestID         `json:"manifest_id"`
	ValidationResultID ids.ValidationResultID `json:"validation_result_id"`

	// AttestationID (schema v2) cites the Trust Admission outcome a
	// trust_denied decision rests on. Required for that reason, optional
	// otherwise.
	AttestationID ids.AttestationID `json:"attestation_id,omitempty"`

	// Release is the boolean outcome.
	Release bool `json:"release"`

	// Reason is the machine-readable reason code, drawn from the closed set.
	Reason Reason `json:"reason"`

	// DecidedAt is the vault-side monotonic moment projected to wall-clock.
	DecidedAt time.Time `json:"decided_at"`

	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`

	// AuditEventID points at the RELEASE_DECIDED audit event that
	// immutably records this decision. An un-evidenced decision is
	// structurally invalid.
	AuditEventID ids.AuditEventID `json:"audit_event_id"`
}
