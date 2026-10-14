// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package validation_result defines the ValidationResult canonical contract —
// the verdict produced by the three-dimension validation service before any
// release decision may be constructed.
//
// # Doctrinal role
//
// A ReleaseDecision cannot be constructed without a preceding
// ValidationResult. The aggregation rule — operational short-circuits first,
// then semantic/behavioral — is authoritative and defined in
// docs/doctrine/validation-thresholds.md §5. Any implementation of that rule lives
// in /internal/validation/service and is tested against the six negative
// scenarios in §8 of that document.
//
// Canonical term: "Validation verdict" — docs/doctrine/terminology.md §2, §3.
package validation_result

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1
)

// Dimension names one of the three validation axes.
type Dimension string

const (
	DimensionSemantic    Dimension = "semantic"
	DimensionBehavioral  Dimension = "behavioral"
	DimensionOperational Dimension = "operational"
)

// Verdict is the result of a single dimension or of the overall aggregation.
type Verdict string

const (
	VerdictPass            Verdict = "pass"
	VerdictFail            Verdict = "fail"
	VerdictConditionalFail Verdict = "conditional_fail"
)

// Severity classifies a single Finding.
type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Finding is one structured diagnostic produced during dimension evaluation.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// DimensionVerdict is the per-dimension verdict, score, threshold, findings.
type DimensionVerdict struct {
	Verdict   Verdict   `json:"verdict"`
	Score     float64   `json:"score"`     // [0.0, 1.0]
	Threshold float64   `json:"threshold"` // threshold evaluated against
	Details   []Finding `json:"details,omitempty"`
}

// EvidenceRef points at an AuditEvent that carries the authoritative record
// of something checked during validation.
type EvidenceRef struct {
	AuditEventID ids.AuditEventID `json:"audit_event_id"`
	Kind         string           `json:"kind"`
}

// ValidationResult is the verdict object.
type ValidationResult struct {
	SchemaVersion uint16 `json:"schema_version"`

	ValidationResultID ids.ValidationResultID `json:"validation_result_id"`
	SessionID          ids.SessionID          `json:"session_id"`
	ManifestID         ids.ManifestID         `json:"manifest_id"`

	// Dimensions carries one entry per validation axis. The operational
	// entry is always present; semantic/behavioral may be absent if
	// operational failed and short-circuited them (§5 aggregation rule).
	Dimensions map[Dimension]DimensionVerdict `json:"dimensions"`

	// OverallVerdict is the aggregated outcome, computed by the aggregation
	// rule in docs/doctrine/validation-thresholds.md §5.
	OverallVerdict Verdict `json:"overall_verdict"`

	// Evidence lists pointers to audit events that back the verdict.
	Evidence []EvidenceRef `json:"evidence,omitempty"`

	// ValidatedAt is the vault-side monotonic timestamp of completion.
	ValidatedAt time.Time `json:"validated_at"`
}
