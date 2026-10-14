// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package validation_result

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

var validVerdicts = map[Verdict]struct{}{
	VerdictPass:            {},
	VerdictFail:            {},
	VerdictConditionalFail: {},
}

var validSeverities = map[Severity]struct{}{
	SeverityInfo:    {},
	SeverityWarning: {},
	SeverityError:   {},
}

var validDimensions = map[Dimension]struct{}{
	DimensionSemantic:    {},
	DimensionBehavioral:  {},
	DimensionOperational: {},
}

// Validate runs static consistency checks. The aggregation-rule enforcement
// itself (operational-first short-circuit, conditional_fail propagation) is
// a test obligation of /internal/validation/service and of the doctrine
// suite; here we only enforce the structural invariants of the verdict
// object itself.
func (v ValidationResult) Validate() error {
	if v.SchemaVersion < SchemaVersionMin || v.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "validation_result: schema_version out of supported range", nil)
	}
	if v.ValidationResultID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "validation_result: validation_result_id required", nil)
	}
	if v.SessionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "validation_result: session_id required", nil)
	}
	if v.ManifestID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "validation_result: manifest_id required", nil)
	}
	if len(v.Dimensions) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "validation_result: dimensions must not be empty", nil)
	}
	// Operational dimension is always present — it is the short-circuit gate.
	if _, ok := v.Dimensions[DimensionOperational]; !ok {
		return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "validation_result: operational dimension must always be present", nil)
	}
	for dim, dv := range v.Dimensions {
		if _, ok := validDimensions[dim]; !ok {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: unknown dimension", nil)
		}
		if _, ok := validVerdicts[dv.Verdict]; !ok {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: unknown per-dimension verdict", nil)
		}
		if dv.Score < 0.0 || dv.Score > 1.0 {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: score out of [0,1]", nil)
		}
		if dv.Threshold < 0.0 || dv.Threshold > 1.0 {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: threshold out of [0,1]", nil)
		}
		for _, f := range dv.Details {
			if f.Code == "" {
				return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "validation_result: finding.code required", nil)
			}
			if _, ok := validSeverities[f.Severity]; !ok {
				return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: unknown finding.severity", nil)
			}
		}
	}
	if _, ok := validVerdicts[v.OverallVerdict]; !ok {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: unknown overall_verdict", nil)
	}
	// Cross-check: if operational is fail, overall must be fail
	// (operational is a veto per docs/doctrine/validation-thresholds.md §5).
	if op, ok := v.Dimensions[DimensionOperational]; ok {
		if op.Verdict == VerdictFail && v.OverallVerdict != VerdictFail {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "validation_result: operational fail must propagate to overall fail", nil)
		}
	}
	for _, ev := range v.Evidence {
		if ev.AuditEventID.IsZero() {
			return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "validation_result: evidence.audit_event_id required", nil)
		}
		if ev.Kind == "" {
			return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "validation_result: evidence.kind required", nil)
		}
	}
	if v.ValidatedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "validation_result: validated_at required", nil)
	}
	return nil
}
