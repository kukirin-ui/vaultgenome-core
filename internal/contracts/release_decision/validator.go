// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package release_decision

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

var validReasons = map[Reason]struct{}{
	ReasonValidationPass:                {},
	ReasonValidationFail:                {},
	ReasonConditionalFailRequiresReview: {},
	ReasonTrustDenied:                   {},
}

// Validate runs static consistency checks. The coupling between Release and
// Reason (pass↔true, fail↔false, conditional_fail↔false-with-review-reason)
// is enforced here per docs/doctrine/validation-thresholds.md §6; the underlying
// aggregation logic (operational-first short-circuit) lives in
// /internal/validation/service.
func (r ReleaseDecision) Validate() error {
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "release_decision: schema_version out of supported range", nil)
	}
	if r.DecisionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: decision_id required", nil)
	}
	if _, ok := validReasons[r.Reason]; !ok {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "release_decision: unknown reason", nil)
	}
	if r.Reason == ReasonTrustDenied {
		// A denial before any session: the decision cites the attestation
		// that denied, and can cite nothing downstream of it.
		if r.SchemaVersion < 2 {
			return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "release_decision: reason=trust_denied needs schema_version 2", nil)
		}
		if r.AttestationID.IsZero() {
			return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: reason=trust_denied requires attestation_id", nil)
		}
		if !r.SessionID.IsZero() || !r.ManifestID.IsZero() || !r.ValidationResultID.IsZero() {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "release_decision: reason=trust_denied cannot cite a session, manifest or validation result", nil)
		}
		if r.Release {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "release_decision: reason=trust_denied requires release=false", nil)
		}
	} else {
		if r.SessionID.IsZero() {
			return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: session_id required", nil)
		}
		if r.ManifestID.IsZero() {
			return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: manifest_id required", nil)
		}
		if r.ValidationResultID.IsZero() {
			return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: validation_result_id required", nil)
		}
	}
	// Release/Reason coupling — docs/doctrine/validation-thresholds.md §6.
	switch r.Reason {
	case ReasonValidationPass:
		if !r.Release {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "release_decision: reason=validation_pass requires release=true", nil)
		}
	case ReasonValidationFail:
		if r.Release {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "release_decision: reason=validation_fail requires release=false", nil)
		}
	case ReasonConditionalFailRequiresReview:
		if r.Release {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "release_decision: reason=conditional_fail_requires_review requires release=false (MVP)", nil)
		}
	}
	if r.DecidedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: decided_at required", nil)
	}
	if r.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: signing_key_id required", nil)
	}
	if len(r.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: signature required", nil)
	}
	// Un-evidenced decisions are structurally invalid: audit is first-class.
	if r.AuditEventID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "release_decision: audit_event_id required (un-evidenced decisions are invalid)", nil)
	}
	return nil
}
