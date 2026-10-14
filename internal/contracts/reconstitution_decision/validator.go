// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstitution_decision

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

var validReasons = map[Reason]struct{}{
	ReasonReconstructedOK:  {},
	ReasonReassemblyFailed: {},
	ReasonValidationFailed: {},
}

// Validate runs static consistency checks. The coupling between Accepted
// and Reason (reconstructed_ok↔true, reassembly_failed↔false,
// validation_failed↔false) is enforced here as the receive-side mirror
// of docs/doctrine/validation-thresholds.md §6 — the underlying receive-side
// validation aggregation lives in /internal/bootstrap.
func (r ReconstitutionDecision) Validate() error {
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "reconstitution_decision: schema_version out of supported range", nil)
	}
	if r.DecisionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: decision_id required", nil)
	}
	if r.BootstrapID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: bootstrap_id required", nil)
	}
	if r.SessionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: session_id required", nil)
	}
	if r.GenomeID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: genome_id required", nil)
	}
	// Receive-side mirror of invariant #5 (validation precedes release):
	// validation precedes reconstitution. An unvalidated reconstitution
	// is structurally invalid.
	if r.ValidationResultID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: validation_result_id required (validation precedes reconstitution)", nil)
	}
	if _, ok := validReasons[r.Reason]; !ok {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstitution_decision: unknown reason", nil)
	}
	// Accepted/Reason coupling — receive-side mirror of
	// docs/doctrine/validation-thresholds.md §6.
	switch r.Reason {
	case ReasonReconstructedOK:
		if !r.Accepted {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "reconstitution_decision: reason=reconstructed_ok requires accepted=true", nil)
		}
	case ReasonReassemblyFailed:
		if r.Accepted {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "reconstitution_decision: reason=reassembly_failed requires accepted=false", nil)
		}
	case ReasonValidationFailed:
		if r.Accepted {
			return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "reconstitution_decision: reason=validation_failed requires accepted=false", nil)
		}
	}
	if r.DecidedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: decided_at required", nil)
	}
	if r.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: signing_key_id required", nil)
	}
	if len(r.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: signature required", nil)
	}
	// Receive-side mirror of invariant #8 (audit is first-class):
	// un-evidenced reconstitutions are structurally invalid.
	if r.AuditEventID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstitution_decision: audit_event_id required (un-evidenced decisions are invalid)", nil)
	}
	return nil
}
