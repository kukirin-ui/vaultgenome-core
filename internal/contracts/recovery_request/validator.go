// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recovery_request

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Validate performs all static, non-authority checks on the RecoveryRequest.
// It does NOT perform trust admission — that is a separate, policy-driven
// decision made by /internal/vault/trust.
//
// Returned errors are classified via /internal/shared/errors so that the
// caller (intake) emits the correct AuditEvent kind. Structural failures
// classify as CategoryStructural; unsupported schema versions classify as
// CategoryStructural with CodeSchemaVersionUnsupported.
func (r RecoveryRequest) Validate() error {

	// SchemaVersion gate — first and unconditional.
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"recovery_request: schema_version out of supported range",
			nil,
		)
	}

	if r.RequestID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"recovery_request: request_id required",
			nil,
		)
	}
	if r.GenomeID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"recovery_request: genome_id required",
			nil,
		)
	}
	if r.PolicyProfile == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"recovery_request: policy_profile required",
			nil,
		)
	}
	if r.RequesterIdentity == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"recovery_request: requester_identity required",
			nil,
		)
	}
	if r.CreatedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"recovery_request: created_at required",
			nil,
		)
	}
	return nil
}
