// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package attestation_result

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

var validOutcomes = map[Outcome]struct{}{
	OutcomeAllow:    {},
	OutcomeDeny:     {},
	OutcomeRestrict: {},
}

// Validate runs static checks. Signature verification is performed by
// /internal/vault/trust and by operational validation sub-check
// op.attestation_valid.
func (a AttestationResult) Validate() error {
	if a.SchemaVersion < SchemaVersionMin || a.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "attestation_result: schema_version out of supported range", nil)
	}
	if a.AttestationID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "attestation_result: attestation_id required", nil)
	}
	if a.RequestID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "attestation_result: request_id required", nil)
	}
	if _, ok := validOutcomes[a.Outcome]; !ok {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "attestation_result: unknown outcome", nil)
	}
	if a.IssuedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "attestation_result: issued_at required", nil)
	}
	if a.TTL <= 0 {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "attestation_result: ttl must be positive", nil)
	}
	if a.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "attestation_result: signing_key_id required", nil)
	}
	if len(a.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "attestation_result: signature required", nil)
	}
	// Deny/Restrict with an empty Reason is a weak governance trace;
	// require a reason so the audit trail has a machine-usable code.
	if (a.Outcome == OutcomeDeny || a.Outcome == OutcomeRestrict) && a.Reason == "" {
		return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "attestation_result: reason required for deny/restrict outcomes", nil)
	}
	return nil
}
