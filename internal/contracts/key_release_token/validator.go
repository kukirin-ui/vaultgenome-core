// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package key_release_token

import (
	"fmt"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Validate runs static consistency checks. Invariants enforced here:
//
//   - SchemaVersion is in the supported range.
//   - All required IDs (TokenID, DecisionID, RequestID, SigningKeyID,
//     AuditEventID) are non-zero — un-evidenced releases are
//     structurally invalid.
//   - DestinationMeasurement is 32, 48 or 64 bytes (ValidMeasurementLen).
//   - Wrapped is non-empty (no token releases zero keys).
//   - Each WrappedKey:
//   - KeyID non-zero
//   - Purpose == PurposeSealing (Phase 4 admits only sealing)
//   - Ciphertext non-empty
//   - AAD non-empty (binds wrap to token)
//   - PolicyVersion is non-empty (audit payload requires it).
//   - AuthorizedAt is non-zero.
//   - Signature is non-empty (sign-before-send required).
//
// The Validate function does NOT verify the signature itself — that is
// VerifySignature's responsibility. Validate does NOT verify that
// each WrappedKey actually unwraps under the destination's Sealer —
// that is the destination's CrossCloudReceiver responsibility at
// consume time.
func (t KeyReleaseToken) Validate() error {
	if t.SchemaVersion < SchemaVersionMin || t.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"key_release_token: schema_version out of supported range",
			nil,
		)
	}
	if t.TokenID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: token_id required",
			nil,
		)
	}
	if t.DecisionID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: decision_id required",
			nil,
		)
	}
	if t.RequestID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: request_id required",
			nil,
		)
	}
	if !ValidMeasurementLen(len(t.DestinationMeasurement)) {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("key_release_token: destination_measurement must be 32, 48 or 64 bytes; got %d", len(t.DestinationMeasurement)),
			nil,
		)
	}
	if len(t.Wrapped) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: wrapped must contain at least one key",
			nil,
		)
	}
	for i, w := range t.Wrapped {
		if w.KeyID.IsZero() {
			return shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				fmt.Sprintf("key_release_token: wrapped[%d].key_id required", i),
				nil,
			)
		}
		if w.Purpose != PurposeSealing {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("key_release_token: wrapped[%d].purpose must be %d (sealing); got %d", i, PurposeSealing, w.Purpose),
				nil,
			)
		}
		if len(w.Ciphertext) == 0 {
			return shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				fmt.Sprintf("key_release_token: wrapped[%d].ciphertext required", i),
				nil,
			)
		}
		if len(w.AAD) == 0 {
			return shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				fmt.Sprintf("key_release_token: wrapped[%d].aad required", i),
				nil,
			)
		}
	}
	if t.PolicyVersion == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: policy_version required",
			nil,
		)
	}
	if t.AuthorizedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: authorized_at required",
			nil,
		)
	}
	if t.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: signing_key_id required",
			nil,
		)
	}
	if len(t.Signature) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: signature required",
			nil,
		)
	}
	if t.AuditEventID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: audit_event_id required (un-evidenced releases are invalid)",
			nil,
		)
	}
	return nil
}

// ValidMeasurementLen reports whether n is the length of a TEE
// measurement the platform can pin in full: 32 bytes (SHA-256; the
// simulated TEE, SGX MRENCLAVE), 48 bytes (SHA-384; SEV-SNP MEASUREMENT,
// Nitro PCR0) or 64 bytes (SHA-512). It mirrors tee.MeasurementFromBytes
// (ADR 0007): a measurement is never truncated to fit.
func ValidMeasurementLen(n int) bool {
	return n == 32 || n == 48 || n == 64
}
