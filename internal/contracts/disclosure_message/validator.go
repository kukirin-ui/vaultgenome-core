// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_message

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Validate runs static checks. Sequence-gap detection and monotonicity
// enforcement live in /internal/vault/disclosure, not here.
func (d DisclosureMessage) Validate() error {
	if d.SchemaVersion < SchemaVersionMin || d.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "disclosure_message: schema_version out of supported range", nil)
	}
	if d.DisclosureID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "disclosure_message: disclosure_id required", nil)
	}
	if d.SessionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "disclosure_message: session_id required", nil)
	}
	if d.ComponentID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "disclosure_message: component_id required", nil)
	}
	if d.PolicyVersion.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "disclosure_message: policy_version required", nil)
	}
	if len(d.SealedPayload) == 0 {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "disclosure_message: sealed_payload must be non-empty", nil)
	}
	if len(d.Nonce) != GCMNonceSize {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "disclosure_message: nonce must be exactly 12 bytes (AES-256-GCM)", nil)
	}
	if d.RecipientKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "disclosure_message: recipient_key_id required", nil)
	}
	if d.AuthorizedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "disclosure_message: authorized_at required", nil)
	}
	if d.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "disclosure_message: signing_key_id required", nil)
	}
	if len(d.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "disclosure_message: signature required", nil)
	}
	return nil
}
