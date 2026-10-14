// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_object

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// validStates is the closed set of session states. Any value outside it
// is a structural error.
var validStates = map[State]struct{}{
	StateActive:      {},
	StateSuspended:   {},
	StateInvalidated: {},
	StateExpired:     {},
}

// Validate runs static consistency checks on the SessionObject. Signature
// verification is NOT performed here — that is an authority-layer concern
// performed by /internal/vault/session against keys managed by
// /internal/vault/keys.
func (s SessionObject) Validate() error {
	if s.SchemaVersion < SchemaVersionMin || s.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "session_object: schema_version out of supported range", nil)
	}
	if s.SessionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "session_object: session_id required", nil)
	}
	if s.RequestID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "session_object: request_id required", nil)
	}
	if s.GenomeID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "session_object: genome_id required", nil)
	}
	if s.PolicyVersion.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "session_object: policy_version required", nil)
	}
	if s.IssuedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "session_object: issued_at required", nil)
	}
	if s.ExpiresAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "session_object: expires_at required", nil)
	}
	if !s.ExpiresAt.After(s.IssuedAt) {
		return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "session_object: expires_at must be strictly after issued_at", nil)
	}
	if _, ok := validStates[s.State]; !ok {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "session_object: unknown state", nil)
	}
	if s.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "session_object: signing_key_id required", nil)
	}
	if len(s.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "session_object: signature required", nil)
	}
	return nil
}
