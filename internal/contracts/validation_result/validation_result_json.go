// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package validation_result

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (v *ValidationResult) UnmarshalJSON(data []byte) error {
	type alias ValidationResult
	tmp := (*alias)(v)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: decode error", err)
	}
	if dec.More() {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: trailing content after JSON value", nil)
	}
	if v.SchemaVersion < SchemaVersionMin || v.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "validation_result: schema_version out of supported range", nil)
	}
	return nil
}

// CanonicalBytes returns a deterministic byte-form of the verdict.
// Encoding is crypto.CanonicalJSON, which imposes UTF-8 key-sort across
// every object including the Dimensions map — giving downstream audit
// entries a stable hash pre-image regardless of map iteration order.
//
// ValidationResult carries no Signature field of its own; the validator
// writes the verdict into an AuditEvent whose hash covers these bytes.
func (v *ValidationResult) CanonicalBytes() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	b, err := crypto.CanonicalJSON(v)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "validation_result: canonical encode failed", err)
	}
	return b, nil
}
