// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package attestation_result

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (a *AttestationResult) UnmarshalJSON(data []byte) error {
	type alias AttestationResult
	tmp := (*alias)(a)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "attestation_result: decode error", err)
	}
	if dec.More() {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "attestation_result: trailing content after JSON value", nil)
	}
	if a.SchemaVersion < SchemaVersionMin || a.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "attestation_result: schema_version out of supported range", nil)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Signature is
// excluded from its own cover-bytes. Encoding is crypto.CanonicalJSON.
func (a *AttestationResult) CanonicalBytes() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	cp := *a
	cp.Signature = nil
	b, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "attestation_result: canonical encode failed", err)
	}
	return b, nil
}
