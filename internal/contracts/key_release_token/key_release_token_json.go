// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package key_release_token

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion against
// the supported [Min, Max] range.
func (t *KeyReleaseToken) UnmarshalJSON(data []byte) error {
	type alias KeyReleaseToken
	tmp := (*alias)(t)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"key_release_token: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"key_release_token: trailing content after JSON value",
			nil,
		)
	}
	if t.SchemaVersion < SchemaVersionMin || t.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"key_release_token: schema_version out of supported range",
			nil,
		)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Signature is
// excluded from its own cover-bytes.
func (t *KeyReleaseToken) CanonicalBytes() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	cp := *t
	cp.Signature = nil
	b, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"key_release_token: canonical encode failed",
			err,
		)
	}
	return b, nil
}
