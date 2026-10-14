// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_object

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion before any
// further interpretation.
func (s *SessionObject) UnmarshalJSON(data []byte) error {
	type alias SessionObject
	tmp := (*alias)(s)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "session_object: decode error", err)
	}
	if dec.More() {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "session_object: trailing content after JSON value", nil)
	}
	if s.SchemaVersion < SchemaVersionMin || s.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "session_object: schema_version out of supported range", nil)
	}
	return nil
}

// CanonicalBytes returns the deterministic byte-form covered by Signature.
// The Signature field is EXCLUDED from its own cover-bytes (a signature
// cannot cover itself). Encoding is crypto.CanonicalJSON — see
// internal/shared/crypto/canonical.go for the JCS-profile rules.
func (s *SessionObject) CanonicalBytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	cp := *s
	cp.Signature = nil
	b, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "session_object: canonical encode failed", err)
	}
	return b, nil
}
