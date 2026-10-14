// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package received_disclosure

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (r *ReceivedDisclosure) UnmarshalJSON(data []byte) error {
	type alias ReceivedDisclosure
	tmp := (*alias)(r)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "received_disclosure: decode error", err)
	}
	if dec.More() {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "received_disclosure: trailing content after JSON value", nil)
	}
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "received_disclosure: schema_version out of supported range", nil)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Signature is
// excluded from its own cover-bytes. Encoding is crypto.CanonicalJSON.
func (r *ReceivedDisclosure) CanonicalBytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	cp := *r
	cp.Signature = nil
	out, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "received_disclosure: canonical encode failed", err)
	}
	return out, nil
}
