// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstitution_decision

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (r *ReconstitutionDecision) UnmarshalJSON(data []byte) error {
	type alias ReconstitutionDecision
	tmp := (*alias)(r)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstitution_decision: decode error", err)
	}
	if dec.More() {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstitution_decision: trailing content after JSON value", nil)
	}
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "reconstitution_decision: schema_version out of supported range", nil)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Signature is
// excluded from its own cover-bytes. Encoding is crypto.CanonicalJSON.
func (r *ReconstitutionDecision) CanonicalBytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	cp := *r
	cp.Signature = nil
	out, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstitution_decision: canonical encode failed", err)
	}
	return out, nil
}
