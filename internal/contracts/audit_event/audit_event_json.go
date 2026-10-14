// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_event

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (e *AuditEvent) UnmarshalJSON(data []byte) error {
	type alias AuditEvent
	tmp := (*alias)(e)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "audit_event: decode error", err)
	}
	if dec.More() {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "audit_event: trailing content after JSON value", nil)
	}
	if e.SchemaVersion < SchemaVersionMin || e.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "audit_event: schema_version out of supported range", nil)
	}
	return nil
}

// CanonicalBytes returns the bytes that Hash is computed over. Both Hash
// and Signature are excluded from the pre-image: Hash cannot cover itself,
// and Signature covers Hash (not the whole event) so that audit-chain
// verification can happen without re-running the encoder on every event.
// Encoding is crypto.CanonicalJSON.
func (e *AuditEvent) CanonicalBytes() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	cp := *e
	cp.Hash = nil
	cp.Signature = nil
	b, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "audit_event: canonical encode failed", err)
	}
	return b, nil
}
