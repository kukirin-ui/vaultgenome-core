// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_manifest

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (b *BootstrapManifest) UnmarshalJSON(data []byte) error {
	type alias BootstrapManifest
	tmp := (*alias)(b)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "bootstrap_manifest: decode error", err)
	}
	if dec.More() {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "bootstrap_manifest: trailing content after JSON value", nil)
	}
	if b.SchemaVersion < SchemaVersionMin || b.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "bootstrap_manifest: schema_version out of supported range", nil)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Signature is
// excluded from its own cover-bytes. Encoding is crypto.CanonicalJSON.
func (b *BootstrapManifest) CanonicalBytes() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	cp := *b
	cp.Signature = nil
	out, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "bootstrap_manifest: canonical encode failed", err)
	}
	return out, nil
}
