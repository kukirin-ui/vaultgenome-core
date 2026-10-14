// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cross_cloud_handshake_request

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion against
// the supported [Min, Max] range. A wire-format reader that sees a
// schema version above its compiled-in Max MUST refuse, because the
// new fields it would gain at the higher version are not understood
// here.
func (r *CrossCloudHandshakeRequest) UnmarshalJSON(data []byte) error {
	type alias CrossCloudHandshakeRequest
	tmp := (*alias)(r)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"cross_cloud_handshake_request: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"cross_cloud_handshake_request: trailing content after JSON value",
			nil,
		)
	}
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"cross_cloud_handshake_request: schema_version out of supported range",
			nil,
		)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Signature is
// excluded from its own cover-bytes. Encoding is crypto.CanonicalJSON.
//
// Validate is invoked first: an invalid request never produces canonical
// bytes, preventing partially-formed requests from being signed.
func (r *CrossCloudHandshakeRequest) CanonicalBytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	cp := *r
	cp.Signature = nil
	b, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"cross_cloud_handshake_request: canonical encode failed",
			err,
		)
	}
	return b, nil
}
