// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recovery_request

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields (belt-and-suspenders against stray
// extension attempts) and runs SchemaVersion gating BEFORE the rest of the
// fields are interpreted. Full Validate() is NOT called here — the caller
// may want to validate separately for clearer error attribution — but the
// schema-version check is part of the decode step.
func (r *RecoveryRequest) UnmarshalJSON(data []byte) error {
	// Use a type alias to avoid recursing into this method.
	type alias RecoveryRequest
	tmp := (*alias)(r)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"recovery_request: decode error",
			err,
		)
	}

	// Tail sanity: the decoder is fed a single JSON value; trailing garbage
	// after it is rejected.
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"recovery_request: trailing content after JSON value",
			nil,
		)
	}

	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"recovery_request: schema_version out of supported range",
			nil,
		)
	}
	return nil
}

// CanonicalBytes returns the deterministic byte-form used for audit-chain
// hashing. The encoder is crypto.CanonicalJSON — a JCS-profile subset with
// sorted object keys and normalized number formatting (see
// internal/shared/crypto/canonical.go for the profile). Two processes on
// two machines produce byte-identical output for byte-identical input.
//
// RecoveryRequest does not carry a Signature field — authentication of
// the originator is handled at the transport edge before the request enters
// the doctrine layer. The bytes returned here are still stable enough to
// serve as a hash pre-image for audit entries that reference the request.
func (r *RecoveryRequest) CanonicalBytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := crypto.CanonicalJSON(r)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"recovery_request: canonical encode failed",
			err,
		)
	}
	return b, nil
}
