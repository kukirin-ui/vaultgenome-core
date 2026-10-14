// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof

import (
	"bytes"
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// UnmarshalJSON rejects unknown fields and gates SchemaVersion. The
// embedded types (GenomeDescriptor, Scorecard, WitnessReceipt) each
// carry their own UnmarshalJSON with DisallowUnknownFields; those
// gates apply transitively, so unknown fields anywhere in the bundle
// are rejected.
func (p *ContinuityProof) UnmarshalJSON(data []byte) error {
	type alias ContinuityProof
	tmp := (*alias)(p)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"continuity_proof: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"continuity_proof: trailing content after JSON value",
			nil,
		)
	}
	if p.SchemaVersion < SchemaVersionMin || p.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"continuity_proof: schema_version out of supported range",
			nil,
		)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Encoding is
// crypto.CanonicalJSON applied to a copy with Signature zeroed.
// Validate() is run up-front — an invalid bundle has no canonical
// cover-bytes.
func (p *ContinuityProof) CanonicalBytes() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	cp := *p
	cp.Signature = nil
	// Deep-copy the ancestor chain so the caller's slice is not
	// aliased into the canonical-byte derivation.
	cp.AncestorChain = append(cp.AncestorChain[:0:0], p.AncestorChain...)
	out, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"continuity_proof: canonical encode failed",
			err,
		)
	}
	return out, nil
}
