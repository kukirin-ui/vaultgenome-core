// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package genome_descriptor

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// CanonicalBytes returns the deterministic byte-form of this descriptor used
// as the cover-bytes of the Signature. The Signature field is zeroed before
// encoding; GenomeID is left as-is so the signature binds the derived
// identity to the descriptor.
//
// Note: derivationBytes() (used by DeriveID) zeros BOTH GenomeID and
// Signature. CanonicalBytes() zeros only Signature. The two are related but
// distinct pre-images — derivation computes the ID, signing binds the ID
// and the body together.
func (g *GenomeDescriptor) CanonicalBytes() ([]byte, error) {
	if g == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: nil receiver",
			nil,
		)
	}
	cp := *g
	cp.Signature = nil
	b, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: canonical encode failed",
			err,
		)
	}
	return b, nil
}

// derivationBytes produces the pre-image used by DeriveID: the canonical
// byte-form with BOTH GenomeID and Signature zeroed. Any change to any
// other field changes the derivation, and therefore the GenomeID.
func (g *GenomeDescriptor) derivationBytes() ([]byte, error) {
	if g == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: nil receiver",
			nil,
		)
	}
	cp := *g
	cp.GenomeID = ""
	cp.Signature = nil
	b, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: derivation encode failed",
			err,
		)
	}
	return b, nil
}
