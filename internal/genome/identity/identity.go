// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Prefix is the human-readable tag every derived GenomeID carries.
// Mirrored from the contract package so callers who only import this
// package don't need to reach for the contract constant.
const Prefix = genome_descriptor.GenomeIDPrefix

// Derive returns the content-addressed GenomeID of g. The derivation is
// a pure function of g's canonical form (with GenomeID and Signature
// zeroed); it does NOT mutate g.
//
// Derive is a thin wrapper over (*GenomeDescriptor).DeriveID that gives
// external callers a package-level entry point. Callers that already
// have a descriptor in hand may call the method directly — the wrapper
// exists for discoverability, not for any additional behavior.
//
// Errors:
//   - nil g returns a Structural error.
//   - any encoding failure propagates the contract's error class.
func Derive(g *genome_descriptor.GenomeDescriptor) (ids.GenomeID, error) {
	if g == nil {
		return "", shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"identity: nil genome descriptor",
			nil,
		)
	}
	return g.DeriveID()
}

// Verify checks that the stored GenomeID on g equals the value that
// would be derived from its current body. It is a lightweight entry
// point for callers that want the content-addressing check in
// isolation, without running the full Validate pipeline.
//
// A mismatch returns an Integrity-classified error — the same
// classification the full Validate emits for R-14 violations — so
// callers can route to the same audit path.
func Verify(g *genome_descriptor.GenomeDescriptor) error {
	derived, err := Derive(g)
	if err != nil {
		return err
	}
	if derived != g.GenomeID {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"identity: stored genome_id disagrees with content-addressed derivation",
			nil,
		)
	}
	return nil
}
