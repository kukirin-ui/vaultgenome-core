// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package genome_descriptor

import (
	"encoding/hex"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// DeriveID returns the content-addressed GenomeID of this descriptor.
//
//	GenomeID = "gen:" + hex(SHA-256(canonical-JSON(descriptor
//	                                 with GenomeID="" and Signature=nil)))
//
// DeriveID is idempotent: calling it on a descriptor whose GenomeID is
// already set returns the same value as calling it with GenomeID zeroed,
// because derivation zeroes the field before hashing.
//
// The method does NOT mutate the receiver. Callers that want to populate
// the descriptor's GenomeID field should assign the result explicitly.
func (g *GenomeDescriptor) DeriveID() (ids.GenomeID, error) {
	b, err := g.derivationBytes()
	if err != nil {
		return "", err
	}
	h := crypto.SHA256(b)
	return ids.GenomeID(GenomeIDPrefix + hex.EncodeToString(h[:])), nil
}
