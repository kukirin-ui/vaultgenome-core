// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package genome_descriptor

import (
	"testing"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// A nil descriptor is refused by every entry point that could otherwise
// dereference it, with the same structural error.
func TestGenomeDescriptor_NilReceiver_Refused(t *testing.T) {
	t.Parallel()
	var g *GenomeDescriptor
	store := newAuthorityStore(t, ids.KeyID("vault-auth-1"))

	_, err := g.CanonicalBytes()
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	_, err = g.DeriveID()
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(g.SignWith(store)))
}

func TestGenomeDescriptor_VerifySignature_NilResolverRefused(t *testing.T) {
	t.Parallel()
	g := signedFixture(t)
	err := g.VerifySignature(nil)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// A parent entry must name a genome, with the canonical prefix, and each
// entry's method must be one the doctrine knows; the error for an unknown
// method names the entry's position.
func TestGenomeDescriptor_Provenance_ParentEntriesRefused(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name    string
		parents []GenomeDerivation
		code    string
		msg     string
	}{
		{
			name:    "zero parent id",
			parents: []GenomeDerivation{{ParentGenomeID: "", Method: DerivationFineTune}},
			code:    shared_errors.CodeFieldValueInvalid,
			msg:     "zero parent_genome_id",
		},
		{
			name:    "parent without the canonical prefix",
			parents: []GenomeDerivation{{ParentGenomeID: "parent-1", Method: DerivationFineTune}},
			code:    shared_errors.CodeFieldValueInvalid,
			msg:     "missing canonical prefix",
		},
		{
			name: "unknown method on the second parent",
			parents: []GenomeDerivation{
				{ParentGenomeID: ids.GenomeID(GenomeIDPrefix + "aa"), Method: DerivationFineTune},
				{ParentGenomeID: ids.GenomeID(GenomeIDPrefix + "bb"), Method: DerivationMethod("teleport")},
			},
			code: shared_errors.CodeFieldValueInvalid,
			msg:  "derived_from[1] unknown method",
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			g := signedFixture(t)
			g.Generation = 1
			g.Provenance.DerivedFrom = row.parents
			err := g.Validate()
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, row.code, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), row.msg)
		})
	}
}

func TestToDec(t *testing.T) {
	t.Parallel()
	for in, want := range map[int]string{0: "0", 1: "1", 9: "9", 10: "10", 1234567: "1234567", -1: "-1", -4096: "-4096"} {
		require.Equal(t, want, toDec(in), "toDec(%d)", in)
	}
}
