// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// A store built without a clock stamps keys from the system clock.
func TestNewInMemoryStore_NilClockUsesTheSystemClock(t *testing.T) {
	t.Parallel()
	s := NewInMemoryStore(nil)
	vk, err := s.GenerateSigning("k", PurposeSigningAudit)
	require.NoError(t, err)
	require.Positive(t, vk.CreatedAt)
	require.NoError(t, s.GenerateSealing("seal"))
	nonce, ct, err := s.Seal("seal", []byte("x"), nil)
	require.NoError(t, err)
	pt, err := s.Open("seal", nonce, ct, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("x"), pt)
}

// Every registration names its key: an empty KeyID is refused before any
// material is generated or copied.
func TestInMemoryStore_RegistrationsRequireAKeyID(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	calls := map[string]func() error{
		"generate signing": func() error { _, err := s.GenerateSigning("", PurposeSigningAuthority); return err },
		"register from seed": func() error {
			_, err := s.RegisterSigningFromSeed("", PurposeSigningAuthority, make([]byte, crypto.Ed25519SeedSize))
			return err
		},
		"register sealing": func() error { return s.RegisterSealing("", make([]byte, crypto.AES256KeySize)) },
		"generate sealing": func() error { return s.GenerateSealing("") },
	}
	for name, call := range calls {
		err := call()
		require.Error(t, err, name)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), name)
		require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err), name)
		require.ErrorContains(t, err, "KeyID required", name)
	}
	require.Empty(t, s.signing)
	require.Empty(t, s.sealing)
}

// A sealing kid is registered once, whether generated or supplied, and
// the first material is the one that stays.
func TestInMemoryStore_GenerateSealing_RejectsDuplicateKID(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	require.NoError(t, s.GenerateSealing("seal"))
	nonce, ct, err := s.Seal("seal", []byte("under the first key"), []byte("aad"))
	require.NoError(t, err)

	err = s.GenerateSealing("seal")
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "already registered (sealing)")
	err = s.RegisterSealing("seal", make([]byte, crypto.AES256KeySize))
	require.ErrorContains(t, err, "already registered (sealing)")

	pt, err := s.Open("seal", nonce, ct, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("under the first key"), pt, "the first key is kept")
}

// Sealing under a kid the store does not hold is an authority refusal,
// the same as opening under one.
func TestInMemoryStore_Seal_UnknownKID(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	nonce, ct, err := s.Seal("absent", []byte("x"), nil)
	require.Nil(t, nonce)
	require.Nil(t, ct)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "unknown sealing kid")
}

// Zeroize wipes sealing material as well as signing keys: what was sealed
// before can no longer be opened, and the kid is free to register again.
func TestInMemoryStore_Zeroize_WipesSealingKeys(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	require.NoError(t, s.GenerateSealing("seal"))
	material := s.sealing["seal"].Material
	nonce, ct, err := s.Seal("seal", []byte("secret"), nil)
	require.NoError(t, err)

	s.Zeroize()
	require.Empty(t, s.sealing)
	require.Equal(t, make([]byte, crypto.AES256KeySize), material, "the material is overwritten, not just forgotten")
	_, err = s.Open("seal", nonce, ct, nil)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.False(t, s.EraseSealing("seal"))
	require.NoError(t, s.GenerateSealing("seal"))
	_, err = s.Open("seal", nonce, ct, nil)
	require.Error(t, err, "a fresh key under the old kid does not open the old ciphertext")
}

// A kid with the tenant layout but an unusable part is not a tenant kid.
func TestParseTenantKeyID_RefusesMalformedParts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		kid  ids.KeyID
	}{
		{"empty master", "/tenant/acme/sealing"},
		{"tenant with a space", "master/tenant/acme corp/sealing"},
		{"empty tenant", "master/tenant//sealing"},
		{"unknown purpose", "master/tenant/acme/encrypting"},
		{"empty purpose", "master/tenant/acme/"},
		{"wrong marker", "master/customer/acme/sealing"},
		{"too many parts", "master/tenant/acme/sealing/extra"},
	}
	for _, tc := range cases {
		master, tenant, purpose, ok := ParseTenantKeyID(tc.kid)
		require.False(t, ok, tc.name)
		require.Empty(t, master, tc.name)
		require.Empty(t, tenant, tc.name)
		require.Equal(t, PurposeUnknown, purpose, tc.name)
	}
	for _, p := range []Purpose{PurposeSealing, PurposeSigningAuthority, PurposeSigningAudit, PurposeSigningWitness} {
		require.Equal(t, p, parsePurpose(p.String()), p.String())
	}
	require.Equal(t, PurposeUnknown, parsePurpose("unknown"))
}

// Tenant derivations refuse a tenant id they cannot name a key for, and a
// signing derivation refuses a master the store does not hold; in every
// case nothing is registered.
func TestTenantDerivations_RefuseWhatTheyCannotName(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	require.NoError(t, s.GenerateSealing("master-seal"))
	_, err := s.GenerateSigning("master-sign", PurposeSigningAuthority)
	require.NoError(t, err)
	const bad = TenantID("not a tenant")

	calls := map[string]func() error{
		"derive sealing": func() error { _, err := s.DeriveTenantSealing("master-seal", bad); return err },
		"ensure sealing": func() error { _, err := s.EnsureTenantSealing("master-seal", bad); return err },
		"derive signing": func() error { _, err := s.DeriveTenantSigning("master-sign", bad, PurposeSigningAuthority); return err },
		"ensure signing": func() error { _, err := s.EnsureTenantSigning("master-sign", bad, PurposeSigningAuthority); return err },
	}
	for name, call := range calls {
		err := call()
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), name)
		require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err), name)
		require.ErrorContains(t, err, "not well-formed", name)
	}

	vk, err := s.DeriveTenantSigning("no-such-master", "acme", PurposeSigningAudit)
	require.Empty(t, vk.KeyID)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, `master signing kid "no-such-master" not registered`)

	require.Len(t, s.sealing, 1, "nothing was derived")
	require.Len(t, s.signing, 1, "nothing was derived")
}
