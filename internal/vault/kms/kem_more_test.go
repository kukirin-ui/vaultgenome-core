// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Wrap refuses what it cannot encapsulate safely: nothing to wrap, a key
// of the wrong length, and a 32-byte key that is a low-order point (the
// shared secret would be all zeros).
func TestX25519KEM_WrapRefusals(t *testing.T) {
	t.Parallel()
	_, pub := newX25519(t)
	cases := []struct {
		name      string
		plaintext []byte
		recipient []byte
		category  shared_errors.Category
		code      string
		want      string
	}{
		{"no plaintext", nil, pub, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing, "plaintext required"},
		{"empty plaintext", []byte{}, pub, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing, "plaintext required"},
		{"short key", []byte("dek"), pub[:31], shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid, "invalid recipient X25519 public key"},
		{"long key", []byte("dek"), append(append([]byte(nil), pub...), 1), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid, "invalid recipient X25519 public key"},
		{"all-zero key", []byte("dek"), make([]byte, RecipientKeySize), shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid, "ECDH failed"},
		{"order-one key", []byte("dek"), append([]byte{1}, make([]byte, 31)...), shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid, "ECDH failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := NewX25519KeyWrapper().Wrap(tc.plaintext, tc.recipient, []byte("aad"))
			require.Nil(t, out)
			require.Error(t, err)
			require.Equal(t, tc.category, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// Unwrap refuses material that cannot have come from Wrap: too short to
// carry an ephemeral share, an ephemeral share that is a low-order point,
// a body too short to carry a nonce, and a private key of the wrong size.
func TestX25519KEM_UnwrapRefusals(t *testing.T) {
	t.Parallel()
	priv, pub := newX25519(t)
	_, ephPub := newX25519(t)
	cases := []struct {
		name     string
		wrapped  []byte
		priv     []byte
		category shared_errors.Category
		code     string
		want     string
	}{
		{"no ephemeral share", pub[:31], priv, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid, "too short"},
		{"empty", nil, priv, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid, "too short"},
		{"low-order ephemeral share", append(make([]byte, RecipientKeySize), []byte("nonce-and-ciphertext-bytes")...), priv, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid, "ECDH failed"},
		{"body shorter than a nonce", append(append([]byte(nil), ephPub...), 1, 2, 3, 4, 5), priv, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid, "ciphertext too short"},
		{"no body at all", append([]byte(nil), ephPub...), priv, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid, "ciphertext too short"},
		{"short private key", append(append([]byte(nil), ephPub...), make([]byte, 28)...), priv[:31], shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid, "invalid recipient X25519 private key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := NewX25519KeyUnwrapper().Unwrap(tc.wrapped, tc.priv, []byte("aad"))
			require.Nil(t, out)
			require.Error(t, err)
			require.Equal(t, tc.category, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// The AEAD layer only runs under a key HKDF derived (32 bytes); any other
// key length is a programming error it refuses rather than hides.
func TestAEAD_RefusesKeysAESCannotUse(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 5, 31, 33} {
		key := make([]byte, n)
		sealed, err := aeadSeal(key, []byte("dek"), []byte("aad"))
		require.Nil(t, sealed, "key length %d", n)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), "key length %d", n)
		require.ErrorContains(t, err, "aes init failed", "key length %d", n)

		opened, err := aeadOpen(key, make([]byte, 40), []byte("aad"))
		require.Nil(t, opened, "key length %d", n)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), "key length %d", n)
		require.ErrorContains(t, err, "aes init failed", "key length %d", n)
	}

	// A 32-byte key seals and opens; the nonce leads the blob.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sealed, err := aeadSeal(key, []byte("dek"), []byte("aad"))
	require.NoError(t, err)
	require.Len(t, sealed, 12+len("dek")+16)
	plain, err := aeadOpen(key, sealed, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("dek"), plain)
	_, err = aeadOpen(key, sealed[:12], []byte("aad"))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err), "a nonce with no tag behind it")
}
