// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

func newX25519(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k.Bytes(), k.PublicKey().Bytes()
}

func TestX25519KEM_RoundTrip(t *testing.T) {
	t.Parallel()
	priv, pub := newX25519(t)
	w := NewX25519KeyWrapper()
	u := NewX25519KeyUnwrapper()
	dek := []byte("a-32-byte-data-encryption-key!!!")
	aad := []byte("token=abc|kid=1")

	wrapped, err := w.Wrap(dek, pub, aad)
	require.NoError(t, err)
	require.Greater(t, len(wrapped), 32+12, "must carry ephemeral pubkey + nonce + tag")
	require.NotContains(t, string(wrapped), string(dek))

	got, err := u.Unwrap(wrapped, priv, aad)
	require.NoError(t, err)
	require.Equal(t, dek, got)
}

func TestX25519KEM_WrongPrivateKeyFails(t *testing.T) {
	t.Parallel()
	_, pub := newX25519(t)
	otherPriv, _ := newX25519(t)
	wrapped, err := NewX25519KeyWrapper().Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	_, err = NewX25519KeyUnwrapper().Unwrap(wrapped, otherPriv, []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestX25519KEM_TamperFails(t *testing.T) {
	t.Parallel()
	priv, pub := newX25519(t)
	wrapped, err := NewX25519KeyWrapper().Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0x01
	_, err = NewX25519KeyUnwrapper().Unwrap(tampered, priv, []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestX25519KEM_WrongAADFails(t *testing.T) {
	t.Parallel()
	priv, pub := newX25519(t)
	wrapped, err := NewX25519KeyWrapper().Wrap([]byte("dek"), pub, []byte("aad-1"))
	require.NoError(t, err)
	_, err = NewX25519KeyUnwrapper().Unwrap(wrapped, priv, []byte("aad-2"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestX25519KEM_FreshEphemeralPerWrap(t *testing.T) {
	t.Parallel()
	_, pub := newX25519(t)
	w := NewX25519KeyWrapper()
	c1, err := w.Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	c2, err := w.Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	require.NotEqual(t, c1, c2, "each Wrap uses a fresh ephemeral key + nonce")
}

// The challenge must commit to both the key and the nonce, unambiguously:
// changing either, or shifting bytes between them, changes it.
func TestRecipientChallenge_BindsKeyAndNonce(t *testing.T) {
	t.Parallel()
	_, pub := newX25519(t)
	_, other := newX25519(t)
	nonce := []byte("0123456789abcdef")

	c := RecipientChallenge(pub, nonce)
	require.Len(t, c, 64)
	require.Equal(t, c, RecipientChallenge(pub, nonce), "deterministic")
	require.NotEqual(t, c, RecipientChallenge(other, nonce), "a substituted key changes the challenge")
	require.NotEqual(t, c, RecipientChallenge(pub, []byte("0123456789abcdeX")), "a different nonce changes the challenge")
	// Length prefixes: moving a byte from the key into the nonce is a different challenge.
	require.NotEqual(t,
		RecipientChallenge(pub[:31], append([]byte{pub[31]}, nonce...)),
		c)
}

func TestValidateRecipientPublicKey(t *testing.T) {
	t.Parallel()
	_, pub := newX25519(t)
	require.NoError(t, ValidateRecipientPublicKey(pub))

	for name, bad := range map[string][]byte{
		"empty":   nil,
		"short":   pub[:31],
		"long":    append(append([]byte(nil), pub...), 0),
		"zero":    make([]byte, 32), // low-order point
		"order-8": {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
		"one":     append([]byte{1}, make([]byte, 31)...), // order-1 point
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, ValidateRecipientPublicKey(bad))
		})
	}
}

func TestX25519KEM_RejectsBadKeys(t *testing.T) {
	t.Parallel()
	_, err := NewX25519KeyWrapper().Wrap([]byte("dek"), make([]byte, 31), []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	_, pub := newX25519(t)
	wrapped, err := NewX25519KeyWrapper().Wrap([]byte("dek"), pub, []byte("aad"))
	require.NoError(t, err)
	_, err = NewX25519KeyUnwrapper().Unwrap(wrapped, make([]byte, 31), []byte("aad"))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}
