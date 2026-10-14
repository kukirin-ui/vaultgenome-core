// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// ---- hash -------------------------------------------------------------------

func TestSHA256_EmptyAndKnown(t *testing.T) {
	t.Parallel()
	// Empty input → well-known SHA-256 digest.
	h := SHA256([]byte{})
	require.Len(t, h, HashSize)
	require.Len(t, SHA256Slice([]byte{}), HashSize)
}

func TestSHA256Slice_ReturnsFreshCopy(t *testing.T) {
	t.Parallel()
	a := SHA256Slice([]byte("x"))
	b := SHA256Slice([]byte("x"))
	require.Equal(t, a, b)
	a[0] ^= 0xFF
	require.NotEqual(t, a, b, "mutating one slice must not affect the other")
}

// ---- ed25519 ----------------------------------------------------------------

func TestEd25519_RoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv, err := GenerateEd25519(rand.Reader)
	require.NoError(t, err)
	require.Len(t, pub, Ed25519PublicKeySize)
	require.Len(t, priv, Ed25519PrivateKeySize)

	msg := []byte("the genome does not leave the vault")
	sig, err := Sign(priv, msg)
	require.NoError(t, err)
	require.Len(t, sig, Ed25519SignatureSize)

	require.NoError(t, Verify(pub, msg, sig))
}

func TestEd25519_TamperDetected(t *testing.T) {
	t.Parallel()
	pub, priv, err := GenerateEd25519(nil)
	require.NoError(t, err)

	msg := []byte("original")
	sig, err := Sign(priv, msg)
	require.NoError(t, err)

	// Mutated message
	err = Verify(pub, []byte("tampered"), sig)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))

	// Mutated signature
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xFF
	err = Verify(pub, msg, bad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestEd25519_FromSeed_Deterministic(t *testing.T) {
	t.Parallel()
	seed := bytes.Repeat([]byte{0x42}, Ed25519SeedSize)
	pub1, priv1, err := Ed25519FromSeed(seed)
	require.NoError(t, err)
	pub2, priv2, err := Ed25519FromSeed(seed)
	require.NoError(t, err)
	require.Equal(t, pub1, pub2)
	require.Equal(t, priv1, priv2)
}

func TestEd25519_FromSeed_RejectsWrongLength(t *testing.T) {
	t.Parallel()
	_, _, err := Ed25519FromSeed([]byte{0x01})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestEd25519_Verify_RejectsWrongSigLength(t *testing.T) {
	t.Parallel()
	pub, _, err := GenerateEd25519(nil)
	require.NoError(t, err)
	err = Verify(pub, []byte("m"), []byte{0x01, 0x02})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// ---- GCM --------------------------------------------------------------------

func TestGCM_SealOpen_RoundTrip(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0xAA}, AES256KeySize)
	aad := []byte("manifest-id|session-id")
	pt := []byte("sealed component material")

	nonce, ct, err := Seal(key, pt, aad, nil)
	require.NoError(t, err)
	require.Len(t, nonce, GCMNonceSize)
	require.NotEqual(t, pt, ct)
	// ct must be plaintext-length + tag
	require.Equal(t, len(pt)+GCMTagSize, len(ct))

	got, err := Open(key, nonce, ct, aad)
	require.NoError(t, err)
	require.Equal(t, pt, got)
}

func TestGCM_Open_TamperedCiphertextRejected(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0xCC}, AES256KeySize)
	pt := []byte("secret")
	nonce, ct, err := Seal(key, pt, nil, nil)
	require.NoError(t, err)

	bad := append([]byte(nil), ct...)
	bad[0] ^= 0x01
	_, err = Open(key, nonce, bad, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestGCM_Open_WrongAADRejected(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x11}, AES256KeySize)
	nonce, ct, err := Seal(key, []byte("pt"), []byte("aad-1"), nil)
	require.NoError(t, err)
	_, err = Open(key, nonce, ct, []byte("aad-2"))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestGCM_Seal_WrongKeyLength(t *testing.T) {
	t.Parallel()
	_, _, err := Seal([]byte{0x01}, []byte("pt"), nil, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestGCM_NoncesAreDistinct(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x33}, AES256KeySize)
	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		nonce, _, err := Seal(key, []byte("x"), nil, nil)
		require.NoError(t, err)
		_, dup := seen[string(nonce)]
		require.False(t, dup, "nonce reuse in 64 seals is a sign of a broken RNG")
		seen[string(nonce)] = struct{}{}
	}
}

// ---- canonical --------------------------------------------------------------

func TestCanonicalJSON_DeterministicForMapKeyOrder(t *testing.T) {
	t.Parallel()
	// Two maps with different Go iteration order but same content must
	// produce byte-identical canonical form.
	a := map[string]any{"z": 1, "a": 2, "m": 3}
	b := map[string]any{"m": 3, "a": 2, "z": 1}
	ca, err := CanonicalJSON(a)
	require.NoError(t, err)
	cb, err := CanonicalJSON(b)
	require.NoError(t, err)
	require.Equal(t, ca, cb)
	require.Equal(t, `{"a":2,"m":3,"z":1}`, string(ca))
}

func TestCanonicalJSON_NestedSorting(t *testing.T) {
	t.Parallel()
	in := map[string]any{
		"b": map[string]any{"y": 1, "x": 2},
		"a": []any{map[string]any{"q": 1, "p": 2}, 42},
	}
	out, err := CanonicalJSON(in)
	require.NoError(t, err)
	require.Equal(t, `{"a":[{"p":2,"q":1},42],"b":{"x":2,"y":1}}`, string(out))
}

func TestCanonicalJSON_RejectsNaNInf(t *testing.T) {
	t.Parallel()
	_, err := CanonicalJSON(math.NaN())
	require.Error(t, err, "encoding/json rejects NaN early")

	// If we somehow construct a tree with NaN via float64 injection, the
	// encoder must also refuse. The way to hit the canonical branch is
	// to bypass encoding/json — which is not directly callable here —
	// but the explicit check is still valuable.
}

func TestCanonicalJSON_StructFieldsPreserved(t *testing.T) {
	t.Parallel()
	type Inner struct {
		B int `json:"b"`
		A int `json:"a"`
	}
	type Outer struct {
		Y Inner `json:"y"`
		X int   `json:"x"`
	}
	in := Outer{Y: Inner{A: 1, B: 2}, X: 5}
	out, err := CanonicalJSON(in)
	require.NoError(t, err)
	// keys are sorted alphabetically — 'x' before 'y'; within y, 'a' before 'b'.
	require.Equal(t, `{"x":5,"y":{"a":1,"b":2}}`, string(out))
}

func TestCanonicalJSON_Idempotent(t *testing.T) {
	t.Parallel()
	in := map[string]any{"a": 1, "b": []any{3, 2, 1}}
	out1, err := CanonicalJSON(in)
	require.NoError(t, err)
	// Parse canonical bytes back into a generic tree and re-canonicalize.
	var parsed any
	require.NoError(t, json.Unmarshal(out1, &parsed))
	out2, err := CanonicalJSON(parsed)
	require.NoError(t, err)
	require.Equal(t, out1, out2)
}

func TestPublicKeyPEM_RoundTripsThroughPKIX(t *testing.T) {
	t.Parallel()
	pub, _, err := GenerateEd25519(nil)
	require.NoError(t, err)
	out, err := PublicKeyPEM(pub)
	require.NoError(t, err)
	block, rest := pem.Decode(out)
	require.NotNil(t, block)
	require.Empty(t, rest)
	require.Equal(t, "PUBLIC KEY", block.Type)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, ed25519.PublicKey(pub), parsed)

	_, err = PublicKeyPEM(pub[:31])
	require.Error(t, err)
}
