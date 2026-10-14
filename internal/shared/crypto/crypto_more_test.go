// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

var errEntropyDown = errors.New("entropy source unavailable")

// TestCanonicalJSON_RefusesWhatItCannotEncode proves the two ways the
// top-level encoder refuses input: a value encoding/json cannot
// marshal, and a number literal that survives marshalling but has no
// finite float64 value.
func TestCanonicalJSON_RefusesWhatItCannotEncode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"unmarshalable value", make(chan int), "intermediate marshal failed"},
		{"number literal out of range", json.Number("1e400"), "unparseable number"},
		{"nan", math.NaN(), "intermediate marshal failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := CanonicalJSON(tc.in)
			require.Nil(t, out)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestCanonicalEncode_Scalars pins the encoder's handling of every node
// type the tree can hold, including the float64 and number-literal
// forms the decoder never produces but the encoder must still define.
func TestCanonicalEncode_Scalars(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "null"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"string with escapes", "a\"b\\c\n", `"a\"b\\c\n"`},
		{"integer literal", json.Number("42"), "42"},
		{"negative integer literal", json.Number("-7"), "-7"},
		{"float literal is normalised", json.Number("1.50"), "1.5"},
		{"big integer literal becomes a float", json.Number("123456789012345678901234567890"), "1.2345678901234568e+29"},
		{"float64", float64(0.25), "0.25"},
		{"float64 integral", float64(3), "3"},
		{"array", []any{json.Number("1"), "x", nil}, `[1,"x",null]`},
		{"object sorted", map[string]any{"b": true, "a": []any{}}, `{"a":[],"b":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			require.NoError(t, canonicalEncode(&buf, tc.in))
			require.Equal(t, tc.want, buf.String())
		})
	}
}

// TestCanonicalEncode_Refusals pins every refusal of the tree encoder:
// non-finite numbers in either form, nested inside arrays and objects,
// a number literal that does not parse, and a Go type the tree cannot
// hold.
func TestCanonicalEncode_Refusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nan literal", json.Number("NaN"), "NaN/Inf disallowed"},
		{"inf literal", json.Number("Inf"), "NaN/Inf disallowed"},
		{"literal that is not a number", json.Number("one"), "unparseable number"},
		{"nan float64", math.NaN(), "NaN/Inf disallowed"},
		{"negative inf float64", math.Inf(-1), "NaN/Inf disallowed"},
		{"nan inside an array", []any{json.Number("1"), math.NaN()}, "NaN/Inf disallowed"},
		{"nan inside an object", map[string]any{"ok": true, "bad": math.Inf(1)}, "NaN/Inf disallowed"},
		{"unsupported type", int(1), "unsupported type in tree"},
		{"unsupported type inside an array", []any{uint8(1)}, "unsupported type in tree"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := canonicalEncode(&buf, tc.in)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestEd25519_Refusals pins the key-length guards and the behaviour when
// the entropy source fails during key generation.
func TestEd25519_Refusals(t *testing.T) {
	t.Parallel()
	pub, priv, err := GenerateEd25519(nil)
	require.NoError(t, err)

	t.Run("entropy failure", func(t *testing.T) {
		t.Parallel()
		gp, gk, err := GenerateEd25519(iotest.ErrReader(errEntropyDown))
		require.Nil(t, gp)
		require.Nil(t, gk)
		require.ErrorIs(t, err, errEntropyDown)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), "key generation failed")
	})
	t.Run("sign with a truncated private key", func(t *testing.T) {
		t.Parallel()
		sig, err := Sign(priv[:Ed25519PrivateKeySize-1], []byte("m"))
		require.Nil(t, sig)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), "private key must be 64 bytes")
	})
	t.Run("verify with a truncated public key", func(t *testing.T) {
		t.Parallel()
		sig, err := Sign(priv, []byte("m"))
		require.NoError(t, err)
		err = Verify(pub[:Ed25519PublicKeySize-1], []byte("m"), sig)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), "public key must be 32 bytes")
	})
}

// TestGCM_Refusals pins the guards around the AEAD: the key length on
// both sides, the nonce length on open, and a nonce source that fails.
func TestGCM_Refusals(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x42}, AES256KeySize)

	t.Run("nonce source failure", func(t *testing.T) {
		t.Parallel()
		nonce, ct, err := Seal(key, []byte("pt"), nil, iotest.ErrReader(errEntropyDown))
		require.Nil(t, nonce)
		require.Nil(t, ct)
		require.ErrorIs(t, err, errEntropyDown)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), "nonce read failed")
	})
	t.Run("open with a short key", func(t *testing.T) {
		t.Parallel()
		nonce, ct, err := Seal(key, []byte("pt"), nil, nil)
		require.NoError(t, err)
		pt, err := Open(key[:16], nonce, ct, nil)
		require.Nil(t, pt)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), "key must be 32 bytes")
	})
	t.Run("open with a nonce of the wrong size", func(t *testing.T) {
		t.Parallel()
		nonce, ct, err := Seal(key, []byte("pt"), nil, nil)
		require.NoError(t, err)
		pt, err := Open(key, nonce[:GCMNonceSize-1], ct, nil)
		require.Nil(t, pt)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), "nonce must be 12 bytes")
	})
	t.Run("new gcm with a short key", func(t *testing.T) {
		t.Parallel()
		aead, err := NewGCM(key[:31])
		require.Nil(t, aead)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	})
}
