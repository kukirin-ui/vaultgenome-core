// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// ---- HMAC-SHA-256 -----------------------------------------------------------

func TestHMACSHA256_DeterministicAndSized(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x33}, 32)
	msg := []byte("MAC-this-message-exactly")

	tag1 := HMACSHA256(key, msg)
	tag2 := HMACSHA256(key, msg)

	require.Equal(t, HMACSize, len(tag1))
	require.Equal(t, tag1, tag2, "HMAC must be deterministic on identical input")
}

func TestHMACSHA256_Verify_HappyAndTamper(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x77}, 32)
	msg := []byte("payload payload payload")
	tag := HMACSHA256(key, msg)

	require.NoError(t, HMACSHA256Verify(key, msg, tag))

	// Flipping any bit in the tag must fail Verify with Integrity.
	bad := append([]byte{}, tag...)
	bad[0] ^= 0x01
	err := HMACSHA256Verify(key, msg, bad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	// Flipping any bit in the message must fail Verify with Integrity.
	badMsg := append([]byte{}, msg...)
	badMsg[len(badMsg)-1] ^= 0x01
	err = HMACSHA256Verify(key, badMsg, tag)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestHMACSHA256_Verify_WrongTagLength(t *testing.T) {
	t.Parallel()
	key := []byte("key-only-for-test")
	msg := []byte("hello")
	tag := HMACSHA256(key, msg)

	// Truncated tag: MUST be Integrity, not Structural, because a
	// truncated tag on the wire is indistinguishable from an attacker
	// shortening the frame.
	err := HMACSHA256Verify(key, msg, tag[:HMACSize-1])
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// ---- HKDF-SHA-256 -----------------------------------------------------------

func TestHKDFSHA256_DeterministicSameInputs(t *testing.T) {
	t.Parallel()
	salt := []byte("salt-label-v1")
	ikm := bytes.Repeat([]byte{0x55}, 64)
	info := []byte("session-mac-key-info")

	out1, err := HKDFSHA256(salt, ikm, info, 64)
	require.NoError(t, err)
	out2, err := HKDFSHA256(salt, ikm, info, 64)
	require.NoError(t, err)
	require.Equal(t, out1, out2)
	require.Len(t, out1, 64)
}

func TestHKDFSHA256_DifferentInfoYieldsDifferentKey(t *testing.T) {
	t.Parallel()
	salt := []byte("salt")
	ikm := []byte("ikm-bytes-that-are-long-enough")
	a, err := HKDFSHA256(salt, ikm, []byte("info-A"), 32)
	require.NoError(t, err)
	b, err := HKDFSHA256(salt, ikm, []byte("info-B"), 32)
	require.NoError(t, err)
	require.NotEqual(t, a, b, "HKDF info domain separation must yield distinct keys")
}

func TestHKDFSHA256_DifferentIKMYieldsDifferentKey(t *testing.T) {
	t.Parallel()
	salt := []byte("salt")
	info := []byte("info-fixed")
	a, err := HKDFSHA256(salt, []byte("ikm-A"), info, 32)
	require.NoError(t, err)
	b, err := HKDFSHA256(salt, []byte("ikm-B"), info, 32)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestHKDFSHA256_NilSaltEqualsZeroSalt(t *testing.T) {
	t.Parallel()
	ikm := []byte("ikm")
	info := []byte("info")
	a, err := HKDFSHA256(nil, ikm, info, 32)
	require.NoError(t, err)
	b, err := HKDFSHA256(make([]byte, HashSize), ikm, info, 32)
	require.NoError(t, err)
	// Per RFC 5869 §2.2, an empty salt is defined as HashSize zero bytes.
	require.Equal(t, a, b)
}

func TestHKDFSHA256_LengthBounds(t *testing.T) {
	t.Parallel()
	_, err := HKDFSHA256(nil, []byte("ikm"), []byte("info"), -1)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = HKDFSHA256(nil, []byte("ikm"), []byte("info"), 255*HashSize+1)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// Zero-length output is legal and returns an empty slice.
	out, err := HKDFSHA256(nil, []byte("ikm"), []byte("info"), 0)
	require.NoError(t, err)
	require.Empty(t, out)
}

// TestHKDFSHA256_RFC5869_TestVector1 verifies HKDFSHA256 against the
// official RFC 5869 Appendix A.1 test vector (Basic SHA-256). A drift
// in the underlying HMAC chain or byte ordering would break this test.
func TestHKDFSHA256_RFC5869_TestVector1(t *testing.T) {
	t.Parallel()
	// A.1. Test Case 1 — Basic test case with SHA-256.
	ikm := decodeHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := decodeHex(t, "000102030405060708090a0b0c")
	info := decodeHex(t, "f0f1f2f3f4f5f6f7f8f9")
	expectedOKM := decodeHex(t,
		"3cb25f25faacd57a90434f64d0362f2a"+
			"2d2d0a90cf1a5a4c5db02d56ecc4c5bf"+
			"34007208d5b887185865")

	out, err := HKDFSHA256(salt, ikm, info, 42)
	require.NoError(t, err)
	require.Equal(t, expectedOKM, out)
}

// decodeHex is a small helper that parses a hex string into bytes and
// fails the test on malformed input. Avoids importing encoding/hex in
// multiple tests.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			default:
				t.Fatalf("decodeHex: bad char %q at index %d", c, i+j)
			}
		}
		out = append(out, b)
	}
	return out
}
