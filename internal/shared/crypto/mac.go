// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// HMACSize is the HMAC-SHA-256 tag length in bytes.
const HMACSize = sha256.Size

// HMACSHA256 computes HMAC-SHA-256(key, msg). Returns a freshly-allocated
// slice of length HMACSize. Thin wrapper over crypto/hmac so every MAC
// path in the codebase goes through the same primitive.
//
// The key length is NOT policed here: HMAC is defined for arbitrary key
// lengths (shorter keys are zero-padded, longer keys are hashed down).
// Callers that require a specific key length (e.g. 32 bytes for the
// Return Path session MAC key) MUST validate length at their own layer.
func HMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// HMACSHA256Verify returns nil if tag equals HMAC-SHA-256(key, msg),
// using a constant-time comparison. On mismatch returns an Integrity-
// classified error (so callers' audit routing treats it as a
// tamper-adjacent event).
//
// tag MUST be exactly HMACSize bytes. A length mismatch is itself an
// integrity failure — a truncated tag on the wire is indistinguishable
// from an adversarial shortening and is handled identically.
func HMACSHA256Verify(key, msg, tag []byte) error {
	if len(tag) != HMACSize {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crypto: HMAC-SHA-256 tag length wrong",
			nil,
		)
	}
	expected := HMACSHA256(key, msg)
	if !hmac.Equal(expected, tag) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crypto: HMAC-SHA-256 verification failed",
			nil,
		)
	}
	return nil
}

// HKDFSHA256 implements the RFC 5869 Extract-then-Expand key-derivation
// function over SHA-256. It is a literal transcription of the RFC — no
// hand-rolled crypto, only the stdlib HMAC primitive chained per the
// spec.
//
// Parameters
//
//   - salt: optional; pass nil for the default all-zero salt of HashSize
//     bytes. Typical use in this codebase is a domain-separation label.
//   - ikm:  input keying material. For a session-key derivation after a
//     simulated TEE handshake, this is the concatenation of both peers'
//     nonces; in a real-hardware Phase-3 swap it would be the shared
//     secret output by the attestation protocol.
//   - info: per-context label; MUST uniquely identify (protocol,
//     version, key-purpose). The Return Path wire derivation uses
//     "rp-wire-v1.0 session-mac" plus the per-handshake
//     DerivationContext.
//   - length: number of bytes to output. RFC 5869 caps this at
//     255*HashSize (= 8160 for SHA-256); we enforce that limit.
//
// Returns the derived bytes, or a Structural error if length is out of
// range. The function never returns an Integrity error — every step is
// a stdlib call over well-formed inputs.
func HKDFSHA256(salt, ikm, info []byte, length int) ([]byte, error) {
	if length < 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: HKDF output length must be non-negative",
			nil,
		)
	}
	if length > 255*HashSize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: HKDF output length exceeds 255*HashSize (RFC 5869)",
			nil,
		)
	}
	if length == 0 {
		return []byte{}, nil
	}

	// Extract step: PRK = HMAC(salt, IKM). Per §2.2 an empty salt is
	// treated as HashSize zero bytes.
	if len(salt) == 0 {
		salt = make([]byte, HashSize)
	}
	prk := HMACSHA256(salt, ikm)

	// Expand step: T(i) = HMAC(PRK, T(i-1) || info || byte(i)).
	// OKM = first `length` bytes of (T(1) || T(2) || ...).
	var (
		okm  = make([]byte, 0, length)
		prev []byte
		n    = (length + HashSize - 1) / HashSize
		h    hash.Hash
	)
	for i := 1; i <= n; i++ {
		h = hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length], nil
}
