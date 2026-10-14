// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/sha256"
)

// HashSize is the length in bytes of a SHA-256 digest. Re-exported here so
// callers can declare fixed-size buffers without importing crypto/sha256
// directly.
const HashSize = sha256.Size

// SHA256 returns the SHA-256 digest of data.
//
// This is a thin wrapper around crypto/sha256.Sum256 that centralizes the
// choice of hash function. Every hash in this project MUST go through one
// of the helpers in this package so that a future algorithm change is a
// one-line refactor, not a grep-through-the-whole-tree exercise.
func SHA256(data []byte) [HashSize]byte {
	return sha256.Sum256(data)
}

// SHA256Slice is identical to SHA256 but returns a freshly-allocated slice
// instead of an array. Use this when the result flows into a contract
// field typed as []byte (e.g., AuditEvent.Hash).
func SHA256Slice(data []byte) []byte {
	sum := sha256.Sum256(data)
	out := make([]byte, HashSize)
	copy(out, sum[:])
	return out
}
