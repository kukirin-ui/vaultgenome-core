// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// GCM constants. The key is 32 bytes (AES-256); the nonce is 12 bytes
// (standard GCM). Both are frozen per docs/doctrine/open-decisions-resolved.md R-10
// and match disclosure_message.GCMNonceSize.
const (
	AES256KeySize = 32
	GCMNonceSize  = 12
	GCMTagSize    = 16
)

// NewGCM constructs an AES-256-GCM AEAD from a 32-byte key.
func NewGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != AES256KeySize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: AES-256 key must be 32 bytes",
			nil,
		)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"crypto: AES cipher construction failed",
			err,
		)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"crypto: GCM mode construction failed",
			err,
		)
	}
	return aead, nil
}

// Seal encrypts plaintext under key with a fresh random nonce, returning
// (nonce, ciphertext||tag). The nonce is generated via crypto/rand; if
// rng is nil, crypto/rand.Reader is used.
//
// Additional data (aad) is authenticated but not encrypted. Callers pass
// the canonical bytes of the binding metadata — for DisclosureMessage,
// that is ManifestID || SessionID || ComponentID.
func Seal(key []byte, plaintext, aad []byte, rng io.Reader) (nonce, ciphertext []byte, err error) {
	aead, err := NewGCM(key)
	if err != nil {
		return nil, nil, err
	}
	if rng == nil {
		rng = rand.Reader
	}
	nonce = make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rng, nonce); err != nil {
		return nil, nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"crypto: nonce read failed",
			err,
		)
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Open decrypts ciphertext under key using nonce and aad. Returns the
// plaintext or an Integrity-classified error on authentication failure.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := NewGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != GCMNonceSize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: GCM nonce must be 12 bytes",
			nil,
		)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// Authentication failure is an integrity event.
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crypto: GCM open failed (authentication)",
			err,
		)
	}
	return plaintext, nil
}
