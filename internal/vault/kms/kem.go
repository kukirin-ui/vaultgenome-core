// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

// X25519 key-encapsulation (ECIES), the only way a DEK crosses clouds (ADR
// 0009). Each DEK is encapsulated to the destination's X25519 public key with
// an ephemeral X25519 key, HKDF-SHA256 and AES-256-GCM; only the holder of the
// destination private key can unwrap. The destination generates that key
// inside its TEE for one handshake and never writes it anywhere, and proves the
// binding in the Evidence itself: it quotes over RecipientChallenge(pub,
// nonce), so a measurement (a public value) is never enough to unwrap and a
// key substituted in transit fails attestation.
//
// Wrapped layout: ephPub(32) || nonce(12) || ciphertext-with-tag.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

const kemInfoLabel = "vault-genome-xcc-kem-v1"

// kemBindLabel domain-separates the key-binding challenge from every other
// value the system asks a TEE to quote over. The Return Path's challenges are
// 32-byte SHA-256 transcripts under their own labels; this one is a 64-byte
// SHA-512, so no quote obtained through one protocol can satisfy the other.
const kemBindLabel = "vault-genome xcc-kem-bind v1"

// RecipientKeySize is the length of an X25519 public or private key.
const RecipientKeySize = 32

// RecipientChallenge is the attestation challenge a destination TEE quotes over
// when it presents recipientPub in answer to a handshake carrying nonce:
//
//	SHA-512(label ‖ len32(recipientPub) ‖ recipientPub ‖ len32(nonce) ‖ nonce)
//
// Quoting over this value instead of the bare nonce makes every tee.Verifier's
// freshness check double as the key binding, whatever the TEE family: Evidence
// that verifies under the challenge proves a genuine TEE with the attested
// measurement committed to recipientPub for this nonce. A key swapped in
// transit changes the challenge, and the Evidence no longer verifies.
func RecipientChallenge(recipientPub, nonce []byte) []byte {
	h := sha512.New()
	h.Write([]byte(kemBindLabel))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(recipientPub)))
	h.Write(n[:])
	h.Write(recipientPub)
	binary.BigEndian.PutUint32(n[:], uint32(len(nonce)))
	h.Write(n[:])
	h.Write(nonce)
	return h.Sum(nil)
}

// ValidateRecipientPublicKey accepts pub only if it is a usable X25519 public
// key: exactly 32 bytes and not a low-order point (which would give every
// encapsulation an all-zero shared secret).
func ValidateRecipientPublicKey(pub []byte) error {
	if len(pub) != RecipientKeySize {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			"kms: recipient public key must be a 32-byte X25519 key", nil)
	}
	curve := ecdh.X25519()
	key, err := curve.NewPublicKey(pub)
	if err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: invalid X25519 recipient public key", err)
	}
	probe, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return shared_errors.Operational(shared_errors.CodeResourceExhausted, "kms: probe key generation failed", err)
	}
	if _, err := probe.ECDH(key); err != nil {
		return shared_errors.Integrity(shared_errors.CodeFieldValueInvalid, "kms: recipient public key is a low-order point", err)
	}
	return nil
}

// X25519KeyWrapper encapsulates a DEK to a recipient X25519 public key.
type X25519KeyWrapper struct{}

// NewX25519KeyWrapper returns a stateless wrapper.
func NewX25519KeyWrapper() *X25519KeyWrapper { return &X25519KeyWrapper{} }

// Wrap encapsulates plaintext to recipientPub (a 32-byte X25519 public key).
// aad is bound into the AES-GCM tag.
func (X25519KeyWrapper) Wrap(plaintext, recipientPub, aad []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.Wrap: plaintext required", nil)
	}
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms.Wrap: invalid recipient X25519 public key", err)
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "kms.Wrap: ephemeral key generation failed", err)
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid, "kms.Wrap: ECDH failed", err)
	}
	key, err := deriveKEMKey(shared, eph.PublicKey().Bytes(), recipientPub)
	if err != nil {
		return nil, err
	}
	ct, err := aeadSeal(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(eph.PublicKey().Bytes())+len(ct))
	out = append(out, eph.PublicKey().Bytes()...)
	out = append(out, ct...)
	return out, nil
}

// X25519KeyUnwrapper is the destination-side counterpart.
type X25519KeyUnwrapper struct{}

// NewX25519KeyUnwrapper returns a stateless unwrapper.
func NewX25519KeyUnwrapper() *X25519KeyUnwrapper { return &X25519KeyUnwrapper{} }

// Unwrap recovers plaintext using recipientPriv (a 32-byte X25519 private key),
// which exists only inside the destination TEE, for one handshake.
func (X25519KeyUnwrapper) Unwrap(wrapped, recipientPriv, aad []byte) ([]byte, error) {
	if len(wrapped) < 32 {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms.Unwrap: wrapped material too short", nil)
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms.Unwrap: invalid recipient X25519 private key", err)
	}
	ephBytes := wrapped[:32]
	ephPub, err := curve.NewPublicKey(ephBytes)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms.Unwrap: invalid ephemeral public key", err)
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms.Unwrap: ECDH failed", err)
	}
	key, err := deriveKEMKey(shared, ephBytes, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return aeadOpen(key, wrapped[32:], aad)
}

func deriveKEMKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	info := make([]byte, 0, len(kemInfoLabel)+len(ephPub)+len(recipientPub))
	info = append(info, []byte(kemInfoLabel)...)
	info = append(info, ephPub...)
	info = append(info, recipientPub...)
	k, err := crypto.HKDFSHA256(nil, shared, info, 32)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: HKDF derivation failed", err)
	}
	return k, nil
}

func aeadSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: aes init failed", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: gcm init failed", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "kms: nonce generation failed", err)
	}
	return append(nonce, gcm.Seal(nil, nonce, plaintext, aad)...), nil
}

func aeadOpen(key, blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: aes init failed", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms: gcm init failed", err)
	}
	if len(blob) < gcm.NonceSize() {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms: ciphertext too short", nil)
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], aad)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "kms: tag verification failed (wrong key, AAD, or tampering)", err)
	}
	return plain, nil
}
