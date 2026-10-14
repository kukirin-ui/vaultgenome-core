// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Ed25519 constants re-exported for callers that don't want to import
// crypto/ed25519 directly.
const (
	Ed25519PublicKeySize  = ed25519.PublicKeySize
	Ed25519PrivateKeySize = ed25519.PrivateKeySize
	Ed25519SignatureSize  = ed25519.SignatureSize
	Ed25519SeedSize       = ed25519.SeedSize
)

// PublicKey is an Ed25519 verification key. Byte form is the 32-byte
// canonical public-key encoding.
type PublicKey = ed25519.PublicKey

// PrivateKey is an Ed25519 signing key. Byte form is the 64-byte encoding
// (32-byte seed || 32-byte public). Do not log or persist unsealed.
type PrivateKey = ed25519.PrivateKey

// PublicKeyPEM encodes pub as a PEM "PUBLIC KEY" block (PKIX
// SubjectPublicKeyInfo) — the form operators exchange between hosts and
// the daemons' key loaders accept alongside the raw 32 bytes.
func PublicKeyPEM(pub PublicKey) ([]byte, error) {
	if len(pub) != Ed25519PublicKeySize {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: Ed25519 public key must be 32 bytes", nil)
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crypto: marshal public key", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// GenerateEd25519 produces a new Ed25519 key pair. If rng is nil,
// crypto/rand.Reader is used.
func GenerateEd25519(rng io.Reader) (PublicKey, PrivateKey, error) {
	if rng == nil {
		rng = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"crypto: ed25519 key generation failed",
			err,
		)
	}
	return pub, priv, nil
}

// Ed25519FromSeed derives a deterministic key pair from a 32-byte seed.
// Used only in tests and in TEE simulation where determinism is required.
// Callers MUST NOT use this with a non-random seed in production.
func Ed25519FromSeed(seed []byte) (PublicKey, PrivateKey, error) {
	if len(seed) != Ed25519SeedSize {
		return nil, nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: ed25519 seed must be 32 bytes",
			nil,
		)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

// Sign produces an Ed25519 signature over msg. Return value is exactly
// Ed25519SignatureSize bytes.
func Sign(priv PrivateKey, msg []byte) ([]byte, error) {
	if len(priv) != Ed25519PrivateKeySize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: ed25519 private key must be 64 bytes",
			nil,
		)
	}
	sig := ed25519.Sign(priv, msg)
	return sig, nil
}

// Verify returns nil if sig is a valid Ed25519 signature of msg under pub.
// Returns an Integrity-classified error on failure so the caller's audit
// emission routes correctly to INCIDENT_DETECTED.
func Verify(pub PublicKey, msg, sig []byte) error {
	if len(pub) != Ed25519PublicKeySize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: ed25519 public key must be 32 bytes",
			nil,
		)
	}
	if len(sig) != Ed25519SignatureSize {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crypto: ed25519 signature length wrong",
			nil,
		)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crypto: ed25519 signature verification failed",
			nil,
		)
	}
	return nil
}
