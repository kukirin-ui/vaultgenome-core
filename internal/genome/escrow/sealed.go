// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// SealedSchema names the file `sagvd escrow-provision` writes: the
// authority's escrow private key sealed to the release host's TEE. The
// key exists in the clear only inside the process that generated it and
// the process that unseals it; on disk it opens only for the same code,
// on the same chip, at the same measurement (ADR 0016).
const SealedSchema = "vault-genome/sealed-escrow-key/v1"

const sealedAADLabel = "vault-genome sealed-escrow-key v1\x00"

// SealedKey is the escrow private key, sealed. Everything but Sealed is
// public and bound into the seal's AAD, so a field changed on disk fails
// to open rather than opening as something else.
type SealedKey struct {
	Schema string `json:"schema"`
	// TEE names the sealer: gcp-sev-snp (the chip's derived key) or
	// simulated (a key from the simulated measurement; development only).
	TEE string `json:"tee"`
	// MeasurementHex is the launch measurement the key was sealed at.
	MeasurementHex string `json:"measurement_hex"`
	// EscrowKey is the tag of the public key inside (KeyTag).
	EscrowKey string `json:"escrow_key"`
	// PublicKeyPEM is the escrow public key, readable without unsealing:
	// what `sagvd identity` prints and sealers pin.
	PublicKeyPEM string `json:"public_key_pem"`
	Sealed       []byte `json:"sealed"`
}

func sealedAAD(provider tee.Provider, measurement tee.Measurement, tag string) []byte {
	aad := []byte(sealedAADLabel)
	aad = append(aad, provider...)
	aad = append(aad, 0)
	aad = append(aad, hex.EncodeToString(measurement)...)
	aad = append(aad, 0)
	return append(aad, tag...)
}

// SealKey seals priv to the TEE behind sealer, recording the provider and
// measurement it was sealed at.
func SealKey(priv *ecdh.PrivateKey, sealer tee.Sealer, provider tee.Provider, measurement tee.Measurement) (SealedKey, error) {
	if priv == nil || sealer == nil || provider == "" || measurement.IsZero() {
		return SealedKey{}, errors.New("escrow: key, sealer, provider and measurement required")
	}
	if priv.Curve() != ecdh.X25519() {
		return SealedKey{}, errors.New("escrow: not an X25519 key")
	}
	pemBytes, err := PublicPEM(priv.PublicKey())
	if err != nil {
		return SealedKey{}, err
	}
	tag := KeyTag(priv.PublicKey())
	sealed, err := sealer.Seal(priv.Bytes(), sealedAAD(provider, measurement, tag))
	if err != nil {
		return SealedKey{}, fmt.Errorf("escrow: seal to %s: %w", provider, err)
	}
	return SealedKey{
		Schema:         SealedSchema,
		TEE:            string(provider),
		MeasurementHex: hex.EncodeToString(measurement),
		EscrowKey:      tag,
		PublicKeyPEM:   string(pemBytes),
		Sealed:         sealed,
	}, nil
}

// PublicKey returns the escrow public key the file carries in the clear,
// checked against its tag.
func (s SealedKey) PublicKey() (*ecdh.PublicKey, error) {
	if s.Schema != SealedSchema {
		return nil, fmt.Errorf("escrow: schema %q, want %q", s.Schema, SealedSchema)
	}
	pub, err := ParsePublicPEM([]byte(s.PublicKeyPEM))
	if err != nil {
		return nil, err
	}
	if KeyTag(pub) != s.EscrowKey {
		return nil, fmt.Errorf("escrow: the sealed file's public key is %s, its tag says %s", KeyTag(pub), s.EscrowKey)
	}
	return pub, nil
}

// Open unseals the private key on the TEE behind sealer. The live
// provider and measurement must be the ones the key was sealed at — said
// plainly before the AEAD is asked — and the key that comes out must be
// the public key's private half.
func (s SealedKey) Open(sealer tee.Sealer, provider tee.Provider, measurement tee.Measurement) (*ecdh.PrivateKey, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}
	if sealer == nil {
		return nil, errors.New("escrow: no TEE sealer to open the sealed escrow key with")
	}
	if s.TEE != string(provider) {
		return nil, fmt.Errorf("escrow: the escrow key was sealed to %s; this host's TEE is %s", s.TEE, provider)
	}
	if s.MeasurementHex != hex.EncodeToString(measurement) {
		return nil, fmt.Errorf("escrow: the escrow key was sealed at measurement %s; this host runs at %s (another image, or another build: re-provision it from its recovery envelope)", short(s.MeasurementHex), short(hex.EncodeToString(measurement)))
	}
	raw, err := sealer.Unseal(s.Sealed, sealedAAD(provider, measurement, s.EscrowKey))
	if err != nil {
		return nil, fmt.Errorf("escrow: unseal on %s: %w (another chip, or a changed file: re-provision it from its recovery envelope)", provider, err)
	}
	defer clear(raw)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("escrow: unsealed bytes are not an X25519 key: %w", err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), pub.Bytes()) {
		return nil, errors.New("escrow: the unsealed key is not the private half of the public key the file carries")
	}
	return priv, nil
}

func short(hexDigest string) string {
	if len(hexDigest) > 12 {
		return hexDigest[:12] + "…"
	}
	return hexDigest
}

// Marshal encodes s.
func (s SealedKey) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// ParseSealed decodes a sealed escrow key file, refusing unknown fields.
func ParseSealed(raw []byte) (SealedKey, error) {
	var s SealedKey
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return SealedKey{}, fmt.Errorf("escrow: sealed key: %w", err)
	}
	if s.Schema != SealedSchema {
		return SealedKey{}, fmt.Errorf("escrow: sealed key schema %q, want %q", s.Schema, SealedSchema)
	}
	if s.TEE == "" || s.MeasurementHex == "" || s.EscrowKey == "" || s.PublicKeyPEM == "" || len(s.Sealed) == 0 {
		return SealedKey{}, errors.New("escrow: sealed key file is incomplete")
	}
	return s, nil
}

// IsSealed reports whether raw is a sealed escrow key file rather than a
// raw 32-byte key: anything but exactly 32 bytes that reads as a JSON
// object. (A raw key may well begin with '{'; its length decides.)
func IsSealed(raw []byte) bool {
	if len(raw) == kms.RecipientKeySize {
		return false
	}
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}
