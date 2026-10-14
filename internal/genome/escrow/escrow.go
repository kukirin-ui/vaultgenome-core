// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package escrow hands a genome's key to the release authority at the
// moment it is sealed, so the machine that sealed it keeps nothing secret.
//
// The authority publishes an X25519 escrow public key. `acpctl genome seal
// --escrow-to` encapsulates the fresh DEK to it (the X25519 KEM of ADR 0009)
// and writes the result beside the bundle; the plaintext key is never
// written. The escrow envelope names the key ID and is bound to it, so it
// can travel with its bundle — to object storage, another cloud — and is
// useless to anyone but the authority. The authority opens it only to
// release the key, by operator policy, to an attested destination
// (`sagvd crosscloud-restore -key-escrow`).
package escrow

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// Schema names the escrow envelope format.
const Schema = "vault-genome/key-escrow/v1"

const aadLabel = "vault-genome key-escrow v1\x00"

// Envelope is a genome key encapsulated to the release authority.
type Envelope struct {
	Schema string `json:"schema"`
	// KeyID is the genome key inside; its tag lets the authority check the
	// key it unwraps is the one named.
	KeyID string `json:"key_id"`
	// EscrowKey is the tag of the escrow public key it was sealed to, so an
	// envelope for another authority is refused before any decryption.
	EscrowKey  string `json:"escrow_key"`
	Ciphertext []byte `json:"ciphertext"`
}

// KeyTag names an escrow public key: the first 16 hex of its SHA-256.
func KeyTag(pub *ecdh.PublicKey) string {
	sum := sha256.Sum256(pub.Bytes())
	return hex.EncodeToString(sum[:8])
}

func aad(keyID string) []byte { return append([]byte(aadLabel), keyID...) }

// Seal encapsulates dek, the key keyID names, to the escrow public key.
func Seal(dek []byte, keyID string, escrowPub *ecdh.PublicKey) (Envelope, error) {
	if err := bundle.CheckKey(keyID, dek); err != nil {
		return Envelope{}, err
	}
	ct, err := kms.X25519KeyWrapper{}.Wrap(dek, escrowPub.Bytes(), aad(keyID))
	if err != nil {
		return Envelope{}, fmt.Errorf("escrow: seal: %w", err)
	}
	return Envelope{Schema: Schema, KeyID: keyID, EscrowKey: KeyTag(escrowPub), Ciphertext: ct}, nil
}

// Open recovers the genome key from env with the escrow private key, and
// checks it is the key the envelope names.
func Open(env Envelope, priv *ecdh.PrivateKey) ([]byte, error) {
	if env.Schema != Schema {
		return nil, fmt.Errorf("escrow: schema %q, want %q", env.Schema, Schema)
	}
	if !bundle.IsKeyID(env.KeyID) {
		return nil, fmt.Errorf("escrow: %q is not a genome key id", env.KeyID)
	}
	if env.EscrowKey != KeyTag(priv.PublicKey()) {
		return nil, fmt.Errorf("escrow: sealed to escrow key %s, this authority holds %s", env.EscrowKey, KeyTag(priv.PublicKey()))
	}
	dek, err := kms.X25519KeyUnwrapper{}.Unwrap(env.Ciphertext, priv.Bytes(), aad(env.KeyID))
	if err != nil {
		return nil, fmt.Errorf("escrow: open %s: %w", env.KeyID, err)
	}
	if err := bundle.CheckKey(env.KeyID, dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// Marshal encodes env.
func (env Envelope) Marshal() ([]byte, error) { return json.MarshalIndent(env, "", "  ") }

// Parse decodes an envelope, refusing unknown fields.
func Parse(b []byte) (Envelope, error) {
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Envelope{}, fmt.Errorf("escrow: %w", err)
	}
	return env, nil
}

// GenerateKey makes an escrow key pair.
func GenerateKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

// ReadPrivate reads an escrow private key — its 32 raw bytes, as `acpctl
// escrow keygen` writes them — refusing a file other users can read.
func ReadPrivate(path string) (*ecdh.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("escrow: %s is open to other users (mode %04o); chmod 600 it", path, perm)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return nil, err
	}
	if len(raw) != kms.RecipientKeySize {
		return nil, fmt.Errorf("escrow: %s holds %d bytes, not a 32-byte X25519 key", path, len(raw))
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// PublicPEM encodes an escrow public key as a PEM SubjectPublicKeyInfo.
func PublicPEM(pub *ecdh.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicPEM decodes an escrow public key and rejects anything but a
// usable X25519 key.
func ParsePublicPEM(b []byte) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("escrow: not a PEM public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("escrow: %w", err)
	}
	pub, ok := key.(*ecdh.PublicKey)
	if !ok || pub.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("escrow: key is %T, want an X25519 public key", key)
	}
	if err := kms.ValidateRecipientPublicKey(pub.Bytes()); err != nil {
		return nil, err
	}
	return pub, nil
}
