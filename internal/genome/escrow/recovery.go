// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// RecoverySchema names the recovery envelope: the escrow private key
// encapsulated to the operator's recovery public key, so a sealed escrow
// key survives the chip it was sealed to. The operator's recovery private
// key lives off the release host; opening the envelope is a ceremony, and
// the key is resealed on the new host without touching its disk in the
// clear (ADR 0016).
const RecoverySchema = "vault-genome/escrow-recovery/v1"

const recoveryAADLabel = "vault-genome escrow-recovery v1\x00"

// Recovery is an escrow private key wrapped to a recovery public key.
type Recovery struct {
	Schema string `json:"schema"`
	// EscrowKey is the tag of the escrow key inside.
	EscrowKey string `json:"escrow_key"`
	// RecoveryKey is the tag of the recovery public key it is wrapped to.
	RecoveryKey string `json:"recovery_key"`
	// PublicKeyPEM is the escrow public key, so the envelope says what it
	// holds without being opened.
	PublicKeyPEM string `json:"public_key_pem"`
	Ciphertext   []byte `json:"ciphertext"`
}

func recoveryAAD(escrowTag, recoveryTag string) []byte {
	return []byte(recoveryAADLabel + escrowTag + "\x00" + recoveryTag)
}

// WrapRecovery encapsulates priv to recoveryPub.
func WrapRecovery(priv *ecdh.PrivateKey, recoveryPub *ecdh.PublicKey) (Recovery, error) {
	if priv == nil || recoveryPub == nil {
		return Recovery{}, errors.New("escrow: escrow key and recovery public key required")
	}
	if err := kms.ValidateRecipientPublicKey(recoveryPub.Bytes()); err != nil {
		return Recovery{}, err
	}
	pemBytes, err := PublicPEM(priv.PublicKey())
	if err != nil {
		return Recovery{}, err
	}
	escrowTag, recoveryTag := KeyTag(priv.PublicKey()), KeyTag(recoveryPub)
	ct, err := kms.X25519KeyWrapper{}.Wrap(priv.Bytes(), recoveryPub.Bytes(), recoveryAAD(escrowTag, recoveryTag))
	if err != nil {
		return Recovery{}, fmt.Errorf("escrow: wrap for recovery: %w", err)
	}
	return Recovery{Schema: RecoverySchema, EscrowKey: escrowTag, RecoveryKey: recoveryTag, PublicKeyPEM: string(pemBytes), Ciphertext: ct}, nil
}

// Open recovers the escrow private key with the operator's recovery
// private key, and checks it is the key the envelope names.
func (r Recovery) Open(recoveryPriv *ecdh.PrivateKey) (*ecdh.PrivateKey, error) {
	if r.Schema != RecoverySchema {
		return nil, fmt.Errorf("escrow: recovery schema %q, want %q", r.Schema, RecoverySchema)
	}
	if recoveryPriv == nil {
		return nil, errors.New("escrow: recovery private key required")
	}
	if tag := KeyTag(recoveryPriv.PublicKey()); tag != r.RecoveryKey {
		return nil, fmt.Errorf("escrow: the envelope is wrapped to recovery key %s; this key is %s", r.RecoveryKey, tag)
	}
	pub, err := ParsePublicPEM([]byte(r.PublicKeyPEM))
	if err != nil {
		return nil, err
	}
	if KeyTag(pub) != r.EscrowKey {
		return nil, fmt.Errorf("escrow: the envelope's public key is %s, its tag says %s", KeyTag(pub), r.EscrowKey)
	}
	raw, err := kms.X25519KeyUnwrapper{}.Unwrap(r.Ciphertext, recoveryPriv.Bytes(), recoveryAAD(r.EscrowKey, r.RecoveryKey))
	if err != nil {
		return nil, fmt.Errorf("escrow: open recovery envelope: %w", err)
	}
	defer clear(raw)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("escrow: recovered bytes are not an X25519 key: %w", err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), pub.Bytes()) {
		return nil, errors.New("escrow: the recovered key is not the private half of the public key the envelope names")
	}
	return priv, nil
}

// Marshal encodes r.
func (r Recovery) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// ParseRecovery decodes a recovery envelope, refusing unknown fields.
func ParseRecovery(raw []byte) (Recovery, error) {
	var r Recovery
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Recovery{}, fmt.Errorf("escrow: recovery envelope: %w", err)
	}
	if r.Schema != RecoverySchema {
		return Recovery{}, fmt.Errorf("escrow: recovery envelope schema %q, want %q", r.Schema, RecoverySchema)
	}
	if r.EscrowKey == "" || r.RecoveryKey == "" || r.PublicKeyPEM == "" || len(r.Ciphertext) == 0 {
		return Recovery{}, errors.New("escrow: recovery envelope is incomplete")
	}
	return r, nil
}
