// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// A sealed secret: a daemon's key file — a signing seed, a session sealing
// key — held on disk only sealed to the host's TEE, and opened at start.
// The file names what it is (the config field), the TEE it was sealed to
// and the measurement it was sealed at, and those three are bound into the
// AEAD's associated data: a file sealed as one key cannot be handed to the
// daemon as another, and one sealed on another host does not open here.
// The sealer is the host's (ADR 0016 on SEV-SNP, ADR 0022 on a vTPM); the
// simulated TEE's sealer is weak by design and says so.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// SealedSecretSchema names the file's shape.
const SealedSecretSchema = "vault-genome/sealed-secret/v1"

const sealedSecretAADLabel = "vault-genome sealed-secret v1\x00"

// SealedSecret is the on-disk form of a sealed key file.
type SealedSecret struct {
	Schema         string `json:"schema"`
	TEE            string `json:"tee"`
	MeasurementHex string `json:"measurement_hex"`
	// Name is what the secret is — the config field it is read as.
	Name   string `json:"name"`
	Sealed []byte `json:"sealed"`
}

func sealedSecretAAD(provider Provider, measurementHex, name string) []byte {
	aad := []byte(sealedSecretAADLabel)
	aad = append(aad, provider...)
	aad = append(aad, 0)
	aad = append(aad, measurementHex...)
	aad = append(aad, 0)
	return append(aad, name...)
}

// SealSecret seals plain as the secret called name to the host the sealer
// belongs to, and returns the file to write.
func SealSecret(plain []byte, sealer Sealer, provider Provider, measurement Measurement, name string) ([]byte, error) {
	if len(plain) == 0 || sealer == nil || provider == "" || measurement.IsZero() || name == "" {
		return nil, errors.New("sealed secret: plaintext, sealer, provider, measurement and name required")
	}
	mh := hex.EncodeToString(measurement)
	sealed, err := sealer.Seal(plain, sealedSecretAAD(provider, mh, name))
	if err != nil {
		return nil, fmt.Errorf("sealed secret %q: seal to %s: %w", name, provider, err)
	}
	raw, err := json.MarshalIndent(SealedSecret{Schema: SealedSecretSchema, TEE: string(provider), MeasurementHex: mh, Name: name, Sealed: sealed}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// ParseSealedSecret parses a sealed key file.
func ParseSealedSecret(raw []byte) (SealedSecret, error) {
	var s SealedSecret
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return SealedSecret{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sealed secret: not a sealed key file", err)
	}
	if s.Schema != SealedSecretSchema {
		return SealedSecret{}, shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, fmt.Sprintf("sealed secret: schema %q, want %q", s.Schema, SealedSecretSchema), nil)
	}
	if s.TEE == "" || s.MeasurementHex == "" || s.Name == "" || len(s.Sealed) == 0 {
		return SealedSecret{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "sealed secret: the file is incomplete", nil)
	}
	return s, nil
}

// OpenSecret opens a sealed key file as the secret called name on a host of
// the given provider, with the host's sealer. The measurement it was sealed
// at is the file's own word, bound into the AEAD: the sealer (the chip's
// derived key, or the vTPM's policy) is what refuses another host.
func OpenSecret(raw []byte, sealer Sealer, provider Provider, name string) ([]byte, error) {
	s, err := ParseSealedSecret(raw)
	if err != nil {
		return nil, err
	}
	if s.Name != name {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("sealed secret: the file is %q, read as %q", s.Name, name), nil)
	}
	if s.TEE != string(provider) {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("sealed secret %q: sealed to %s, this host is %s", name, s.TEE, provider), nil)
	}
	if sealer == nil {
		return nil, errors.New("sealed secret: no sealer on this host")
	}
	plain, err := sealer.Unseal(s.Sealed, sealedSecretAAD(provider, s.MeasurementHex, s.Name))
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("sealed secret %q: this host does not open it (sealed at %s on %s): %v", name, s.MeasurementHex[:min(16, len(s.MeasurementHex))]+"…", s.TEE, err), err)
	}
	return plain, nil
}

// IsSealedSecret reports whether raw is a sealed key file rather than the
// bare bytes of a key.
func IsSealedSecret(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{' && bytes.Contains(trimmed, []byte(SealedSecretSchema))
}
