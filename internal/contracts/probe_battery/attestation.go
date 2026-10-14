// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe_battery

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ProbeAttestation is the signed, audit-citable claim:
//
//	"Runner R executed battery B against genome G inside TEE
//	 measurement M between T_start and T_end, and produced
//	 scorecard S."
//
// A disclosure that claims behavioral continuity cites ONE
// ProbeAttestation per link in the succession chain it is vouching
// for. Policy layers that accept a continuity claim evaluate the
// attestation's TEE measurement against the set of enclave identities
// it trusts; this package does not enforce trust — only structure.
type ProbeAttestation struct {
	// SchemaVersion gates the wire format.
	SchemaVersion uint16 `json:"schema_version"`

	// GenomeID is the subject of the attestation — the genome whose
	// scorecard was produced.
	GenomeID ids.GenomeID `json:"genome_id"`

	// BatteryName is the human-readable battery name. MUST equal the
	// referenced battery's Name.
	BatteryName string `json:"battery_name"`

	// BatteryMerkleRoot is the content commitment of the battery.
	// Exactly 32 bytes.
	BatteryMerkleRoot []byte `json:"battery_merkle_root"`

	// ScorecardRoot is the Scorecard.MerkleRoot of the scorecard this
	// attestation vouches for. Exactly 32 bytes.
	ScorecardRoot []byte `json:"scorecard_root"`

	// RunnerIdentity is the stable identity string of the probe
	// runner (subject or fingerprint). Distinct from SigningKeyID:
	// one runner may rotate keys but keep a stable identity.
	RunnerIdentity string `json:"runner_identity"`

	// TEEMeasurement is the enclave measurement, carried whole: 32
	// bytes (SGX MRENCLAVE, SHA-256), 48 (SEV-SNP MEASUREMENT, Nitro
	// PCR0) or 64 (SHA-512). Required — a probe attestation with no
	// TEE measurement has no integrity story.
	TEEMeasurement []byte `json:"tee_measurement"`

	// RunStartedAt and RunCompletedAt bracket the probe run.
	// RunCompletedAt > RunStartedAt. Both required.
	RunStartedAt   time.Time `json:"run_started_at"`
	RunCompletedAt time.Time `json:"run_completed_at"`

	// IssuedAt is wall-clock of attestation issuance (after
	// RunCompletedAt). Required.
	IssuedAt time.Time `json:"issued_at"`

	// SigningKeyID identifies the runner's signing key. Binds under
	// keys.PurposeSigningAuthority.
	SigningKeyID ids.KeyID `json:"signing_key_id"`

	// Signature is the Ed25519 signature over CanonicalBytes (which
	// excludes Signature itself).
	Signature []byte `json:"signature"`
}

// Validate enforces the structural contract.
func (a *ProbeAttestation) Validate() error {
	if a == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: nil receiver",
			nil,
		)
	}
	if a.SchemaVersion < SchemaVersionMin || a.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"probe_attestation: schema_version out of supported range",
			nil,
		)
	}
	if a.GenomeID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: genome_id required",
			nil,
		)
	}
	if a.BatteryName == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: battery_name required",
			nil,
		)
	}
	if len(a.BatteryMerkleRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_attestation: battery_merkle_root must be 32 bytes",
			nil,
		)
	}
	if len(a.ScorecardRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_attestation: scorecard_root must be 32 bytes",
			nil,
		)
	}
	if a.RunnerIdentity == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: runner_identity required",
			nil,
		)
	}
	if n := len(a.TEEMeasurement); n != 32 && n != 48 && n != 64 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_attestation: tee_measurement must be 32, 48 or 64 bytes",
			nil,
		)
	}
	if a.RunStartedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: run_started_at required",
			nil,
		)
	}
	if a.RunCompletedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: run_completed_at required",
			nil,
		)
	}
	if !a.RunCompletedAt.After(a.RunStartedAt) {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"probe_attestation: run_completed_at must be after run_started_at",
			nil,
		)
	}
	if a.IssuedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: issued_at required",
			nil,
		)
	}
	if a.IssuedAt.Before(a.RunCompletedAt) {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"probe_attestation: issued_at must be at or after run_completed_at",
			nil,
		)
	}
	if a.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: signing_key_id required",
			nil,
		)
	}
	if len(a.Signature) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: signature required",
			nil,
		)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature.
func (a *ProbeAttestation) CanonicalBytes() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	cp := *a
	cp.Signature = nil
	out, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_attestation: canonical encode failed",
			err,
		)
	}
	return out, nil
}

// SignWith signs the canonical cover bytes under a.SigningKeyID.
// Does not call Validate — the attestation may still be being
// populated when SignWith is called.
func (a *ProbeAttestation) SignWith(signer keys.Signer) error {
	if a == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: nil receiver",
			nil,
		)
	}
	if a.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: signing_key_id required before sign",
			nil,
		)
	}
	cp := *a
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_attestation: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(a.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	a.Signature = sig
	return nil
}

// VerifySignature resolves a.SigningKeyID and verifies the stored
// signature against canonical cover bytes.
func (a *ProbeAttestation) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_attestation: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := a.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(a.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, a.Signature)
}

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (a *ProbeAttestation) UnmarshalJSON(data []byte) error {
	type alias ProbeAttestation
	tmp := (*alias)(a)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_attestation: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_attestation: trailing content after JSON value",
			nil,
		)
	}
	if a.SchemaVersion < SchemaVersionMin || a.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"probe_attestation: schema_version out of supported range",
			nil,
		)
	}
	return nil
}
