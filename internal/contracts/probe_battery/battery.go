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

const (
	// SchemaVersionMin is the lowest battery-format version this build
	// will accept on read.
	SchemaVersionMin uint16 = 1
	// SchemaVersionMax is the highest battery-format version this build
	// will accept on read.
	SchemaVersionMax uint16 = 1
	// SchemaVersionCurrent is the version this build writes.
	SchemaVersionCurrent uint16 = 1
)

// ProbeBattery is a content-addressable, signed set of probes.
//
// The battery's MerkleRoot is derived over the probes sorted by
// content-addressed ProbeID. Two batteries that share exactly the
// same probe set (and TolerancePolicy) have byte-identical Merkle
// roots — regardless of probe insertion order, file origin, or
// publisher.
type ProbeBattery struct {
	// SchemaVersion gates the wire format. Readers MUST validate first.
	SchemaVersion uint16 `json:"schema_version"`

	// Name is the human-readable battery identifier, matching the
	// BatteryID field in a GenomeDescriptor's ProbeBatteryRoot.
	// Non-empty. Convention: "<family>-<purpose>-v<major>", e.g.
	// "continuity-llm-reasoning-v3".
	Name string `json:"name"`

	// MerkleRoot is DERIVED over the probes' leaf hashes. It equals
	// the GenomeDescriptor's BehavioralFingerprint.BatteryMerkleRoot
	// iff the AGD was issued against this battery.
	//
	// Validate recomputes MerkleRoot and rejects on mismatch — this
	// battery's content-address gate.
	MerkleRoot []byte `json:"merkle_root"`

	// Probes is the full ordered (by ID) list. Empty batteries are
	// rejected — a battery with no probes commits to nothing.
	Probes []Probe `json:"probes"`

	// Policy is the declared per-method tolerance algebra. Bound by
	// the signature: the battery publisher commits to the semantics
	// under which its probes are meant to be compared. Downstream
	// policy layers may tighten, never loosen, these bounds.
	Policy TolerancePolicy `json:"policy"`

	// IssuedAt is wall-clock of battery issuance. Required.
	IssuedAt time.Time `json:"issued_at"`

	// SigningKeyID identifies the battery-issuing authority. Signatures
	// use keys.PurposeSigningAuthority.
	SigningKeyID ids.KeyID `json:"signing_key_id"`

	// Signature is the Ed25519 signature over CanonicalBytes (which
	// excludes Signature itself).
	Signature []byte `json:"signature"`
}

// DeriveMerkleRoot returns the RFC 6962-style Merkle root over the
// battery's probes, sorted by their content-addressed IDs. Each probe
// must have a non-zero ID (run DeriveID on each probe first) — a
// missing ID is a structural error.
//
// The returned slice is a fresh copy; mutating it does not affect the
// battery.
func (b *ProbeBattery) DeriveMerkleRoot() ([]byte, error) {
	if b == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: nil receiver",
			nil,
		)
	}
	if len(b.Probes) == 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: at least one probe required",
			nil,
		)
	}
	// Defensive sorted copy — do not mutate caller's slice.
	cp := make([]Probe, len(b.Probes))
	copy(cp, b.Probes)
	for i := range cp {
		if cp[i].ID.IsZero() {
			return nil, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"probe_battery: probe missing id (run DeriveID first)",
				nil,
			)
		}
	}
	sortProbesByID(cp)
	// Duplicate-ID gate after sort.
	for i := 1; i < len(cp); i++ {
		if cp[i].ID == cp[i-1].ID {
			return nil, shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"probe_battery: duplicate probe id: "+cp[i].ID.String(),
				nil,
			)
		}
	}
	leaves := make([][]byte, len(cp))
	for i := range cp {
		leaves[i] = probeLeafHash(&cp[i])
	}
	root := computeProbeRoot(leaves)
	out := make([]byte, crypto.HashSize)
	copy(out, root[:])
	return out, nil
}

// Validate runs structural checks, per-probe Validate (which is the
// content-address gate for each probe), and re-derives MerkleRoot to
// confirm it matches. A mismatch surfaces as Integrity.
func (b *ProbeBattery) Validate() error {
	if b == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: nil receiver",
			nil,
		)
	}
	if b.SchemaVersion < SchemaVersionMin || b.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"probe_battery: schema_version out of supported range",
			nil,
		)
	}
	if b.Name == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: name required",
			nil,
		)
	}
	if len(b.MerkleRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: merkle_root must be 32 bytes",
			nil,
		)
	}
	if len(b.Probes) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: probes required",
			nil,
		)
	}
	// Per-probe validation — each probe's stored ID must match its
	// own derivation.
	for i := range b.Probes {
		if err := b.Probes[i].Validate(); err != nil {
			return err
		}
	}
	if err := b.Policy.Validate(); err != nil {
		return err
	}
	if b.IssuedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: issued_at required",
			nil,
		)
	}
	if b.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: signing_key_id required",
			nil,
		)
	}
	if len(b.Signature) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: signature required",
			nil,
		)
	}
	// Content-address gate: stored MerkleRoot must equal the root we
	// re-derive from the probes. Disagreement is Integrity.
	derived, err := b.DeriveMerkleRoot()
	if err != nil {
		return err
	}
	if !bytes.Equal(derived, b.MerkleRoot) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"probe_battery: stored merkle_root disagrees with derivation",
			nil,
		)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Signature is
// excluded from its own cover bytes. Encoding is crypto.CanonicalJSON,
// matching the rest of the platform.
func (b *ProbeBattery) CanonicalBytes() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	cp := *b
	cp.Signature = nil
	// Canonical cover bytes must also encode probes in canonical
	// order; sort defensively.
	cp.Probes = append([]Probe(nil), b.Probes...)
	sortProbesByID(cp.Probes)
	out, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: canonical encode failed",
			err,
		)
	}
	return out, nil
}

// SignWith signs the canonical cover bytes of this battery under
// b.SigningKeyID, binding to keys.PurposeSigningAuthority. The
// produced signature is assigned to b.Signature.
//
// SignWith does NOT call Validate — a battery mid-construction may
// have Signature empty and MerkleRoot unset. The caller is expected
// to have populated Probes, called DeriveMerkleRoot to fill
// MerkleRoot, then called SignWith. VerifySignature DOES call
// Validate, which enforces end-to-end integrity on verification.
func (b *ProbeBattery) SignWith(signer keys.Signer) error {
	if b == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: nil receiver",
			nil,
		)
	}
	if b.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: signing_key_id required before sign",
			nil,
		)
	}
	if len(b.MerkleRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: merkle_root required before sign (run DeriveMerkleRoot first)",
			nil,
		)
	}
	cp := *b
	cp.Signature = nil
	cp.Probes = append([]Probe(nil), b.Probes...)
	sortProbesByID(cp.Probes)
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(b.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	b.Signature = sig
	return nil
}

// VerifySignature resolves b.SigningKeyID under
// keys.PurposeSigningAuthority and verifies the stored signature
// against canonical cover bytes. Calls Validate first — a stored
// MerkleRoot that disagrees with the probes is caught before the
// signature gate even runs.
func (b *ProbeBattery) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := b.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(b.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, b.Signature)
}

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (b *ProbeBattery) UnmarshalJSON(data []byte) error {
	type alias ProbeBattery
	tmp := (*alias)(b)

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: trailing content after JSON value",
			nil,
		)
	}
	if b.SchemaVersion < SchemaVersionMin || b.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"probe_battery: schema_version out of supported range",
			nil,
		)
	}
	return nil
}
