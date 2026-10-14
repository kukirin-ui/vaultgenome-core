// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe_battery

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"sort"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ScoreEntry is one row in a Scorecard: the response a genome
// produced on one probe. The entry does NOT carry the response bytes
// — only the content-address of the response. A runner with the
// original inputs can re-run the probe and re-derive ResponseHash;
// anyone else gets a verifiable commitment without access to the
// model's outputs.
type ScoreEntry struct {
	// ProbeID names the probe the entry corresponds to. MUST match
	// a probe in the battery whose MerkleRoot is cited.
	ProbeID ProbeID `json:"probe_id"`

	// ResponseHash is SHA-256 of the canonical bytes of the genome's
	// response to the probe. Exactly 32 bytes. Required.
	ResponseHash []byte `json:"response_hash"`
}

// Scorecard is the signed, content-addressable record of one
// genome's responses on one battery.
//
// The Scorecard's own MerkleRoot is derived over the entries sorted
// by ProbeID. Two scorecards with the same entries produce identical
// Merkle roots regardless of measurement order.
//
// The AGD's BehavioralFingerprint.CanonicalScoresRoot cites this
// MerkleRoot — that is how an AGD pins itself to a specific
// scorecard.
type Scorecard struct {
	// SchemaVersion gates the wire format. Readers MUST validate first.
	SchemaVersion uint16 `json:"schema_version"`

	// GenomeID names the genome these scores are claimed for.
	GenomeID ids.GenomeID `json:"genome_id"`

	// BatteryName is the human-readable battery identifier this
	// scorecard was measured against. MUST match the signed battery's
	// Name — a policy layer cross-checks.
	BatteryName string `json:"battery_name"`

	// BatteryMerkleRoot is the content commitment of the battery this
	// scorecard was measured against. Exactly 32 bytes.
	BatteryMerkleRoot []byte `json:"battery_merkle_root"`

	// Entries are the per-probe response commitments. Empty
	// scorecards are rejected — a scorecard with no entries commits
	// to nothing.
	Entries []ScoreEntry `json:"entries"`

	// MerkleRoot is DERIVED over Entries sorted by ProbeID. Equals
	// the AGD's CanonicalScoresRoot iff the AGD cites this scorecard.
	// Validate recomputes and rejects on mismatch.
	MerkleRoot []byte `json:"merkle_root"`

	// MeasuredAt is wall-clock of when the scorecard was recorded.
	// Required.
	MeasuredAt time.Time `json:"measured_at"`

	// SigningKeyID identifies the probe-runner authority that signed
	// this scorecard. Binds under keys.PurposeSigningAuthority.
	SigningKeyID ids.KeyID `json:"signing_key_id"`

	// Signature is the Ed25519 signature over CanonicalBytes (which
	// excludes Signature itself).
	Signature []byte `json:"signature"`
}

// DeriveMerkleRoot returns the Merkle root over the scorecard's
// entries, sorted by ProbeID. The leaf-hash pre-image is the stable,
// fixed encoding defined in scoreEntryLeafBytes.
func (s *Scorecard) DeriveMerkleRoot() ([]byte, error) {
	if s == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: nil receiver",
			nil,
		)
	}
	if len(s.Entries) == 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: at least one entry required",
			nil,
		)
	}
	cp := make([]ScoreEntry, len(s.Entries))
	copy(cp, s.Entries)
	for i := range cp {
		if cp[i].ProbeID.IsZero() {
			return nil, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"scorecard: entry missing probe_id",
				nil,
			)
		}
		if len(cp[i].ResponseHash) != crypto.HashSize {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"scorecard: response_hash must be 32 bytes",
				nil,
			)
		}
	}
	sort.Slice(cp, func(i, j int) bool { return cp[i].ProbeID < cp[j].ProbeID })
	for i := 1; i < len(cp); i++ {
		if cp[i].ProbeID == cp[i-1].ProbeID {
			return nil, shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"scorecard: duplicate probe_id: "+cp[i].ProbeID.String(),
				nil,
			)
		}
	}
	leaves := make([][]byte, len(cp))
	for i := range cp {
		leaves[i] = scoreEntryLeafHash(cp[i])
	}
	root := computeProbeRoot(leaves)
	out := make([]byte, crypto.HashSize)
	copy(out, root[:])
	return out, nil
}

// Validate enforces structural invariants, including the content-
// address gate: the stored MerkleRoot must equal the derivation over
// the current Entries. Disagreement is Integrity.
func (s *Scorecard) Validate() error {
	if s == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: nil receiver",
			nil,
		)
	}
	if s.SchemaVersion < SchemaVersionMin || s.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"scorecard: schema_version out of supported range",
			nil,
		)
	}
	if s.GenomeID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: genome_id required",
			nil,
		)
	}
	if s.BatteryName == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: battery_name required",
			nil,
		)
	}
	if len(s.BatteryMerkleRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"scorecard: battery_merkle_root must be 32 bytes",
			nil,
		)
	}
	if len(s.Entries) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: entries required",
			nil,
		)
	}
	if len(s.MerkleRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"scorecard: merkle_root must be 32 bytes",
			nil,
		)
	}
	if s.MeasuredAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: measured_at required",
			nil,
		)
	}
	if s.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: signing_key_id required",
			nil,
		)
	}
	if len(s.Signature) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: signature required",
			nil,
		)
	}
	derived, err := s.DeriveMerkleRoot()
	if err != nil {
		return err
	}
	if !bytes.Equal(derived, s.MerkleRoot) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"scorecard: stored merkle_root disagrees with derivation",
			nil,
		)
	}
	return nil
}

// CanonicalBytes returns the bytes covered by Signature. Encoding is
// crypto.CanonicalJSON; Signature is excluded; entries are sorted.
func (s *Scorecard) CanonicalBytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	cp := *s
	cp.Signature = nil
	cp.Entries = append([]ScoreEntry(nil), s.Entries...)
	sort.Slice(cp.Entries, func(i, j int) bool { return cp.Entries[i].ProbeID < cp.Entries[j].ProbeID })
	out, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"scorecard: canonical encode failed",
			err,
		)
	}
	return out, nil
}

// SignWith signs the canonical cover bytes under s.SigningKeyID.
// Matches the rest of the platform: no Validate pre-call so
// scorecards mid-construction may still sign.
func (s *Scorecard) SignWith(signer keys.Signer) error {
	if s == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: nil receiver",
			nil,
		)
	}
	if s.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: signing_key_id required before sign",
			nil,
		)
	}
	if len(s.MerkleRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: merkle_root required before sign (run DeriveMerkleRoot first)",
			nil,
		)
	}
	cp := *s
	cp.Signature = nil
	cp.Entries = append([]ScoreEntry(nil), s.Entries...)
	sort.Slice(cp.Entries, func(i, j int) bool { return cp.Entries[i].ProbeID < cp.Entries[j].ProbeID })
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"scorecard: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(s.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	s.Signature = sig
	return nil
}

// VerifySignature resolves s.SigningKeyID and checks the signature
// against canonical cover bytes. Calls Validate up-front.
func (s *Scorecard) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"scorecard: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := s.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(s.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, s.Signature)
}

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (s *Scorecard) UnmarshalJSON(data []byte) error {
	type alias Scorecard
	tmp := (*alias)(s)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"scorecard: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"scorecard: trailing content after JSON value",
			nil,
		)
	}
	if s.SchemaVersion < SchemaVersionMin || s.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"scorecard: schema_version out of supported range",
			nil,
		)
	}
	return nil
}

// ---- leaf encoding for scorecard entries ----------------------------------

// scoreEntryLeafBytes is the stable, fixed pre-image of a ScoreEntry's
// Merkle leaf hash. Mirrors canonicalProbeBytes' style.
//
// Layout (fixed, NEVER change):
//
//	 4-byte  big-endian  length of ProbeID
//	 N-byte              ProbeID UTF-8
//	32-byte              ResponseHash
func scoreEntryLeafBytes(e ScoreEntry) []byte {
	pid := []byte(e.ProbeID)
	out := make([]byte, 0, 4+len(pid)+crypto.HashSize)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(pid)))
	out = append(out, u32[:]...)
	out = append(out, pid...)
	out = append(out, e.ResponseHash...)
	return out
}

// scoreEntryLeafHash returns SHA-256(0x00 || scoreEntryLeafBytes(e)).
func scoreEntryLeafHash(e ScoreEntry) []byte {
	inner := scoreEntryLeafBytes(e)
	buf := make([]byte, 0, 1+len(inner))
	buf = append(buf, probeLeafTag)
	buf = append(buf, inner...)
	h := crypto.SHA256(buf)
	out := make([]byte, crypto.HashSize)
	copy(out, h[:])
	return out
}
