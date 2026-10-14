// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Schema versioning for witness-log artifacts. The three constants advance
// together when a wire-format change is shipped.
const (
	// SchemaVersionMin is the lowest witness-log format version this build
	// will accept on read.
	SchemaVersionMin uint16 = 1
	// SchemaVersionMax is the highest witness-log format version this build
	// will accept on read.
	SchemaVersionMax uint16 = 1
	// SchemaVersionCurrent is the version this build writes.
	SchemaVersionCurrent uint16 = 1
)

// EntryIDPrefix is the human-readable tag that every derived EntryID
// carries. NEVER change — a change re-addresses every entry ever issued.
const EntryIDPrefix = "log:"

// Domain-separation tags for the RFC 6962 hash scheme. NEVER change —
// a tag flip re-addresses every leaf and every internal node in every
// tree this package has ever produced.
const (
	leafTag byte = 0x00
	nodeTag byte = 0x01
)

// EntryID is the content-addressed identifier of a single LogEntry.
// Derived, not assigned:
//
//	EntryID = "log:" + hex(LeafHash)
//
// where LeafHash is the RFC 6962 leaf hash of the entry (see below).
// The typed string keeps EntryIDs from being silently interchanged with
// other typed IDs.
type EntryID string

// String returns the rendered form of the ID.
func (e EntryID) String() string { return string(e) }

// IsZero reports whether the ID is the empty value.
func (e EntryID) IsZero() bool { return e == "" }

// LogEntry is one witnessed event in the ACP transparency log.
//
// Every entry commits in TWO ways:
//
//   - As a LEAF of the operator's RFC 6962 Merkle tree. LeafHash is
//     SHA-256(0x00 || canonicalLeafBytes(entry)) where canonicalLeafBytes
//     is the fixed byte form of the entry's doctrinal payload plus
//     {Index, Timestamp, PrevLeafHash}.
//
//   - As a LINK in a hash chain. PrevLeafHash equals the LeafHash of the
//     previous entry (all zeros at Index 0). Because PrevLeafHash is
//     INCLUDED in canonicalLeafBytes, a tamper anywhere in history
//     propagates forward: any change to entry K changes K's LeafHash,
//     which changes K+1's PrevLeafHash, which changes K+1's LeafHash,
//     and so on — making retroactive rewrites cryptographically
//     infeasible without a pre-image break.
//
// The entry carries the content-commitments of the artifacts being
// witnessed (attestation hash, battery root, scorecard root, genome IDs,
// derivation method), not the artifacts themselves. A witness log is
// therefore small, shareable, and safe to publish even when the
// underlying inputs are sensitive.
type LogEntry struct {
	// SchemaVersion gates the wire format. Readers MUST validate first.
	SchemaVersion uint16 `json:"schema_version"`

	// EntryID is DERIVED, not assigned. Validate recomputes and rejects
	// on mismatch.
	EntryID EntryID `json:"entry_id"`

	// Index is the 0-based position of this entry in the log. MUST be
	// gap-free and monotonically increasing from 0. Append-time gate.
	Index uint64 `json:"index"`

	// PrevLeafHash is the LeafHash of the entry at Index-1. All zeros at
	// Index 0. Exactly 32 bytes.
	PrevLeafHash []byte `json:"prev_leaf_hash"`

	// LeafHash is DERIVED: SHA-256(0x00 || canonicalLeafBytes(entry)).
	// Exactly 32 bytes. Validate recomputes and rejects on mismatch.
	LeafHash []byte `json:"leaf_hash"`

	// Timestamp is wall-clock of witnessing (UTC, unix-nanos granularity).
	// The log enforces Timestamp monotonicity across indices at append
	// time; every entry's Timestamp MUST be >= its predecessor's.
	Timestamp time.Time `json:"timestamp"`

	// --- doctrinal payload: commitments the log witnesses ---

	// GenomeID is the subject — the genome whose continuity event is
	// being witnessed. Required.
	GenomeID ids.GenomeID `json:"genome_id"`

	// AttestationRoot is SHA-256 over the canonical bytes of the
	// ProbeAttestation being witnessed. Exactly 32 bytes.
	AttestationRoot []byte `json:"attestation_root"`

	// BatteryMerkleRoot is the ProbeBattery.MerkleRoot the attestation
	// was run against. Exactly 32 bytes.
	BatteryMerkleRoot []byte `json:"battery_merkle_root"`

	// ScorecardRoot is the Scorecard.MerkleRoot the attestation vouches
	// for. Exactly 32 bytes.
	ScorecardRoot []byte `json:"scorecard_root"`

	// ParentGenomeID identifies the parent in a succession edge. Empty
	// for a genesis witnessing (a self-attested root genome).
	// ParentGenomeID and DerivationMethod MUST be set together: either
	// both empty (genesis) or both populated (succession edge).
	ParentGenomeID ids.GenomeID `json:"parent_genome_id,omitempty"`

	// DerivationMethod names the succession method (fine-tune, distill,
	// merge, quantize, reconstruct). Required iff ParentGenomeID is
	// non-empty; closed set enforced at validation.
	DerivationMethod genome_descriptor.DerivationMethod `json:"derivation_method,omitempty"`
}

// DeriveLeafHashAndID computes the RFC 6962 leaf hash and the content-
// addressed EntryID. Does NOT mutate the receiver — returns both
// values to the caller, who is expected to store them before signing
// or appending. Returns a Structural error if the entry's payload
// invariants are violated; we refuse to address a structurally
// invalid entry.
func (e *LogEntry) DeriveLeafHashAndID() ([]byte, EntryID, error) {
	if e == nil {
		return nil, "", shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"log_entry: nil receiver",
			nil,
		)
	}
	if err := e.validateStructural(); err != nil {
		return nil, "", err
	}
	payload := canonicalLeafBytes(e)
	inner := make([]byte, 0, 1+len(payload))
	inner = append(inner, leafTag)
	inner = append(inner, payload...)
	h := crypto.SHA256(inner)
	leaf := make([]byte, crypto.HashSize)
	copy(leaf, h[:])
	id := EntryID(EntryIDPrefix + hex.EncodeToString(h[:]))
	return leaf, id, nil
}

// Validate runs structural checks and the content-addressing gate:
// the stored LeafHash and EntryID MUST agree with the derivation from
// the rest of the fields. Disagreement surfaces as Integrity.
func (e *LogEntry) Validate() error {
	if err := e.validateStructural(); err != nil {
		return err
	}
	if len(e.LeafHash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"log_entry: leaf_hash must be 32 bytes",
			nil,
		)
	}
	if e.EntryID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"log_entry: entry_id required (run DeriveLeafHashAndID before Validate)",
			nil,
		)
	}
	derivedLeaf, derivedID, err := (&LogEntry{
		SchemaVersion:     e.SchemaVersion,
		Index:             e.Index,
		PrevLeafHash:      e.PrevLeafHash,
		Timestamp:         e.Timestamp,
		GenomeID:          e.GenomeID,
		AttestationRoot:   e.AttestationRoot,
		BatteryMerkleRoot: e.BatteryMerkleRoot,
		ScorecardRoot:     e.ScorecardRoot,
		ParentGenomeID:    e.ParentGenomeID,
		DerivationMethod:  e.DerivationMethod,
	}).DeriveLeafHashAndID()
	if err != nil {
		return err
	}
	if !bytes.Equal(derivedLeaf, e.LeafHash) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"log_entry: derived leaf_hash disagrees with stored",
			nil,
		)
	}
	if derivedID != e.EntryID {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"log_entry: derived entry_id disagrees with stored",
			nil,
		)
	}
	return nil
}

// validateStructural enforces field-shape invariants with no crypto.
// Separate from Validate so DeriveLeafHashAndID can call it without
// recursing.
func (e *LogEntry) validateStructural() error {
	if e.SchemaVersion < SchemaVersionMin || e.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"log_entry: schema_version out of supported range",
			nil,
		)
	}
	if len(e.PrevLeafHash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"log_entry: prev_leaf_hash must be 32 bytes",
			nil,
		)
	}
	// Genesis rule: at Index 0, PrevLeafHash MUST be all-zero. At any
	// other index it MUST NOT be — otherwise the chain anchors to
	// nothing and the operator could forge a "new genesis" mid-log.
	allZero := true
	for i := 0; i < crypto.HashSize; i++ {
		if e.PrevLeafHash[i] != 0 {
			allZero = false
			break
		}
	}
	if e.Index == 0 && !allZero {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"log_entry: prev_leaf_hash must be all-zero at index 0",
			nil,
		)
	}
	if e.Index != 0 && allZero {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"log_entry: prev_leaf_hash must be non-zero at index > 0",
			nil,
		)
	}
	if e.Timestamp.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"log_entry: timestamp required",
			nil,
		)
	}
	if e.GenomeID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"log_entry: genome_id required",
			nil,
		)
	}
	if len(e.AttestationRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"log_entry: attestation_root must be 32 bytes",
			nil,
		)
	}
	if len(e.BatteryMerkleRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"log_entry: battery_merkle_root must be 32 bytes",
			nil,
		)
	}
	if len(e.ScorecardRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"log_entry: scorecard_root must be 32 bytes",
			nil,
		)
	}
	// Succession-edge co-presence rule. Both fields empty = genesis
	// witnessing; both populated = succession edge. Any mix is a
	// structural error.
	hasParent := !e.ParentGenomeID.IsZero()
	hasMethod := e.DerivationMethod != ""
	if hasParent != hasMethod {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"log_entry: parent_genome_id and derivation_method must be set together",
			nil,
		)
	}
	if hasMethod && !isKnownDerivation(e.DerivationMethod) {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"log_entry: unknown derivation_method: "+string(e.DerivationMethod),
			nil,
		)
	}
	return nil
}

// isKnownDerivation gates DerivationMethod to the closed set defined
// in the genome_descriptor package. Additions are a schema-version bump.
func isKnownDerivation(m genome_descriptor.DerivationMethod) bool {
	switch m {
	case genome_descriptor.DerivationFineTune,
		genome_descriptor.DerivationDistill,
		genome_descriptor.DerivationMerge,
		genome_descriptor.DerivationQuantize,
		genome_descriptor.DerivationReconstruct:
		return true
	}
	return false
}

// canonicalLeafBytes is the fixed, minimal, stable-forever byte form of
// a LogEntry's doctrinal payload — used as the pre-image of the RFC
// 6962 leaf hash. The format is a binary packing rather than JSON so
// that cross-language verifiers can reproduce it without depending on
// the Go-specific JCS profile.
//
// Layout (fixed, NEVER change):
//
//	 2-byte  big-endian  SchemaVersion
//	 8-byte  big-endian  Index
//	32-byte              PrevLeafHash
//	 8-byte  big-endian  Timestamp UnixNano (UTC)
//	 4-byte  big-endian  len(GenomeID)
//	 N-byte              GenomeID UTF-8
//	32-byte              AttestationRoot
//	32-byte              BatteryMerkleRoot
//	32-byte              ScorecardRoot
//	 4-byte  big-endian  len(ParentGenomeID)
//	 N-byte              ParentGenomeID UTF-8
//	 4-byte  big-endian  len(DerivationMethod)
//	 N-byte              DerivationMethod UTF-8
//
// Deliberately excludes EntryID and LeafHash — both derived from this
// byte form.
func canonicalLeafBytes(e *LogEntry) []byte {
	gid := []byte(e.GenomeID)
	pid := []byte(e.ParentGenomeID)
	method := []byte(e.DerivationMethod)
	size := 2 + 8 + crypto.HashSize + 8 + 4 + len(gid) +
		crypto.HashSize + crypto.HashSize + crypto.HashSize +
		4 + len(pid) + 4 + len(method)
	out := make([]byte, 0, size)

	var u16 [2]byte
	var u32 [4]byte
	var u64 [8]byte

	binary.BigEndian.PutUint16(u16[:], e.SchemaVersion)
	out = append(out, u16[:]...)

	binary.BigEndian.PutUint64(u64[:], e.Index)
	out = append(out, u64[:]...)

	out = append(out, e.PrevLeafHash...)

	binary.BigEndian.PutUint64(u64[:], uint64(e.Timestamp.UTC().UnixNano()))
	out = append(out, u64[:]...)

	binary.BigEndian.PutUint32(u32[:], uint32(len(gid)))
	out = append(out, u32[:]...)
	out = append(out, gid...)

	out = append(out, e.AttestationRoot...)
	out = append(out, e.BatteryMerkleRoot...)
	out = append(out, e.ScorecardRoot...)

	binary.BigEndian.PutUint32(u32[:], uint32(len(pid)))
	out = append(out, u32[:]...)
	out = append(out, pid...)

	binary.BigEndian.PutUint32(u32[:], uint32(len(method)))
	out = append(out, u32[:]...)
	out = append(out, method...)

	return out
}

// CombineNodes returns SHA-256(0x01 || left || right) — the RFC 6962
// internal-node domain separator. Exported so external verifiers
// auditing STHs can reproduce the tree arithmetic without reimporting
// the unexported helpers.
func CombineNodes(left, right []byte) ([]byte, error) {
	if len(left) != crypto.HashSize || len(right) != crypto.HashSize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"witness: combine: inputs must be 32 bytes",
			nil,
		)
	}
	buf := make([]byte, 0, 1+2*crypto.HashSize)
	buf = append(buf, nodeTag)
	buf = append(buf, left...)
	buf = append(buf, right...)
	h := crypto.SHA256(buf)
	out := make([]byte, crypto.HashSize)
	copy(out, h[:])
	return out, nil
}

// ComputeMerkleRoot returns the RFC 6962 Merkle root over the given
// leaves (each leaf is a 32-byte RFC 6962 leaf hash). Odd-level last
// nodes are promoted unchanged — no duplication, per RFC 6962 §2.1.
// An empty input returns a freshly-allocated all-zero 32-byte slice,
// which is also the TreeHash of an empty log's STH.
func ComputeMerkleRoot(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return make([]byte, crypto.HashSize), nil
	}
	for i := range leaves {
		if len(leaves[i]) != crypto.HashSize {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"witness: leaf at index N not 32 bytes",
				nil,
			)
		}
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		i := 0
		for ; i+1 < len(level); i += 2 {
			h, err := CombineNodes(level[i], level[i+1])
			if err != nil {
				return nil, err
			}
			next = append(next, h)
		}
		if i < len(level) {
			next = append(next, level[i])
		}
		level = next
	}
	out := make([]byte, crypto.HashSize)
	copy(out, level[0])
	return out, nil
}

// UnmarshalJSON rejects unknown fields and gates SchemaVersion.
func (e *LogEntry) UnmarshalJSON(data []byte) error {
	type alias LogEntry
	tmp := (*alias)(e)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(tmp); err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"log_entry: decode error",
			err,
		)
	}
	if dec.More() {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"log_entry: trailing content after JSON value",
			nil,
		)
	}
	if e.SchemaVersion < SchemaVersionMin || e.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"log_entry: schema_version out of supported range",
			nil,
		)
	}
	return nil
}

// Compile-time check that EntryID satisfies the platform ID interface
// shape (String/IsZero) even though it is not registered in
// shared/ids — EntryID is content-addressed and witness-internal.
var _ interface {
	String() string
	IsZero() bool
} = EntryID("")
