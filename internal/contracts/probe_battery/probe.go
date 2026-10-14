// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe_battery

import (
	"encoding/binary"
	"encoding/hex"
	"sort"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// ProbeIDPrefix is the human-readable tag that every derived ProbeID
// carries. Part of the content-addressing rule — changing it
// invalidates every previously-issued battery.
const ProbeIDPrefix = "prb:"

// ProbeKind enumerates the three doctrinal probe classes. The set is
// closed; additions are a schema-version bump.
type ProbeKind string

const (
	// ProbeKindIdentity — response must round-trip bit-identically
	// across any succession method. A single drift is a swap signal.
	ProbeKindIdentity ProbeKind = "identity"

	// ProbeKindCapability — drift permitted within a per-method budget
	// declared by the battery's TolerancePolicy.
	ProbeKindCapability ProbeKind = "capability"

	// ProbeKindNegative — the genome is expected to fail in a specific
	// way. A flip to passing (or to a different failure shape) in a
	// descendant is evidence of a swap.
	ProbeKindNegative ProbeKind = "negative"
)

// validProbeKinds is the closed set of allowed ProbeKind values.
var validProbeKinds = map[ProbeKind]struct{}{
	ProbeKindIdentity:   {},
	ProbeKindCapability: {},
	ProbeKindNegative:   {},
}

// leaf/node domain-separation tags, matching componenttree. NEVER
// change these; a change invalidates every signed battery and every
// scorecard ever produced.
const (
	probeLeafTag byte = 0x00
	probeNodeTag byte = 0x01
)

// ProbeID is the content-addressed identifier of a single Probe.
// Derived, not assigned:
//
//	ProbeID = "prb:" + hex(SHA-256(canonicalProbeBytes(probe with ID=""))).
//
// The typed string keeps ProbeIDs from being silently interchanged
// with other typed IDs.
type ProbeID string

// String returns the rendered form of the ID.
func (p ProbeID) String() string { return string(p) }

// IsZero reports whether the ID is the empty value.
func (p ProbeID) IsZero() bool { return p == "" }

// Probe is one entry in a ProbeBattery. The probe commits to the
// SHA-256 of the input (stored out-of-band) and, for identity and
// negative probes, to the SHA-256 of the expected output-shape schema
// so a scorecard reader can sanity-check the runner's response format.
//
// The probe does NOT carry the input or the expected output bytes —
// those live alongside the battery and are materialized by the probe
// runner. A battery is thus small, shareable, and safe to embed in
// signatures even when the underlying inputs are sensitive.
type Probe struct {
	// ID is DERIVED (see DeriveID), not assigned. Validate recomputes
	// and rejects on mismatch.
	ID ProbeID `json:"id"`

	// Kind partitions the probe into the three doctrinal classes.
	Kind ProbeKind `json:"kind"`

	// InputHash is SHA-256 of the canonical bytes of the probe input.
	// Exactly 32 bytes. Required.
	InputHash []byte `json:"input_hash"`

	// ExpectedShapeHash is SHA-256 of the canonical JSON of the output
	// shape schema. May be empty (the zero byte slice) when the probe
	// does not constrain output shape — e.g. an open-ended generation
	// identity probe where only the output hash matters.
	ExpectedShapeHash []byte `json:"expected_shape_hash,omitempty"`

	// Label is a free-form human-readable tag. Not part of the
	// content-address (Validate ignores it for identity derivation)
	// but IS covered by the battery's Merkle root, so a tamper-flip
	// on the label is detectable. Use for "math-word-problem-042",
	// "jailbreak-negative-007", etc.
	Label string `json:"label,omitempty"`
}

// DeriveID computes the content-addressed ID of p under the rule:
//
//	ProbeID = "prb:" + hex(SHA-256(derivationBytes(p with ID=""))).
//
// Returns an Integrity error if the probe's structural invariants are
// violated — we refuse to address a structurally invalid probe.
func (p *Probe) DeriveID() (ProbeID, error) {
	if p == nil {
		return "", shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe: nil receiver",
			nil,
		)
	}
	if err := p.validateStructural(); err != nil {
		return "", err
	}
	cp := *p
	cp.ID = ""
	buf := canonicalProbeBytes(&cp)
	h := crypto.SHA256(buf)
	return ProbeID(ProbeIDPrefix + hex.EncodeToString(h[:])), nil
}

// Validate runs structural checks AND the content-addressing gate. A
// stored ID that disagrees with the derivation is an Integrity fail.
func (p *Probe) Validate() error {
	if err := p.validateStructural(); err != nil {
		return err
	}
	if p.ID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe: id required (run DeriveID before Validate)",
			nil,
		)
	}
	derived, err := (&Probe{
		Kind:              p.Kind,
		InputHash:         p.InputHash,
		ExpectedShapeHash: p.ExpectedShapeHash,
		Label:             p.Label,
	}).DeriveID()
	if err != nil {
		return err
	}
	if derived != p.ID {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"probe: derived id disagrees with stored id",
			nil,
		)
	}
	return nil
}

// validateStructural enforces field-shape invariants with no crypto.
// Separate from Validate so DeriveID can call it without recursing.
func (p *Probe) validateStructural() error {
	if _, ok := validProbeKinds[p.Kind]; !ok {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe: unknown kind: "+string(p.Kind),
			nil,
		)
	}
	if len(p.InputHash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe: input_hash must be 32 bytes",
			nil,
		)
	}
	if len(p.ExpectedShapeHash) != 0 && len(p.ExpectedShapeHash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe: expected_shape_hash must be empty or 32 bytes",
			nil,
		)
	}
	// Identity and negative probes must bind to a shape schema —
	// otherwise "matches expected" is undefined.
	if (p.Kind == ProbeKindIdentity || p.Kind == ProbeKindNegative) &&
		len(p.ExpectedShapeHash) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"probe: identity/negative probes require expected_shape_hash",
			nil,
		)
	}
	return nil
}

// canonicalProbeBytes is the fixed, minimal, stable-forever encoding
// of a probe used BOTH as the pre-image of the probe's content-
// addressed ID AND as the pre-image of its Merkle leaf. The format
// deliberately mirrors componenttree.encodeComponent's style.
//
// Layout (fixed, NEVER change):
//
//	 4-byte  big-endian  length of Kind
//	 N-byte              Kind UTF-8
//	32-byte              InputHash
//	 4-byte  big-endian  length of ExpectedShapeHash (0 or 32)
//	 N-byte              ExpectedShapeHash
//	 4-byte  big-endian  length of Label
//	 N-byte              Label UTF-8
//
// Deliberately excludes ID — both because DeriveID zeroes it and
// because the Merkle tree's root already commits to every leaf's
// content-addressed identity through its bytes.
func canonicalProbeBytes(p *Probe) []byte {
	kind := []byte(p.Kind)
	label := []byte(p.Label)
	out := make([]byte, 0, 4+len(kind)+crypto.HashSize+4+len(p.ExpectedShapeHash)+4+len(label))

	var u32 [4]byte

	binary.BigEndian.PutUint32(u32[:], uint32(len(kind)))
	out = append(out, u32[:]...)
	out = append(out, kind...)

	// InputHash is exactly 32 bytes (validated upstream). Write
	// unprefixed for a compact, fixed layout.
	out = append(out, p.InputHash...)

	binary.BigEndian.PutUint32(u32[:], uint32(len(p.ExpectedShapeHash)))
	out = append(out, u32[:]...)
	out = append(out, p.ExpectedShapeHash...)

	binary.BigEndian.PutUint32(u32[:], uint32(len(label)))
	out = append(out, u32[:]...)
	out = append(out, label...)

	return out
}

// probeLeafHash returns SHA-256(0x00 || canonicalProbeBytes(p)). Used
// to build the battery's Merkle root.
func probeLeafHash(p *Probe) []byte {
	inner := canonicalProbeBytes(p)
	buf := make([]byte, 0, 1+len(inner))
	buf = append(buf, probeLeafTag)
	buf = append(buf, inner...)
	h := crypto.SHA256(buf)
	out := make([]byte, crypto.HashSize)
	copy(out, h[:])
	return out
}

// combineProbeNodes returns SHA-256(0x01 || left || right) — the
// RFC 6962 internal-node domain separator. Mirrors componenttree.
func combineProbeNodes(left, right []byte) ([]byte, error) {
	if len(left) != crypto.HashSize || len(right) != crypto.HashSize {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: combine: inputs must be 32 bytes",
			nil,
		)
	}
	buf := make([]byte, 0, 1+2*crypto.HashSize)
	buf = append(buf, probeNodeTag)
	buf = append(buf, left...)
	buf = append(buf, right...)
	h := crypto.SHA256(buf)
	out := make([]byte, crypto.HashSize)
	copy(out, h[:])
	return out, nil
}

// computeProbeRoot returns the RFC 6962 root over leaves. Odd-level
// last nodes are promoted unchanged (no duplication, per RFC 6962
// §2.1). Empty input returns a zero [32]byte.
func computeProbeRoot(leaves [][]byte) [crypto.HashSize]byte {
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		i := 0
		for ; i+1 < len(level); i += 2 {
			h, _ := combineProbeNodes(level[i], level[i+1])
			next = append(next, h)
		}
		if i < len(level) {
			next = append(next, level[i])
		}
		level = next
	}
	var out [crypto.HashSize]byte
	if len(level) == 1 {
		copy(out[:], level[0])
	}
	return out
}

// sortProbesByID sorts probes ascending by their content-addressed
// ID. Used before Merkle-root derivation so two equal probe sets
// produce byte-identical roots regardless of insertion order.
func sortProbesByID(probes []Probe) {
	sort.Slice(probes, func(i, j int) bool {
		return probes[i].ID < probes[j].ID
	})
}

// Compile-time check that ProbeID satisfies the platform ID interface
// via the standard String/IsZero pair — not imported because the
// shared ids package owns platform-wide IDs; ProbeID is content-
// internal to this package.
var _ interface {
	String() string
	IsZero() bool
} = ProbeID("")
