// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"encoding/binary"
	"sort"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// Reconstructor is the R-11 frozen interface for the generative
// reconstruction mechanism described in patents P1 §[0021]–[0023] and
// P2 §[0018]. The V1 MVP ships a deterministic placeholder
// (DeterministicReconstructor); the V2 production backend replaces only
// this interface's implementation. No caller outside /internal/compute
// should depend on any concrete Reconstructor type — the interface is
// what survives the swap.
//
// # Contract
//
// Reconstruct receives the manifest describing the job and the already-
// unsealed component materials. It must:
//
//  1. Return a CandidateOutput whose ManifestID, SessionID, and
//     OutputKind match the manifest exactly.
//
//  2. Honour the manifest's ExpectedOutputMaxBytes; a produced output
//     that would exceed the bound is an operational fault and must be
//     rejected before it is handed back.
//
//  3. Populate ProducedAt via the injected Clock. The worker never calls
//     time.Now() directly (00_Bootstrap_Contracts_Doctrine §4 —
//     monotonic clock discipline).
//
//  4. Refuse empty component lists Structurally (a job with nothing to
//     reconstruct is malformed on the issuance side).
//
//  5. Refuse duplicate ComponentIDs Structurally; the reconstruction
//     must see exactly the set of components the manifest's
//     DisclosureIDs resolved to.
//
// A conforming Reconstructor is pure in its output: the same (manifest,
// components) MUST produce byte-identical CandidateOutput.Bytes on
// repeated invocation. The deterministic MVP enforces this by
// construction; V2 implementations MUST preserve it (modulo the
// ProducedAt wall-clock timestamp, which is the only legitimate source
// of non-determinism in the return value).
type Reconstructor interface {
	Reconstruct(
		ctx context.Context,
		manifest rjm.ReconstructionJobManifest,
		components []ComponentMaterial,
	) (returnpath.CandidateOutput, error)
}

// ComponentMaterial is one already-unsealed component the worker has
// available for reconstruction. The worker receives DisclosureMessage
// envelopes over the wire, unseals them with the manifest-bound
// recipient key, and hands an ordered slice of ComponentMaterial to the
// Reconstructor.
//
// Freeze status. Same as CandidateOutput: R-11 freezes the shape for
// V1; adding a field requires amending 00_Bootstrap_Contracts_Doctrine
// §15 and the frozen-interface test.
type ComponentMaterial struct {
	// ComponentID identifies the component inside the AI Genome. The
	// worker never sees the GenomeID directly; it only sees components
	// by their opaque ID.
	ComponentID ids.ComponentID

	// SequenceIndex is the staged-disclosure order of the component.
	// Must match the manifest's DisclosureIDs order after the vault-side
	// staged sequencer has authorized the disclosures.
	SequenceIndex uint32

	// Plaintext is the component material AFTER unseal. Treated as
	// opaque bytes by the Reconstructor.
	Plaintext []byte
}

// ---- deterministic MVP placeholder -----------------------------------------

// DeterministicReconstructor is the V1 MVP placeholder for the
// generative mechanism in P1/P2. It is NOT a neural-network inference;
// it is a content-addressed digest expansion that is:
//
//   - pure: output depends only on (manifest, components).
//   - deterministic: same inputs → same bytes.
//   - bounded: output length equals manifest.ExpectedOutputMaxBytes.
//   - sensitive: any change to any component plaintext changes the
//     output (property-tested in reconstruction_test.go).
//
// The purpose of this implementation is to give /internal/validation,
// /internal/compute/returnpath, and /internal/integration a stable,
// exerciseable surface so that the release-side and receive-side
// pipelines can be built end-to-end before the production generative
// mechanism lands. When the V2 backend arrives, it swaps in via
// NewReconstructor(clock) with a different implementation; nothing
// else in /internal/compute needs to change.
//
// Internal construction is intentionally simple: we compute a
// SHA-256 over a canonical digest over (manifest.ManifestID ||
// manifest.SessionID || manifest.GenomeID || for each component:
// SequenceIndex || ComponentID || SHA-256(Plaintext)) and then expand
// that digest by iterated SHA-256 into exactly ExpectedOutputMaxBytes
// bytes. That gives us a cryptographically-pure function of the inputs
// at a cost that is trivially understandable in a code review.
type DeterministicReconstructor struct {
	clock shared_time.Clock
}

// NewDeterministicReconstructor builds a DeterministicReconstructor.
// A nil clock is rejected Structurally; a Reconstructor without a Clock
// would fall back to time.Now() and violate the monotonic-clock
// discipline.
func NewDeterministicReconstructor(clock shared_time.Clock) (*DeterministicReconstructor, error) {
	if clock == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"worker: Reconstructor requires a non-nil Clock",
			nil,
		)
	}
	return &DeterministicReconstructor{clock: clock}, nil
}

// Reconstruct implements the R-11 contract for the deterministic MVP.
//
// Error behaviour
//
//   - CategoryStructural when inputs are malformed (empty components,
//     zero ExpectedOutputMaxBytes, duplicate ComponentID).
//   - CategoryOperational when the context is already cancelled before
//     any work is done (the worker loop in cmd/acp-compute treats that
//     as a deadline-driven abort).
//
// A V2 backend is free to return CategoryIncident for backend-internal
// failures (e.g., attestation failure mid-compute); this MVP has no
// such paths.
func (r *DeterministicReconstructor) Reconstruct(
	ctx context.Context,
	manifest rjm.ReconstructionJobManifest,
	components []ComponentMaterial,
) (returnpath.CandidateOutput, error) {
	var zero returnpath.CandidateOutput

	// Fast-fail on a cancelled context. The worker is permitted to be
	// slow; it is not permitted to ignore cancellation, because that is
	// what the operator uses to cut a run after the manifest deadline.
	if err := ctx.Err(); err != nil {
		return zero, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"worker: context already done at Reconstruct entry",
			err,
		)
	}

	if manifest.ManifestID.IsZero() {
		return zero, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"worker: manifest.ManifestID is empty", nil)
	}
	if manifest.SessionID.IsZero() {
		return zero, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"worker: manifest.SessionID is empty", nil)
	}
	if manifest.ExpectedOutputMaxBytes == 0 {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"worker: manifest.ExpectedOutputMaxBytes must be > 0", nil)
	}
	if len(components) == 0 {
		return zero, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"worker: at least one component material required", nil)
	}

	// Duplicate-ID check. A manifest's DisclosureIDs list is unique by
	// validation, so the unsealed components must also be unique by
	// ComponentID; a dup means the worker's unseal path has bug.
	seen := make(map[ids.ComponentID]struct{}, len(components))
	for _, c := range components {
		if c.ComponentID.IsZero() {
			return zero, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"worker: ComponentMaterial.ComponentID is empty", nil)
		}
		if _, dup := seen[c.ComponentID]; dup {
			return zero, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"worker: duplicate ComponentID in components", nil)
		}
		seen[c.ComponentID] = struct{}{}
	}

	// Canonical digest over the inputs. The digest captures every byte
	// that could legitimately influence the reconstruction; any change
	// to any component, to the manifest identity, or to the session
	// identity must ripple into a different output. We sort components
	// by SequenceIndex (ties broken by ComponentID lexicographic) so
	// that the digest is stable regardless of the caller's slice order —
	// this reflects the doctrinal property that the staged-disclosure
	// sequence is what defines identity, not the in-memory slice order.
	sorted := append([]ComponentMaterial(nil), components...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].SequenceIndex != sorted[j].SequenceIndex {
			return sorted[i].SequenceIndex < sorted[j].SequenceIndex
		}
		return sorted[i].ComponentID < sorted[j].ComponentID
	})

	seed := digestInputs(manifest, sorted)

	// Expand seed into exactly ExpectedOutputMaxBytes bytes by iterated
	// SHA-256: block[i] = SHA-256(seed || uint64be(i)). This is a
	// deliberate MVP construction — not an NIST-approved KDF — because
	// the output is not a key, it is a placeholder reconstruction.
	out := expandDigest(seed, manifest.ExpectedOutputMaxBytes)

	return returnpath.CandidateOutput{
		ManifestID: manifest.ManifestID,
		SessionID:  manifest.SessionID,
		OutputKind: manifest.ExpectedOutputKind,
		Bytes:      out,
		ProducedAt: r.clock.Now(),
	}, nil
}

// digestInputs computes the canonical SHA-256 digest over the fields
// that define a reconstruction's identity. The layout is length-prefixed
// so that string boundaries cannot be shifted by a malicious or buggy
// caller to produce a collision.
func digestInputs(manifest rjm.ReconstructionJobManifest, components []ComponentMaterial) [crypto.HashSize]byte {
	// A running SHA-256 via iterated hashing: we concatenate all fields
	// (each length-prefixed) into a buffer, then SHA-256 the buffer.
	// For a small number of components this is simpler and cheaper than
	// maintaining a streaming hash.
	var buf []byte
	buf = appendLP(buf, []byte(manifest.ManifestID))
	buf = appendLP(buf, []byte(manifest.SessionID))
	buf = appendLP(buf, []byte(manifest.GenomeID))
	buf = appendLP(buf, []byte(manifest.ExpectedOutputKind))

	var nlen [8]byte
	binary.BigEndian.PutUint64(nlen[:], uint64(len(components)))
	buf = append(buf, nlen[:]...)

	for _, c := range components {
		var seq [4]byte
		binary.BigEndian.PutUint32(seq[:], c.SequenceIndex)
		buf = append(buf, seq[:]...)
		buf = appendLP(buf, []byte(c.ComponentID))
		// Hash the plaintext separately so we don't inflate the buffer
		// with multi-megabyte tensor shards.
		pt := crypto.SHA256(c.Plaintext)
		buf = appendLP(buf, pt[:])
	}
	return crypto.SHA256(buf)
}

// appendLP appends a 4-byte big-endian length prefix followed by b.
func appendLP(dst []byte, b []byte) []byte {
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(b)))
	dst = append(dst, ln[:]...)
	dst = append(dst, b...)
	return dst
}

// expandDigest produces exactly n bytes from seed via iterated SHA-256.
// n is the manifest's ExpectedOutputMaxBytes; since that field is
// uint64, we convert carefully.
func expandDigest(seed [crypto.HashSize]byte, n uint64) []byte {
	out := make([]byte, 0, n)
	var counter uint64
	var ctrBuf [8]byte
	for uint64(len(out)) < n {
		binary.BigEndian.PutUint64(ctrBuf[:], counter)
		block := crypto.SHA256(append(append([]byte(nil), seed[:]...), ctrBuf[:]...))
		remaining := n - uint64(len(out))
		if remaining >= uint64(len(block)) {
			out = append(out, block[:]...)
		} else {
			out = append(out, block[:remaining]...)
		}
		counter++
	}
	return out
}

// Compile-time assertion that the deterministic MVP satisfies the
// frozen Reconstructor interface. This is the paired guard with
// frozen_test.go: the test locks the interface SHAPE; this assertion
// locks the implementation's CONFORMANCE to it.
var _ Reconstructor = (*DeterministicReconstructor)(nil)
