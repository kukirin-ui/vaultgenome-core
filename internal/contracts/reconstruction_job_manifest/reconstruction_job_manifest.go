// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package reconstruction_job_manifest defines the ReconstructionJobManifest
// canonical contract — the description of a bounded compute job handed off
// to the external recovery contour.
//
// # Doctrinal role
//
// Delegated External Compute does not carry continuity authority. The
// manifest is the sole object that tells the external worker what to do,
// which sealed disclosures it will receive, and what shape of result is
// acceptable. The manifest SHA-256 is what the operational validation
// sub-check op.manifest_integrity re-verifies before release
// (docs/doctrine/validation-thresholds.md §4.2).
//
// The manifest is signed by the vault, bound to a specific SessionID, and
// carries a unique ManifestID. The worker never sees the Genome itself;
// it sees sealed payloads that it cannot open without the recipient key
// bound to the manifest.
//
// Corresponds to Hardware Reference Architecture #4 §2. Canonical term:
// "Delegated External Compute job" — docs/doctrine/terminology.md §2.
package reconstruction_job_manifest

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1
)

// OutputKind enumerates the admissible shapes of a CandidateOutput. The
// set is deliberately small for the MVP; extensions require schema bump.
type OutputKind string

const (
	OutputKindBytesFixedLength OutputKind = "bytes/fixed-length"
	OutputKindTokensStream     OutputKind = "tokens/stream"
)

// ReconstructionJobManifest describes one delegated compute job.
type ReconstructionJobManifest struct {
	SchemaVersion uint16            `json:"schema_version"`
	ManifestID    ids.ManifestID    `json:"manifest_id"`
	SessionID     ids.SessionID     `json:"session_id"`
	GenomeID      ids.GenomeID      `json:"genome_id"`
	PolicyVersion ids.PolicyVersion `json:"policy_version"`

	// DisclosureIDs are the staged disclosures this job is authorized to
	// consume, in order. The worker must not accept any disclosure outside
	// this list. Must be non-empty and contain no duplicates.
	DisclosureIDs []ids.DisclosureID `json:"disclosure_ids"`

	// ExpectedOutputKind names the shape of the acceptable CandidateOutput.
	ExpectedOutputKind OutputKind `json:"expected_output_kind"`

	// ExpectedOutputMaxBytes is the upper bound on candidate size. A worker
	// that produces more than this is a protocol violation. Must be > 0.
	ExpectedOutputMaxBytes uint64 `json:"expected_output_max_bytes"`

	// RecipientKeyID is the external-compute binding key. Disclosures are
	// sealed to this key.
	RecipientKeyID ids.KeyID `json:"recipient_key_id"`

	// Deadline is the latest wall-clock moment at which the worker may
	// return a CandidateOutput. Later returns are treated as expired and
	// trigger operational fail. Must be strictly after IssuedAt.
	Deadline time.Time `json:"deadline"`

	IssuedAt     time.Time `json:"issued_at"`
	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`
}
