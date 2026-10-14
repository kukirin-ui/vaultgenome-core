// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package returnpath

import (
	"time"

	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// CandidateOutput is what the external compute worker hands back over
// the Return Path to the vault-side validator. It is NOT a released
// artifact; it is a proposal that the vault-side ReturnPath handler
// will run through operational and validation checks (see
// docs/doctrine/validation-thresholds.md §4.2) before any release can happen.
//
// # Doctrinal role
//
// CandidateOutput crosses the authority boundary. The worker is
// explicitly non-authority (see /cmd/acp-compute/doc.go); the CandidateOutput
// is therefore the worker's only emission, and every field is what the
// vault-side code re-checks:
//
//   - ManifestID / SessionID pin the output to exactly the job the vault
//     authorized. The vault-side handler rejects any CandidateOutput
//     whose (ManifestID, SessionID) does not resolve to an issued
//     ReconstructionJobManifest it holds.
//
//   - OutputKind must match the manifest's ExpectedOutputKind; divergence
//     is an operational fault (shape check is part of
//     op.manifest_integrity, validation thresholds §4.2).
//
//   - Bytes must satisfy len(Bytes) ≤ manifest.ExpectedOutputMaxBytes.
//     The vault-side handler rejects over-budget outputs before any
//     downstream probe sees them, to keep a misbehaving worker from
//     consuming unbounded memory in the validation pipeline.
//
//   - ProducedAt must satisfy manifest.IssuedAt ≤ ProducedAt ≤
//     manifest.Deadline. A late output is operationally expired; the
//     vault-side handler rejects it without running validation, per the
//     §4.2 release-ordering rule.
//
// # Freeze status
//
// This struct is part of the iteration-5 R-11 hardening: the shape of a
// worker emission is frozen for V1 and the V2 generative backend swaps
// only the Reconstructor implementation (see /internal/compute/worker).
// Adding a field to CandidateOutput — or changing an existing field's
// type — requires amending docs/doctrine/bootstrap-contracts.md §15 and
// the /internal/compute/worker frozen test that pins the Reconstructor
// signature.
//
// JSON is explicitly NOT part of the contract here: CandidateOutput is
// handed across an in-process boundary (Return Path inbound handler).
// The serialized form is the Return Path envelope, which is a separate
// contract owned by /internal/compute/returnpath's future wire module.
type CandidateOutput struct {
	// ManifestID is the ReconstructionJobManifest.ManifestID this
	// candidate satisfies. Required; empty ManifestID is a structural
	// protocol violation.
	ManifestID ids.ManifestID

	// SessionID is the TrustedSession.SessionID under which the job
	// was authorized. Required; must equal the manifest's SessionID.
	SessionID ids.SessionID

	// OutputKind echoes the manifest's ExpectedOutputKind so the
	// vault-side handler can check the shape without looking the
	// manifest up again.
	OutputKind rjm.OutputKind

	// Bytes is the worker's proposed reconstruction. Bounded by the
	// manifest's ExpectedOutputMaxBytes; an empty Bytes slice is a
	// protocol violation (the worker must either produce output or
	// return an error, never an empty "success").
	Bytes []byte

	// ProducedAt is the wall-clock moment the worker finished computing
	// this candidate. The vault-side handler compares this against the
	// manifest's Deadline.
	ProducedAt time.Time
}
