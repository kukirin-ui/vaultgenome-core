// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package worker implements the external compute worker loop that cmd/acp-compute
// runs. It receives ReconstructionJobManifest objects over the Return Path
// inbound side, unseals authorized DisclosureMessage payloads with the
// recipient key bound to the manifest, runs the reconstruction, and returns
// a CandidateOutput.
//
// # Doctrinal role
//
// The worker is explicitly non-authority. It does not decide anything
// continuity-relevant; it computes. It cannot import any package under
// /internal/vault (enforced by the import-graph doctrine test).
//
// # Backends
//
// Two Reconstructor implementations live in this package:
//
//   - GenomeReconstructor (genome.go). The production backend, and the
//     only one cmd/acp-compute builds: a gate job's components carry a
//     sealed genome's model side — genome.json, the LoRA adapter, the
//     fixtures' prompts — behind a descriptor (internal/genome/gatejob).
//     The reconstructor checks every file against the descriptor, hands
//     them to the vg_genome door (workers/genome) on stdin, and returns
//     the door's outputs — the restored model's logits at the reference
//     tokens — as the candidate. The base model is public and read from
//     the worker's disk; the adapter stays in memory. The authority
//     judges the outputs against the sealed references with the
//     equivalence gate.
//
//   - DeterministicReconstructor (reconstruction.go). A content-addressed
//     SHA-256 expansion over the canonical digest of (manifest,
//     components): pure, bounded, deterministic. It is the reference the
//     Return Path's own tests and the in-process pipeline demo use to
//     exercise the frozen interface without a model; no binary builds it.
//
// Both satisfy the frozen Reconstructor interface, whose shape frozen_test.go
// pins: a backend drops in behind it, and the daemon loop, the Return Path
// client and the validation surface consume the interface only. See
// docs/doctrine/bootstrap-contracts.md §15 for the freeze policy and
// docs/doctrine/open-decisions-resolved.md R-11 for the doctrinal rationale.
package worker
