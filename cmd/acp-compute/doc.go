// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package main (cmd/acp-compute) is the entry point for the external
// compute worker of the AI Continuity Platform.
//
// # Doctrinal role
//
// acp-compute executes delegated reconstruction jobs described by a
// signed ReconstructionJobManifest. It is explicitly NOT an authority.
// It cannot issue a ReleaseDecision, it cannot authorize staged
// disclosure, and it must never import any package under
// /internal/vault beyond the read-only keystore it uses to hold its
// own signing identity and a pre-shared session-sealing key.
//
// The worker receives work only over the Return Path inbound side,
// produces a CandidateOutput only (never a validated or released
// artifact), and emits its result back into the vault-side Return Path
// handler, which performs operational checks before Validation runs.
//
// See docs/doctrine/terminology.md §2 for the canonical definitions of
// "Delegated External Compute," "Return Path," and "Candidate Output."
//
// # Phase 1 status
//
// Production-shape daemon. Dials sagvd over TCP (optionally wrapped
// in mTLS v1.3), runs the 4-frame Return Path handshake with its TEE —
// AMD SEV-SNP through configfs-tsm, or the simulated one (ADR 0014) —
// serves exactly one gate job per session, signs the
// resulting CandidateOutputFrame under an operator-provisioned Ed25519
// key, then closes and reconnects. Reconstruction is
// worker.GenomeReconstructor (/internal/compute/worker, ADR 0013): the
// job's components — a sealed genome's description, its LoRA adapter and
// the prompts of its fixtures — go to the door genome.door.command names
// (python3 -m vg_genome door --stdin-genome --base BASE_DIR), which
// restores the model in memory over the public base model on this host
// and answers the prompts; the outputs are the candidate, and sagvd
// judges them against the sealed references. Nothing of the genome is
// written to this host's disk.
//
// # Configuration
//
// The daemon is configured via a single JSON file (see
// cmd/acp-compute/config.go for the full schema). Top-level keys:
//
//   - vault.address          host:port of sagvd's Return Path listener
//   - vault.tls              mTLS material when TLS is enabled
//   - tee.provider           "gcp-sev-snp" (the chip signs), "gcp-tdx" (a
//     TDX quote; the measurement is SHA-384 of MRTD and RTMR0..3),
//     "azure-cgpu" (an Azure confidential GPU VM: the SEV-SNP report from
//     the vTPM, a TPM quote binding the challenge, NVIDIA's tokens for
//     the H100; gpu_attest_command required) or "simulated"
//     (+insecure_simulation; development and tests)
//   - tee.workload_descriptor names the workload; the simulator hashes it
//   - tee.seed_path          32-byte Ed25519 seed (simulated only)
//   - tee.peer.*             the vault's TEE pin: provider, measurement (48
//     bytes for SEV-SNP and TDX), amd_cert_chain_path for a
//     SEV-SNP vault, pcs_cache_dir (pcs_url,
//     acceptable_tcb_statuses) for a TDX vault, the AMD
//     fields plus nras_cache_dir (nras_jwks_url, gpu_policy)
//     for an azure-cgpu vault, or public_key_path for a
//     simulated one
//   - keys.worker_signing    kid + 32-byte Ed25519 seed for frame signing
//   - keys.session_sealing   kid + 32-byte AES-256 key for unsealing
//   - genome.door.command    the door: argv of the program that restores a
//     genome from stdin and answers its prompts (required)
//   - genome.door.env        extra KEY=VALUE for the door (PYTHONPATH, ...)
//   - genome.door.timeout_seconds  bound on one door run (0: the job's deadline)
//   - runtime.*              dial / handshake / job timeouts and backoff
//   - health.listen_address  HTTP listener for /healthz /readyz /metrics
//   - log.level, log.format  debug|info|warn|error, json|text
//
// # HTTP surface
//
// Exposes three read-only endpoints on the configured health listener:
//
//   - GET /healthz → 200 "ok\n" while the process is alive
//   - GET /readyz  → 200 "ready\n" after the first successful job
//   - GET /metrics → Prometheus text-format exposition
//
// Metrics family (all `acp_compute_*`):
//
//   - jobs_total{outcome=success|reject|fail}
//   - handshake_failures_total{phase=...}
//   - dial_failures_total
//   - sessions_opened_total
//   - last_success_unix
//   - session_active (gauge 0/1)
//   - start_unix
//
// # Operational notes
//
// The daemon is intentionally single-threaded in the dial loop: Phase 1
// processes one job at a time with exponential backoff on failure. A
// bounded pool lands in Phase 2 when multi-tenant parallelism is on
// the critical path.
//
// SIGINT and SIGTERM trigger a graceful shutdown: health flips to 503,
// the in-flight session is allowed to finish (bounded by JobTimeout),
// the HTTP server drains, and the in-memory keystore is zeroized.
//
// # Binaries
//
// Three binaries ship together:
//
//   - acp-compute : THIS daemon (worker side).
//   - sagvd       : the vault / authority side.
//   - acpctl      : operator control-plane CLI.
//
// See docs/internal/phase1-v2-plan.md for how these three compose into the
// investor-demo round-trip.
package main
