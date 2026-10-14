// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package main (cmd/sagvd) is the entry point for the Secure AI Genome
// Vault Daemon — the authority process of the AI Continuity Platform.
//
// # Doctrinal role
//
// sagvd is the sole authority on every continuity-relevant decision:
// trust admission, trusted-session issuance, staged-disclosure
// authorization, validation coordination, and release. No other binary
// in this repository may produce authority artifacts. This constraint
// is enforced by the doctrine tests in /test/doctrine and by the
// import-graph rule that /internal/compute and
// /internal/validation/semantic may not import any package under
// /internal/vault.
//
// Corresponds to the "Neural Seed Vault" daemon in USPTO filing P1
// (April 2026). The canonical name in this repository is the Secure AI
// Genome Vault (SAGV), per docs/doctrine/terminology.md §1.1.
//
// # Phase 1 status
//
// Production-shape authority daemon. Listens on two TCP sockets:
//
//   - vault.listen_address — Return Path inbound: acp-compute workers
//     dial here, complete the 4-frame handshake, and receive one
//     JobRequest per session.
//   - http_api.listen_address — operator REST API: POST /v1/jobs names a
//     sealed genome in genome.bundle_dir and enqueues a gate job for it;
//     GET /v1/jobs/{id} reports status, the genome, and — once the
//     worker has answered — the gate's signed verdict and the worker's
//     CandidateOutput.
//
// Dispatch is single-worker in Phase 1 (one handshake in flight at a
// time). A bounded dispatcher pool lands in Phase 2 when multi-tenant
// parallelism is on the critical path.
//
// A job is a gate job (ADR 0013, genome_job.go) and a RecoveryRequest into
// the nine-stage flow (ADR 0015, internal/vault/orchestration): sagvd admits
// the request at intake, and when a worker that proved its pinned TEE
// identity is ready it decides trust for it (the operator's stop list, the
// policy profile, the attested peer), issues the session, opens the named
// genome with its key and discloses its model side to that session — one
// signed, sealed envelope per component — issues the signed manifest, ships
// the disclosures as the JobRequest, and — after the CandidateOutputFrame's
// signature, manifest binding, output-kind binding and size budget have
// been checked — holds the worker's outputs to the references on two
// dimensions (top-1 agreement; the determinism ladder, byte-exact first,
// then within genome.gate's tolerance), runs the six operational sub-checks
// over the job's own artifacts, signs the release decision and seals the
// flow. A refusal is a signed decision too. Every one of those decisions is
// on audit.log_path first (ADR 0014): a log that cannot take a record stops
// the stage.
//
// # Configuration
//
// Configured via a single JSON file (see cmd/sagvd/config.go for the
// full schema). Top-level keys:
//
//   - vault.listen_address      TCP listener for Return Path inbound
//   - vault.tls                 mTLS material when TLS is enabled
//   - http_api.listen_address   TCP listener for the operator REST API
//   - http_api.bearer_token     optional Bearer token for POST /v1/jobs
//   - tee.provider              "gcp-sev-snp" (the chip signs, reports through
//     configfs-tsm), "gcp-tdx" (a TDX quote through configfs-tsm; the
//     measurement is SHA-384 of MRTD and RTMR0..3, ADR 0018), "azure-cgpu"
//     (an Azure confidential GPU VM: the SEV-SNP report from the vTPM, a
//     TPM quote binding the challenge, NVIDIA's tokens for the H100;
//     gpu_attest_command required, ADR 0019) or "simulated"
//     (+insecure_simulation)
//   - tee.workload_descriptor   names the workload; the simulator hashes it
//   - tee.seed_path             32-byte Ed25519 seed (simulated only)
//   - tee.peer.*                the worker's TEE pin: provider, measurement
//     (48 bytes for SEV-SNP and TDX), amd_cert_chain_path
//     (vcek_cache_dir, amd_kds_url, min_reported_tcb) for
//     a SEV-SNP peer, pcs_cache_dir (pcs_url,
//     acceptable_tcb_statuses) for a TDX peer, the AMD
//     fields plus nras_cache_dir (nras_jwks_url, gpu_policy)
//     for an azure-cgpu peer, or public_key_path for a
//     simulated one
//   - keys.authority_signing    kid + seed for authority-bound signatures (signs gate verdicts)
//   - keys.audit_signing        kid + seed that signs the audit logs
//   - keys.session_sealing      kid + AES-256 key for SealedMaterial (pre-shared with worker)
//   - audit.log_path            the Return Path audit log: every decision about a
//     job, before it takes effect (required with gate jobs)
//   - operator_stop.*           the operator's signed stop list (kid,
//     public_key_path, list_path) trust consults at every admission:
//     stop-all denies every job, a revoked measurement denies that worker
//   - workers.registry_path     JSON file of {kid, signing_pubkey_hex}
//   - genome.bundle_dir         the .genome bundles a job may name, with
//     their key files or escrow envelopes beside them
//   - genome.key_escrow_path    the escrow private key that opens <bundle>.escrow,
//     as `sagvd escrow-provision` wrote it: sealed to this host's TEE and
//     unsealed in memory at start (ADR 0016); a plaintext key is accepted
//     under tee.insecure_simulation only (falls back to
//     crosscloud.key_escrow_path)
//   - tee.sev_guest_device      the sev-guest device the sealer derives its key
//     through (default /dev/sev-guest; gcp-sev-snp only)
//   - genome.gate               atol, rtol, max_non_critical_outliers of the
//     native-float door (defaults 1e-2, 1e-3, 0); genome.gate.bfloat16
//     {atol, rtol}, when set, is the tolerance a genome whose recipe
//     computed in bfloat16 is held to (its logits differ by bfloat16
//     quanta across devices); part of the session's policy version
//   - runtime.*                 handshake / job / http timeouts; max_payload_bytes
//     bounds the model side of one job; evidence_max_age_seconds is how
//     old a worker's Evidence may be when it is handed a job (default: the
//     attestation TTL, 5 min)
//   - health.listen_address     HTTP listener for /healthz /readyz /metrics
//   - log.level, log.format     debug|info|warn|error, json|text
//
// # HTTP surfaces
//
// Operator REST API (configured by http_api.listen_address):
//
//   - POST /v1/jobs                 → {"job_id","request_id","state","genome"}
//     Body: {"genome": {"bundle": "<name in genome.bundle_dir>",
//     "key_file": "<name>" (omit to use <bundle>.escrow)},
//     "deadline_seconds_from_now": N,
//     "request_id", "policy_profile" ("gate"), "requester_identity",
//     "contour": {…} — all optional}
//   - GET  /v1/jobs/{id}            → status, state, genome, the flow (every
//     transition taken; the signed attestation, session, manifest,
//     validation result and release decision; the disclosures' digests),
//     and when released the gate verdict (level, door, attempts,
//     signed_verdict), the top-1 report and the candidate
//
// Health / observability (configured by health.listen_address):
//
//   - GET /healthz → 200 "ok\n" while the process is alive
//   - GET /readyz  → 200 "ready\n" after bootstrap validation
//   - GET /metrics → Prometheus text-format exposition
//
// Metrics family (all `sagvd_*`, backed by
// /internal/observability/metrics):
//
//   - jobs_submitted_total            (counter)
//   - jobs_completed_total{outcome}   (counter: success|reject|fail)
//   - gate_verdicts_total{level}      (counter: EXACT|EQUIVALENT|FAIL|ERROR)
//   - release_decisions_total{decision} (counter: release|refuse|trust_denied)
//   - audit_events_total{kind}        (counter)
//   - sessions_opened_total           (counter)
//   - handshake_failures_total        (counter)
//   - http_requests_total{route,status} (counter)
//   - queue_depth                     (gauge)
//   - last_success_unix               (gauge)
//   - start_unix                      (gauge)
//
// # Operational notes
//
// Graceful shutdown: SIGINT / SIGTERM flip health to 503, drain the
// two HTTP servers, stop accepting new Return Path connections, allow
// the in-flight session to finish (bounded by RuntimeConfig.JobTimeout),
// then Zeroize the in-memory keystore.
//
// # Binaries
//
// Three binaries ship together:
//
//   - sagvd       : THIS authority / vault daemon.
//   - acp-compute : external compute worker.
//   - acpctl      : operator control-plane CLI.
//
// See docs/internal/phase1-v2-plan.md for how these three compose into the
// investor-demo round-trip.
package main
