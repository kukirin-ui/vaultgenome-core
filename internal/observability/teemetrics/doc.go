// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package teemetrics instruments TEE Producer / Verifier / Sealer
// implementations with Prometheus-format counters + histograms.
//
// Daemons that want metrics call New(registry) once at startup and
// then wrap each constructed adapter:
//
//	rec := teemetrics.New(registry)
//	producer := rec.WrapProducer(string(provider), rawProducer)
//	verifier := rec.WrapVerifier(string(provider), rawVerifier)
//	sealer := rec.WrapSealer(string(provider), rawSealer)
//
// The wrappers preserve every method's existing semantics — same
// inputs, same outputs, same error categories — and emit:
//
//   - vg_tee_attestation_total{provider, role, result}: count of
//     Quote (role=produce) and Verify (role=verify) calls split by
//     success / error.
//   - vg_tee_attestation_duration_seconds{provider, role}: latency
//     distribution per call. Useful for SLO setting and detecting
//     when MAA / KMS / DCAP-collateral fetches start regressing.
//   - vg_tee_sealing_total{provider, op, result}: count of Seal
//     (op=seal) and Unseal (op=unseal) calls.
//   - vg_tee_sealing_duration_seconds{provider, op}: latency
//     distribution per Sealer call. Particularly useful on AWS Nitro
//     where each Seal/Unseal is a KMS round-trip.
//   - vg_tee_capability_total{provider, available}: count of
//     Capability() calls per provider. Bumped manually via
//     RecordCapability when the daemon first probes available
//     backends at startup.
//
// All metrics are low-cardinality: provider is one of the five known
// constants ("simulated", "aws-nitro", …); role/op are fixed
// vocabularies; result is success|error. Total cardinality across all
// labels is 5 × 2 × 2 = 20 cells max.
//
// # Why a wrapper, not in-adapter instrumentation
//
// Wrapping keeps the TEE adapters' own code path metrics-free. Tests
// that build adapters directly (without a Recorder) keep working.
// Daemons that DO want metrics opt in by wrapping. The wrap pattern
// also means new metrics can be added without modifying adapter code.
package teemetrics
