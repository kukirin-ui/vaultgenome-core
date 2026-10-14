// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package equivalence is the numerical reconstruction-fidelity gate. After a
// genome is restored on a (possibly different) machine, the destination re-runs
// a sealed set of reference fixtures (input id -> expected output tensor) and
// this gate decides whether the reconstructed model may go live:
//
//   - EXACT      every reference output is byte-identical to the sealed expected
//     output (highest assurance: a pinned/deterministic runtime held, so the
//     recomputation reproduced the original bit-for-bit).
//   - EQUIVALENT every output matches within tolerance (allclose:
//     |a-e| <= Atol + Rtol*|e|) but not all byte-identical — the attested
//     functional-equivalence mode used when byte-exactness is not guaranteed
//     across CPU architecture, BLAS build, or dtype-promotion path.
//   - FAIL       any reference output is outside tolerance — fail-closed: the
//     reconstruction is blocked (tampering, a wrong genome, or a broken
//     runtime). Business never goes live on a model it cannot prove is right.
//
// The verdict is bound to the exact fixture set (SHA-256 FixturesHash,
// order-independent) and is Ed25519-signable, so the release authority records a
// non-repudiable proof that the recovered model is exact or provably equivalent.
//
// # Why this exists alongside probe_battery
//
// This gate is deliberately NOT the same instrument as
// /internal/contracts/probe_battery, and the boundary matters:
//
//   - probe_battery answers behavioral SUCCESSION between DIFFERENT genomes
//     (parent -> child under a DerivationMethod). It compares 32-byte
//     RESPONSE HASHES — a probe either round-trips bit-identically or it does
//     not — and aggregates the result as a per-method drift FRACTION (e.g.
//     MaxDriftReconstruct = 8% of capability probes may change hash).
//
//   - equivalence answers numerical RECONSTRUCTION FIDELITY of the SAME genome
//     recomputed on possibly different hardware. It compares raw tensor VALUES
//     under an allclose tolerance.
//
// A hash test cannot express "numerically within 1e-6": a single last-bit
// difference in one float changes the whole response hash, so a numerically
// faithful cross-hardware reconstruction would register as ~100% hash drift and
// blow through probe_battery's 8% DerivationReconstruct budget — even though the
// model is, to any measurable tolerance, the same model. The cross-hardware
// determinism experiments confirmed this: byte-identical output holds only under
// a pinned+attested runtime, and breaks under BLAS build/version drift and
// mixed-dtype promotion. This package is the numerical layer that lets such a
// reconstruction be judged EQUIVALENT (safe) rather than falsely flagged as a
// swap — the "funnel" that guarantees a correct-but-not-bit-identical failover
// still comes up, while a genuinely wrong one is blocked.
//
// The two layers compose: probe_battery's identity probes map onto EXACT/critical
// fixtures here; its capability drift budget is the coarse, hash-level cousin of
// this package's value-level tolerance. See docs/adr/0008-equivalence-gate.md.
package equivalence
