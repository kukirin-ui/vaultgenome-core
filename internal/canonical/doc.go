// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package canonical holds the platform's deterministic, portable reference
// compute kernels — the "converter" half of the cross-hardware regeneration
// story, paired with the equivalence gate's "funnel" (internal/validation/
// equivalence, ADR 0008).
//
// # The problem it solves
//
// The cross-hardware determinism experiments (docs/testing/
// cross-hardware-determinism.md) established that a genome recomputed with a
// stock BLAS is byte-identical across CPU architectures ONLY under a pinned
// runtime version; a different BLAS build (e.g. a newer numpy pip wheel) makes
// the output diverge across both version and architecture. The equivalence gate
// can *detect* that drift, but detection alone would mean an emergency failover
// onto mismatched hardware fails the gate and the business does not come back
// up. The converter removes the dependence on a fragile external BLAS.
//
// # Determinism ladder
//
// The package implements two rungs of increasing portability guarantee:
//
//   - Rung 2 — float64 reference kernel (kernel.go). Pure Go, single-threaded,
//     fixed ascending-index reduction order, no BLAS, no cross-statement FMA
//     contraction. Bit-identical run to run and across CPU architectures WITHIN A
//     PINNED GO TOOLCHAIN. It is NOT cross-runtime/cross-accelerator byte-
//     identical: its transcendentals are Go's software math.Exp/math.Sqrt, which
//     differ from a CPU libm or a CUDA runtime (exp measured at ~1 ULP on ~6% of
//     values CPU vs GPU — see docs/testing/cross-hardware-determinism.md). So this
//     is a self-contained deterministic REFERENCE, not the production cross-
//     accelerator float path: for byte-identical float across heterogeneous CPUs
//     and GPUs, the reproducible-float rung integrates an external RepDL/ReproBLAS
//     backend (correct-rounded ops + fixed order) — borrowed, not ours; see
//     docs/prior-art-and-attribution.md.
//
//   - Rung 3 — fixed-point path. Integer arithmetic is byte-portable BY
//     CONSTRUCTION: the same integer program yields the same bytes on any
//     platform, under any BLAS, at any thread count. The only portability risk
//     is overflow, which the primitives detect and reject. fixedpoint.go holds
//     the primitives (DotI8, DotQuant); fixedpoint_block.go holds a FULLY
//     INTEGER transformer block — integer GEMM, i-BERT-style integer exp/softmax,
//     and integer isqrt/LayerNorm, with no float arithmetic in the hot path. It
//     is only approximately equal to the original float64 model (quantization
//     error, measured at ~3.6e-3 abs / ~1.2% rel), which is precisely what the
//     gate's EQUIVALENT verdict certifies.
//
// The two rungs compose with the gate: rung 2 targets EXACT (byte-identical) on
// a pinned+attested+verified runtime; rung 3 guarantees the reconstruction
// agrees with itself across hardware (availability) and relies on the gate to
// certify EQUIVALENT against the original.
package canonical
