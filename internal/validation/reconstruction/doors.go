// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import "github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"

// ExactTolerance is the byte-exact (zero) tolerance: only EXACT passes.
var ExactTolerance = equivalence.Tolerance{}

// PinnedReplayDoor builds the top ladder rung ("door 0"): a byte-exact replay of
// the sealed computation on a pinned + attested runtime of the SAME hardware
// class. It is held to ExactTolerance — EXACT or nothing — so it opens only when
// the recomputation reproduces the sealed reference bit-for-bit.
//
// Attestation gate: the caller includes door 0 ONLY when the destination's
// attestation matches the sealed runtime measurement (same TEE measurement /
// pinned image). On a matching runtime it opens EXACT; if the caller includes it
// on a runtime that turns out to diverge (e.g. a silent BLAS/driver difference),
// it simply FAILs at tol 0 and the descent falls through to the reproducible-
// float and fixed-point rungs — never a wrong model, only a lower-fidelity but
// still-gated one. recompute is backed by the same deterministic kernel that
// produced the sealed reference (run under the attested pinned runtime).
func PinnedReplayDoor(name string, recompute RecomputeFunc) Strategy {
	return Strategy{
		Rung:      0,
		Kind:      KindPinnedReplay,
		Name:      name,
		Recompute: recompute,
		Tol:       ExactTolerance,
		Pol:       equivalence.StrictPolicy(),
	}
}
