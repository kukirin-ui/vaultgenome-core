// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// door 0 on a matching runtime reproduces the sealed reference byte-exact and
// opens first, as EXACT — the highest-fidelity outcome.
func TestPinnedReplayDoor_OpensExactFirst(t *testing.T) {
	exp := f64Tensor([]int{2}, []float64{1, 2})
	fx := []equivalence.Fixture{{ID: "a", Expected: exp}}

	pinned := PinnedReplayDoor("pinned-attested", func(id string) (equivalence.Tensor, error) {
		return exp, nil // same runtime → byte-exact
	})
	// A lower door that would also pass, to prove door 0 wins by order.
	lower := Strategy{
		Rung: 3, Kind: KindFixedPoint, Name: "integer",
		Tol: equivalence.Tolerance{Atol: 0.05, Rtol: 0.05}, Pol: equivalence.StrictPolicy(),
		Recompute: func(id string) (equivalence.Tensor, error) { return exp, nil },
	}
	res, err := Regenerate("g", fx, []Strategy{pinned, lower})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if !res.Opened || res.Rung != 0 || res.Kind != KindPinnedReplay {
		t.Fatalf("door 0 must open first as pinned-replay, got %+v", res)
	}
	if res.Verdict.Level != equivalence.LevelExact {
		t.Fatalf("door 0 must be EXACT, got %s", res.Verdict.Level)
	}
}

// door 0 on a drifting runtime FAILs at tol 0 and the descent falls through to
// the fixed-point rung (EQUIVALENT) — lower fidelity, still gated, never wrong.
func TestPinnedReplayDoor_DriftFallsThroughToFixedPoint(t *testing.T) {
	exp := f64Tensor([]int{1}, []float64{1.0})
	fx := []equivalence.Fixture{{ID: "a", Expected: exp}}

	drift := PinnedReplayDoor("pinned-attested", func(id string) (equivalence.Tensor, error) {
		return f64Tensor([]int{1}, []float64{1.0 + 1e-12}), nil // 1-ULP-ish drift
	})
	integer := Strategy{
		Rung: 3, Kind: KindFixedPoint, Name: "integer",
		Tol: equivalence.Tolerance{Atol: 0.05, Rtol: 0.05}, Pol: equivalence.StrictPolicy(),
		Recompute: func(id string) (equivalence.Tensor, error) {
			return f64Tensor([]int{1}, []float64{1.0004}), nil // within tolerance
		},
	}
	res, err := Regenerate("g", fx, []Strategy{drift, integer})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if !res.Opened || res.Kind != KindFixedPoint {
		t.Fatalf("descent should fall through to fixed-point, got %+v", res)
	}
	if len(res.Attempts) != 2 || res.Attempts[0].Rung != 0 || res.Attempts[0].Level != equivalence.LevelFail {
		t.Fatalf("door 0 must be tried first and FAIL at tol 0, got %+v", res.Attempts)
	}
	if res.Verdict.Level != equivalence.LevelEquivalent {
		t.Fatalf("fixed-point fall-through should be EQUIVALENT, got %s", res.Verdict.Level)
	}
}
