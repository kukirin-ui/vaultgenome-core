// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// A door with its own references: the float doors miss the float
// references, the integer door meets its own byte for byte, and the
// ladder records which references it was held to by opening at rung 2.
func TestRegenerate_ADoorMayBeHeldToItsOwnReferences(t *testing.T) {
	float := f64Tensor([]int{2}, []float64{1, 2})
	integer := f64Tensor([]int{2}, []float64{1.25, 1.75})
	fx := []equivalence.Fixture{{ID: "a", Expected: float, Critical: true}}
	own := []equivalence.Fixture{{ID: "a", Expected: integer, Critical: true}}
	floatDoor := func(string) (equivalence.Tensor, error) { return f64Tensor([]int{2}, []float64{1.5, 2.5}), nil }
	integerDoor := func(string) (equivalence.Tensor, error) { return integer, nil }

	res, err := Regenerate("g", fx, []Strategy{
		PinnedReplayDoor("pinned", floatDoor),
		{Rung: 1, Kind: KindNativeFloat, Name: "native", Recompute: floatDoor, Tol: equivalence.Tolerance{Atol: 1e-3}, Pol: equivalence.StrictPolicy()},
		{Rung: 2, Kind: KindFixedPoint, Name: "integer", Recompute: integerDoor, Tol: ExactTolerance, Pol: equivalence.StrictPolicy(), Fixtures: own},
	})
	require.NoError(t, err)
	require.True(t, res.Opened)
	require.Equal(t, 2, res.Rung)
	require.Equal(t, KindFixedPoint, res.Kind)
	require.Equal(t, equivalence.LevelExact, res.Verdict.Level, "byte for byte against its own references")
	require.Len(t, res.Attempts, 3)
	require.Equal(t, equivalence.LevelFail, res.Attempts[0].Level)
	require.Equal(t, equivalence.LevelFail, res.Attempts[1].Level)

	// The same integer door off by one bit fails at tol 0: no door opens.
	drifted := func(string) (equivalence.Tensor, error) { return f64Tensor([]int{2}, []float64{1.25, 1.7500001}), nil }
	res, err = Regenerate("g", fx, []Strategy{
		{Rung: 2, Kind: KindFixedPoint, Name: "integer", Recompute: drifted, Tol: ExactTolerance, Pol: equivalence.StrictPolicy(), Fixtures: own},
	})
	require.NoError(t, err)
	require.False(t, res.Opened)
	require.Equal(t, equivalence.LevelFail, res.Attempts[0].Level)
}

// The batched backend names the door it wants in the request, and the
// integer rung it builds is held to the references it is given.
func TestBatchedBackend_NamesTheIntegerDoorInItsRequest(t *testing.T) {
	dir := t.TempDir()
	seen := filepath.Join(dir, "request.json")
	a := f64Tensor([]int{1}, []float64{7})
	body := filepath.Join(dir, "resp.json")
	require.NoError(t, os.WriteFile(body, []byte(outputs(t, map[string]equivalence.Tensor{"a": a})), 0o644))
	argv := []string{"sh", "-c", `cat > "` + seen + `"; cat "` + body + `"`}

	be := &BatchedExternalBackend{Argv: argv, IDs: []string{"a"}, Which: DoorInteger}
	own := []equivalence.Fixture{{ID: "a", Expected: a}}
	door := be.IntegerDoor(2, "integer", own)
	require.Equal(t, 2, door.Rung)
	require.Equal(t, KindFixedPoint, door.Kind)
	require.Equal(t, ExactTolerance, door.Tol)
	require.Equal(t, own, door.Fixtures)

	res, err := Regenerate("g", []equivalence.Fixture{{ID: "a", Expected: f64Tensor([]int{1}, []float64{6})}}, []Strategy{door})
	require.NoError(t, err)
	require.True(t, res.Opened)
	require.Equal(t, equivalence.LevelExact, res.Verdict.Level)
	req, err := os.ReadFile(seen)
	require.NoError(t, err)
	require.Contains(t, string(req), `"door":"integer"`)
	require.Contains(t, string(req), `"fixture_ids":["a"]`)

	// Without Which the request names no door: the float kernels answer.
	plain := &BatchedExternalBackend{Argv: argv, IDs: []string{"a"}}
	_, err = plain.Recompute("a")
	require.NoError(t, err)
	req, err = os.ReadFile(seen)
	require.NoError(t, err)
	require.False(t, strings.Contains(string(req), "door"))
}
