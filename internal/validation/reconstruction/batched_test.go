// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// script writes a backend that counts its runs and answers with resp.
func script(t *testing.T, resp string) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	count := filepath.Join(dir, "runs")
	body := filepath.Join(dir, "resp.json")
	require.NoError(t, os.WriteFile(body, []byte(resp), 0o644))
	return []string{"sh", "-c", `cat >/dev/null; echo run >> "` + count + `"; cat "` + body + `"`}, count
}

func outputs(t *testing.T, m map[string]equivalence.Tensor) string {
	t.Helper()
	out := map[string]map[string]any{}
	for id, tsr := range m {
		out[id] = map[string]any{"dtype": tsr.DType, "shape": tsr.Shape, "raw_b64": base64.StdEncoding.EncodeToString(tsr.Raw)}
	}
	b, err := json.Marshal(map[string]any{"outputs": out})
	require.NoError(t, err)
	return string(b)
}

// The model loads once for every fixture and every door.
func TestBatchedBackend_RunsOnceForTheWholeLadder(t *testing.T) {
	a := f64Tensor([]int{2}, []float64{1, 2})
	b := f64Tensor([]int{2}, []float64{3, 4.000001})
	argv, count := script(t, outputs(t, map[string]equivalence.Tensor{"a": a, "b": b}))
	be := &BatchedExternalBackend{Argv: argv, IDs: []string{"a", "b"}}

	fx := []equivalence.Fixture{{ID: "a", Expected: a, Critical: true}, {ID: "b", Expected: f64Tensor([]int{2}, []float64{3, 4})}}
	res, err := Regenerate("g", fx, []Strategy{
		be.Door(0, KindPinnedReplay, "pinned", ExactTolerance, equivalence.StrictPolicy()),
		be.Door(1, KindNativeFloat, "native", equivalence.Tolerance{Atol: 1e-5}, equivalence.StrictPolicy()),
	})
	require.NoError(t, err)
	require.True(t, res.Opened)
	require.Equal(t, 1, res.Rung, "not byte-exact, so the exact door fails and the tolerant one opens")
	require.Equal(t, KindNativeFloat, res.Kind)
	require.Equal(t, equivalence.LevelEquivalent, res.Verdict.Level)
	runs, err := os.ReadFile(count)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(runs), "run"), "one backend run for two doors and two fixtures")
	require.Greater(t, be.Seconds, 0.0)
}

func TestBatchedBackend_FailuresErrorEveryFixture(t *testing.T) {
	a := f64Tensor([]int{1}, []float64{1})
	for name, resp := range map[string]string{
		"missing id": outputs(t, map[string]equivalence.Tensor{"a": a}),
		"not json":   "hello",
		"bad base64": `{"outputs":{"a":{"dtype":"f32","shape":[1],"raw_b64":"!!"},"b":{"dtype":"f32","shape":[1],"raw_b64":"AAAAAA=="}}}`,
		"bad dtype":  `{"outputs":{"a":{"dtype":"i8","shape":[1],"raw_b64":"AA=="},"b":{"dtype":"i8","shape":[1],"raw_b64":"AA=="}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			argv, _ := script(t, resp)
			be := &BatchedExternalBackend{Argv: argv, IDs: []string{"a", "b"}}
			_, err := be.Recompute("a")
			require.Error(t, err)
			_, err2 := be.Recompute("b")
			require.Equal(t, err, err2, "the batch fails once, for every fixture")
		})
	}

	be := &BatchedExternalBackend{Argv: []string{"sh", "-c", "exit 3"}, IDs: []string{"a"}}
	_, err := be.Recompute("a")
	require.ErrorContains(t, err, "failed")

	be = &BatchedExternalBackend{IDs: []string{"a"}}
	_, err = be.Recompute("a")
	require.ErrorContains(t, err, "needs a command")

	argv, _ := script(t, outputs(t, map[string]equivalence.Tensor{"a": a}))
	be = &BatchedExternalBackend{Argv: argv, IDs: []string{"a"}}
	_, err = be.Recompute("zzz")
	require.ErrorContains(t, err, "was not in the batch")
}

func TestBatchedBackend_PassesItsEnvironment(t *testing.T) {
	a := f64Tensor([]int{1}, []float64{1})
	dir := t.TempDir()
	body := filepath.Join(dir, "resp.json")
	require.NoError(t, os.WriteFile(body, []byte(outputs(t, map[string]equivalence.Tensor{"a": a})), 0o644))
	be := &BatchedExternalBackend{
		Argv: []string{"sh", "-c", `cat >/dev/null; [ "$VG_TEST_MARK" = yes ] && cat "` + body + `"`},
		Env:  []string{"VG_TEST_MARK=yes"},
		IDs:  []string{"a"},
	}
	_, err := be.Recompute("a")
	require.NoError(t, err)
}
