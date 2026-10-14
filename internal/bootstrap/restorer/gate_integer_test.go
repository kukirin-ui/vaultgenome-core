// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// modelGenomeWithIntegerDoor is modelGenome with the integer door's
// references beside the float ones: fx-000 = [1.375, -2.125], fx-001 =
// [0.25, 3.0625].
func modelGenomeWithIntegerDoor(t *testing.T) map[string]string {
	t.Helper()
	fx, err := json.Marshal(map[string]any{"schema": "vault-genome/lora-fixtures/v1", "fixtures": []map[string]any{
		{"id": "fx-000", "critical": true,
			"expected":         map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(1.5, -2)},
			"expected_integer": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(1.375, -2.125)}},
		{"id": "fx-001",
			"expected":         map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(0.25, 3)},
			"expected_integer": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(0.25, 3.0625)}},
	}, "integer": map[string]any{"scheme": "vg-integer-door/v1"}})
	require.NoError(t, err)
	sum := sha256.Sum256(fx)
	g, err := json.Marshal(map[string]any{
		"schema": "vault-genome/lora-genome/v1",
		"base": map[string]any{"name": "Qwen/Qwen2.5-0.5B-Instruct", "manifest": map[string]any{
			"files": map[string]string{"model.safetensors": "sha256:00"}, "digest": "sha256:base"}},
		"adapter": map[string]any{"dir": "adapter", "weights_sha256": "sha256:cd"},
		"fixtures": map[string]any{"file": "fixtures.json", "sha256": "sha256:" + hex.EncodeToString(sum[:]),
			"integer": map[string]any{"scheme": "vg-integer-door/v1", "fidelity": map[string]any{"fixtures": 2, "top1_same": 2, "max_abs_err": 0.125}}},
	})
	require.NoError(t, err)
	return map[string]string{
		"genome.json":                       string(g),
		"fixtures.json":                     string(fx),
		"adapter/adapter_model.safetensors": "lora weights",
	}
}

// doorByRequest answers a float request with (a, b) and a request naming
// the integer door with (ia, ib); it checks it was pointed at the
// restored genome.
func doorByRequest(t *testing.T, a, b, ia, ib []float32) []string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, x, y []float32) string {
		resp, err := json.Marshal(map[string]any{"outputs": map[string]any{
			"fx-000": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(x...)},
			"fx-001": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(y...)},
		}})
		require.NoError(t, err)
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, resp, 0o644))
		return p
	}
	fl, in := write("float.json", a, b), write("integer.json", ia, ib)
	return []string{"sh", "-c", `req=$(cat); [ -f "$1/genome.json" ] || exit 7; case "$req" in *'"door":"integer"'*) cat "` + in + `";; *) cat "` + fl + `";; esac`, "door", GenomePlaceholder}
}

// On other hardware the float doors miss the references; the integer
// door meets its own byte for byte, and the receipt says which door
// opened.
func TestGate_IntegerDoorOpensWhenTheFloatDoorsDoNot(t *testing.T) {
	door := doorByRequest(t, []float32{2, -2}, []float32{0.25, 3}, []float32{1.375, -2.125}, []float32{0.25, 3.0625})
	f, kid := restoreWith(t, &GateConfig{Command: door, Tolerance: equivalence.Tolerance{Atol: 1e-3}, Required: true}, modelGenomeWithIntegerDoor(t))
	rec := f.record(kid)
	require.Equal(t, StateRestored, rec.State, rec.Error)
	require.Equal(t, receipt.GateExact, rec.Gate.Level)
	require.Equal(t, "integer", rec.Gate.Door)
	rc := verified(t, f, kid)
	require.Equal(t, receipt.GateExact, rc.Gate.Level)
	require.Equal(t, "integer", rc.Gate.Door)
	require.Equal(t, 2, rc.Gate.Fixtures)
}

// The integer door off by a bit fails at tol 0, and with the float doors
// failing too the restore is signed for as FAIL.
func TestGate_IntegerDoorIsHeldByteForByte(t *testing.T) {
	door := doorByRequest(t, []float32{2, -2}, []float32{0.25, 3}, []float32{1.375, -2.125}, []float32{0.25, 3.0626})
	f, kid := restoreWith(t, &GateConfig{Command: door, Tolerance: equivalence.Tolerance{Atol: 1e-3}, Required: true}, modelGenomeWithIntegerDoor(t))
	rec := f.record(kid)
	require.Equal(t, StateGateFailed, rec.State)
	require.Equal(t, receipt.GateFail, rec.Gate.Level)
	require.Empty(t, rec.Gate.Door)
}

// A genome without integer references never asks the door for them: the
// float doors alone decide.
func TestGate_NoIntegerDoorWithoutReferences(t *testing.T) {
	door := doorByRequest(t, []float32{2, -2}, []float32{0.25, 3}, []float32{1.375, -2.125}, []float32{0.25, 3.0625})
	f, kid := restoreWith(t, &GateConfig{Command: door, Tolerance: equivalence.Tolerance{Atol: 1e-3}, Required: true}, modelGenome(t))
	rec := f.record(kid)
	require.Equal(t, StateGateFailed, rec.State)
	require.Equal(t, receipt.GateFail, rec.Gate.Level)
}
