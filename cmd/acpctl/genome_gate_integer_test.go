// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// loraGenomeWithIntegerDoor is loraGenome with the integer door's
// references beside the float ones: fx-000 = [1.375, -2.125], fx-001 =
// [0.25, 3.0625].
func loraGenomeWithIntegerDoor(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fx, err := json.Marshal(map[string]any{"schema": "vault-genome/lora-fixtures/v1", "fixtures": []map[string]any{
		{"id": "fx-000", "critical": true,
			"expected":         map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(1.5, -2)},
			"expected_integer": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(1.375, -2.125)}},
		{"id": "fx-001", "critical": false,
			"expected":         map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(0.25, 3)},
			"expected_integer": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(0.25, 3.0625)}},
	}, "integer": map[string]any{"scheme": "vg-integer-door/v1"}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fixtures.json"), fx, 0o644))
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
	require.NoError(t, os.WriteFile(filepath.Join(dir, "genome.json"), g, 0o644))
	return dir
}

// backendByDoor answers a float request with (a, b) and a request naming
// the integer door with (ia, ib).
func backendByDoor(t *testing.T, a, b, ia, ib []float32) []string {
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
	return []string{"sh", "-c", `req=$(cat); case "$req" in *'"door":"integer"'*) cat "` + in + `";; *) cat "` + fl + `";; esac`}
}

type gateOutInteger struct {
	gateOut
	IntegerDoor bool `json:"integer_door"`
}

// Other hardware: the float doors miss the float references by more than
// the tolerance, and the integer door meets its own byte for byte.
func TestGenomeGate_IntegerDoorOpensWhenTheFloatDoorsDoNot(t *testing.T) {
	dir := loraGenomeWithIntegerDoor(t)
	args := append([]string{"--genome", dir, "--atol", "1e-3", "--json", "--"},
		backendByDoor(t, []float32{2, -2}, []float32{0.25, 3}, []float32{1.375, -2.125}, []float32{0.25, 3.0625})...)
	c, stdout, stderr := runGenome(append([]string{"gate"}, args...)...)
	require.Equal(t, 0, c, stderr)
	var out gateOutInteger
	require.NoError(t, json.Unmarshal([]byte(stdout), &out), stdout)
	require.True(t, out.IntegerDoor)
	require.Equal(t, "EXACT", out.Level)
	require.True(t, out.Ladder.Opened)
	require.Equal(t, 2, out.Ladder.Rung)
	require.Equal(t, "fixed-point", out.Ladder.Kind)
	require.Len(t, out.Ladder.Attempts, 3)
	require.Equal(t, "FAIL", out.Ladder.Attempts[0].Level)
	require.Equal(t, "FAIL", out.Ladder.Attempts[1].Level)
	require.Equal(t, "EXACT", out.Ladder.Attempts[2].Level)

	// The integer door off by a bit: nothing opens, exit 5.
	args = append([]string{"--genome", dir, "--atol", "1e-3", "--json", "--"},
		backendByDoor(t, []float32{2, -2}, []float32{0.25, 3}, []float32{1.375, -2.125}, []float32{0.25, 3.0626})...)
	c, stdout, _ = runGenome(append([]string{"gate"}, args...)...)
	require.Equal(t, 5, c)
	require.NoError(t, json.Unmarshal([]byte(stdout), &out), stdout)
	require.False(t, out.Ladder.Opened)
	require.Equal(t, "FAIL", out.Ladder.Attempts[2].Level)

	// A genome without integer references tries two doors only.
	plain := loraGenome(t)
	args = append([]string{"--genome", plain, "--atol", "1e-3", "--json", "--"},
		backendByDoor(t, []float32{2, -2}, []float32{0.25, 3}, []float32{1.375, -2.125}, []float32{0.25, 3.0625})...)
	c, stdout, _ = runGenome(append([]string{"gate"}, args...)...)
	require.Equal(t, 5, c)
	require.NoError(t, json.Unmarshal([]byte(stdout), &out), stdout)
	require.False(t, out.IntegerDoor)
	require.Len(t, out.Ladder.Attempts, 2)
}
