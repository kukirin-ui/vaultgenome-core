// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func f32b64(vals ...float32) string {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// loraGenome writes a restored model genome: genome.json and fixtures
// with references fx-000 = [1.5, -2] (critical) and fx-001 = [0.25, 3].
func loraGenome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fx, err := json.Marshal(map[string]any{"schema": "vault-genome/lora-fixtures/v1", "fixtures": []map[string]any{
		{"id": "fx-000", "critical": true, "expected": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(1.5, -2)}},
		{"id": "fx-001", "critical": false, "expected": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(0.25, 3)}},
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fixtures.json"), fx, 0o644))
	sum := sha256.Sum256(fx)
	g, err := json.Marshal(map[string]any{
		"schema": "vault-genome/lora-genome/v1",
		"base": map[string]any{"name": "Qwen/Qwen2.5-0.5B-Instruct", "manifest": map[string]any{
			"files": map[string]string{"model.safetensors": "sha256:00"}, "digest": "sha256:base"}},
		"adapter":  map[string]any{"dir": "adapter", "weights_sha256": "sha256:cd"},
		"fixtures": map[string]any{"file": "fixtures.json", "sha256": "sha256:" + hex.EncodeToString(sum[:])},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "genome.json"), g, 0o644))
	return dir
}

// backend returns a command line that answers the batch request with
// the given outputs for fx-000 and fx-001.
func backend(t *testing.T, a, b []float32) []string {
	t.Helper()
	resp, err := json.Marshal(map[string]any{"outputs": map[string]any{
		"fx-000": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(a...)},
		"fx-001": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(b...)},
	}})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "resp.json")
	require.NoError(t, os.WriteFile(p, resp, 0o644))
	return []string{"sh", "-c", "cat >/dev/null; cat " + p}
}

type gateOut struct {
	Level    string `json:"level"`
	Fixtures int    `json:"fixtures"`
	Ladder   struct {
		Opened   bool   `json:"opened"`
		Rung     int    `json:"rung"`
		Kind     string `json:"kind"`
		Attempts []struct {
			Level string `json:"level"`
			Err   string `json:"err"`
		} `json:"attempts"`
	} `json:"ladder"`
}

func runGate(t *testing.T, code int, args ...string) gateOut {
	t.Helper()
	c, stdout, stderr := runGenome(append([]string{"gate"}, args...)...)
	require.Equal(t, code, c, stderr)
	var out gateOut
	require.NoError(t, json.Unmarshal([]byte(stdout), &out), stdout)
	return out
}

func TestGenomeGate_Verdicts(t *testing.T) {
	dir := loraGenome(t)

	// The same bytes: the pinned-replay door opens EXACT.
	out := runGate(t, 0, append([]string{"--genome", dir, "--json", "--"}, backend(t, []float32{1.5, -2}, []float32{0.25, 3})...)...)
	require.Equal(t, "EXACT", out.Level)
	require.Equal(t, 0, out.Ladder.Rung)
	require.Equal(t, "pinned-replay", out.Ladder.Kind)
	require.Equal(t, 2, out.Fixtures)

	// Other hardware, the last bits differ: EXACT fails, the float door
	// opens EQUIVALENT.
	out = runGate(t, 0, append([]string{"--genome", dir, "--json", "--"}, backend(t, []float32{1.5001, -2}, []float32{0.25, 3.0002})...)...)
	require.Equal(t, "EQUIVALENT", out.Level)
	require.Equal(t, 1, out.Ladder.Rung)
	require.Equal(t, "native-float", out.Ladder.Kind)
	require.Equal(t, "FAIL", out.Ladder.Attempts[0].Level)

	// A different model: every door fails, exit 5.
	out = runGate(t, 5, append([]string{"--genome", dir, "--json", "--"}, backend(t, []float32{9, -2}, []float32{0.25, 3})...)...)
	require.Equal(t, "FAIL", out.Level)
	require.False(t, out.Ladder.Opened)

	// A non-critical outlier passes only with the operator's allowance;
	// a critical one never does.
	nonCritical := backend(t, []float32{1.5, -2}, []float32{7, 3})
	runGate(t, 5, append([]string{"--genome", dir, "--json", "--"}, nonCritical...)...)
	out = runGate(t, 0, append([]string{"--genome", dir, "--json", "--max-outliers", "1", "--"}, nonCritical...)...)
	require.Equal(t, "EQUIVALENT", out.Level)
	runGate(t, 5, append([]string{"--genome", dir, "--json", "--max-outliers", "1", "--"}, backend(t, []float32{7, -2}, []float32{0.25, 3})...)...)

	// A backend that dies: both doors error, nothing opens.
	out = runGate(t, 5, "--genome", dir, "--json", "--", "sh", "-c", "exit 3")
	require.Len(t, out.Ladder.Attempts, 2)
	require.Contains(t, out.Ladder.Attempts[0].Err, "failed")

	// Text output.
	c, stdout, _ := runGenome(append([]string{"gate", "--genome", dir, "--"}, backend(t, []float32{1.5, -2}, []float32{0.25, 3})...)...)
	require.Equal(t, 0, c)
	require.Contains(t, stdout, "✓ EXACT — 2 fixtures of Qwen/Qwen2.5-0.5B-Instruct")
}

func TestGenomeGate_UsageErrors(t *testing.T) {
	dir := loraGenome(t)
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"no genome":       {[]string{"--", "true"}, 2},
		"no backend":      {[]string{"--genome", dir}, 2},
		"negative atol":   {[]string{"--genome", dir, "--atol", "-1", "--", "true"}, 2},
		"bad flag":        {[]string{"--nope"}, 2},
		"not a genome":    {[]string{"--genome", t.TempDir(), "--", "true"}, 1},
		"edited fixtures": {[]string{"--genome", editedFixtures(t, dir), "--", "true"}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, _ := runGenome(append([]string{"gate"}, tc.args...)...)
			require.Equal(t, tc.code, c)
		})
	}
}

func editedFixtures(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	for _, name := range []string{"genome.json", "fixtures.json"} {
		b, err := os.ReadFile(filepath.Join(src, name))
		require.NoError(t, err)
		if name == "fixtures.json" {
			b = []byte(strings.Replace(string(b), `"critical":true`, `"critical":false`, 1))
		}
		require.NoError(t, os.WriteFile(filepath.Join(dst, name), b, 0o644))
	}
	return dst
}

// With the worker and torch installed (VG_GENOME_WORKER=workers/genome),
// the real door restores a genome the real finetune wrote.
func TestGenomeGate_RealWorker(t *testing.T) {
	worker := os.Getenv("VG_GENOME_WORKER")
	if worker == "" {
		t.Skip("set VG_GENOME_WORKER to the workers/genome directory to run the real door")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	work := t.TempDir()
	setup := exec.Command(py, "-c", `import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))`, filepath.Join(work, "base"), filepath.Join(work, "train.jsonl"))
	setup.Dir, setup.Env = worker, append(os.Environ(), "PYTHONPATH="+worker, "TOKENIZERS_PARALLELISM=false")
	out, err := setup.CombinedOutput()
	require.NoError(t, err, string(out))
	ft := exec.Command(py, "-m", "vg_genome", "finetune", "--base", filepath.Join(work, "base"), "--base-name", "tiny",
		"--data", filepath.Join(work, "train.jsonl"), "--out", filepath.Join(work, "genome"), "--targets", "q_proj,v_proj,lm_head",
		"--steps", "20", "--lr", "1e-2", "--max-len", "32", "--threads", "1", "--top-k", "8", "--new-tokens", "4")
	ft.Dir, ft.Env = worker, setup.Env
	out, err = ft.CombinedOutput()
	require.NoError(t, err, string(out))

	b, k := filepath.Join(work, "g.genome"), filepath.Join(work, "g.key")
	sealDir(t, filepath.Join(work, "genome"), b, k)
	restored := filepath.Join(work, "restored")
	c, _, stderr := runGenome("open", "--bundle", b, "--key-file", k, "--target", restored)
	require.Equal(t, 0, c, stderr)
	res := runGate(t, 0, "--genome", restored, "--json", "--", "env", "PYTHONPATH="+worker, "TOKENIZERS_PARALLELISM=false",
		py, "-m", "vg_genome", "door", "--genome", restored, "--base", filepath.Join(work, "base"))
	require.Equal(t, "EXACT", res.Level)
}
