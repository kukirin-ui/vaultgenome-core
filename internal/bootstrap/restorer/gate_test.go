// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

func f32b64(vals ...float32) string {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// modelGenome is a model genome as the vg_genome worker writes it: an
// adapter, genome.json and fixtures fx-000 = [1.5, -2] (critical) and
// fx-001 = [0.25, 3].
func modelGenome(t *testing.T) map[string]string {
	t.Helper()
	fx, err := json.Marshal(map[string]any{"schema": "vault-genome/lora-fixtures/v1", "fixtures": []map[string]any{
		{"id": "fx-000", "critical": true, "expected": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(1.5, -2)}},
		{"id": "fx-001", "expected": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(0.25, 3)}},
	}})
	require.NoError(t, err)
	sum := sha256.Sum256(fx)
	g, err := json.Marshal(map[string]any{
		"schema": "vault-genome/lora-genome/v1",
		"base": map[string]any{"name": "Qwen/Qwen2.5-0.5B-Instruct", "manifest": map[string]any{
			"files": map[string]string{"model.safetensors": "sha256:00"}, "digest": "sha256:base"}},
		"adapter":  map[string]any{"dir": "adapter", "weights_sha256": "sha256:cd"},
		"fixtures": map[string]any{"file": "fixtures.json", "sha256": "sha256:" + hex.EncodeToString(sum[:])},
	})
	require.NoError(t, err)
	return map[string]string{
		"genome.json":                       string(g),
		"fixtures.json":                     string(fx),
		"adapter/adapter_model.safetensors": "lora weights",
	}
}

// door returns a gate command answering with outputs for the two
// fixtures, and checks it was pointed at the restored genome.
func door(t *testing.T, a, b []float32) []string {
	t.Helper()
	resp, err := json.Marshal(map[string]any{"outputs": map[string]any{
		"fx-000": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(a...)},
		"fx-001": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(b...)},
	}})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "resp.json")
	require.NoError(t, os.WriteFile(p, resp, 0o644))
	return []string{"sh", "-c", `cat >/dev/null; [ -f "$1/genome.json" ] && cat "` + p + `"`, "door", GenomePlaceholder}
}

func (f *fixture) gated(cfg *GateConfig) *Restorer {
	f.t.Helper()
	r, err := New(Config{BundleDir: f.bundles, RestoreDir: f.restores, Keys: f.keys, Erase: f.keys.EraseSealing,
		TEE: f.tee, Kind: tee.ProviderSimulated, Rescan: 20 * time.Millisecond, Gate: cfg,
		Logger: f.r.log})
	require.NoError(f.t, err)
	return r
}

func restoreWith(t *testing.T, cfg *GateConfig, files map[string]string) (*fixture, string) {
	t.Helper()
	f := newFixture(t)
	f.r = f.gated(cfg)
	blob, dek, kid := f.seal(files)
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
	f.release(kid, dek, "gated")
	f.r.work(context.Background())
	return f, kid
}

func verified(t *testing.T, f *fixture, kid string) receipt.Receipt {
	t.Helper()
	signed, _, ok := f.r.Receipt(kid)
	require.True(t, ok)
	require.NotNil(t, signed.Receipt)
	rc, _, err := receipt.Verify(signed, tee.NewSimulatedVerifier(f.tee.PublicKey(), f.tee.Measurement()))
	require.NoError(t, err)
	return rc
}

// The restored model reproduces its references here: EXACT, in the
// receipt the TEE signs.
func TestGate_ExactModelIsSignedForWithItsVerdict(t *testing.T) {
	f, kid := restoreWith(t, &GateConfig{Command: door(t, []float32{1.5, -2}, []float32{0.25, 3}), Tolerance: equivalence.Tolerance{Atol: 1e-3}}, modelGenome(t))
	rec := f.record(kid)
	require.Equal(t, StateRestored, rec.State, rec.Error)
	require.Equal(t, receipt.GateExact, rec.Gate.Level)
	rc := verified(t, f, kid)
	require.Equal(t, receipt.GateExact, rc.Gate.Level)
	require.Equal(t, "pinned replay", rc.Gate.Door)
	require.Equal(t, 2, rc.Gate.Fixtures)
	require.True(t, rc.Gate.Meets(receipt.GateEquivalent))
}

// Other hardware: the float door opens within tolerance.
func TestGate_EquivalentModel(t *testing.T) {
	f, kid := restoreWith(t, &GateConfig{Command: door(t, []float32{1.5001, -2}, []float32{0.25, 3.0001}), Tolerance: equivalence.Tolerance{Atol: 1e-3}}, modelGenome(t))
	rc := verified(t, f, kid)
	require.Equal(t, receipt.GateEquivalent, rc.Gate.Level)
	require.Equal(t, "native float", rc.Gate.Door)
	require.InDelta(t, 1e-4, rc.Gate.MaxAbsErr, 1e-5)
	require.Equal(t, 1e-3, rc.Gate.Atol)
}

// A model whose outputs miss: restored, signed for as FAIL, so the source
// can see it did not come back right.
func TestGate_FailingModelIsSignedForAsFail(t *testing.T) {
	f, kid := restoreWith(t, &GateConfig{Command: door(t, []float32{9, -2}, []float32{0.25, 3}), Tolerance: equivalence.Tolerance{Atol: 1e-3}}, modelGenome(t))
	rec := f.record(kid)
	require.Equal(t, StateGateFailed, rec.State)
	rc := verified(t, f, kid)
	require.Equal(t, receipt.GateFail, rc.Gate.Level)
	require.False(t, rc.Gate.Meets(receipt.GateEquivalent))
	require.InDelta(t, 7.5, rc.Gate.MaxAbsErr, 1e-6)

	// A restarted daemon still says gate_failed.
	again := f.gated(&GateConfig{Command: []string{"true"}})
	_, rec2, ok := again.Receipt(kid)
	require.True(t, ok)
	require.Equal(t, StateGateFailed, rec2.State)
}

// A backend that cannot run says nothing about the model: without a
// required gate the restore is signed for without a verdict; with one,
// it fails and nothing is signed.
func TestGate_BackendThatCannotRun(t *testing.T) {
	broken := []string{"sh", "-c", "exit 7"}
	f, kid := restoreWith(t, &GateConfig{Command: broken}, modelGenome(t))
	require.Equal(t, StateRestored, f.record(kid).State)
	require.Nil(t, verified(t, f, kid).Gate)

	f, kid = restoreWith(t, &GateConfig{Command: broken, Required: true}, modelGenome(t))
	rec := f.record(kid)
	require.Equal(t, StateFailed, rec.State)
	require.Contains(t, rec.Error, "could not run")
	signed, _, _ := f.r.Receipt(kid)
	require.Nil(t, signed.Receipt)
}

// A genome with no model fixtures cannot be gated.
func TestGate_GenomeWithoutAModel(t *testing.T) {
	f, kid := restoreWith(t, &GateConfig{Command: []string{"true"}}, adapter)
	require.Equal(t, StateRestored, f.record(kid).State)
	require.Nil(t, verified(t, f, kid).Gate)

	f, kid = restoreWith(t, &GateConfig{Command: []string{"true"}, Required: true}, adapter)
	rec := f.record(kid)
	require.Equal(t, StateFailed, rec.State)
	require.Contains(t, rec.Error, "no model fixtures")
}
