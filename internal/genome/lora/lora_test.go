// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package lora

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

func f32(vals ...float32) string {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// WriteGenome writes a genome directory the way the vg_genome worker
// does, with the given fixtures document; it returns the directory.
func writeGenome(t *testing.T, fixtures map[string]any, mutate func(g map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	fx, err := json.Marshal(fixtures)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fixtures.json"), fx, 0o644))
	sum := sha256.Sum256(fx)
	g := map[string]any{
		"schema":     GenomeSchema,
		"created_at": "2026-09-15T00:00:00Z",
		"base": map[string]any{"name": "tiny", "manifest": map[string]any{
			"files": map[string]string{"model.safetensors": "sha256:" + hex.EncodeToString(make([]byte, 32))}, "digest": "sha256:ab"}},
		"adapter":  map[string]any{"dir": "adapter", "format": "peft-lora", "r": 8, "weights_sha256": "sha256:cd"},
		"recipe":   map[string]any{"steps": 3, "seed": 7, "threads": 1},
		"fixtures": map[string]any{"file": "fixtures.json", "sha256": "sha256:" + hex.EncodeToString(sum[:]), "count": 2},
	}
	if mutate != nil {
		mutate(g)
	}
	raw, err := json.Marshal(g)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "genome.json"), raw, 0o644))
	return dir
}

func twoFixtures() map[string]any {
	return map[string]any{"schema": FixturesSchema, "fixtures": []map[string]any{
		{"id": "fx-000", "critical": true, "prompt": "q0", "expected": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32(1.5, -2)}},
		{"id": "fx-001", "critical": false, "prompt": "q1", "expected": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32(0.25, 3)}},
	}}
}

func TestLoadAndFixtures(t *testing.T) {
	dir := writeGenome(t, twoFixtures(), nil)
	g, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, "tiny", g.Base.Name)
	fx, err := Fixtures(dir, g)
	require.NoError(t, err)
	require.Len(t, fx, 2)
	require.Equal(t, []string{"fx-000", "fx-001"}, IDs(fx))
	require.True(t, fx[0].Critical)
	require.False(t, fx[1].Critical)
	require.Equal(t, equivalence.F32, fx[0].Expected.DType)
	require.Equal(t, []int{2}, fx[0].Expected.Shape)
	require.Equal(t, math.Float32bits(1.5), binary.LittleEndian.Uint32(fx[0].Expected.Raw))
}

func TestLoad_RefusesIncompleteGenomes(t *testing.T) {
	for name, mutate := range map[string]func(g map[string]any){
		"schema":      func(g map[string]any) { g["schema"] = "vault-genome/lora-genome/v0" },
		"no base":     func(g map[string]any) { g["base"] = map[string]any{"name": "x"} },
		"no adapter":  func(g map[string]any) { g["adapter"] = map[string]any{} },
		"no fixtures": func(g map[string]any) { g["fixtures"] = map[string]any{} },
		"escape":      func(g map[string]any) { g["fixtures"].(map[string]any)["file"] = "../fixtures.json" },
		"abs adapter": func(g map[string]any) { g["adapter"].(map[string]any)["dir"] = "/etc" },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeGenome(t, twoFixtures(), mutate))
			require.Error(t, err)
		})
	}
	_, err := Load(t.TempDir())
	require.Error(t, err, "no genome.json")
	bad := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bad, "genome.json"), []byte("{"), 0o644))
	_, err = Load(bad)
	require.Error(t, err)
}

func TestFixtures_RefusesWhatTheGenomeDidNotSeal(t *testing.T) {
	dir := writeGenome(t, twoFixtures(), nil)
	g, err := Load(dir)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fixtures.json"), []byte(`{"schema":"x"}`), 0o644))
	_, err = Fixtures(dir, g)
	require.ErrorContains(t, err, "do not match the genome")

	mk := func(fx map[string]any) (string, Genome) {
		d := writeGenome(t, fx, nil)
		g, err := Load(d)
		require.NoError(t, err)
		return d, g
	}
	for name, fx := range map[string]map[string]any{
		"schema":     {"schema": "vault-genome/lora-fixtures/v0", "fixtures": twoFixtures()["fixtures"]},
		"empty":      {"schema": FixturesSchema, "fixtures": []any{}},
		"duplicate":  {"schema": FixturesSchema, "fixtures": []map[string]any{twoFixtures()["fixtures"].([]map[string]any)[0], twoFixtures()["fixtures"].([]map[string]any)[0]}},
		"no id":      {"schema": FixturesSchema, "fixtures": []map[string]any{{"expected": map[string]any{"dtype": "f32", "shape": []int{1}, "raw_b64": f32(1)}}}},
		"bad dtype":  {"schema": FixturesSchema, "fixtures": []map[string]any{{"id": "a", "expected": map[string]any{"dtype": "i8", "shape": []int{1}, "raw_b64": "AA=="}}}},
		"bad base64": {"schema": FixturesSchema, "fixtures": []map[string]any{{"id": "a", "expected": map[string]any{"dtype": "f32", "shape": []int{1}, "raw_b64": "!!"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			d, g := mk(fx)
			_, err := Fixtures(d, g)
			require.Error(t, err)
		})
	}
	d, g := mk(twoFixtures())
	require.NoError(t, os.Remove(filepath.Join(d, "fixtures.json")))
	_, err = Fixtures(d, g)
	require.Error(t, err)
	d, g = mk(twoFixtures())
	require.NoError(t, os.WriteFile(filepath.Join(d, "fixtures.json"), []byte("{"), 0o644))
	g.Fixtures.SHA256 = "sha256:" + func() string { s := sha256.Sum256([]byte("{")); return hex.EncodeToString(s[:]) }()
	_, err = Fixtures(d, g)
	require.Error(t, err, "digest matches but JSON does not parse")
}

func TestParseFixtures_CarriesPromptsAndChecksShapes(t *testing.T) {
	fx := twoFixtures()
	items := fx["fixtures"].([]map[string]any)
	items[0]["input_ids"] = []int{3, 5, 8}
	items[0]["topk_index"] = []int{7, 1}
	items[1]["input_ids"] = []int{4}
	items[1]["topk_index"] = []int{0, 9}
	dir := writeGenome(t, fx, nil)
	g, err := Load(dir)
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(dir, "fixtures.json"))
	require.NoError(t, err)
	refs, prompts, err := ParseFixtures(g, raw)
	require.NoError(t, err)
	require.Len(t, refs, 2)
	require.Equal(t, []Prompt{
		{ID: "fx-000", InputIDs: []int{3, 5, 8}, TopKIndex: []int{7, 1}},
		{ID: "fx-001", InputIDs: []int{4}, TopKIndex: []int{0, 9}},
	}, prompts)

	// Fixtures written without their prompt side judge but do not travel.
	dir = writeGenome(t, twoFixtures(), nil)
	g, err = Load(dir)
	require.NoError(t, err)
	raw, err = os.ReadFile(filepath.Join(dir, "fixtures.json"))
	require.NoError(t, err)
	_, prompts, err = ParseFixtures(g, raw)
	require.NoError(t, err)
	require.Empty(t, prompts)

	// A reference whose raw bytes do not fill its shape is refused.
	bad := twoFixtures()
	bad["fixtures"].([]map[string]any)[0]["expected"] = map[string]any{"dtype": "f32", "shape": []int{3}, "raw_b64": f32(1, 2)}
	dir = writeGenome(t, bad, nil)
	g, err = Load(dir)
	require.NoError(t, err)
	_, err = Fixtures(dir, g)
	require.ErrorContains(t, err, "do not fill shape")

	// Parse reads the same genome.json Load does.
	genomeJSON, err := os.ReadFile(filepath.Join(dir, "genome.json"))
	require.NoError(t, err)
	parsed, err := Parse(genomeJSON)
	require.NoError(t, err)
	require.Equal(t, g, parsed)
	_, err = Parse([]byte("{"))
	require.Error(t, err)
}
