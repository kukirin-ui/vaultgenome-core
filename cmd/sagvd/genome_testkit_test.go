// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// doorValue is the arithmetic a test "model" computes: the logit at token
// idx for a prompt is the prompt's token sum plus half the index. The
// genome's references are built from it, and a right answer reproduces it.
func doorValue(inputIDs []int, idx int) float32 {
	sum := 0
	for _, id := range inputIDs {
		sum += id
	}
	return float32(sum) + float32(idx)*0.5
}

func f32(vals ...float32) []byte {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return b
}

// testGenome is a model genome sealed into a bundle directory the way an
// operator does it, with what a test needs to judge the job built from it.
type testGenome struct {
	Bundle   string // file name of the bundle
	KeyFile  string // file name of the key file ("" when escrowed)
	KeyID    string
	Prompts  gatejob.Prompts
	Fixtures []equivalence.Fixture
	Files    map[string][]byte
}

// genomeOptions shape the sealed genome.
type genomeOptions struct {
	name       string
	escrowPub  string // escrow public key PEM path: seal to escrow instead of a key file
	mutate     func(files map[string][]byte)
	noPrompts  bool
	wrongWeigh bool
	dtype      string // the recipe's dtype ("" = a genome that predates the field)
	integer    bool   // the fixtures carry the integer door's references
}

// sealTestGenome writes the genome the vg_genome worker would write —
// genome.json, adapter/, fixtures.json, data/ — packs it as contentdir
// does, seals it as a v3 bundle and drops bundle + key (or envelope) in
// dir.
func sealTestGenome(t *testing.T, dir string, opts genomeOptions) testGenome {
	t.Helper()
	if opts.name == "" {
		opts.name = "gen-0"
	}
	prompts := gatejob.Prompts{Schema: gatejob.PromptsSchema, Prompts: []gatejob.Prompt{
		{ID: "fx-000", InputIDs: []int{3, 5, 8}, TopKIndex: []int{7, 1, 4}},
		{ID: "fx-001", InputIDs: []int{4, 4}, TopKIndex: []int{0, 9, 2}},
		{ID: "fx-002", InputIDs: []int{12}, TopKIndex: []int{5, 6, 1}},
	}}
	var fixtures []equivalence.Fixture
	var fxDoc []map[string]any
	for i, p := range prompts.Prompts {
		vals := make([]float32, len(p.TopKIndex))
		for j, idx := range p.TopKIndex {
			vals[j] = doorValue(p.InputIDs, idx)
		}
		raw := f32(vals...)
		fixtures = append(fixtures, equivalence.Fixture{ID: p.ID, Critical: i < 2, Expected: equivalence.Tensor{DType: equivalence.F32, Shape: []int{len(vals)}, Raw: raw}})
		entry := map[string]any{
			"id": p.ID, "critical": i < 2, "prompt": "prompt " + p.ID,
			"expected": map[string]any{"dtype": "f32", "shape": []int{len(vals)}, "raw_b64": base64.StdEncoding.EncodeToString(raw)},
			"greedy":   map[string]any{"ids": []int{1, 2}, "text": "x y"},
		}
		if !opts.noPrompts {
			entry["input_ids"], entry["topk_index"] = p.InputIDs, p.TopKIndex
		}
		if opts.integer {
			ivals := make([]float32, len(p.TopKIndex))
			for j, idx := range p.TopKIndex {
				ivals[j] = integerDoorValue(p.InputIDs, idx)
			}
			entry["expected_integer"] = map[string]any{"dtype": "f32", "shape": []int{len(ivals)}, "raw_b64": base64.StdEncoding.EncodeToString(f32(ivals...))}
		}
		fxDoc = append(fxDoc, entry)
	}
	fxTop := map[string]any{"schema": "vault-genome/lora-fixtures/v1", "top_k": 3, "new_tokens": 2, "fixtures": fxDoc}
	genomeFixtures := map[string]any{"file": "fixtures.json", "count": 3, "critical": 2, "top_k": 3}
	if opts.integer {
		desc := map[string]any{"scheme": "vg-integer-door/v1", "fidelity": map[string]any{"fixtures": 3, "top1_same": 3, "max_abs_err": 0.125, "max_rel_err": 0.1}}
		fxTop["integer"], genomeFixtures["integer"] = desc, desc
	}
	fixturesJSON, err := json.Marshal(fxTop)
	require.NoError(t, err)
	weights := make([]byte, 6000)
	rand.New(rand.NewSource(11)).Read(weights)
	weightsSum := sha256.Sum256(weights)
	if opts.wrongWeigh {
		weightsSum[0] ^= 0xff
	}
	fxSum := sha256.Sum256(fixturesJSON)
	genomeFixtures["sha256"] = "sha256:" + hex.EncodeToString(fxSum[:])
	genomeJSON, err := json.Marshal(map[string]any{
		"schema": "vault-genome/lora-genome/v1", "created_at": "2026-09-15T00:00:00Z",
		"base": map[string]any{"name": "tiny-llama", "manifest": map[string]any{
			"files":  map[string]string{"config.json": "sha256:" + hex.EncodeToString(make([]byte, 32)), "model.safetensors": "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32))},
			"digest": "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{2}, 32))}},
		"adapter":  map[string]any{"dir": "adapter", "format": "peft-lora", "r": 8, "alpha": 16.0, "targets": []string{"q_proj", "v_proj"}, "parameters": 1234, "weights_sha256": "sha256:" + hex.EncodeToString(weightsSum[:])},
		"recipe":   recipe(opts.dtype),
		"fixtures": genomeFixtures,
		"runtime":  map[string]any{"torch": "2.7.1"},
	})
	require.NoError(t, err)
	files := map[string][]byte{
		"genome.json":                       genomeJSON,
		"adapter/adapter_config.json":       []byte(`{"peft_type":"LORA","r":8,"lora_alpha":16.0,"target_modules":["q_proj","v_proj"]}`),
		"adapter/adapter_model.safetensors": weights,
		"fixtures.json":                     fixturesJSON,
		"data/train.jsonl":                  []byte(`{"prompt":"p","completion":"c"}` + "\n"),
	}
	if opts.mutate != nil {
		opts.mutate(files)
	}

	// The deterministic tar internal/contentdir writes: sorted, PAX,
	// regular files only.
	var payload bytes.Buffer
	tw := tar.NewWriter(&payload)
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: p, Mode: 0o644, Size: int64(len(files[p])), Typeflag: tar.TypeReg, Format: tar.FormatPAX}))
		_, err := tw.Write(files[p])
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	blob, dek, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentDir, ContentRef: "test-genome"}, payload.Bytes())
	require.NoError(t, err)
	rd, err := bundle.NewReader(bytes.NewReader(blob))
	require.NoError(t, err)
	g := testGenome{Bundle: opts.name + ".genome", KeyID: rd.Header.KeyID, Prompts: prompts, Fixtures: fixtures, Files: files}
	require.NoError(t, os.WriteFile(filepath.Join(dir, g.Bundle), blob, 0o644))
	if opts.escrowPub != "" {
		pem, err := os.ReadFile(opts.escrowPub)
		require.NoError(t, err)
		pub, err := escrow.ParsePublicPEM(pem)
		require.NoError(t, err)
		env, err := escrow.Seal(dek, rd.Header.KeyID, pub)
		require.NoError(t, err)
		raw, err := env.Marshal()
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, g.Bundle+".escrow"), raw, 0o644))
	} else {
		g.KeyFile = opts.name + ".key"
		require.NoError(t, os.WriteFile(filepath.Join(dir, g.KeyFile), dek, 0o600))
	}
	return g
}

// escrowKeyPair writes an escrow private key (0600, raw 32 bytes) and its
// public PEM into dir and returns both paths.
func escrowKeyPair(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	priv, err := escrow.GenerateKey()
	require.NoError(t, err)
	privPath = filepath.Join(dir, "escrow.key")
	require.NoError(t, os.WriteFile(privPath, priv.Bytes(), 0o600))
	pem, err := escrow.PublicPEM(priv.PublicKey())
	require.NoError(t, err)
	pubPath = filepath.Join(dir, "escrow.pem")
	require.NoError(t, os.WriteFile(pubPath, pem, 0o644))
	return privPath, pubPath
}

// rightOutput is the canonical output a worker that restored the model
// gives; perturb changes the value at (prompt index, top-k position).
func (g testGenome) rightOutput(t *testing.T, perturb map[[2]int]float32) []byte {
	t.Helper()
	return g.output(t, perturb, nil, false)
}

// output is rightOutput with, when withInteger, the integer door's
// outputs too, perturbed by integerPerturb.
func (g testGenome) output(t *testing.T, perturb, integerPerturb map[[2]int]float32, withInteger bool) []byte {
	t.Helper()
	outputs := map[string]equivalence.Tensor{}
	var integer map[string]equivalence.Tensor
	if withInteger {
		integer = map[string]equivalence.Tensor{}
	}
	for i, p := range g.Prompts.Prompts {
		vals := make([]float32, len(p.TopKIndex))
		ivals := make([]float32, len(p.TopKIndex))
		for j, idx := range p.TopKIndex {
			vals[j] = doorValue(p.InputIDs, idx) + perturb[[2]int{i, j}]
			ivals[j] = integerDoorValue(p.InputIDs, idx) + integerPerturb[[2]int{i, j}]
		}
		outputs[p.ID] = equivalence.Tensor{DType: equivalence.F32, Shape: []int{len(vals)}, Raw: f32(vals...)}
		if withInteger {
			integer[p.ID] = equivalence.Tensor{DType: equivalence.F32, Shape: []int{len(ivals)}, Raw: f32(ivals...)}
		}
	}
	out, err := gatejob.EncodeOutput(g.KeyID, outputs, integer)
	require.NoError(t, err)
	return out
}

// integerDoorValue is the test integer door's arithmetic: near the float
// door's, never equal to it.
func integerDoorValue(inputIDs []int, idx int) float32 {
	return doorValue(inputIDs, idx) + 0.125
}

// recipe is a test genome's recipe, in dtype when one is named.
func recipe(dtype string) map[string]any {
	r := map[string]any{"data": "data/train.jsonl", "steps": 3, "seed": 7, "threads": 1, "losses": []float64{1, 0.5, 0.25}}
	if dtype != "" {
		r["device"], r["dtype"] = "cuda", dtype
	}
	return r
}
