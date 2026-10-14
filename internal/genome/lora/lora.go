// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lora reads the model side of a genome — the directory the
// vg_genome worker (workers/genome) writes and `acpctl genome seal`
// seals: genome.json (base model manifest, adapter, recipe) and
// fixtures.json (the fine-tuned model's reference outputs).
//
// It turns the fixtures into the equivalence gate's references, so a
// destination that restored the genome can prove the model came back —
// recomputing each fixture on its own hardware and holding the result to
// the sealed reference (internal/validation/reconstruction).
package lora

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// Schemas the worker writes.
const (
	GenomeSchema   = "vault-genome/lora-genome/v1"
	FixturesSchema = "vault-genome/lora-fixtures/v1"
)

// Genome is genome.json, as far as the gate needs it.
type Genome struct {
	Schema    string `json:"schema"`
	CreatedAt string `json:"created_at"`
	Base      struct {
		Name     string `json:"name"`
		Manifest struct {
			Files  map[string]string `json:"files"`
			Digest string            `json:"digest"`
		} `json:"manifest"`
	} `json:"base"`
	Adapter struct {
		Dir           string   `json:"dir"`
		Format        string   `json:"format"`
		R             int      `json:"r"`
		Alpha         float64  `json:"alpha"`
		Targets       []string `json:"targets"`
		Parameters    int64    `json:"parameters"`
		WeightsSHA256 string   `json:"weights_sha256"`
	} `json:"adapter"`
	Recipe struct {
		Steps        int       `json:"steps"`
		Seed         int64     `json:"seed"`
		Threads      int       `json:"threads"`
		Losses       []float64 `json:"losses"`
		TrainSeconds float64   `json:"train_seconds"`
		// Device and Dtype are where and in what the base computed when
		// the fixtures were recorded (workers/genome); a genome that
		// predates them is float32 on the CPU.
		Device string `json:"device"`
		Dtype  string `json:"dtype"`
	} `json:"recipe"`
	Fixtures struct {
		File     string `json:"file"`
		SHA256   string `json:"sha256"`
		Count    int    `json:"count"`
		Critical int    `json:"critical"`
		TopK     int    `json:"top_k"`
		// Integer describes the integer door's references the fixtures
		// carry (workers/genome, integer.py): the scheme and how far its
		// logits were from the float ones where the genome was made. Nil
		// for a genome without them.
		Integer *IntegerDoor `json:"integer"`
	} `json:"fixtures"`
	Runtime map[string]any `json:"runtime"`
}

// IntegerDoor is what a genome says about its integer door: the scheme
// the references were computed under and the door's measured fidelity to
// the float model.
type IntegerDoor struct {
	Scheme   string `json:"scheme"`
	Fidelity struct {
		Fixtures  int     `json:"fixtures"`
		Top1Same  int     `json:"top1_same"`
		MaxAbsErr float64 `json:"max_abs_err"`
		MaxRelErr float64 `json:"max_rel_err"`
	} `json:"fidelity"`
}

// IntegerDoorScheme is the integer door this build knows.
const IntegerDoorScheme = "vg-integer-door/v1"

type wireTensor struct {
	DType  string `json:"dtype"`
	Shape  []int  `json:"shape"`
	RawB64 string `json:"raw_b64"`
}

type fixtureDoc struct {
	Schema   string `json:"schema"`
	Fixtures []struct {
		ID        string     `json:"id"`
		Critical  bool       `json:"critical"`
		Prompt    string     `json:"prompt"`
		InputIDs  []int      `json:"input_ids"`
		TopKIndex []int      `json:"topk_index"`
		Expected  wireTensor `json:"expected"`
		// ExpectedInteger is the integer door's output for the fixture,
		// absent from a genome made without that door.
		ExpectedInteger *wireTensor `json:"expected_integer"`
	} `json:"fixtures"`
}

// Prompt is the input side of a fixture: the prompt's token ids and the
// reference top-k token indices its output is gathered at. It is what a
// destination needs to recompute the fixture; the expected output stays
// with whoever judges the result.
type Prompt struct {
	ID        string
	InputIDs  []int
	TopKIndex []int
}

// Load reads genome.json in dir and checks it names what it needs.
func Load(dir string) (Genome, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "genome.json"))
	if err != nil {
		return Genome{}, err
	}
	return Parse(raw)
}

// Parse reads a genome.json held in memory and checks it names what it
// needs.
func Parse(raw []byte) (Genome, error) {
	var g Genome
	if err := json.Unmarshal(raw, &g); err != nil {
		return g, fmt.Errorf("lora: genome.json: %w", err)
	}
	switch {
	case g.Schema != GenomeSchema:
		return g, fmt.Errorf("lora: genome.json schema %q, want %q", g.Schema, GenomeSchema)
	case g.Base.Manifest.Digest == "" || len(g.Base.Manifest.Files) == 0:
		return g, errors.New("lora: genome.json names no base model")
	case g.Adapter.WeightsSHA256 == "" || g.Adapter.Dir == "":
		return g, errors.New("lora: genome.json names no adapter")
	case g.Fixtures.File == "" || g.Fixtures.SHA256 == "":
		return g, errors.New("lora: genome.json names no fixtures")
	case !filepath.IsLocal(g.Fixtures.File) || !filepath.IsLocal(g.Adapter.Dir):
		return g, errors.New("lora: genome.json points outside the genome")
	}
	return g, nil
}

// Fixtures reads the fixtures g names, checks them against g's digest,
// and returns them as gate references.
func Fixtures(dir string, g Genome) ([]equivalence.Fixture, error) {
	raw, err := os.ReadFile(filepath.Join(dir, g.Fixtures.File))
	if err != nil {
		return nil, err
	}
	fx, _, err := ParseFixtures(g, raw)
	return fx, err
}

// ParseFixtures reads a fixtures document held in memory, checks it
// against g's digest, and returns the gate references and, in the same
// order, the prompts. A fixture the worker wrote carries its prompt's
// token ids and top-k indices; a fixture without them has no prompt and
// can be judged but not recomputed elsewhere.
func ParseFixtures(g Genome, raw []byte) ([]equivalence.Fixture, []Prompt, error) {
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != g.Fixtures.SHA256 {
		return nil, nil, errors.New("lora: fixtures do not match the genome")
	}
	var doc fixtureDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("lora: fixtures: %w", err)
	}
	if doc.Schema != FixturesSchema {
		return nil, nil, fmt.Errorf("lora: fixtures schema %q, want %q", doc.Schema, FixturesSchema)
	}
	if len(doc.Fixtures) == 0 {
		return nil, nil, errors.New("lora: no fixtures")
	}
	seen := map[string]bool{}
	out := make([]equivalence.Fixture, 0, len(doc.Fixtures))
	prompts := make([]Prompt, 0, len(doc.Fixtures))
	for _, f := range doc.Fixtures {
		if f.ID == "" || seen[f.ID] {
			return nil, nil, fmt.Errorf("lora: fixture id %q missing or repeated", f.ID)
		}
		seen[f.ID] = true
		t, err := f.Expected.tensor(f.ID)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, equivalence.Fixture{ID: f.ID, Critical: f.Critical, Expected: t})
		if len(f.InputIDs) > 0 || len(f.TopKIndex) > 0 {
			prompts = append(prompts, Prompt{ID: f.ID, InputIDs: f.InputIDs, TopKIndex: f.TopKIndex})
		}
	}
	return out, prompts, nil
}

// IntegerFixtures reads the fixtures g names and returns the integer
// door's references, in fixture order; nil, nil for a genome made without
// the integer door.
func IntegerFixtures(dir string, g Genome) ([]equivalence.Fixture, error) {
	raw, err := os.ReadFile(filepath.Join(dir, g.Fixtures.File))
	if err != nil {
		return nil, err
	}
	return ParseIntegerFixtures(g, raw)
}

// ParseIntegerFixtures is IntegerFixtures for a fixtures document held in
// memory: the integer door's references (`expected_integer`), which the
// door is held to byte for byte on any device. A genome that carries them
// says so in genome.json (fixtures.integer, the scheme this build knows)
// and carries one for every fixture; a genome that carries none yields
// nil, nil. Anything in between is refused.
func ParseIntegerFixtures(g Genome, raw []byte) ([]equivalence.Fixture, error) {
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != g.Fixtures.SHA256 {
		return nil, errors.New("lora: fixtures do not match the genome")
	}
	var doc fixtureDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("lora: fixtures: %w", err)
	}
	if doc.Schema != FixturesSchema {
		return nil, fmt.Errorf("lora: fixtures schema %q, want %q", doc.Schema, FixturesSchema)
	}
	var with int
	for _, f := range doc.Fixtures {
		if f.ExpectedInteger != nil {
			with++
		}
	}
	switch {
	case with == 0 && g.Fixtures.Integer == nil:
		return nil, nil
	case g.Fixtures.Integer == nil:
		return nil, errors.New("lora: the fixtures carry integer references genome.json does not describe")
	case with != len(doc.Fixtures):
		return nil, fmt.Errorf("lora: %d of %d fixtures carry an integer reference", with, len(doc.Fixtures))
	case g.Fixtures.Integer.Scheme != IntegerDoorScheme:
		return nil, fmt.Errorf("lora: integer door scheme %q, want %q", g.Fixtures.Integer.Scheme, IntegerDoorScheme)
	}
	out := make([]equivalence.Fixture, 0, len(doc.Fixtures))
	for _, f := range doc.Fixtures {
		t, err := f.ExpectedInteger.tensor(f.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, equivalence.Fixture{ID: f.ID, Critical: f.Critical, Expected: t})
	}
	return out, nil
}

// tensor decodes a wire tensor, refusing an unknown dtype, bad base64 or
// raw bytes that do not fill the shape.
func (w wireTensor) tensor(id string) (equivalence.Tensor, error) {
	var elem int
	switch equivalence.DType(w.DType) {
	case equivalence.F32:
		elem = 4
	case equivalence.F64:
		elem = 8
	default:
		return equivalence.Tensor{}, fmt.Errorf("lora: fixture %s: dtype %q", id, w.DType)
	}
	data, err := base64.StdEncoding.DecodeString(w.RawB64)
	if err != nil {
		return equivalence.Tensor{}, fmt.Errorf("lora: fixture %s: %w", id, err)
	}
	n := 1
	for _, d := range w.Shape {
		if d < 0 {
			return equivalence.Tensor{}, fmt.Errorf("lora: fixture %s: negative dimension", id)
		}
		n *= d
	}
	if len(w.Shape) == 0 {
		n = 0
	}
	if len(data) != n*elem {
		return equivalence.Tensor{}, fmt.Errorf("lora: fixture %s: %d raw bytes do not fill shape %v of %s", id, len(data), w.Shape, w.DType)
	}
	return equivalence.Tensor{DType: equivalence.DType(w.DType), Shape: w.Shape, Raw: data}, nil
}

// IDs lists fixture ids in order.
func IDs(fx []equivalence.Fixture) []string {
	out := make([]string, len(fx))
	for i, f := range fx {
		out[i] = f.ID
	}
	return out
}

// RecipeDtype is the dtype the genome's base computed in: the recipe's, or
// float32 for a genome that predates the field.
func (g Genome) RecipeDtype() string {
	if g.Recipe.Dtype == "" {
		return "float32"
	}
	return g.Recipe.Dtype
}
