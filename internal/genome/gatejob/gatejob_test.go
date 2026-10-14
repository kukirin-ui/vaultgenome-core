// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package gatejob

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

func f32(vals ...float32) []byte {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return b
}

func goodDescriptor() Descriptor {
	digest := strings.Repeat("ab", 32)
	return Descriptor{Schema: DescriptorSchema, GenomeID: "genome-0123456789ab-g0-0123456789ab", Files: []File{
		{Path: GenomePath, SHA256: digest, Bytes: 10, Component: 1},
		{Path: "adapter/adapter_config.json", SHA256: digest, Bytes: 20, Component: 2},
		{Path: "adapter/adapter_model.safetensors", SHA256: digest, Bytes: 30, Component: 3},
		{Path: PromptsPath, SHA256: digest, Bytes: 40, Component: 4},
	}}
}

func TestDescriptor_RoundTrip(t *testing.T) {
	raw, err := EncodeDescriptor(goodDescriptor())
	require.NoError(t, err)
	d, err := DecodeDescriptor(raw)
	require.NoError(t, err)
	require.Equal(t, goodDescriptor(), d)
}

func TestDescriptor_RefusesMalformed(t *testing.T) {
	for name, mutate := range map[string]func(d *Descriptor){
		"schema":           func(d *Descriptor) { d.Schema = "vault-genome/gate-job/v0" },
		"no genome":        func(d *Descriptor) { d.GenomeID = " " },
		"no files":         func(d *Descriptor) { d.Files = nil },
		"absolute path":    func(d *Descriptor) { d.Files[1].Path = "/etc/passwd" },
		"escaping path":    func(d *Descriptor) { d.Files[1].Path = "../x" },
		"unclean path":     func(d *Descriptor) { d.Files[1].Path = "adapter//x" },
		"duplicate path":   func(d *Descriptor) { d.Files[1].Path = GenomePath },
		"bad digest":       func(d *Descriptor) { d.Files[0].SHA256 = "abc" },
		"negative size":    func(d *Descriptor) { d.Files[0].Bytes = -1 },
		"component zero":   func(d *Descriptor) { d.Files[0].Component = 0 },
		"shared component": func(d *Descriptor) { d.Files[0].Component = d.Files[1].Component },
		"no genome.json":   func(d *Descriptor) { d.Files[0].Path = "other.json" },
		"no prompts.json":  func(d *Descriptor) { d.Files[3].Path = "other.json" },
		"too many files":   func(d *Descriptor) { d.Files = append(d.Files, make([]File, MaxFiles)...) },
	} {
		t.Run(name, func(t *testing.T) {
			d := goodDescriptor()
			mutate(&d)
			require.Error(t, d.Validate())
			_, err := EncodeDescriptor(d)
			require.Error(t, err)
		})
	}
	_, err := DecodeDescriptor([]byte(`{"schema":"vault-genome/gate-job/v1","genome_id":"g","files":[],"extra":1}`))
	require.Error(t, err, "unknown field")
	_, err = DecodeDescriptor([]byte(`{} {}`))
	require.Error(t, err, "trailing data")
}

func goodPrompts() Prompts {
	return Prompts{Schema: PromptsSchema, Prompts: []Prompt{
		{ID: "fx-000", InputIDs: []int{3, 5, 8}, TopKIndex: []int{7, 1}},
		{ID: "fx-001", InputIDs: []int{4}, TopKIndex: []int{0, 9}},
	}}
}

func TestPrompts_RoundTripAndIDs(t *testing.T) {
	raw, err := EncodePrompts(goodPrompts())
	require.NoError(t, err)
	p, err := DecodePrompts(raw)
	require.NoError(t, err)
	require.Equal(t, goodPrompts(), p)
	require.Equal(t, []string{"fx-000", "fx-001"}, p.IDs())
}

func TestPrompts_RefusesMalformed(t *testing.T) {
	for name, mutate := range map[string]func(p *Prompts){
		"schema":         func(p *Prompts) { p.Schema = "x" },
		"empty":          func(p *Prompts) { p.Prompts = nil },
		"no id":          func(p *Prompts) { p.Prompts[0].ID = "" },
		"duplicate id":   func(p *Prompts) { p.Prompts[1].ID = p.Prompts[0].ID },
		"no tokens":      func(p *Prompts) { p.Prompts[0].InputIDs = nil },
		"negative token": func(p *Prompts) { p.Prompts[0].InputIDs = []int{-1} },
		"no topk":        func(p *Prompts) { p.Prompts[0].TopKIndex = nil },
		"repeated topk":  func(p *Prompts) { p.Prompts[0].TopKIndex = []int{2, 2} },
		"negative topk":  func(p *Prompts) { p.Prompts[0].TopKIndex = []int{-3} },
	} {
		t.Run(name, func(t *testing.T) {
			p := goodPrompts()
			mutate(&p)
			require.Error(t, p.Validate())
		})
	}
}

func TestDoorRequest_RoundTrip(t *testing.T) {
	files := map[string][]byte{GenomePath: []byte(`{}`), "adapter/w.safetensors": {0, 1, 2, 255}}
	raw, err := EncodeDoorRequest("genome-1", files)
	require.NoError(t, err)
	// The bytes travel base64, the form the Python door decodes.
	var probe struct {
		Files map[string]string `json:"files"`
	}
	require.NoError(t, json.Unmarshal(raw, &probe))
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255}), probe.Files["adapter/w.safetensors"])
	r, err := DecodeDoorRequest(raw)
	require.NoError(t, err)
	require.Equal(t, DoorRequestSchema, r.Schema)
	require.Equal(t, "genome-1", r.GenomeID)
	require.Equal(t, files, r.Files)

	_, err = EncodeDoorRequest("", files)
	require.Error(t, err)
	_, err = EncodeDoorRequest("g", nil)
	require.Error(t, err)
	_, err = EncodeDoorRequest("g", map[string][]byte{"../x": {1}})
	require.Error(t, err)
	_, err = DecodeDoorRequest([]byte(`{"schema":"other","genome_id":"g","files":{"a":"AA=="}}`))
	require.Error(t, err)
}

func TestTensor_WireChecksShape(t *testing.T) {
	src := equivalence.Tensor{DType: equivalence.F32, Shape: []int{3}, Raw: f32(1, 2, 3)}
	back, err := FromTensor(src).ToTensor()
	require.NoError(t, err)
	require.Equal(t, src, back)

	for name, w := range map[string]Tensor{
		"dtype":      {DType: "i8", Shape: []int{1}, RawB64: "AA=="},
		"base64":     {DType: "f32", Shape: []int{1}, RawB64: "!!"},
		"short raw":  {DType: "f32", Shape: []int{2}, RawB64: base64.StdEncoding.EncodeToString(f32(1))},
		"long raw":   {DType: "f64", Shape: []int{1}, RawB64: base64.StdEncoding.EncodeToString(make([]byte, 16))},
		"negative":   {DType: "f32", Shape: []int{-1}, RawB64: ""},
		"scalar raw": {DType: "f32", Shape: nil, RawB64: base64.StdEncoding.EncodeToString(f32(1))},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := w.ToTensor()
			require.Error(t, err)
		})
	}
	scalar, err := (Tensor{DType: "f32", Shape: nil, RawB64: ""}).ToTensor()
	require.NoError(t, err)
	require.Empty(t, scalar.Raw)
}

func TestOutput_CanonicalAndBudgetExact(t *testing.T) {
	outputs := map[string]equivalence.Tensor{
		"fx-001": {DType: equivalence.F32, Shape: []int{2}, Raw: f32(0.25, 3)},
		"fx-000": {DType: equivalence.F32, Shape: []int{2}, Raw: f32(1.5, -2)},
	}
	a, err := EncodeOutput("genome-1", outputs, nil)
	require.NoError(t, err)
	b, err := EncodeOutput("genome-1", outputs, nil)
	require.NoError(t, err)
	require.Equal(t, a, b, "canonical: the same outputs encode to the same bytes")
	require.True(t, strings.Index(string(a), `"fx-000"`) < strings.Index(string(a), `"fx-001"`), "keys sorted")
	require.NotContains(t, string(a), "\n")

	gid, got, _, err := DecodeOutput(a)
	require.NoError(t, err)
	require.Equal(t, "genome-1", gid)
	require.Equal(t, outputs, got)

	fixtures := []equivalence.Fixture{
		{ID: "fx-000", Expected: outputs["fx-000"], Critical: true},
		{ID: "fx-001", Expected: outputs["fx-001"]},
	}
	budget, err := OutputBudget("genome-1", fixtures, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(len(a)), budget, "the budget is the exact size of an output with the references' shapes")

	// Different values, same shapes: same size.
	other := map[string]equivalence.Tensor{
		"fx-000": {DType: equivalence.F32, Shape: []int{2}, Raw: f32(9e9, -9e9)},
		"fx-001": {DType: equivalence.F32, Shape: []int{2}, Raw: f32(0, 0)},
	}
	c, err := EncodeOutput("genome-1", other, nil)
	require.NoError(t, err)
	require.Equal(t, len(a), len(c))

	require.Equal(t, []string{"fx-000", "fx-001"}, SortedIDs(outputs))
}

func TestOutput_RefusesMalformed(t *testing.T) {
	_, err := EncodeOutput("", map[string]equivalence.Tensor{"a": {DType: equivalence.F32}}, nil)
	require.Error(t, err)
	_, err = EncodeOutput("g", nil, nil)
	require.Error(t, err)
	_, err = EncodeOutput("g", map[string]equivalence.Tensor{"": {DType: equivalence.F32}}, nil)
	require.Error(t, err)
	_, _, _, err = DecodeOutput([]byte(`{"schema":"vault-genome/gate-output/v0","genome_id":"g","outputs":{"a":{"dtype":"f32","shape":[1],"raw_b64":"AAAAAA=="}}}`))
	require.Error(t, err, "schema")
	_, _, _, err = DecodeOutput([]byte(`{"schema":"vault-genome/gate-output/v1","genome_id":"","outputs":{"a":{"dtype":"f32","shape":[1],"raw_b64":"AAAAAA=="}}}`))
	require.Error(t, err, "genome")
	_, _, _, err = DecodeOutput([]byte(`{"schema":"vault-genome/gate-output/v1","genome_id":"g","outputs":{}}`))
	require.Error(t, err, "empty")
	_, _, _, err = DecodeOutput([]byte(`{"schema":"vault-genome/gate-output/v1","genome_id":"g","outputs":{"a":{"dtype":"f32","shape":[2],"raw_b64":"AAAAAA=="}}}`))
	require.Error(t, err, "shape")
	_, err = OutputBudget("g", nil, nil)
	require.Error(t, err)
	_, err = OutputBudget("g", []equivalence.Fixture{{ID: "a"}, {ID: "a"}}, nil)
	require.Error(t, err)
}

func TestDoorResponse_Decode(t *testing.T) {
	raw := []byte("\n" + `{"outputs":{"fx-000":{"dtype":"f32","shape":[2],"raw_b64":"` + base64.StdEncoding.EncodeToString(f32(1, 2)) + `"}}}` + "\n")
	got, _, err := DecodeDoorResponse(raw)
	require.NoError(t, err)
	require.Equal(t, f32(1, 2), got["fx-000"].Raw)
	_, _, err = DecodeDoorResponse([]byte(`{"outputs":{}}`))
	require.Error(t, err)
	_, _, err = DecodeDoorResponse([]byte(`not json`))
	require.Error(t, err)
	_, _, err = DecodeDoorResponse([]byte(`{"outputs":{"":{"dtype":"f32","shape":[0],"raw_b64":""}}}`))
	require.Error(t, err)
}
