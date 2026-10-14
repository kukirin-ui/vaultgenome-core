// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gatejob is what the authority and the compute worker exchange for
// a gate job — the job the Return Path carries:
//
//   - the authority opens a sealed genome (internal/genome/bundle), keeps its
//     reference fixtures, and ships the worker the model side of the genome —
//     genome.json and the adapter — plus the fixtures' prompts. Each file is
//     one component, sealed under the session key; component 0 is a
//     Descriptor that names every file, its digest and its component.
//   - the worker checks every file against the descriptor and hands them to
//     the vg_genome door (workers/genome) on stdin as a DoorRequest. The
//     model comes back in memory; nothing reaches the worker's disk. The
//     door answers with a DoorResponse, and the worker returns the outputs
//     as its candidate output, an Output.
//   - the authority holds the outputs to the sealed references with the
//     equivalence gate (internal/validation/reconstruction).
//
// Every document is JSON with a schema string, so a peer speaking another
// version is refused rather than misread. Output is encoded canonically —
// keys sorted, no whitespace — so its size is a function of the fixtures'
// shapes alone (OutputBudget) and two workers computing the same outputs
// return the same bytes.
package gatejob

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// Schemas.
const (
	DescriptorSchema  = "vault-genome/gate-job/v1"
	PromptsSchema     = "vault-genome/door-prompts/v1"
	DoorRequestSchema = "vault-genome/door-request/v1"
	OutputSchema      = "vault-genome/gate-output/v1"
)

// Files every gate job carries, by their path inside the job.
const (
	GenomePath  = "genome.json"  // the genome's own description (internal/genome/lora)
	PromptsPath = "prompts.json" // the fixtures' prompts, a Prompts document
)

// MaxFiles bounds the files one job may carry: a genome is a description,
// an adapter of a few files, and the prompts.
const MaxFiles = 256

var hexDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// File is one file of the job: where it belongs in the genome, what it
// must hash to, and which component carries it.
type File struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"` // hex
	Bytes     int64  `json:"bytes"`
	Component uint32 `json:"component"` // SequenceIndex of the component carrying it; never 0
}

// Descriptor is component 0 of a gate job.
type Descriptor struct {
	Schema   string `json:"schema"`
	GenomeID string `json:"genome_id"`
	Files    []File `json:"files"`
}

// Validate checks the descriptor's shape: schema, a genome id, at least
// the genome and the prompts, local unique paths, well-formed digests, and
// one distinct non-zero component per file.
func (d Descriptor) Validate() error {
	if d.Schema != DescriptorSchema {
		return fmt.Errorf("gatejob: descriptor schema %q, want %q", d.Schema, DescriptorSchema)
	}
	if strings.TrimSpace(d.GenomeID) == "" {
		return errors.New("gatejob: descriptor names no genome")
	}
	if len(d.Files) == 0 {
		return errors.New("gatejob: descriptor lists no files")
	}
	if len(d.Files) > MaxFiles {
		return fmt.Errorf("gatejob: descriptor lists %d files, more than %d", len(d.Files), MaxFiles)
	}
	paths := make(map[string]bool, len(d.Files))
	components := make(map[uint32]bool, len(d.Files))
	for _, f := range d.Files {
		if !localPath(f.Path) {
			return fmt.Errorf("gatejob: file path %q is not a local path", f.Path)
		}
		if paths[f.Path] {
			return fmt.Errorf("gatejob: file %q listed twice", f.Path)
		}
		paths[f.Path] = true
		if !hexDigestRE.MatchString(f.SHA256) {
			return fmt.Errorf("gatejob: file %q: digest %q is not 64 hex digits", f.Path, f.SHA256)
		}
		if f.Bytes < 0 {
			return fmt.Errorf("gatejob: file %q: negative size", f.Path)
		}
		if f.Component == 0 {
			return fmt.Errorf("gatejob: file %q: component 0 is the descriptor", f.Path)
		}
		if components[f.Component] {
			return fmt.Errorf("gatejob: component %d carries two files", f.Component)
		}
		components[f.Component] = true
	}
	for _, want := range []string{GenomePath, PromptsPath} {
		if !paths[want] {
			return fmt.Errorf("gatejob: descriptor lists no %s", want)
		}
	}
	return nil
}

// EncodeDescriptor renders d after validating it.
func EncodeDescriptor(d Descriptor) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// DecodeDescriptor parses and validates a descriptor.
func DecodeDescriptor(raw []byte) (Descriptor, error) {
	var d Descriptor
	if err := decodeStrict(raw, &d); err != nil {
		return Descriptor{}, fmt.Errorf("gatejob: descriptor: %w", err)
	}
	if err := d.Validate(); err != nil {
		return Descriptor{}, err
	}
	return d, nil
}

// Prompt is the input side of one fixture: the token ids of its prompt
// and the reference top-k token indices the output is gathered at.
type Prompt struct {
	ID        string `json:"id"`
	InputIDs  []int  `json:"input_ids"`
	TopKIndex []int  `json:"topk_index"`
}

// Prompts is the prompts.json document. Integer asks the door for the
// integer door's outputs as well (integer_outputs in its response): the
// job's genome carries integer references the authority holds them to.
type Prompts struct {
	Schema  string   `json:"schema"`
	Prompts []Prompt `json:"prompts"`
	Integer bool     `json:"integer,omitempty"`
}

// Validate checks the schema and that every prompt has a distinct id, at
// least one token and distinct non-negative top-k indices.
func (p Prompts) Validate() error {
	if p.Schema != PromptsSchema {
		return fmt.Errorf("gatejob: prompts schema %q, want %q", p.Schema, PromptsSchema)
	}
	if len(p.Prompts) == 0 {
		return errors.New("gatejob: no prompts")
	}
	seen := make(map[string]bool, len(p.Prompts))
	for _, pr := range p.Prompts {
		if pr.ID == "" {
			return errors.New("gatejob: prompt without id")
		}
		if seen[pr.ID] {
			return fmt.Errorf("gatejob: prompt %q listed twice", pr.ID)
		}
		seen[pr.ID] = true
		if len(pr.InputIDs) == 0 {
			return fmt.Errorf("gatejob: prompt %q has no tokens", pr.ID)
		}
		for _, id := range pr.InputIDs {
			if id < 0 {
				return fmt.Errorf("gatejob: prompt %q has a negative token id", pr.ID)
			}
		}
		if len(pr.TopKIndex) == 0 {
			return fmt.Errorf("gatejob: prompt %q has no top-k indices", pr.ID)
		}
		idx := make(map[int]bool, len(pr.TopKIndex))
		for _, i := range pr.TopKIndex {
			if i < 0 || idx[i] {
				return fmt.Errorf("gatejob: prompt %q: top-k indices must be distinct and non-negative", pr.ID)
			}
			idx[i] = true
		}
	}
	return nil
}

// IDs lists the prompt ids in order.
func (p Prompts) IDs() []string {
	out := make([]string, len(p.Prompts))
	for i, pr := range p.Prompts {
		out[i] = pr.ID
	}
	return out
}

// EncodePrompts renders p after validating it.
func EncodePrompts(p Prompts) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

// DecodePrompts parses and validates a prompts document.
func DecodePrompts(raw []byte) (Prompts, error) {
	var p Prompts
	if err := decodeStrict(raw, &p); err != nil {
		return Prompts{}, fmt.Errorf("gatejob: prompts: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Prompts{}, err
	}
	return p, nil
}

// DoorRequest is what the worker writes to the door's stdin: every file of
// the job, by path. The door reads the genome and the prompts from it and
// loads the adapter from memory. encoding/json carries the bytes base64.
type DoorRequest struct {
	Schema   string            `json:"schema"`
	GenomeID string            `json:"genome_id"`
	Files    map[string][]byte `json:"files"`
}

// EncodeDoorRequest renders a request for the door.
func EncodeDoorRequest(genomeID string, files map[string][]byte) ([]byte, error) {
	if strings.TrimSpace(genomeID) == "" {
		return nil, errors.New("gatejob: door request names no genome")
	}
	if len(files) == 0 {
		return nil, errors.New("gatejob: door request carries no files")
	}
	for p := range files {
		if !localPath(p) {
			return nil, fmt.Errorf("gatejob: file path %q is not a local path", p)
		}
	}
	return json.Marshal(DoorRequest{Schema: DoorRequestSchema, GenomeID: genomeID, Files: files})
}

// DecodeDoorRequest parses a door request (the Go side of what the Python
// door reads; used by test doors and tools).
func DecodeDoorRequest(raw []byte) (DoorRequest, error) {
	var r DoorRequest
	if err := decodeStrict(raw, &r); err != nil {
		return DoorRequest{}, fmt.Errorf("gatejob: door request: %w", err)
	}
	if r.Schema != DoorRequestSchema {
		return DoorRequest{}, fmt.Errorf("gatejob: door request schema %q, want %q", r.Schema, DoorRequestSchema)
	}
	if r.GenomeID == "" || len(r.Files) == 0 {
		return DoorRequest{}, errors.New("gatejob: door request incomplete")
	}
	return r, nil
}

// Tensor is the wire form of an equivalence.Tensor: dtype, shape and the
// little-endian raw bytes, base64.
type Tensor struct {
	DType  string `json:"dtype"`
	Shape  []int  `json:"shape"`
	RawB64 string `json:"raw_b64"`
}

// FromTensor renders t on the wire.
func FromTensor(t equivalence.Tensor) Tensor {
	return Tensor{DType: string(t.DType), Shape: append([]int(nil), t.Shape...), RawB64: base64.StdEncoding.EncodeToString(t.Raw)}
}

// ToTensor decodes w, refusing an unknown dtype, bad base64, or raw bytes
// that do not fill the shape.
func (w Tensor) ToTensor() (equivalence.Tensor, error) {
	var size int
	switch equivalence.DType(w.DType) {
	case equivalence.F32:
		size = 4
	case equivalence.F64:
		size = 8
	default:
		return equivalence.Tensor{}, fmt.Errorf("gatejob: dtype %q", w.DType)
	}
	raw, err := base64.StdEncoding.DecodeString(w.RawB64)
	if err != nil {
		return equivalence.Tensor{}, fmt.Errorf("gatejob: raw_b64: %w", err)
	}
	n := 1
	for _, d := range w.Shape {
		if d < 0 {
			return equivalence.Tensor{}, errors.New("gatejob: negative dimension")
		}
		n *= d
		if n > 1<<28 {
			return equivalence.Tensor{}, errors.New("gatejob: tensor too large")
		}
	}
	if len(w.Shape) == 0 {
		n = 0
	}
	if len(raw) != n*size {
		return equivalence.Tensor{}, fmt.Errorf("gatejob: %d raw bytes do not fill shape %v of %s", len(raw), w.Shape, w.DType)
	}
	return equivalence.Tensor{DType: equivalence.DType(w.DType), Shape: append([]int(nil), w.Shape...), Raw: raw}, nil
}

// DoorResponse is what the door writes to stdout: one output per prompt,
// and, when the prompts asked for the integer door, its outputs too.
type DoorResponse struct {
	Outputs        map[string]Tensor `json:"outputs"`
	IntegerOutputs map[string]Tensor `json:"integer_outputs,omitempty"`
}

// DecodeDoorResponse parses the door's stdout and decodes every tensor:
// the float outputs and the integer door's (nil when the door gave none).
func DecodeDoorResponse(raw []byte) (outputs, integerOutputs map[string]equivalence.Tensor, err error) {
	var r DoorResponse
	if err := json.Unmarshal(bytes.TrimSpace(raw), &r); err != nil {
		return nil, nil, fmt.Errorf("gatejob: door response: %w", err)
	}
	if len(r.Outputs) == 0 {
		return nil, nil, errors.New("gatejob: door response carries no outputs")
	}
	outputs, err = decodeTensors(r.Outputs)
	if err != nil {
		return nil, nil, err
	}
	if len(r.IntegerOutputs) > 0 {
		integerOutputs, err = decodeTensors(r.IntegerOutputs)
		if err != nil {
			return nil, nil, fmt.Errorf("gatejob: integer outputs: %w", err)
		}
	}
	return outputs, integerOutputs, nil
}

// Output is the worker's candidate output: the door's outputs, bound to
// the genome they were computed for, and the integer door's when the job
// asked for them.
type Output struct {
	Schema         string            `json:"schema"`
	GenomeID       string            `json:"genome_id"`
	Outputs        map[string]Tensor `json:"outputs"`
	IntegerOutputs map[string]Tensor `json:"integer_outputs,omitempty"`
}

// EncodeOutput renders the outputs canonically; integerOutputs may be nil.
func EncodeOutput(genomeID string, outputs, integerOutputs map[string]equivalence.Tensor) ([]byte, error) {
	if strings.TrimSpace(genomeID) == "" {
		return nil, errors.New("gatejob: output names no genome")
	}
	if len(outputs) == 0 {
		return nil, errors.New("gatejob: no outputs")
	}
	wire, err := encodeTensors(outputs)
	if err != nil {
		return nil, err
	}
	o := Output{Schema: OutputSchema, GenomeID: genomeID, Outputs: wire}
	if len(integerOutputs) > 0 {
		if o.IntegerOutputs, err = encodeTensors(integerOutputs); err != nil {
			return nil, err
		}
	}
	// encoding/json sorts map keys and emits no whitespace: canonical.
	return json.Marshal(o)
}

func encodeTensors(outputs map[string]equivalence.Tensor) (map[string]Tensor, error) {
	wire := make(map[string]Tensor, len(outputs))
	for id, t := range outputs {
		if id == "" {
			return nil, errors.New("gatejob: output without id")
		}
		wire[id] = FromTensor(t)
	}
	return wire, nil
}

// DecodeOutput parses a candidate output and decodes every tensor; the
// integer door's outputs are nil when the output carries none.
func DecodeOutput(raw []byte) (genomeID string, outputs, integerOutputs map[string]equivalence.Tensor, err error) {
	var o Output
	if err := decodeStrict(raw, &o); err != nil {
		return "", nil, nil, fmt.Errorf("gatejob: output: %w", err)
	}
	if o.Schema != OutputSchema {
		return "", nil, nil, fmt.Errorf("gatejob: output schema %q, want %q", o.Schema, OutputSchema)
	}
	if o.GenomeID == "" {
		return "", nil, nil, errors.New("gatejob: output names no genome")
	}
	if len(o.Outputs) == 0 {
		return "", nil, nil, errors.New("gatejob: output carries no tensors")
	}
	outputs, err = decodeTensors(o.Outputs)
	if err != nil {
		return "", nil, nil, err
	}
	if len(o.IntegerOutputs) > 0 {
		if integerOutputs, err = decodeTensors(o.IntegerOutputs); err != nil {
			return "", nil, nil, fmt.Errorf("gatejob: integer outputs: %w", err)
		}
	}
	return o.GenomeID, outputs, integerOutputs, nil
}

// OutputBudget is the exact size of the Output a worker returns for these
// fixtures (and, when given, the integer references): the encoding
// depends on the ids, dtypes and shapes only, so an output with the
// reference's shapes fills the same number of bytes whatever its values.
// The authority sets the job's ExpectedOutputMaxBytes to it; an output of
// any other size is refused.
func OutputBudget(genomeID string, fixtures, integerFixtures []equivalence.Fixture) (uint64, error) {
	if len(fixtures) == 0 {
		return 0, errors.New("gatejob: no fixtures")
	}
	blank, err := blankOutputs(fixtures)
	if err != nil {
		return 0, err
	}
	var blankInteger map[string]equivalence.Tensor
	if len(integerFixtures) > 0 {
		if blankInteger, err = blankOutputs(integerFixtures); err != nil {
			return 0, err
		}
	}
	out, err := EncodeOutput(genomeID, blank, blankInteger)
	if err != nil {
		return 0, err
	}
	return uint64(len(out)), nil
}

func blankOutputs(fixtures []equivalence.Fixture) (map[string]equivalence.Tensor, error) {
	blank := make(map[string]equivalence.Tensor, len(fixtures))
	for _, f := range fixtures {
		if _, dup := blank[f.ID]; dup {
			return nil, fmt.Errorf("gatejob: fixture %q listed twice", f.ID)
		}
		blank[f.ID] = equivalence.Tensor{DType: f.Expected.DType, Shape: f.Expected.Shape, Raw: make([]byte, len(f.Expected.Raw))}
	}
	return blank, nil
}

// SortedIDs lists the keys of outputs in order.
func SortedIDs(outputs map[string]equivalence.Tensor) []string {
	ids := make([]string, 0, len(outputs))
	for id := range outputs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func decodeTensors(wire map[string]Tensor) (map[string]equivalence.Tensor, error) {
	out := make(map[string]equivalence.Tensor, len(wire))
	for id, w := range wire {
		if id == "" {
			return nil, errors.New("gatejob: output without id")
		}
		t, err := w.ToTensor()
		if err != nil {
			return nil, fmt.Errorf("gatejob: output %q: %w", id, err)
		}
		out[id] = t
	}
	return out, nil
}

// decodeStrict parses one JSON document, refusing unknown fields and
// trailing data.
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// localPath reports whether p is a clean, relative, forward-slash path
// that stays inside its root.
func localPath(p string) bool {
	if p == "" || p == "." || strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') || strings.ContainsRune(p, 0) {
		return false
	}
	if path.Clean(p) != p {
		return false
	}
	return p != ".." && !strings.HasPrefix(p, "../")
}
