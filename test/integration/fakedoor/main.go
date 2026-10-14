// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command fakedoor stands in for the vg_genome door in the live-daemon
// tests: a program that reads a gate job on stdin and answers its prompts
// on stdout, speaking the door protocol exactly (internal/genome/gatejob),
// with a model that is arithmetic instead of a network — the logit at
// token idx for a prompt is the prompt's token sum plus half the index.
// The test seals a genome whose references were computed the same way, so
// a worker running this door restores it EXACT; a genome sealed with other
// references fails the gate.
//
// Only the standard library, and only stdin/stdout: the door is a separate
// program to the worker, as the real one is.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
)

type request struct {
	Schema   string            `json:"schema"`
	GenomeID string            `json:"genome_id"`
	Files    map[string][]byte `json:"files"`
}

type prompts struct {
	Schema  string `json:"schema"`
	Prompts []struct {
		ID        string `json:"id"`
		InputIDs  []int  `json:"input_ids"`
		TopKIndex []int  `json:"topk_index"`
	} `json:"prompts"`
}

type tensor struct {
	DType  string `json:"dtype"`
	Shape  []int  `json:"shape"`
	RawB64 string `json:"raw_b64"`
}

func main() {
	if err := run(os.Stdin, os.Stdout, os.Getenv("FAKEDOOR_EXPECT_GENOME")); err != nil {
		fmt.Fprintln(os.Stderr, "fakedoor:", err)
		os.Exit(1)
	}
}

// run answers the gate job on stdin with the arithmetic model; when
// expectGenome is set, a job for any other genome is refused, as a door
// that serves one genome would refuse it.
func run(stdin io.Reader, stdout io.Writer, expectGenome string) error {
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if req.Schema != "vault-genome/door-request/v1" {
		return fmt.Errorf("request schema %q", req.Schema)
	}
	for _, p := range []string{"genome.json", "adapter/adapter_config.json", "adapter/adapter_model.safetensors", "prompts.json"} {
		if len(req.Files[p]) == 0 {
			return fmt.Errorf("request lacks %s", p)
		}
	}
	if expectGenome != "" && req.GenomeID != expectGenome {
		return fmt.Errorf("asked to restore %s, this door serves %s", req.GenomeID, expectGenome)
	}
	var ps prompts
	if err := json.Unmarshal(req.Files["prompts.json"], &ps); err != nil {
		return fmt.Errorf("prompts: %w", err)
	}
	if ps.Schema != "vault-genome/door-prompts/v1" {
		return fmt.Errorf("prompts schema %q", ps.Schema)
	}
	outputs := map[string]tensor{}
	for _, p := range ps.Prompts {
		sum := 0
		for _, id := range p.InputIDs {
			sum += id
		}
		b := make([]byte, 4*len(p.TopKIndex))
		for j, idx := range p.TopKIndex {
			binary.LittleEndian.PutUint32(b[4*j:], math.Float32bits(float32(sum)+float32(idx)*0.5))
		}
		outputs[p.ID] = tensor{DType: "f32", Shape: []int{len(p.TopKIndex)}, RawB64: base64.StdEncoding.EncodeToString(b)}
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"outputs": outputs})
}
