// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func doorRequest(t *testing.T, genome string, promptsJSON string) string {
	t.Helper()
	files := map[string][]byte{
		"genome.json":                       []byte(`{"genome_id":"` + genome + `"}`),
		"adapter/adapter_config.json":       []byte(`{}`),
		"adapter/adapter_model.safetensors": []byte("weights"),
		"prompts.json":                      []byte(promptsJSON),
	}
	raw, err := json.Marshal(map[string]any{"schema": "vault-genome/door-request/v1", "genome_id": genome, "files": files})
	require.NoError(t, err)
	return string(raw)
}

const goodPrompts = `{"schema":"vault-genome/door-prompts/v1","prompts":[{"id":"p1","input_ids":[1,2,3],"topk_index":[0,4]},{"id":"p2","input_ids":[10],"topk_index":[7]}]}`

// The door answers each prompt with the token sum plus half the index, as
// float32 little-endian, which is what the sealed references were built from.
func TestFakeDoorAnswersThePromptsArithmetically(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, run(strings.NewReader(doorRequest(t, "gen:1", goodPrompts)), &out, ""))
	var reply struct {
		Outputs map[string]struct {
			DType  string `json:"dtype"`
			Shape  []int  `json:"shape"`
			RawB64 string `json:"raw_b64"`
		} `json:"outputs"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &reply))
	require.Len(t, reply.Outputs, 2)
	p1 := reply.Outputs["p1"]
	require.Equal(t, "f32", p1.DType)
	require.Equal(t, []int{2}, p1.Shape)
	raw, err := base64.StdEncoding.DecodeString(p1.RawB64)
	require.NoError(t, err)
	require.Len(t, raw, 8)
	require.Equal(t, float32(6), math.Float32frombits(binary.LittleEndian.Uint32(raw[0:])))
	require.Equal(t, float32(8), math.Float32frombits(binary.LittleEndian.Uint32(raw[4:])))
	p2 := reply.Outputs["p2"]
	raw, err = base64.StdEncoding.DecodeString(p2.RawB64)
	require.NoError(t, err)
	require.Equal(t, float32(13.5), math.Float32frombits(binary.LittleEndian.Uint32(raw[0:])))

	out.Reset()
	require.NoError(t, run(strings.NewReader(doorRequest(t, "gen:1", goodPrompts)), &out, "gen:1"), "the genome this door serves")
}

func TestFakeDoorRefusesWhatIsNotItsJob(t *testing.T) {
	rows := []struct {
		name, stdin, expect, fragment string
	}{
		{"not JSON", "{", "", "request:"},
		{"another schema", `{"schema":"vault-genome/door-request/v0","genome_id":"g","files":{}}`, "", `request schema "vault-genome/door-request/v0"`},
		{"missing adapter", `{"schema":"vault-genome/door-request/v1","genome_id":"g","files":{"genome.json":"e30="}}`, "", "lacks adapter/adapter_config.json"},
		{"another genome", doorRequest(t, "gen:2", goodPrompts), "gen:1", "this door serves gen:1"},
		{"prompts not JSON", doorRequest(t, "gen:1", "{"), "", "prompts:"},
		{"prompts of another schema", doorRequest(t, "gen:1", `{"schema":"vault-genome/door-prompts/v0","prompts":[]}`), "", `prompts schema "vault-genome/door-prompts/v0"`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(strings.NewReader(row.stdin), &out, row.expect)
			require.ErrorContains(t, err, row.fragment)
			require.Empty(t, out.Bytes(), "a refused job gets no answer")
		})
	}
	require.Error(t, run(failingReader{}, &bytes.Buffer{}, ""))
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errReadFailed }

var errReadFailed = &readError{}

type readError struct{}

func (*readError) Error() string { return "stdin closed" }
