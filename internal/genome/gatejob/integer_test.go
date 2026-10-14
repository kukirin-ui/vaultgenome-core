// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package gatejob

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

func TestPrompts_AskForTheIntegerDoor(t *testing.T) {
	p := Prompts{Schema: PromptsSchema, Integer: true, Prompts: []Prompt{{ID: "fx-000", InputIDs: []int{1, 2}, TopKIndex: []int{3}}}}
	raw, err := EncodePrompts(p)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"integer":true`)
	back, err := DecodePrompts(raw)
	require.NoError(t, err)
	require.True(t, back.Integer)

	raw, err = EncodePrompts(Prompts{Schema: PromptsSchema, Prompts: p.Prompts})
	require.NoError(t, err)
	require.NotContains(t, string(raw), "integer", "a job that does not ask says nothing")
}

func TestDoorResponse_CarriesTheIntegerDoorsOutputs(t *testing.T) {
	a := equivalence.Tensor{DType: equivalence.F32, Shape: []int{1}, Raw: []byte{0, 0, 128, 63}}
	b := equivalence.Tensor{DType: equivalence.F32, Shape: []int{1}, Raw: []byte{0, 0, 0, 64}}
	raw, err := json.Marshal(DoorResponse{Outputs: map[string]Tensor{"fx-000": FromTensor(a)}, IntegerOutputs: map[string]Tensor{"fx-000": FromTensor(b)}})
	require.NoError(t, err)
	outputs, integer, err := DecodeDoorResponse(raw)
	require.NoError(t, err)
	require.Equal(t, a.Raw, outputs["fx-000"].Raw)
	require.Equal(t, b.Raw, integer["fx-000"].Raw)

	outputs, integer, err = DecodeDoorResponse([]byte(`{"outputs":{"fx-000":{"dtype":"f32","shape":[1],"raw_b64":"AACAPw=="}}}`))
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	require.Nil(t, integer, "a door that was not asked gives none")

	_, _, err = DecodeDoorResponse([]byte(`{"outputs":{"fx-000":{"dtype":"f32","shape":[1],"raw_b64":"AACAPw=="}},"integer_outputs":{"fx-000":{"dtype":"i8","shape":[1],"raw_b64":"AA=="}}}`))
	require.ErrorContains(t, err, "integer outputs")
}

func TestOutput_CarriesTheIntegerDoorsOutputsInsideTheBudget(t *testing.T) {
	a := equivalence.Tensor{DType: equivalence.F32, Shape: []int{2}, Raw: make([]byte, 8)}
	fixtures := []equivalence.Fixture{{ID: "fx-000", Expected: a}, {ID: "fx-001", Expected: a}}
	outputs := map[string]equivalence.Tensor{"fx-000": a, "fx-001": a}
	integer := map[string]equivalence.Tensor{"fx-000": a, "fx-001": a}

	plain, err := EncodeOutput("genome-1", outputs, nil)
	require.NoError(t, err)
	both, err := EncodeOutput("genome-1", outputs, integer)
	require.NoError(t, err)
	require.Greater(t, len(both), len(plain))
	require.Contains(t, string(both), `"integer_outputs"`)
	require.NotContains(t, string(plain), "integer_outputs")

	budget, err := OutputBudget("genome-1", fixtures, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(len(plain)), budget)
	budgetBoth, err := OutputBudget("genome-1", fixtures, fixtures)
	require.NoError(t, err)
	require.Equal(t, uint64(len(both)), budgetBoth, "the budget is the exact size, integer outputs included")

	gid, got, gotInteger, err := DecodeOutput(both)
	require.NoError(t, err)
	require.Equal(t, "genome-1", gid)
	require.Len(t, got, 2)
	require.Len(t, gotInteger, 2)
	_, _, gotInteger, err = DecodeOutput(plain)
	require.NoError(t, err)
	require.Nil(t, gotInteger)

	bad := `{"schema":"vault-genome/gate-output/v1","genome_id":"g","outputs":{"a":{"dtype":"f32","shape":[1],"raw_b64":"AACAPw=="}},"integer_outputs":{"a":{"dtype":"f32","shape":[2],"raw_b64":"` + base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}) + `"}}}`
	_, _, _, err = DecodeOutput([]byte(bad))
	require.ErrorContains(t, err, "integer outputs")

	_, err = OutputBudget("g", fixtures, []equivalence.Fixture{{ID: "a"}, {ID: "a"}})
	require.ErrorContains(t, err, "listed twice")
}
