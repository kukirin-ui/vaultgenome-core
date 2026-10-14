// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker_test

import (
	"context"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// askIntegerDoor rewrites the job's prompts to ask for the integer door
// and re-derives the descriptor, budget and expected output.
func (j *gateJob) askIntegerDoor(t *testing.T) {
	t.Helper()
	j.prompts.Integer = true
	promptsJSON, err := gatejob.EncodePrompts(j.prompts)
	require.NoError(t, err)
	j.files[gatejob.PromptsPath] = promptsJSON
	j.rebuild(t)
}

// A job that asks for the integer door gets its outputs beside the float
// ones, canonically encoded, exactly filling the authority's budget.
func TestGenome_IntegerOutputsComeBackWhenAskedFor(t *testing.T) {
	t.Parallel()
	j := newGateJob(t)
	j.askIntegerDoor(t)
	r := doorReconstructor(t, "echo-sum")

	out, err := r.Reconstruct(context.Background(), j.manifest, j.components)
	require.NoError(t, err)
	require.Equal(t, j.expected, out.Bytes)
	require.Equal(t, j.manifest.ExpectedOutputMaxBytes, uint64(len(out.Bytes)), "the budget counts the integer outputs")

	gid, outputs, integer, err := gatejob.DecodeOutput(out.Bytes)
	require.NoError(t, err)
	require.Equal(t, j.genomeID, gid)
	require.Len(t, outputs, 3)
	require.Len(t, integer, 3)
	got := math.Float32frombits(binary.LittleEndian.Uint32(integer["fx-000"].Raw))
	require.Equal(t, integerDoorValue([]int{3, 5, 8}, 7), got)
	require.NotEqual(t, math.Float32frombits(binary.LittleEndian.Uint32(outputs["fx-000"].Raw)), got, "its own arithmetic")
}

// A door that ignores the request for the integer door gives an answer
// the worker refuses: the authority asked for those outputs.
func TestGenome_MissingIntegerOutputsAreRefused(t *testing.T) {
	t.Parallel()
	j := newGateJob(t)
	j.askIntegerDoor(t)
	r := doorReconstructor(t, "no-integer")
	_, err := r.Reconstruct(context.Background(), j.manifest, j.components)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.ErrorContains(t, err, "integer output")
}

// Integer outputs nobody asked for are not returned: the output fills
// the budget the authority set for the float outputs alone.
func TestGenome_UnaskedIntegerOutputsAreDropped(t *testing.T) {
	t.Parallel()
	j := newGateJob(t)
	r := doorReconstructor(t, "unasked-integer")
	out, err := r.Reconstruct(context.Background(), j.manifest, j.components)
	require.NoError(t, err)
	require.Equal(t, j.expected, out.Bytes)
	_, _, integer, err := gatejob.DecodeOutput(out.Bytes)
	require.NoError(t, err)
	require.Nil(t, integer)
}
