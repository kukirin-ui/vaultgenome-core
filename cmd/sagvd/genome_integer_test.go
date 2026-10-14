// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// A genome that carries the integer door's references: the job asks the
// worker for that door, budgets its outputs, and judges them byte for
// byte at rung 2 when the float doors do not open.
func TestGenomeJobs_IntegerDoorJudgesTheWorkersIntegerOutputs(t *testing.T) {
	dir := t.TempDir()
	withInteger := sealTestGenome(t, dir, genomeOptions{name: "int", integer: true})
	plain := sealTestGenome(t, dir, genomeOptions{name: "plain"})
	g := newTestGenomeJobs(t, dir, "")

	info, err := g.inspect(genomeRef{Bundle: withInteger.Bundle, KeyFile: withInteger.KeyFile})
	require.NoError(t, err)
	require.Len(t, info.Gate.IntegerFixtures, 3)
	require.Equal(t, info.Gate.Fixtures[0].Critical, info.Gate.IntegerFixtures[0].Critical)
	plainInfo, err := g.inspect(genomeRef{Bundle: plain.Bundle, KeyFile: plain.KeyFile})
	require.NoError(t, err)
	require.Nil(t, plainInfo.Gate.IntegerFixtures)
	require.Greater(t, info.Budget, plainInfo.Budget, "the budget counts the integer outputs")

	// The worker is asked for the integer door.
	comps, err := g.components(info)
	require.NoError(t, err)
	var asked bool
	for _, c := range comps {
		if p, err := gatejob.DecodePrompts(c.Plaintext); err == nil {
			asked = p.Integer
		}
	}
	require.True(t, asked, "prompts.json asks for the integer door")

	// Other hardware: the float outputs miss by half a unit, the integer
	// outputs are the references: the integer door opens EXACT.
	off := map[[2]int]float32{{0, 0}: 0.5}
	view, gateErr := evaluateGate(info.Gate, returnpath.CandidateOutput{Bytes: withInteger.output(t, off, nil, true)})
	require.NoError(t, gateErr)
	require.Equal(t, string(equivalence.LevelExact), view.Level)
	require.Equal(t, doorInteger, view.Door)
	require.Equal(t, 2, view.Rung)
	require.Equal(t, "fixed-point", view.Kind)
	require.Len(t, view.Attempts, 3)
	require.Equal(t, equivalence.LevelFail, view.Attempts[1].Level)

	// The same worker with the float outputs right: the float door opens
	// first and the integer outputs are not consulted.
	view, gateErr = evaluateGate(info.Gate, returnpath.CandidateOutput{Bytes: withInteger.output(t, nil, nil, true)})
	require.NoError(t, gateErr)
	require.Equal(t, doorPinnedReplay, view.Door)
	require.Len(t, view.Attempts, 1)

	// Integer outputs off by a bit fail at tol 0: no door opens.
	view, gateErr = evaluateGate(info.Gate, returnpath.CandidateOutput{Bytes: withInteger.output(t, off, map[[2]int]float32{{2, 1}: 0.0001}, true)})
	require.Error(t, gateErr)
	require.Equal(t, CodeGateFailed, shared_errors.CodeOf(gateErr))
	require.Equal(t, string(equivalence.LevelFail), view.Level)
	require.Len(t, view.Attempts, 3)

	// Integer outputs the worker did not return: not an answer to this job.
	_, gateErr = evaluateGate(info.Gate, returnpath.CandidateOutput{Bytes: withInteger.output(t, off, nil, false)})
	require.Error(t, gateErr)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(gateErr))
	require.ErrorContains(t, gateErr, "integer output")

	// A genome without the references never consults integer outputs.
	view, gateErr = evaluateGate(plainInfo.Gate, returnpath.CandidateOutput{Bytes: plain.output(t, off, nil, true)})
	require.Error(t, gateErr)
	require.Len(t, view.Attempts, 2)
}
