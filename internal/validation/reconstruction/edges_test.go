// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// replyWith returns an ExternalBackend whose process answers every request
// with the given bytes (which must contain no single quote).
func replyWith(resp string) ExternalBackend {
	return ExternalBackend{Argv: []string{"sh", "-c", "cat >/dev/null; printf '%s' '" + resp + "'"}}
}

// TestExternalBackend_MalformedResponsesAreOperational proves that a
// backend answer the adapter cannot turn into a tensor — not JSON, not
// base64, an unknown dtype — is an Operational refusal naming the defect,
// so the ladder records the door as errored instead of gating garbage.
func TestExternalBackend_MalformedResponsesAreOperational(t *testing.T) {
	cases := map[string]struct {
		resp string
		want string
	}{
		"not json":      {`{"dtype":"f64",`, "malformed JSON"},
		"bad base64":    {`{"dtype":"f64","shape":[1],"raw_b64":"***"}`, "not valid base64"},
		"unknown dtype": {`{"dtype":"int8","shape":[1],"raw_b64":"AA=="}`, "unknown dtype int8"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := replyWith(tc.resp).Recompute("a")
			require.Error(t, err)
			require.Equal(t, equivalence.Tensor{}, got)
			require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestBatchedBackend_LongOutputIsTailed proves that a failing backend's
// output is kept to its last 400 characters in the error, marked as cut,
// so a verbose backend cannot flood the audit record.
func TestBatchedBackend_LongOutputIsTailed(t *testing.T) {
	long := strings.Repeat("x", 450) + "END"
	be := &BatchedExternalBackend{
		Argv: []string{"sh", "-c", "cat >/dev/null; printf '%s' '" + long + "' >&2; exit 2"},
		IDs:  []string{"a"},
	}
	_, err := be.Recompute("a")
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Contains(t, err.Error(), "…"+strings.Repeat("x", 397)+"END")
	require.NotContains(t, err.Error(), strings.Repeat("x", 398)+"END")

	require.Equal(t, "short", tail("short"))
	exact := strings.Repeat("y", 400)
	require.Equal(t, exact, tail(exact), "exactly 400 characters are kept whole")
	require.Equal(t, "…"+strings.Repeat("z", 400), tail("a"+strings.Repeat("z", 400)))
}

// TestLadderToDimensionVerdict proves the ladder-to-contract mapping: an
// opened ladder is the opened verdict's dimension verdict; a closed one is
// a fail with score zero and one error finding per door tried (errored or
// gate-failed, each naming the door and rung) plus the fail-closed finding.
func TestLadderToDimensionVerdict(t *testing.T) {
	g := sealGenome(6, 2)
	opened, err := Regenerate("g", g.fixtures, []Strategy{
		{Rung: 1, Name: "f64", Recompute: f64Door(g.p, g.inputs), Tol: exactTol, Pol: equivalence.StrictPolicy()},
	})
	require.NoError(t, err)
	require.True(t, opened.Opened)
	dv := LadderToDimensionVerdict(opened, 0.9)
	require.Equal(t, ToDimensionVerdict(opened.Verdict, 0.9), dv)
	require.Equal(t, validation_result.VerdictPass, dv.Verdict)
	require.Equal(t, 0.9, dv.Threshold)

	closed := LadderResult{Attempts: []Attempt{
		{Rung: 0, Name: "pinned", Level: attemptError, Err: "backend exited 3"},
		{Rung: 3, Name: "integer", Level: equivalence.LevelFail, MaxAbsErr: 0.25},
	}}
	dv = LadderToDimensionVerdict(closed, 0.9)
	require.Equal(t, validation_result.VerdictFail, dv.Verdict)
	require.Equal(t, 0.0, dv.Score)
	require.Equal(t, 0.9, dv.Threshold)
	require.Len(t, dv.Details, 3)
	for _, f := range dv.Details {
		require.Equal(t, validation_result.SeverityError, f.Severity)
	}
	require.Equal(t, "reconstruction_door_failed", dv.Details[0].Code)
	require.Equal(t, `door "pinned" (rung 0) errored: backend exited 3`, dv.Details[0].Message)
	require.Equal(t, "reconstruction_door_failed", dv.Details[1].Code)
	require.Equal(t, `door "integer" (rung 3) failed the gate: FAIL (maxAbs=0.25)`, dv.Details[1].Message)
	require.Equal(t, "reconstruction_no_door_opened", dv.Details[2].Code)
	require.Contains(t, dv.Details[2].Message, "fail-closed")

	empty := LadderToDimensionVerdict(LadderResult{}, 0.5)
	require.Equal(t, validation_result.VerdictFail, empty.Verdict)
	require.Len(t, empty.Details, 1, "no doors tried still yields the fail-closed finding")
}

// TestToDimensionVerdict_NoteReplacesErrorFigures proves that a fixture
// the gate could not even compare (a shape mismatch) is reported by its
// note rather than by meaningless error magnitudes.
func TestToDimensionVerdict_NoteReplacesErrorFigures(t *testing.T) {
	exp := f64Tensor([]int{2}, []float64{1, 2})
	wrongShape := f64Tensor([]int{1, 2}, []float64{1, 2})
	v, err := equivalence.Evaluate("g",
		[]equivalence.Fixture{{ID: "a", Expected: exp}},
		map[string]equivalence.Tensor{"a": wrongShape},
		equivalence.Tolerance{Atol: 1, Rtol: 1}, equivalence.StrictPolicy())
	require.NoError(t, err)
	require.Equal(t, equivalence.LevelFail, v.Level)

	dv := ToDimensionVerdict(v, 0.5)
	require.Equal(t, validation_result.VerdictFail, dv.Verdict)
	require.Equal(t, 0.0, dv.Score)
	require.Len(t, dv.Details, 1)
	require.Equal(t, "equivalence_outlier", dv.Details[0].Code)
	require.Equal(t, `fixture "a": shape mismatch`, dv.Details[0].Message)
}

// TestReason_MapsVerdictToDecision proves the reconstitution reason: a
// passing gate reconstructs, a failing one is a validation failure.
func TestReason_MapsVerdictToDecision(t *testing.T) {
	require.Equal(t, reconstitution_decision.ReasonReconstructedOK, Reason(equivalence.Verdict{Level: equivalence.LevelExact}))
	require.Equal(t, reconstitution_decision.ReasonReconstructedOK, Reason(equivalence.Verdict{Level: equivalence.LevelEquivalent}))
	require.Equal(t, reconstitution_decision.ReasonValidationFailed, Reason(equivalence.Verdict{Level: equivalence.LevelFail}))
}
