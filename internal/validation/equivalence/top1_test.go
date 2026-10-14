// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package equivalence

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTop1Agreement_SameAnswerDespiteDifferentNumbers(t *testing.T) {
	t.Parallel()
	fixtures := []Fixture{
		{ID: "a", Critical: true, Expected: f32t([]int{3}, 0.1, 0.7, 0.2)},
		{ID: "b", Critical: false, Expected: f32t([]int{3}, 5, 4, 3)},
	}
	actuals := map[string]Tensor{
		"a": f32t([]int{3}, 0.11, 0.69, 0.2), // numbers drift, answer holds
		"b": f32t([]int{3}, 5.5, 4, 3),
	}
	rep, err := Top1Agreement(fixtures, actuals)
	require.NoError(t, err)
	require.Equal(t, 2, rep.Total)
	require.Equal(t, 2, rep.Agreed)
	require.Equal(t, 0, rep.CriticalDisagreed)
	require.Equal(t, 1.0, rep.Score())
	require.Equal(t, 1, rep.Results[0].ExpectedIndex)
	require.Equal(t, 1, rep.Results[0].ActualIndex)
}

func TestTop1Agreement_DisagreementsAndDefects(t *testing.T) {
	t.Parallel()
	fixtures := []Fixture{
		{ID: "flip", Critical: true, Expected: f32t([]int{2}, 1, 2)},
		{ID: "shape", Critical: false, Expected: f32t([]int{2}, 1, 2)},
		{ID: "nan", Critical: false, Expected: f32t([]int{2}, 1, 2)},
		{ID: "tie", Critical: false, Expected: f32t([]int{2}, 2, 2)},
	}
	actuals := map[string]Tensor{
		"flip":  f32t([]int{2}, 2, 1),
		"shape": f32t([]int{3}, 1, 2, 0),
		"nan":   f32t([]int{2}, float32(math.NaN()), 2),
		"tie":   f32t([]int{2}, 2, 2),
	}
	rep, err := Top1Agreement(fixtures, actuals)
	require.NoError(t, err)
	require.Equal(t, 4, rep.Total)
	require.Equal(t, 1, rep.Agreed, "only the tie agrees (first index on both sides)")
	require.Equal(t, 1, rep.CriticalDisagreed)
	require.False(t, rep.Results[0].Agree)
	require.Contains(t, rep.Results[1].Note, "shape")
	require.Contains(t, rep.Results[2].Note, "NaN")
	require.Equal(t, 0.25, rep.Score())

	_, err = Top1Agreement(fixtures[:1], map[string]Tensor{})
	require.Error(t, err, "a missing actual is the caller's fault")
	_, err = Top1Agreement(nil, actuals)
	require.Error(t, err)
	require.Equal(t, 0.0, Top1Report{}.Score())
}
