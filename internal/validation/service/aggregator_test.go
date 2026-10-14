// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
)

// dv is a tiny DimensionVerdict constructor for table-driven tests.
func dv(v validation_result.Verdict) validation_result.DimensionVerdict {
	return validation_result.DimensionVerdict{Verdict: v, Score: 1.0, Threshold: 1.0}
}

// TestAggregate_AllPass — the happy-path release case: every dimension
// pass → OverallVerdict=pass.
func TestAggregate_AllPass(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
	})
	require.Equal(t, validation_result.VerdictPass, got)
}

// TestAggregate_OperationalFailVetoesEverything — §5: operational fail
// short-circuits. Every combination of sem/beh must still fail.
func TestAggregate_OperationalFailVetoesEverything(t *testing.T) {
	t.Parallel()
	others := []validation_result.Verdict{
		validation_result.VerdictPass,
		validation_result.VerdictFail,
		validation_result.VerdictConditionalFail,
	}
	for _, s := range others {
		for _, b := range others {
			got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
				validation_result.DimensionOperational: dv(validation_result.VerdictFail),
				validation_result.DimensionSemantic:    dv(s),
				validation_result.DimensionBehavioral:  dv(b),
			})
			require.Equalf(t, validation_result.VerdictFail, got,
				"op=fail must force fail regardless of sem=%s, beh=%s", s, b)
		}
	}
}

// TestAggregate_OperationalConditionalMappedToFail — operational is
// binary by contract; a buggy producer emitting conditional is vetoed.
func TestAggregate_OperationalConditionalMappedToFail(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictConditionalFail),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
	})
	require.Equal(t, validation_result.VerdictFail, got,
		"operational=conditional must defensively map to fail (operational is binary)")
}

// TestAggregate_OperationalMissingFails — operational is always present
// on the release side; absence is a Service-layer bug.
func TestAggregate_OperationalMissingFails(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionSemantic:   dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral: dv(validation_result.VerdictPass),
	})
	require.Equal(t, validation_result.VerdictFail, got)
}

// TestAggregate_SemanticFailForcesFail — §5 clause 2.
func TestAggregate_SemanticFailForcesFail(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictFail),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
	})
	require.Equal(t, validation_result.VerdictFail, got)
}

// TestAggregate_BehavioralFailForcesFail — §5 clause 2.
func TestAggregate_BehavioralFailForcesFail(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictFail),
	})
	require.Equal(t, validation_result.VerdictFail, got)
}

// TestAggregate_BehavioralConditionalWhenSemPass — §5 clause 3:
// op=pass + sem=pass + beh=conditional_fail → conditional_fail.
func TestAggregate_BehavioralConditionalWhenSemPass(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictConditionalFail),
	})
	require.Equal(t, validation_result.VerdictConditionalFail, got,
		"§8(6): op+sem pass + beh conditional → OverallVerdict=conditional_fail")
}

// TestAggregate_SemanticConditionalMappedToFail — semantic has no
// conditional band (§2.3); a buggy producer's conditional is fail.
func TestAggregate_SemanticConditionalMappedToFail(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictConditionalFail),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
	})
	require.Equal(t, validation_result.VerdictFail, got,
		"semantic has no conditional band; emit must be fail-closed")
}

// TestAggregate_MissingSemanticFails — if operational passes but
// semantic wasn't evaluated, the Service caller skipped a dimension.
func TestAggregate_MissingSemanticFails(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
	})
	require.Equal(t, validation_result.VerdictFail, got,
		"§5 assumes all three dimensions are evaluated after op-pass")
}

// TestAggregate_MissingBehavioralFails — symmetric to above.
func TestAggregate_MissingBehavioralFails(t *testing.T) {
	t.Parallel()
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
	})
	require.Equal(t, validation_result.VerdictFail, got)
}

// TestAggregate_UnknownVerdictFails — any unknown verdict string
// (producer bug) fails closed.
func TestAggregate_UnknownVerdictFails(t *testing.T) {
	t.Parallel()
	unknown := validation_result.Verdict("unknown")
	cases := []struct {
		name string
		dims map[validation_result.Dimension]validation_result.DimensionVerdict
	}{
		{
			"unknown on operational",
			map[validation_result.Dimension]validation_result.DimensionVerdict{
				validation_result.DimensionOperational: dv(unknown),
				validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
				validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
			},
		},
		{
			"unknown on semantic",
			map[validation_result.Dimension]validation_result.DimensionVerdict{
				validation_result.DimensionOperational: dv(validation_result.VerdictPass),
				validation_result.DimensionSemantic:    dv(unknown),
				validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
			},
		},
		{
			"unknown on behavioral",
			map[validation_result.Dimension]validation_result.DimensionVerdict{
				validation_result.DimensionOperational: dv(validation_result.VerdictPass),
				validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
				validation_result.DimensionBehavioral:  dv(unknown),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, validation_result.VerdictFail, Aggregate(tc.dims))
		})
	}
}

// TestAggregate_MatchesDoctrineTable is a consolidated table mirroring
// the release-side §5 rule exactly — the invariant-06 doctrine test
// asserts the same shape against a "reference" implementation in the
// doctrine suite. If these two ever diverge, that's a Stage G/Iteration-2
// doctrine regression.
func TestAggregate_MatchesDoctrineTable(t *testing.T) {
	t.Parallel()
	p := validation_result.VerdictPass
	f := validation_result.VerdictFail
	c := validation_result.VerdictConditionalFail
	table := []struct {
		op, sem, beh validation_result.Verdict
		want         validation_result.Verdict
		note         string
	}{
		{p, p, p, p, "all-pass"},
		{f, p, p, f, "op veto"},
		{p, f, p, f, "sem fail"},
		{p, p, f, f, "beh fail"},
		{p, p, c, c, "beh conditional"},
		{p, f, c, f, "sem-fail dominates beh-conditional"},
		{p, c, p, f, "sem conditional → fail (no band)"},
		{f, f, f, f, "all fail"},
	}
	for _, tc := range table {
		t.Run(tc.note, func(t *testing.T) {
			got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
				validation_result.DimensionOperational: dv(tc.op),
				validation_result.DimensionSemantic:    dv(tc.sem),
				validation_result.DimensionBehavioral:  dv(tc.beh),
			})
			require.Equalf(t, tc.want, got, "op=%s sem=%s beh=%s", tc.op, tc.sem, tc.beh)
		})
	}
}
