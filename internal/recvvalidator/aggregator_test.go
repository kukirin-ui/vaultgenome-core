// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recvvalidator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
)

// dv is a tiny helper that manufactures a DimensionVerdict with the
// Threshold set to 1.0 — the receive-side operational dimension is
// binary, so every test case shares that threshold. Score is
// parameterised because the aggregator must not inspect it.
func dv(v validation_result.Verdict) validation_result.DimensionVerdict {
	return validation_result.DimensionVerdict{Verdict: v, Score: 1.0, Threshold: 1.0}
}

// The "operational missing" rule — a receive-side verdict that does
// not contain an operational dimension is mandatorily a fail. This is
// the mirror of the release-side §5 rule: operational is the veto
// dimension on both sides.
func TestAggregate_OperationalMissingFails(t *testing.T) {
	t.Parallel()
	// Empty map.
	got := Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{})
	require.Equal(t, validation_result.VerdictFail, got)

	// Map containing only a non-operational dimension still fails:
	// without an operational verdict the receive side has no veto
	// dimension to anchor on.
	got = Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionSemantic: dv(validation_result.VerdictPass),
	})
	require.Equal(t, validation_result.VerdictFail, got)
}

// Operational-Fail is a hard veto regardless of any other dimension.
func TestAggregate_OperationalFailForcesOverallFail(t *testing.T) {
	t.Parallel()
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictFail),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
	}
	require.Equal(t, validation_result.VerdictFail, Aggregate(dims))
}

// ConditionalFail from the operational dimension is DEFENSIVELY mapped
// to Fail: operational is binary by contract, so a producer emitting
// ConditionalFail is treated as having failed rather than silently
// promoted to a looser category.
func TestAggregate_OperationalConditionalMapsToFail(t *testing.T) {
	t.Parallel()
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictConditionalFail),
	}
	require.Equal(t, validation_result.VerdictFail, Aggregate(dims))
}

// Operational-Pass alone passes — Stage G typically emits no other
// dimensions, so the happy path has operational as the lone dim.
func TestAggregate_OperationalPassAloneYieldsPass(t *testing.T) {
	t.Parallel()
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
	}
	require.Equal(t, validation_result.VerdictPass, Aggregate(dims))
}

// Forward-compat: a future non-operational dimension reporting Fail
// must propagate to overall=Fail even with operational=Pass.
func TestAggregate_OperationalPassPlusFutureDimFailStillFails(t *testing.T) {
	t.Parallel()
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictFail),
	}
	require.Equal(t, validation_result.VerdictFail, Aggregate(dims))
}

// Forward-compat: an other-dim ConditionalFail with operational=Pass
// lifts the overall verdict to ConditionalFail. This keeps receive-
// side aggregation consistent with the release-side rule that
// conditional-only signals never silently become Pass.
func TestAggregate_OperationalPassPlusFutureDimConditionalYieldsConditional(t *testing.T) {
	t.Parallel()
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictConditionalFail),
	}
	require.Equal(t, validation_result.VerdictConditionalFail, Aggregate(dims))
}

// Forward-compat: operational=Pass + semantic=Pass + behavioral=Pass
// yields overall=Pass even with the aggregator loop involved. This
// is the mirror of the release-side happy-path.
func TestAggregate_AllDimensionsPassYieldsPass(t *testing.T) {
	t.Parallel()
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
	}
	require.Equal(t, validation_result.VerdictPass, Aggregate(dims))
}

// Unknown verdict on a non-operational dimension is treated as Fail.
// This mirrors the release-side aggregator's defensive stance:
// unrecognised producers never promote silently.
func TestAggregate_UnknownNonOperationalVerdictTreatedAsFail(t *testing.T) {
	t.Parallel()
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic: {
			Verdict:   validation_result.Verdict("UnknownFutureState"),
			Score:     1.0,
			Threshold: 1.0,
		},
	}
	require.Equal(t, validation_result.VerdictFail, Aggregate(dims))
}

// Fail-dominates-conditional. With operational=Pass, if any future
// dim reports Fail while another reports ConditionalFail, the result
// is Fail (not ConditionalFail) — the hardest signal wins.
func TestAggregate_FailDominatesConditional(t *testing.T) {
	t.Parallel()
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		validation_result.DimensionSemantic:    dv(validation_result.VerdictFail),
		validation_result.DimensionBehavioral:  dv(validation_result.VerdictConditionalFail),
	}
	require.Equal(t, validation_result.VerdictFail, Aggregate(dims))
}
