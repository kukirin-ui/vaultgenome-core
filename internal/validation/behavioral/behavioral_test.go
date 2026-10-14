// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package behavioral

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
)

// probe builds a Probe whose Evaluate returns the given (ok, diag). The
// candidate argument is intentionally ignored — these tests exercise the
// aggregation rule, not probe internals.
func probe(id string, critical bool, ok bool, diag string) Probe {
	return Probe{
		ID:       id,
		Name:     id,
		Critical: critical,
		Evaluate: func(_ []byte) (bool, string) { return ok, diag },
	}
}

// buildSuite returns the Phase-6 baseline — ≥3 critical and ≥7
// non-critical, all passing. Individual tests override specific
// entries before calling Run.
func buildSuite() []Probe {
	probes := []Probe{
		probe("C-001", true, true, ""),
		probe("C-002", true, true, ""),
		probe("C-003", true, true, ""),
		probe("N-001", false, true, ""),
		probe("N-002", false, true, ""),
		probe("N-003", false, true, ""),
		probe("N-004", false, true, ""),
		probe("N-005", false, true, ""),
		probe("N-006", false, true, ""),
		probe("N-007", false, true, ""),
	}
	return probes
}

func TestRun_AllPass(t *testing.T) {
	t.Parallel()
	v := Run(Inputs{Candidate: []byte{0x01}, Probes: buildSuite()})
	require.Equal(t, validation_result.VerdictPass, v.Verdict, "findings: %+v", v.Details)
	require.Equal(t, 1.0, v.Score)
	require.Equal(t, PassThreshold, v.Threshold)
	require.Empty(t, v.Details)
}

// TestRun_CriticalFailForcesFail — §3.3: any critical fail fails the
// dimension regardless of non-critical performance. This is the
// §8(2) negative-test shape at the dimension level.
func TestRun_CriticalFailForcesFail(t *testing.T) {
	t.Parallel()
	suite := buildSuite()
	suite[1] = probe("C-002", true, false, "returned wrong property")

	v := Run(Inputs{Candidate: []byte{0x01}, Probes: suite})
	require.Equal(t, validation_result.VerdictFail, v.Verdict,
		"critical fail must force dimension=fail even with 100% non-critical pass")
	require.Contains(t, findingCodes(v), CodeCriticalProbeFailed)
	// Non-critical is at 100%, so NO conditional or below-conditional
	// codes should appear.
	require.NotContains(t, findingCodes(v), CodeNonCriticalConditional)
	require.NotContains(t, findingCodes(v), CodeNonCriticalBelowConditional)
}

// TestRun_CriticalFail_CarriesMessage — the finding message must cite
// the probe ID and the probe's diagnostic so an auditor can identify
// what failed without running the suite again.
func TestRun_CriticalFail_CarriesMessage(t *testing.T) {
	t.Parallel()
	suite := buildSuite()
	suite[0] = probe("C-001", true, false, "reproducibility divergence at seed 0x42")

	v := Run(Inputs{Probes: suite})
	found := false
	for _, d := range v.Details {
		if d.Code == CodeCriticalProbeFailed {
			require.Contains(t, d.Message, "C-001")
			require.Contains(t, d.Message, "reproducibility divergence")
			found = true
		}
	}
	require.True(t, found, "critical-fail must emit a finding with probe ID + diagnostic")
}

// TestRun_NonCriticalConditionalBand — §3.3: [85%, 95%) pass rate on
// non-critical probes yields ConditionalFail when all criticals pass.
// 6-of-7 non-critical passes = 85.7% — inside the band.
func TestRun_NonCriticalConditional_6of7(t *testing.T) {
	t.Parallel()
	suite := buildSuite()
	// Flip one non-critical to fail: 6/7 ≈ 85.71% ∈ [85%, 95%).
	suite[3] = probe("N-001", false, false, "output shape minor variance")

	v := Run(Inputs{Probes: suite})
	require.Equal(t, validation_result.VerdictConditionalFail, v.Verdict,
		"6/7 non-critical ≈ 85.7%% must be ConditionalFail")
	require.Contains(t, findingCodes(v), CodeNonCriticalConditional,
		"conditional band must surface its own finding code")
}

// TestRun_NonCritical90_Conditional matches §8(6) — "pass-rate 90% →
// behavioral=conditional_fail". Uses 10 non-critical probes for exact
// 90%.
func TestRun_NonCritical90_Conditional(t *testing.T) {
	t.Parallel()
	probes := []Probe{
		probe("C-001", true, true, ""),
		probe("C-002", true, true, ""),
		probe("C-003", true, true, ""),
	}
	// 10 non-critical probes, 9 pass, 1 fail = 90.0%.
	for i := 1; i <= 10; i++ {
		id := "N-" + itoa(i)
		probes = append(probes, probe(id, false, i != 7, "minor variance"))
	}

	v := Run(Inputs{Probes: probes})
	require.Equal(t, validation_result.VerdictConditionalFail, v.Verdict,
		"§8(6) — 90%% non-critical must yield ConditionalFail")
}

// TestRun_NonCriticalBelowConditional — pass rate < 85% is hard Fail.
// 5-of-7 ≈ 71.4%.
func TestRun_NonCriticalBelowConditional(t *testing.T) {
	t.Parallel()
	suite := buildSuite()
	suite[3] = probe("N-001", false, false, "x")
	suite[4] = probe("N-002", false, false, "y")

	v := Run(Inputs{Probes: suite})
	require.Equal(t, validation_result.VerdictFail, v.Verdict,
		"5/7 ≈ 71.4%% is below 85%% conditional floor — must Fail")
	require.Contains(t, findingCodes(v), CodeNonCriticalBelowConditional)
}

// TestRun_ExactlyAtPassBoundary — 95% non-critical rate is Pass
// (strict inequality at the upper boundary).
func TestRun_ExactlyAtPassBoundary(t *testing.T) {
	t.Parallel()
	// 19/20 = 95.0% exactly.
	probes := []Probe{
		probe("C-001", true, true, ""),
		probe("C-002", true, true, ""),
		probe("C-003", true, true, ""),
	}
	for i := 1; i <= 20; i++ {
		id := "N-" + itoa(i)
		probes = append(probes, probe(id, false, i != 1, ""))
	}

	v := Run(Inputs{Probes: probes})
	require.Equal(t, validation_result.VerdictPass, v.Verdict,
		"19/20 = 95.0%% lands at the Pass floor — must be Pass, not Conditional")
}

// TestRun_ExactlyAtConditionalBoundary — 85% non-critical rate is
// ConditionalFail (boundary is inclusive of 85%).
func TestRun_ExactlyAtConditionalBoundary(t *testing.T) {
	t.Parallel()
	// 17/20 = 85.0% exactly.
	probes := []Probe{
		probe("C-001", true, true, ""),
		probe("C-002", true, true, ""),
		probe("C-003", true, true, ""),
	}
	for i := 1; i <= 20; i++ {
		id := "N-" + itoa(i)
		probes = append(probes, probe(id, false, i > 3, ""))
	}

	v := Run(Inputs{Probes: probes})
	require.Equal(t, validation_result.VerdictConditionalFail, v.Verdict,
		"17/20 = 85.0%% lands at the ConditionalFail floor — must be ConditionalFail")
}

// TestRun_EmptySuiteFailsClosed — an empty suite is a governance
// defect; fail closed with CodeEmptySuite. NEVER silently pass.
func TestRun_EmptySuiteFailsClosed(t *testing.T) {
	t.Parallel()
	v := Run(Inputs{Probes: nil})
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Len(t, v.Details, 1)
	require.Equal(t, CodeEmptySuite, v.Details[0].Code)
}

// TestRun_NoCriticalProbesFailsClosed — §3.4 requires ≥3 critical
// probes; a suite without any fails with a specific code.
func TestRun_NoCriticalProbesFailsClosed(t *testing.T) {
	t.Parallel()
	probes := []Probe{
		probe("N-001", false, true, ""),
		probe("N-002", false, true, ""),
	}
	v := Run(Inputs{Probes: probes})
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Contains(t, findingCodes(v), CodeNoCriticalProbes)
}

// TestRun_DuplicateProbeIDFailsClosed — duplicate IDs would confuse the
// audit trail (auditors cite probes by ID). Structural fail.
func TestRun_DuplicateProbeIDFailsClosed(t *testing.T) {
	t.Parallel()
	suite := buildSuite()
	suite[4] = probe("N-001", false, true, "") // duplicate of suite[3]

	v := Run(Inputs{Probes: suite})
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Equal(t, CodeDuplicateProbeID, v.Details[0].Code)
	require.Contains(t, v.Details[0].Message, "N-001")
}

// TestRun_EmptyProbeIDFailsClosed — probes MUST have non-empty IDs.
func TestRun_EmptyProbeIDFailsClosed(t *testing.T) {
	t.Parallel()
	suite := buildSuite()
	suite[0].ID = ""

	v := Run(Inputs{Probes: suite})
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Equal(t, CodeProbeBadID, v.Details[0].Code)
}

// TestRun_OnlyCriticalProbes_AllPass — a suite with zero non-critical
// probes is vacuously 100% on the non-critical axis. The verdict
// hinges entirely on criticals.
func TestRun_OnlyCriticalProbes_AllPass(t *testing.T) {
	t.Parallel()
	probes := []Probe{
		probe("C-001", true, true, ""),
		probe("C-002", true, true, ""),
		probe("C-003", true, true, ""),
	}
	v := Run(Inputs{Probes: probes})
	require.Equal(t, validation_result.VerdictPass, v.Verdict,
		"vacuous non-critical (zero probes) must count as 100%%")
}

// TestRun_DeterministicOutput — same inputs produce byte-identical
// DimensionVerdicts across calls. Details are sorted.
func TestRun_DeterministicOutput(t *testing.T) {
	t.Parallel()
	suite := buildSuite()
	suite[3] = probe("N-001", false, false, "x")
	suite[4] = probe("N-002", false, false, "y")

	a := Run(Inputs{Probes: suite})
	b := Run(Inputs{Probes: suite})
	require.Equal(t, a.Verdict, b.Verdict)
	require.Equal(t, a.Score, b.Score)
	require.Equal(t, len(a.Details), len(b.Details))
	for i := range a.Details {
		require.Equal(t, a.Details[i].Code, b.Details[i].Code)
		require.Equal(t, a.Details[i].Message, b.Details[i].Message)
	}
}

// TestRun_DetailsSortedByCode — Details slice is sorted by Code for
// stable audit rendering.
func TestRun_DetailsSortedByCode(t *testing.T) {
	t.Parallel()
	// Mix one critical failure with one non-critical failure so both
	// code strings appear in Details.
	suite := buildSuite()
	suite[0] = probe("C-001", true, false, "crit diag")
	suite[3] = probe("N-001", false, false, "non diag")
	// Drop two more to stay below 95% (to avoid overwriting the verdict).
	suite[4] = probe("N-002", false, false, "")
	suite[5] = probe("N-003", false, false, "")

	v := Run(Inputs{Probes: suite})
	for i := 1; i < len(v.Details); i++ {
		require.Truef(t, v.Details[i-1].Code <= v.Details[i].Code,
			"Details must be sorted by Code: %q > %q", v.Details[i-1].Code, v.Details[i].Code)
	}
}

// TestRun_NilEvaluatorTreatedAsFail — a probe whose Evaluate callback
// is nil counts as failed (fail-closed; a probe without evaluation
// cannot be said to have passed).
func TestRun_NilEvaluatorTreatedAsFail(t *testing.T) {
	t.Parallel()
	suite := buildSuite()
	suite[0].Evaluate = nil

	v := Run(Inputs{Probes: suite})
	require.Equal(t, validation_result.VerdictFail, v.Verdict,
		"nil evaluator on a critical probe must be fail")
}

// --- helpers --------------------------------------------------------------

func findingCodes(v validation_result.DimensionVerdict) []string {
	out := make([]string, 0, len(v.Details))
	for _, d := range v.Details {
		out = append(out, d.Code)
	}
	return out
}

// TestFmtPct_StableAcrossRuns — audit messages with percent strings
// must not drift run-to-run.
func TestFmtPct_StableAcrossRuns(t *testing.T) {
	t.Parallel()
	require.Equal(t, "95.00%", fmtPct(0.95))
	require.Equal(t, "85.00%", fmtPct(0.85))
	require.Equal(t, "0.00%", fmtPct(0.0))
	require.Equal(t, "100.00%", fmtPct(1.0))
	// Out-of-range clamps rather than panicking.
	require.True(t, strings.HasPrefix(fmtPct(1.5), "100."))
	require.Equal(t, "0.00%", fmtPct(-0.1))
}
