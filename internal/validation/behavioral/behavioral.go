// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package behavioral

import (
	"sort"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
)

// Machine-readable finding codes. Stable across schema versions; they
// are part of the external-auditor contract. Renaming one is a schema
// bump, not an internal refactor.
const (
	// CodeCriticalProbeFailed surfaces any critical-probe failure.
	// Per §3.3, a single critical failure forces the dimension verdict
	// to Fail — no amount of non-critical passes can rescue it.
	CodeCriticalProbeFailed = "beh.critical_probe_failed"

	// CodeNonCriticalBelowConditional surfaces when the non-critical
	// pass rate falls into [0%, 85%) — the hard-fail band.
	CodeNonCriticalBelowConditional = "beh.non_critical_below_conditional"

	// CodeNonCriticalConditional surfaces when the non-critical pass
	// rate lands in [85%, 95%) — the governance-review band. The
	// verdict is ConditionalFail (not silent approval — §9(3)).
	CodeNonCriticalConditional = "beh.non_critical_conditional"

	// CodeNoCriticalProbes surfaces when the probe suite contains zero
	// critical probes. Phase 6 sign-off requires at least three; a
	// suite that violates this is a governance defect, not a
	// candidate-level failure, but it still fails closed.
	CodeNoCriticalProbes = "beh.no_critical_probes"

	// CodeEmptySuite surfaces when the probe suite is empty. Running
	// validation against an empty suite would mean "rubber-stamp any
	// candidate" — fail closed rather than silently pass.
	CodeEmptySuite = "beh.empty_suite"

	// CodeDuplicateProbeID surfaces when two probes share an ID. Probe
	// IDs are the audit-key for per-probe findings; duplicates break
	// the auditor's ability to cite a single failure.
	CodeDuplicateProbeID = "beh.duplicate_probe_id"

	// CodeProbeBadID surfaces when a probe has an empty ID. See above.
	CodeProbeBadID = "beh.probe_missing_id"
)

// threshold values pinned to docs/doctrine/validation-thresholds.md §3.3. Any
// change here is a doctrine change — the §3 probe-rate thresholds are
// part of the Phase 6 sign-off contract.
const (
	// PassThreshold is the non-critical pass-rate floor for Pass
	// (all critical must also pass).
	PassThreshold = 0.95

	// ConditionalThreshold is the non-critical pass-rate floor for
	// ConditionalFail (governance review, MVP treats as not-release).
	ConditionalThreshold = 0.85
)

// Probe is one behavioral-suite entry. A probe is either Critical
// (any failure is a dimension fail) or non-critical (failures lower
// the non-critical pass rate).
//
// The Evaluate callback returns (passed, diagnostic). A passed=true
// probe contributes to the pass rate; a passed=false probe
// contributes a Finding whose message is diag.
type Probe struct {
	ID       string
	Name     string
	Critical bool

	// Evaluate runs the probe. Must be deterministic over its inputs
	// (same candidate bytes → same result); randomness breaks the
	// CI-level repeatability guarantee.
	Evaluate func(candidate []byte) (passed bool, diag string)
}

// Inputs carries one candidate and the probe suite to evaluate.
type Inputs struct {
	// Candidate is the bytes returned by external compute, the same
	// payload the semantic dimension sees.
	Candidate []byte

	// Probes is the full probe suite for this Genome. Must contain at
	// least three critical probes to satisfy Phase 6 sign-off — the
	// evaluator enforces this at run time.
	Probes []Probe
}

// Run evaluates every probe in the suite and aggregates their results
// according to the three-band rule from docs/doctrine/validation-thresholds.md §3.3:
//
//   - Pass:             all critical pass AND non-critical pass-rate ≥ 95%
//   - ConditionalFail:  all critical pass AND non-critical pass-rate ∈ [85%, 95%)
//   - Fail:             any critical fail OR  non-critical pass-rate < 85%
//
// Edge cases:
//
//   - A non-critical suite with zero non-critical probes is treated as
//     100% (vacuously all pass). Pass hinges entirely on criticals.
//   - An empty suite fails closed with CodeEmptySuite.
//   - A suite with no critical probes fails closed with CodeNoCriticalProbes.
//
// Deterministic by construction: probes run in their slice order and
// Details are sorted by probe ID so repeated calls produce byte-
// identical verdicts on the same (candidate, suite).
//
// No short-circuit on critical fail: every probe runs so auditors see
// the full picture. Probe-level panics are the caller's responsibility
// to contain; this function does NOT recover them (a panicking probe
// is a suite-author bug, not a candidate-level condition).
func Run(in Inputs) validation_result.DimensionVerdict {
	if len(in.Probes) == 0 {
		return failClosed(CodeEmptySuite,
			"behavioral: probe suite is empty — running validation against zero probes is not governed validation")
	}

	// Structural pre-checks: duplicate IDs and blank IDs are governance
	// defects that would confuse audit-trail reading. Fail closed
	// with a specific code.
	seen := make(map[string]struct{}, len(in.Probes))
	for _, p := range in.Probes {
		if p.ID == "" {
			return failClosed(CodeProbeBadID,
				"behavioral: probe with empty ID in suite")
		}
		if _, dup := seen[p.ID]; dup {
			return failClosed(CodeDuplicateProbeID,
				"behavioral: duplicate probe ID in suite: "+p.ID)
		}
		seen[p.ID] = struct{}{}
	}

	critTotal := 0
	critFailed := 0
	nonTotal := 0
	nonPassed := 0

	var details []validation_result.Finding
	for _, p := range in.Probes {
		passed := false
		diag := ""
		if p.Evaluate != nil {
			passed, diag = p.Evaluate(in.Candidate)
		}
		if p.Critical {
			critTotal++
			if !passed {
				critFailed++
				details = append(details, validation_result.Finding{
					Code:     CodeCriticalProbeFailed,
					Severity: validation_result.SeverityError,
					Message:  "probe " + p.ID + " (" + p.Name + ") failed: " + diag,
				})
			}
		} else {
			nonTotal++
			if passed {
				nonPassed++
			} else {
				details = append(details, validation_result.Finding{
					Code:     "beh.non_critical_probe_failed",
					Severity: validation_result.SeverityWarning,
					Message:  "probe " + p.ID + " (" + p.Name + ") failed: " + diag,
				})
			}
		}
	}

	if critTotal == 0 {
		// A suite with no critical probes cannot satisfy §3.4's minimum
		// of three. This is a governance defect; fail closed without a
		// score (we cannot meaningfully score a suite whose pass bar is
		// undefined).
		return failClosed(CodeNoCriticalProbes,
			"behavioral: suite has zero critical probes; §3.4 requires at least three")
	}

	// Score model for the dimension: blended pass rate across all
	// probes. Critical probes count 1-for-1; non-critical count 1-for-1.
	// This is a reporting value (auditors want to see "how close did
	// this candidate get?"); the actual verdict below hinges on the
	// two-band rule, not on this number.
	totalProbes := critTotal + nonTotal
	totalPassed := (critTotal - critFailed) + nonPassed
	score := float64(totalPassed) / float64(totalProbes)

	// Non-critical pass rate — only this drives the conditional/fail
	// boundaries when all criticals pass.
	nonRate := 1.0 // vacuously 100% when there are no non-critical probes
	if nonTotal > 0 {
		nonRate = float64(nonPassed) / float64(nonTotal)
	}

	// Verdict decision — §3.3.
	verdict := validation_result.VerdictPass
	switch {
	case critFailed > 0:
		verdict = validation_result.VerdictFail
	case nonRate < ConditionalThreshold:
		verdict = validation_result.VerdictFail
		details = append(details, validation_result.Finding{
			Code:     CodeNonCriticalBelowConditional,
			Severity: validation_result.SeverityError,
			Message:  "non-critical probe pass rate " + fmtPct(nonRate) + " is below conditional floor " + fmtPct(ConditionalThreshold),
		})
	case nonRate < PassThreshold:
		verdict = validation_result.VerdictConditionalFail
		details = append(details, validation_result.Finding{
			Code:     CodeNonCriticalConditional,
			Severity: validation_result.SeverityWarning,
			Message:  "non-critical probe pass rate " + fmtPct(nonRate) + " is in the governance-review band [85%, 95%)",
		})
	}

	// Sort details by code then by message so the Findings slice is
	// stable across runs on the same inputs. Critical failures land
	// ahead of non-critical because "beh.critical_probe_failed" sorts
	// lexicographically before "beh.non_critical_probe_failed".
	sort.SliceStable(details, func(i, j int) bool {
		if details[i].Code != details[j].Code {
			return details[i].Code < details[j].Code
		}
		return details[i].Message < details[j].Message
	})

	return validation_result.DimensionVerdict{
		Verdict:   verdict,
		Score:     score,
		Threshold: PassThreshold,
		Details:   details,
	}
}

// failClosed renders a single-finding Fail verdict for structural
// suite defects. Score=0, Threshold=PassThreshold so downstream
// auditors still see the pass bar we were evaluating against.
func failClosed(code, msg string) validation_result.DimensionVerdict {
	return validation_result.DimensionVerdict{
		Verdict:   validation_result.VerdictFail,
		Score:     0.0,
		Threshold: PassThreshold,
		Details: []validation_result.Finding{
			{
				Code:     code,
				Severity: validation_result.SeverityError,
				Message:  msg,
			},
		},
	}
}

// fmtPct renders a float in [0, 1] as a two-decimal percentage. Kept as
// a private helper to avoid bringing in fmt on the validator hot path.
func fmtPct(f float64) string {
	// Clamp defensively — inputs outside [0,1] would indicate a bug
	// elsewhere, but the message still needs to be readable.
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	// Integer percent, then two fractional digits.
	whole := int(f * 100)
	frac := int((f*100 - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	return itoa(whole) + "." + pad2(frac) + "%"
}

// pad2 renders 0..99 as two ASCII digits. Extra paranoia for >99 (only
// possible under rounding drift with floats very near 1.0) caps at 99.
func pad2(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 99 {
		n = 99
	}
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
