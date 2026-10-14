// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package semantic

import (
	"bytes"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
)

// Machine-readable finding codes for the Semantic dimension. These are
// stable across schema versions; external auditors key off these strings,
// so renaming one is a schema-bump event.
//
// The MVP produces only byte-equality findings; the production migration
// (semantic-similarity over a real evaluation suite) adds more codes but
// MUST NOT redefine any of these.
const (
	// CodeByteEquality is the MVP's one-and-only sub-check — exact
	// byte-for-byte match against the fixture's expected output.
	CodeByteEquality = "sem.byte_equality"

	// CodeByteLengthMismatch is a structural pre-check: candidate and
	// expected have different lengths. Reported alongside
	// CodeByteEquality so an auditor sees both the high-level verdict
	// and the proximate cause.
	CodeByteLengthMismatch = "sem.byte_length_mismatch"

	// CodeMissingExpected surfaces when the fixture contract is
	// violated — callers owe a non-nil expected payload even when it
	// is the empty byte slice ([]byte{}). A nil Expected is a Service
	// contract bug, not a candidate problem.
	CodeMissingExpected = "sem.missing_expected"
)

// threshold is the doctrinal pass bar for the Semantic dimension in the
// MVP: Score == 1.0 to pass; anything less fails. No conditional band
// for semantic per docs/doctrine/validation-thresholds.md §2.3.
const threshold = 1.0

// Inputs carries the artifacts the Semantic evaluator needs for one
// candidate.
//
// The struct is deliberately concrete (no interfaces) to match the
// discipline set by /internal/validation/operational — the evaluator has
// zero latitude to reinterpret what "the candidate" or "the expected
// output" means. The fixture layer above resolves those bytes; this
// layer only compares them.
type Inputs struct {
	// Candidate is the bytes returned by external compute.
	Candidate []byte

	// Expected is the fixture's pre-computed expected output. A zero-
	// length slice is legal (empty candidate is a legitimate edge case
	// in docs/doctrine/validation-thresholds.md §2.4); nil is a caller-side
	// contract violation and fails with CodeMissingExpected.
	Expected []byte

	// HaveExpected distinguishes "no fixture loaded" (HaveExpected=false)
	// from "empty fixture loaded" (HaveExpected=true, len(Expected)==0).
	// Callers that always resolve a fixture before calling Run SHOULD
	// set this to true; the zero value fails closed.
	HaveExpected bool
}

// Run executes the Semantic dimension evaluator.
//
// MVP contract (docs/doctrine/validation-thresholds.md §2):
//
//   - Score == 1.0 if and only if Candidate and Expected are byte-
//     identical (including equal length, including both empty).
//   - Any divergence — length mismatch or any differing byte — yields
//     Score = 0.0 and Verdict = Fail.
//   - No conditional band; semantic in MVP is binary.
//
// Threshold is reported as 1.0 so external auditors reading the
// DimensionVerdict see the exact pass bar that was applied.
//
// Determinism: for any fixed (Candidate, Expected) pair, Run produces
// byte-identical output — no random IDs, no clocks. This is relied on
// by the CI fixture-regeneration test (§2.6).
func Run(in Inputs) validation_result.DimensionVerdict {
	// Contract violation: caller must resolve a fixture before
	// invoking the evaluator. Fail closed with a distinct code so
	// auditors can tell a missing-fixture bug apart from a genuine
	// candidate-vs-fixture mismatch.
	if !in.HaveExpected || in.Expected == nil {
		return validation_result.DimensionVerdict{
			Verdict:   validation_result.VerdictFail,
			Score:     0.0,
			Threshold: threshold,
			Details: []validation_result.Finding{
				{
					Code:     CodeMissingExpected,
					Severity: validation_result.SeverityError,
					Message:  "semantic: expected fixture not provided; cannot evaluate byte-equality",
				},
			},
		}
	}

	var details []validation_result.Finding
	if len(in.Candidate) != len(in.Expected) {
		details = append(details, validation_result.Finding{
			Code:     CodeByteLengthMismatch,
			Severity: validation_result.SeverityError,
			Message:  byteLenMessage(len(in.Candidate), len(in.Expected)),
		})
	}

	equal := bytes.Equal(in.Candidate, in.Expected)
	if !equal {
		// Always emit CodeByteEquality when they differ — the length-
		// mismatch finding, if any, is a proximate-cause attachment
		// rather than a replacement.
		details = append(details, validation_result.Finding{
			Code:     CodeByteEquality,
			Severity: validation_result.SeverityError,
			Message:  firstDiffMessage(in.Candidate, in.Expected),
		})
	}

	if equal {
		return validation_result.DimensionVerdict{
			Verdict:   validation_result.VerdictPass,
			Score:     1.0,
			Threshold: threshold,
		}
	}
	return validation_result.DimensionVerdict{
		Verdict:   validation_result.VerdictFail,
		Score:     0.0,
		Threshold: threshold,
		Details:   details,
	}
}

// byteLenMessage renders a length-mismatch message deterministically.
// Kept as a free function so it is directly testable.
func byteLenMessage(got, want int) string {
	return "candidate length " + itoa(got) + " does not match expected length " + itoa(want)
}

// firstDiffMessage names the first differing byte offset. When the
// candidate is a prefix of expected (or vice versa), the offset is the
// length of the shorter of the two. This is strictly diagnostic — the
// verdict was already decided by the caller.
func firstDiffMessage(candidate, expected []byte) string {
	n := len(candidate)
	if len(expected) < n {
		n = len(expected)
	}
	for i := 0; i < n; i++ {
		if candidate[i] != expected[i] {
			return "candidate differs from expected at offset " + itoa(i)
		}
	}
	// The common prefix matched; the divergence is purely in length.
	return "candidate and expected agree on first " + itoa(n) + " bytes but differ in length"
}

// itoa converts a small non-negative integer to decimal ASCII without
// pulling in fmt. Tight loop — avoids allocation in a hot path that
// might be invoked from fuzz tests later.
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
