// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
)

// Aggregate computes the overall verdict from the three per-dimension
// verdicts according to docs/doctrine/validation-thresholds.md §5:
//
//	IF O == fail
//	    → OverallVerdict = fail          (operational veto; short-circuits)
//	ELSE IF S == fail OR B == fail
//	    → OverallVerdict = fail
//	ELSE IF B == conditional_fail
//	    → OverallVerdict = conditional_fail
//	ELSE  (S == pass AND B == pass AND O == pass)
//	    → OverallVerdict = pass
//
// Defensive extensions (non-doctrine, but doctrine-consistent):
//
//   - Missing operational dimension → fail. Operational is always
//     present on the release side (it is the veto dimension);
//     absence is a Service-layer bug. Fail closed per §9(4):
//     un-evidenced decisions are not governed decisions.
//
//   - Operational verdict == conditional_fail → fail. Operational is
//     binary by contract (§4.3: "This dimension is binary by design");
//     a producer that emits conditional_fail on operational is buggy.
//     Map it to fail rather than silently loosening the rule.
//
//   - Semantic verdict == conditional_fail → fail. Semantic has no
//     conditional band in MVP (§2.3). A producer that emits it is
//     buggy; fail closed.
//
//   - Unknown verdict on any dimension → fail.
//
// This function is pure: no logging, no audit writes, no timestamps.
// It is the §5 rule expressed as code. The caller (ValidationService.Run)
// is responsible for emitting audit events around it.
func Aggregate(dims map[validation_result.Dimension]validation_result.DimensionVerdict) validation_result.Verdict {
	op, hasOp := dims[validation_result.DimensionOperational]
	if !hasOp {
		return validation_result.VerdictFail
	}
	// Operational veto — including the defensive conditional_fail
	// mapping. Mirror of the receive-side recvvalidator.Aggregate.
	switch op.Verdict {
	case validation_result.VerdictFail, validation_result.VerdictConditionalFail:
		return validation_result.VerdictFail
	case validation_result.VerdictPass:
		// operational passed — continue
	default:
		return validation_result.VerdictFail
	}

	sem, hasSem := dims[validation_result.DimensionSemantic]
	beh, hasBeh := dims[validation_result.DimensionBehavioral]

	// After operational-pass, semantic and behavioral MUST both have
	// been evaluated — §5 aggregation assumes all three dimensions
	// are present when operational is pass. Absence means the Service
	// caller skipped a dimension, which is a governance defect.
	if !hasSem || !hasBeh {
		return validation_result.VerdictFail
	}

	// Fail bias: any semantic or behavioral fail — including the
	// defensive mapping of an unexpected conditional_fail on the
	// semantic dimension — forces overall fail.
	if sem.Verdict == validation_result.VerdictFail ||
		beh.Verdict == validation_result.VerdictFail {
		return validation_result.VerdictFail
	}
	// Semantic has no conditional band (§2.3); fail closed.
	if sem.Verdict == validation_result.VerdictConditionalFail {
		return validation_result.VerdictFail
	}
	// Defensive: unknown semantic verdict → fail.
	if sem.Verdict != validation_result.VerdictPass {
		return validation_result.VerdictFail
	}

	// Operational pass + semantic pass. Now behavioral drives the
	// final three-band decision.
	switch beh.Verdict {
	case validation_result.VerdictPass:
		return validation_result.VerdictPass
	case validation_result.VerdictConditionalFail:
		return validation_result.VerdictConditionalFail
	default:
		// Unknown behavioral verdict → fail.
		return validation_result.VerdictFail
	}
}
