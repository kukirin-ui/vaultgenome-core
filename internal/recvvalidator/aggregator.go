// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recvvalidator

import (
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
)

// Aggregate computes the overall receive-side verdict from the
// per-dimension verdicts. Stage G produces only the operational
// dimension; this function is deliberately written to be insensitive
// to the presence of other dimensions so that a future extension
// (e.g. a post-reconstitution semantic dimension emitted by an
// out-of-process compute-side verifier) can be slotted in without
// rewriting the aggregation rule.
//
// Aggregation rule:
//
//	operational fail  → overall fail
//	operational miss  → overall fail   (operational is mandatory on receive side)
//	operational pass  + any other-dim fail → overall fail
//	operational pass  + every other-dim pass → overall pass
//	operational pass  + any other-dim conditional_fail → overall conditional_fail
//
// The mandatory-operational rule mirrors the release-side §5
// aggregation rule exactly — operational is the veto dimension on
// both sides.
//
// VerdictConditionalFail from the operational dimension is mapped
// defensively to VerdictFail because the operational dimension is
// binary by contract; a producer that nevertheless emits
// ConditionalFail is treated as having failed rather than silently
// promoted to a looser category.
func Aggregate(dims map[validation_result.Dimension]validation_result.DimensionVerdict) validation_result.Verdict {
	op, hasOp := dims[validation_result.DimensionOperational]
	if !hasOp {
		return validation_result.VerdictFail
	}
	if op.Verdict == validation_result.VerdictFail ||
		op.Verdict == validation_result.VerdictConditionalFail {
		return validation_result.VerdictFail
	}

	// Operational passed. Inspect every OTHER dimension. Stage G
	// typically has none; the loop is defensive so that a future
	// receive-side dimension will land cleanly.
	anyConditional := false
	for dim, dv := range dims {
		if dim == validation_result.DimensionOperational {
			continue
		}
		switch dv.Verdict {
		case validation_result.VerdictFail:
			return validation_result.VerdictFail
		case validation_result.VerdictConditionalFail:
			anyConditional = true
		case validation_result.VerdictPass:
			// OK — keep scanning.
		default:
			// Unknown verdict is treated as fail, same as the
			// release-side aggregator in invariants_test.go.
			return validation_result.VerdictFail
		}
	}
	if anyConditional {
		return validation_result.VerdictConditionalFail
	}
	return validation_result.VerdictPass
}
