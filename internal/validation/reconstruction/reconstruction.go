// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reconstruction is the receive-side glue that turns a numerical
// equivalence verdict into the platform's validation and reconstitution
// artifacts. It connects the three pieces of the cross-hardware regeneration
// flagship end to end:
//
//	restored genome
//	    │  recompute the sealed reference fixtures on the destination hardware
//	    │  (internal/canonical — deterministic/portable kernels)
//	    ▼
//	equivalence gate  (internal/validation/equivalence — EXACT/EQUIVALENT/FAIL)
//	    ▼
//	behavioral DimensionVerdict  (internal/contracts/validation_result)
//	    ▼
//	ReconstitutionDecision.Reason  (validation precedes reconstitution)
//
// It deliberately maps the gate onto the EXISTING behavioral dimension of the
// frozen ValidationResult contract rather than inventing a new dimension: the
// gate is a numerical behavioral check (does the restored model compute the
// sealed reference outputs?), complementary to the hash-based behavioral
// succession check (see ADR-0008). No frozen contract changes.
package reconstruction

import (
	"fmt"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// RecomputeFunc returns the output tensor the restored genome produces for a
// fixture id on the destination hardware. The caller backs it with the canonical
// kernel run over the reassembled weights.
type RecomputeFunc func(fixtureID string) (equivalence.Tensor, error)

// Evaluate recomputes every sealed fixture on the destination and runs the
// numerical equivalence gate, returning its verdict. A recompute error is
// surfaced to the caller (it is an operational failure, not a FAIL verdict:
// the gate never saw an output to judge).
func Evaluate(
	genomeID string,
	fixtures []equivalence.Fixture,
	recompute RecomputeFunc,
	tol equivalence.Tolerance,
	pol equivalence.Policy,
) (equivalence.Verdict, error) {
	actuals := make(map[string]equivalence.Tensor, len(fixtures))
	for _, f := range fixtures {
		out, err := recompute(f.ID)
		if err != nil {
			return equivalence.Verdict{}, fmt.Errorf("reconstruction: recompute fixture %q: %w", f.ID, err)
		}
		actuals[f.ID] = out
	}
	return equivalence.Evaluate(genomeID, fixtures, actuals, tol, pol)
}

// ToDimensionVerdict maps a gate verdict onto the behavioral dimension of the
// frozen ValidationResult contract. A passing gate (EXACT or EQUIVALENT) is
// VerdictPass; FAIL is VerdictFail. Score is the fraction of fixtures within
// tolerance; each outlier becomes an error finding, critical outliers flagged
// with a distinct code so the operator sees why release was blocked.
func ToDimensionVerdict(v equivalence.Verdict, threshold float64) validation_result.DimensionVerdict {
	total := v.NExact + v.NEquivalent + v.NMismatch
	score := 1.0
	if total > 0 {
		score = float64(v.NExact+v.NEquivalent) / float64(total)
	}
	verdict := validation_result.VerdictPass
	if !v.Passed() {
		verdict = validation_result.VerdictFail
	}
	var details []validation_result.Finding
	for _, r := range v.Results {
		if r.Within {
			continue
		}
		code := "equivalence_outlier"
		if r.Critical {
			code = "equivalence_critical_outlier"
		}
		msg := fmt.Sprintf("fixture %q outside tolerance (maxAbs=%.3g maxRel=%.3g)",
			r.ID, r.MaxAbsErr, r.MaxRelErr)
		if r.Note != "" {
			msg = fmt.Sprintf("fixture %q: %s", r.ID, r.Note)
		}
		details = append(details, validation_result.Finding{
			Code:     code,
			Severity: validation_result.SeverityError,
			Message:  msg,
		})
	}
	return validation_result.DimensionVerdict{
		Verdict:   verdict,
		Score:     score,
		Threshold: threshold,
		Details:   details,
	}
}

// Reason maps a gate verdict to the reconstitution-decision reason. A passing
// gate yields ReasonReconstructedOK; a FAIL blocks reconstitution as
// ReasonValidationFailed (validation precedes reconstitution). Reassembly
// failures are decided upstream and are not this function's concern.
func Reason(v equivalence.Verdict) reconstitution_decision.Reason {
	if v.Passed() {
		return reconstitution_decision.ReasonReconstructedOK
	}
	return reconstitution_decision.ReasonValidationFailed
}
