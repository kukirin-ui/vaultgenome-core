// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"fmt"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

var errEmptyLadder = shared_errors.Structural(
	shared_errors.CodeRequiredFieldMissing, "reconstruction: empty ladder", nil)

// This file implements the determinism-ladder descent: the automatic
// "find the working door" behavior for cross-hardware regeneration. When a genome
// is restored on new hardware, the destination tries recompute strategies in
// order of decreasing fidelity, VERIFYING each against the sealed reference
// fixtures with the equivalence gate. A strategy that fails the gate does NOT
// abort the regeneration — the descent falls through to the next door. The
// regeneration is blocked only if NO door produces a provably-correct model,
// which is the fail-closed safety property: a corrupted or wrong genome fails
// every door and is never brought up, while a healthy genome always finds a door.

// StrategyKind names the class of a recompute door so the audit trail records
// which technology actually regenerated the model — including, honestly, which
// rungs are ours and which stand on external prior art. See
// docs/prior-art-and-attribution.md.
type StrategyKind string

const (
	// KindPinnedReplay — byte-exact replay of the sealed computation on a
	// pinned + attested runtime of the same hardware class (highest fidelity,
	// tol 0). Ours: the attestation + seal layer.
	KindPinnedReplay StrategyKind = "pinned-replay"

	// KindReproducibleFloat — byte-identical float across heterogeneous CPUs and
	// GPUs via correct-rounded ops (incl. transcendentals) + a fixed reduction
	// order. This rung is BORROWED: its reference implementations are RepDL and
	// ReproBLAS (see the attribution doc); we integrate and attest it, we do not
	// claim it.
	KindReproducibleFloat StrategyKind = "reproducible-float"

	// KindFixedPoint — the integer/fixed-point path (internal/canonical):
	// byte-portable by construction across any CPU or GPU, EQUIVALENT to the
	// original within quantization error. Ours.
	KindFixedPoint StrategyKind = "fixed-point"

	// KindNativeFloat — the model's own float kernels on the destination
	// (PyTorch on its CPU or GPU). Byte-exact only on the runtime that
	// sealed the reference; across hardware it is EQUIVALENT within the
	// tolerance the gate measures, never assumed. The framework is
	// borrowed; the gate that holds it to a tolerance is ours.
	KindNativeFloat StrategyKind = "native-float"
)

// Strategy is one door on the ladder: a named recompute path the destination can
// try, plus the fidelity contract (tolerance/policy) the gate holds it to. Order
// strategies from highest fidelity (byte-exact, tol 0) to most portable (integer
// kernel, a small EQUIVALENT tolerance).
type Strategy struct {
	Rung      int                   // ladder rung (lower = higher fidelity)
	Kind      StrategyKind          // door class, recorded for audit/attribution
	Name      string                // human-readable door name, recorded for audit
	Recompute RecomputeFunc         // how this door recomputes a fixture's output
	Tol       equivalence.Tolerance // tolerance the gate enforces for this door
	Pol       equivalence.Policy    // aggregation policy for this door
	// Fixtures, when set, are the references this door is held to instead
	// of the ladder's: the integer door computes its own arithmetic and is
	// held, byte for byte, to the references that arithmetic sealed.
	Fixtures []equivalence.Fixture
}

// Attempt records one door's outcome for the audit trail.
type Attempt struct {
	Rung      int               `json:"rung"`
	Kind      StrategyKind      `json:"kind,omitempty"`
	Name      string            `json:"name"`
	Level     equivalence.Level `json:"level"` // gate level, or "ERROR" if recompute failed
	Err       string            `json:"err,omitempty"`
	MaxAbsErr float64           `json:"max_abs_err"`
}

// attemptError is the Level recorded when a door could not even produce outputs.
const attemptError equivalence.Level = "ERROR"

// LadderResult is the outcome of a descent.
type LadderResult struct {
	Opened   bool                `json:"opened"`         // did a door pass the gate?
	Rung     int                 `json:"rung"`           // which rung opened (valid iff Opened)
	Kind     StrategyKind        `json:"kind,omitempty"` // which door class opened
	Name     string              `json:"name"`           // which door opened
	Verdict  equivalence.Verdict `json:"verdict"`        // the passing verdict (iff Opened)
	Attempts []Attempt           `json:"attempts"`       // every door tried, in order
}

// Regenerate descends the ladder: it tries each strategy in order, gating its
// output against the sealed fixtures, and returns as soon as one PASSES (EXACT
// or EQUIVALENT). A door that fails the gate — or whose recompute errors — does
// not abort; the descent continues to the next door. If no door passes,
// LadderResult.Opened is false: the caller maps that to ReasonValidationFailed
// (fail-closed — never bring up a model no strategy could prove correct).
//
// The returned error is non-nil only for a caller fault (e.g. an empty ladder or
// empty fixture set); a genome that simply cannot be regenerated is a normal
// Opened=false result, not an error.
func Regenerate(
	genomeID string,
	fixtures []equivalence.Fixture,
	ladder []Strategy,
) (LadderResult, error) {
	var res LadderResult
	if len(ladder) == 0 {
		return res, errEmptyLadder
	}
	for _, s := range ladder {
		refs := fixtures
		if s.Fixtures != nil {
			refs = s.Fixtures
		}
		v, err := Evaluate(genomeID, refs, s.Recompute, s.Tol, s.Pol)
		if err != nil {
			res.Attempts = append(res.Attempts, Attempt{
				Rung: s.Rung, Kind: s.Kind, Name: s.Name, Level: attemptError, Err: err.Error(),
			})
			continue // a broken door is not a broken genome — try the next one
		}
		res.Attempts = append(res.Attempts, Attempt{
			Rung: s.Rung, Kind: s.Kind, Name: s.Name, Level: v.Level, MaxAbsErr: v.MaxAbsErr,
		})
		if v.Passed() {
			res.Opened = true
			res.Rung = s.Rung
			res.Kind = s.Kind
			res.Name = s.Name
			res.Verdict = v
			return res, nil
		}
	}
	return res, nil // no door opened → fail-closed
}

// LadderToDimensionVerdict maps a ladder descent onto the behavioral dimension
// of the frozen ValidationResult contract. If a door opened, it defers to
// ToDimensionVerdict on the passing verdict. If no door opened (fail-closed), it
// is VerdictFail with score 0 and one error finding per attempted door, so the
// operator sees exactly which doors were tried and why each failed.
func LadderToDimensionVerdict(res LadderResult, threshold float64) validation_result.DimensionVerdict {
	if res.Opened {
		return ToDimensionVerdict(res.Verdict, threshold)
	}
	details := make([]validation_result.Finding, 0, len(res.Attempts)+1)
	for _, a := range res.Attempts {
		var msg string
		switch {
		case a.Err != "":
			msg = fmt.Sprintf("door %q (rung %d) errored: %s", a.Name, a.Rung, a.Err)
		default:
			msg = fmt.Sprintf("door %q (rung %d) failed the gate: %s (maxAbs=%.3g)", a.Name, a.Rung, a.Level, a.MaxAbsErr)
		}
		details = append(details, validation_result.Finding{
			Code:     "reconstruction_door_failed",
			Severity: validation_result.SeverityError,
			Message:  msg,
		})
	}
	details = append(details, validation_result.Finding{
		Code:     "reconstruction_no_door_opened",
		Severity: validation_result.SeverityError,
		Message:  "no determinism-ladder door reproduced the sealed reference; reconstitution blocked (fail-closed)",
	})
	return validation_result.DimensionVerdict{
		Verdict:   validation_result.VerdictFail,
		Score:     0.0,
		Threshold: threshold,
		Details:   details,
	}
}
