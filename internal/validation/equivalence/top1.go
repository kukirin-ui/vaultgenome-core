// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package equivalence

import (
	"fmt"
	"math"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Top1Result is one fixture's top-1 comparison: the index of the largest
// value in the sealed reference against the index of the largest value
// in the reconstructed output.
type Top1Result struct {
	ID            string `json:"id"`
	Critical      bool   `json:"critical"`
	ExpectedIndex int    `json:"expected_index"`
	ActualIndex   int    `json:"actual_index"`
	Agree         bool   `json:"agree"`
	Note          string `json:"note,omitempty"`
}

// Top1Report aggregates Top1Agreement over a fixture set.
type Top1Report struct {
	Total             int          `json:"total"`
	Agreed            int          `json:"agreed"`
	CriticalDisagreed int          `json:"critical_disagreed"`
	Results           []Top1Result `json:"results"`
}

// Score is the fraction of fixtures whose top-1 index agrees.
func (r Top1Report) Score() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.Agreed) / float64(r.Total)
}

// Top1Agreement compares, for every fixture, the argmax of the sealed
// reference with the argmax of the reconstructed output in actuals. It is
// the semantic question — does the restored model give the same answer at
// every reference position? — asked independently of how close the
// numbers are (that is the tolerance gate, Evaluate). A missing actual is
// a Structural error, as in Evaluate; a shape or dtype mismatch, a NaN in
// either tensor, or an empty tensor is a disagreement with a note.
func Top1Agreement(fixtures []Fixture, actuals map[string]Tensor) (Top1Report, error) {
	if len(fixtures) == 0 {
		return Top1Report{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "equivalence: no fixtures", nil)
	}
	rep := Top1Report{Results: make([]Top1Result, 0, len(fixtures))}
	for _, f := range fixtures {
		act, ok := actuals[f.ID]
		if !ok {
			return Top1Report{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
				fmt.Sprintf("equivalence: no actual for fixture %q", f.ID), nil)
		}
		r := Top1Result{ID: f.ID, Critical: f.Critical, ExpectedIndex: -1, ActualIndex: -1}
		exp, expErr := argmax(f.Expected)
		got, gotErr := argmax(act)
		switch {
		case expErr != nil:
			r.Note = "reference: " + expErr.Error()
		case gotErr != nil:
			r.Note = "actual: " + gotErr.Error()
		case !shapeEqual(f.Expected.Shape, act.Shape):
			r.ExpectedIndex, r.ActualIndex = exp, got
			r.Note = fmt.Sprintf("shape %v != reference %v", act.Shape, f.Expected.Shape)
		default:
			r.ExpectedIndex, r.ActualIndex = exp, got
			r.Agree = exp == got
		}
		rep.Total++
		if r.Agree {
			rep.Agreed++
		} else if f.Critical {
			rep.CriticalDisagreed++
		}
		rep.Results = append(rep.Results, r)
	}
	return rep, nil
}

// argmax is the index of the largest value; the first one on ties. A NaN
// anywhere, or an empty tensor, is an error: there is no largest value.
func argmax(t Tensor) (int, error) {
	vals, err := decode(t)
	if err != nil {
		return -1, err
	}
	if len(vals) == 0 {
		return -1, fmt.Errorf("empty tensor")
	}
	best := 0
	for i, v := range vals {
		if math.IsNaN(v) {
			return -1, fmt.Errorf("NaN at index %d", i)
		}
		if v > vals[best] {
			best = i
		}
	}
	return best, nil
}
