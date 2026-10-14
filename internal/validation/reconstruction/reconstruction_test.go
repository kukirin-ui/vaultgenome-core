// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"encoding/binary"
	"math"
	"math/rand"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/canonical"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

const genomeL, genomeD = 8, 16

// mkParams builds a seeded transformer block (the "genome" weights).
func mkParams(seed int64) canonical.Params {
	r := rand.New(rand.NewSource(seed))
	rv := func(n int) []float64 {
		out := make([]float64, n)
		for i := range out {
			out[i] = r.NormFloat64()
		}
		return out
	}
	d := genomeD
	return canonical.Params{
		D: d, Wq: rv(d * d), Wk: rv(d * d), Wv: rv(d * d), Wo: rv(d * d),
		W1: rv(d * 4 * d), W2: rv(4 * d * d), G: rv(d), B: rv(d), Eps: 1e-5,
	}
}

func f64Tensor(shape []int, vals []float64) equivalence.Tensor {
	raw := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(raw[i*8:], math.Float64bits(v))
	}
	return equivalence.Tensor{DType: equivalence.F64, Shape: shape, Raw: raw}
}

// genome bundles the sealed weights, the reference fixtures (input id -> sealed
// expected output computed on the origin with the f64 kernel), and the inputs.
type genome struct {
	p        canonical.Params
	fixtures []equivalence.Fixture
	inputs   map[string][]float64
}

func sealGenome(seed int64, nFixtures int) genome {
	p := mkParams(seed)
	g := genome{p: p, inputs: map[string][]float64{}}
	for i := 0; i < nFixtures; i++ {
		id := string(rune('a' + i))
		r := rand.New(rand.NewSource(seed*100 + int64(i)))
		x := make([]float64, genomeL*genomeD)
		for j := range x {
			x[j] = r.NormFloat64()
		}
		out := p.TransformerBlock(x, genomeL) // sealed reference behavior
		g.inputs[id] = x
		g.fixtures = append(g.fixtures, equivalence.Fixture{
			ID:       id,
			Expected: f64Tensor([]int{genomeL, genomeD}, out),
			Critical: i == 0, // first fixture is a critical identity probe
		})
	}
	return g
}

// door builders — each returns a RecomputeFunc for a compute strategy.

func f64Door(p canonical.Params, inputs map[string][]float64) RecomputeFunc {
	return func(id string) (equivalence.Tensor, error) {
		out := p.TransformerBlock(inputs[id], genomeL)
		return f64Tensor([]int{genomeL, genomeD}, out), nil
	}
}

// driftingF64Door simulates a host whose BLAS build makes the f64 path diverge
// from the sealed byte-exact reference: it perturbs the output by one ULP-ish
// amount so a tol-0 gate rejects it (exactly the cross-hardware drift the
// experiments measured).
func driftingF64Door(p canonical.Params, inputs map[string][]float64) RecomputeFunc {
	base := f64Door(p, inputs)
	return func(id string) (equivalence.Tensor, error) {
		tsr, _ := base(id)
		// bump the first float by a tiny amount
		v := math.Float64frombits(binary.LittleEndian.Uint64(tsr.Raw[0:8]))
		binary.LittleEndian.PutUint64(tsr.Raw[0:8], math.Float64bits(v+1e-9))
		return tsr, nil
	}
}

func integerDoor(p canonical.Params, inputs map[string][]float64) RecomputeFunc {
	fp := canonical.QuantizeParams(p)
	return func(id string) (equivalence.Tensor, error) {
		out := canonical.DequantizeVec(fp.TransformerBlockQ(canonical.QuantizeVec(inputs[id]), genomeL))
		return f64Tensor([]int{genomeL, genomeD}, out), nil
	}
}

var (
	exactTol = equivalence.Tolerance{}                       // byte-exact
	intTol   = equivalence.Tolerance{Atol: 0.05, Rtol: 0.05} // integer door fidelity
)

// TestRegenerate_HappyPathOpensHighestDoor: same hardware, the byte-exact f64
// replay reproduces the sealed reference → the first door opens as EXACT.
func TestRegenerate_HappyPathOpensHighestDoor(t *testing.T) {
	g := sealGenome(1, 4)
	ladder := []Strategy{
		{Rung: 1, Name: "pinned-f64-replay", Recompute: f64Door(g.p, g.inputs), Tol: exactTol, Pol: equivalence.StrictPolicy()},
		{Rung: 3, Name: "integer-canonical", Recompute: integerDoor(g.p, g.inputs), Tol: intTol, Pol: equivalence.StrictPolicy()},
	}
	res, err := Regenerate("genome-1", g.fixtures, ladder)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if !res.Opened || res.Rung != 1 {
		t.Fatalf("expected door 1 to open EXACT, got %+v", res)
	}
	if res.Verdict.Level != equivalence.LevelExact {
		t.Fatalf("door 1 should be EXACT, got %s", res.Verdict.Level)
	}
}

// TestRegenerate_FallsThroughToWorkingDoor: cross-hardware drift makes the f64
// door FAIL, but the descent does NOT abort — it falls to the integer door,
// which is byte-portable by construction and passes as EQUIVALENT.
func TestRegenerate_FallsThroughToWorkingDoor(t *testing.T) {
	g := sealGenome(2, 4)
	ladder := []Strategy{
		{Rung: 1, Name: "host-blas-f64", Recompute: driftingF64Door(g.p, g.inputs), Tol: exactTol, Pol: equivalence.StrictPolicy()},
		{Rung: 3, Name: "integer-canonical", Recompute: integerDoor(g.p, g.inputs), Tol: intTol, Pol: equivalence.StrictPolicy()},
	}
	res, err := Regenerate("genome-2", g.fixtures, ladder)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if !res.Opened {
		t.Fatalf("a healthy genome must find a working door, got %+v", res)
	}
	if res.Rung != 3 {
		t.Fatalf("expected fall-through to integer door (rung 3), opened rung %d", res.Rung)
	}
	if len(res.Attempts) != 2 || res.Attempts[0].Level != equivalence.LevelFail {
		t.Fatalf("door 1 should have been tried and FAILed: %+v", res.Attempts)
	}
	if res.Verdict.Level != equivalence.LevelEquivalent {
		t.Fatalf("integer door should be EQUIVALENT, got %s", res.Verdict.Level)
	}
}

// TestRegenerate_CorruptedGenomeFailsClosed: a wrong/corrupted genome fails EVERY
// door — the descent tries them all and blocks (Opened=false), which maps to
// ReasonValidationFailed. This is the anti-corruption / anti-worm guarantee: a
// wrong model is never brought up automatically.
func TestRegenerate_CorruptedGenomeFailsClosed(t *testing.T) {
	g := sealGenome(3, 4)    // sealed reference from the REAL genome
	corrupt := mkParams(999) // a completely different ("corrupted") genome
	ladder := []Strategy{
		{Rung: 1, Name: "pinned-f64-replay", Recompute: f64Door(corrupt, g.inputs), Tol: exactTol, Pol: equivalence.StrictPolicy()},
		{Rung: 3, Name: "integer-canonical", Recompute: integerDoor(corrupt, g.inputs), Tol: intTol, Pol: equivalence.StrictPolicy()},
	}
	res, err := Regenerate("genome-3", g.fixtures, ladder)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if res.Opened {
		t.Fatal("a corrupted genome must NOT open any door (fail-closed)")
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("all doors must be tried before failing closed, got %d attempts", len(res.Attempts))
	}
	if Reason(res.Verdict) != reconstitution_decision.ReasonValidationFailed {
		t.Fatalf("blocked regeneration must map to validation_failed, got %s", Reason(res.Verdict))
	}
}

// TestToDimensionVerdict_MapsOntoBehavioralDimension checks the frozen-contract
// mapping: a pass becomes VerdictPass score 1.0; a fail becomes VerdictFail with
// error findings, and a critical outlier gets the distinct code.
func TestToDimensionVerdict_MapsOntoBehavioralDimension(t *testing.T) {
	g := sealGenome(4, 3)

	// passing (integer door within tolerance)
	vPass, err := Evaluate("g", g.fixtures, integerDoor(g.p, g.inputs), intTol, equivalence.StrictPolicy())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	dv := ToDimensionVerdict(vPass, 0.99)
	if dv.Verdict != validation_result.VerdictPass || dv.Score != 1.0 {
		t.Fatalf("passing gate must map to VerdictPass score 1.0, got %+v", dv)
	}
	if len(dv.Details) != 0 {
		t.Fatalf("passing gate should have no findings, got %v", dv.Details)
	}

	// failing (wrong genome), first fixture is critical → distinct code
	vFail, _ := Evaluate("g", g.fixtures, f64Door(mkParams(888), g.inputs), exactTol, equivalence.StrictPolicy())
	dvf := ToDimensionVerdict(vFail, 0.99)
	if dvf.Verdict != validation_result.VerdictFail {
		t.Fatalf("failing gate must map to VerdictFail, got %s", dvf.Verdict)
	}
	sawCritical := false
	for _, f := range dvf.Details {
		if f.Code == "equivalence_critical_outlier" {
			sawCritical = true
		}
		if f.Severity != validation_result.SeverityError {
			t.Fatalf("outlier findings must be error severity, got %s", f.Severity)
		}
	}
	if !sawCritical {
		t.Fatalf("a failing critical fixture must produce a critical finding: %+v", dvf.Details)
	}
}

func TestRegenerate_EmptyLadderRejected(t *testing.T) {
	g := sealGenome(5, 2)
	if _, err := Regenerate("g", g.fixtures, nil); err == nil {
		t.Fatal("empty ladder must error")
	}
}
