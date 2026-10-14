// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"encoding/binary"
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// ---- basic kernel correctness ---------------------------------------------

func TestMatMul_ExactSmallCase(t *testing.T) {
	a := []float64{1, 2, 3, 4} // 2×2
	b := []float64{5, 6, 7, 8} // 2×2
	got := MatMul(a, 2, 2, b, 2)
	want := []float64{19, 22, 43, 50}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("MatMul[%d]=%v want %v", i, got[i], want[i])
		}
	}
}

func TestTranspose(t *testing.T) {
	x := []float64{1, 2, 3, 4, 5, 6} // 2×3
	got := Transpose(x, 2, 3)        // 3×2
	want := []float64{1, 4, 2, 5, 3, 6}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Transpose[%d]=%v want %v", i, got[i], want[i])
		}
	}
}

func TestSoftmaxRows_StableAndNormalized(t *testing.T) {
	// Large equal logits must not overflow and must give a uniform distribution.
	z := []float64{1000, 1000, 1000, 0, 1, 2}
	SoftmaxRows(z, 2, 3)
	if math.Abs(z[0]-1.0/3) > 1e-12 || math.Abs(z[1]-1.0/3) > 1e-12 {
		t.Fatalf("row0 not uniform: %v", z[:3])
	}
	var sum float64
	for _, v := range z[3:] {
		sum += v
	}
	if math.Abs(sum-1) > 1e-12 {
		t.Fatalf("row1 not normalized: sum=%v", sum)
	}
	if !(z[3] < z[4] && z[4] < z[5]) {
		t.Fatalf("softmax must be monotonic: %v", z[3:])
	}
}

func TestLayerNormRows_ZeroMean(t *testing.T) {
	t2 := []float64{1, 2, 3, 4}
	g := []float64{1, 1, 1, 1}
	b := []float64{0, 0, 0, 0}
	LayerNormRows(t2, 1, 4, g, b, 0)
	var mean float64
	for _, v := range t2 {
		mean += v
	}
	if math.Abs(mean/4) > 1e-12 {
		t.Fatalf("layernorm output mean should be ~0, got %v", mean/4)
	}
}

// ---- determinism: the availability guarantee (rung 2) ---------------------

func randParams(seed int64, d int) (Params, []float64, int) {
	r := rand.New(rand.NewSource(seed))
	rv := func(n int) []float64 {
		out := make([]float64, n)
		for i := range out {
			out[i] = r.NormFloat64()
		}
		return out
	}
	L := 8
	p := Params{
		D: d, Wq: rv(d * d), Wk: rv(d * d), Wv: rv(d * d), Wo: rv(d * d),
		W1: rv(d * 4 * d), W2: rv(4 * d * d),
		G: rv(d), B: rv(d), Eps: 1e-5,
	}
	return p, rv(L * d), L
}

func TestTransformerBlock_Deterministic(t *testing.T) {
	p, x, L := randParams(42, 16)
	o1 := p.TransformerBlock(x, L)
	o2 := p.TransformerBlock(x, L)
	if len(o1) != L*p.D {
		t.Fatalf("wrong output size %d", len(o1))
	}
	for i := range o1 {
		if math.Float64bits(o1[i]) != math.Float64bits(o2[i]) {
			t.Fatalf("nondeterministic at %d: %x vs %x",
				i, math.Float64bits(o1[i]), math.Float64bits(o2[i]))
		}
	}
}

// TestTransformerBlock_GateEXACT proves the core failover value: two nodes
// running the same deterministic canonical kernel on the same sealed genome
// produce byte-identical output, so the equivalence gate returns EXACT. This is
// what removes the BLAS-drift fragility that the cross-hardware experiments
// exposed (within a pinned Go toolchain; cross-arch to be confirmed on the
// matrix — see docs/testing/cross-hardware-determinism.md).
func TestTransformerBlock_GateEXACT(t *testing.T) {
	p, x, L := randParams(7, 16)
	sealed := p.TransformerBlock(x, L) // "original" node
	restored := p.TransformerBlock(x, L)

	fx := []equivalence.Fixture{{ID: "block-0", Expected: f64Tensor([]int{L, p.D}, sealed), Critical: true}}
	act := map[string]equivalence.Tensor{"block-0": f64Tensor([]int{L, p.D}, restored)}
	v, err := equivalence.Evaluate("genome-canon", fx, act, equivalence.Tolerance{}, equivalence.StrictPolicy())
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if v.Level != equivalence.LevelExact {
		t.Fatalf("canonical kernel must be gate-EXACT, got %s (maxAbs=%g)", v.Level, v.MaxAbsErr)
	}
}

// ---- fixed point: byte-portable by construction (rung 3) ------------------

func TestDotI8_ExactVsBigIntOracle(t *testing.T) {
	r := rand.New(rand.NewSource(99))
	for trial := 0; trial < 200; trial++ {
		n := 1 + r.Intn(1024)
		a := make([]int8, n)
		b := make([]int8, n)
		oracle := big.NewInt(0)
		for i := 0; i < n; i++ {
			a[i] = int8(r.Intn(256) - 128)
			b[i] = int8(r.Intn(256) - 128)
			oracle.Add(oracle, big.NewInt(int64(a[i])*int64(b[i])))
		}
		got, err := DotI8(a, b)
		// n <= 1024, |term| <= 127*128 = 16256, |sum| <= ~16.6M < int32 max.
		if err != nil {
			t.Fatalf("unexpected overflow at n=%d: %v", n, err)
		}
		if oracle.Int64() != int64(got) {
			t.Fatalf("DotI8=%d oracle=%d (n=%d)", got, oracle.Int64(), n)
		}
	}
}

func TestDotI8_OverflowDetected(t *testing.T) {
	n := 200000 // 127*127*200000 >> int32 max
	a := make([]int8, n)
	b := make([]int8, n)
	for i := range a {
		a[i], b[i] = 127, 127
	}
	if _, err := DotI8(a, b); err == nil {
		t.Fatal("expected int32 overflow error")
	}
}

func TestDotQuant_DeterministicAndClose(t *testing.T) {
	r := rand.New(rand.NewSource(123))
	n := 512
	a := make([]float64, n)
	b := make([]float64, n)
	for i := 0; i < n; i++ {
		a[i] = r.NormFloat64() * 0.1
		b[i] = r.NormFloat64() * 0.1
	}
	// Symmetric quantization (zero=0) with a scale covering ~[-4σ,4σ] over 127 steps.
	qa := Quant{Scale: 0.4 / 127, Zero: 0}
	qb := Quant{Scale: 0.4 / 127, Zero: 0}

	q1, err := DotQuant(a, b, qa, qb)
	if err != nil {
		t.Fatalf("DotQuant: %v", err)
	}
	q2, _ := DotQuant(a, b, qa, qb)
	if math.Float64bits(q1) != math.Float64bits(q2) {
		t.Fatal("DotQuant must be byte-identical for identical inputs (portable by construction)")
	}

	exact := Dot(a, b)
	// Quantization error bound is loose but must be well within an EQUIVALENT
	// tolerance — the gate is what certifies this formally.
	tol := equivalence.Tolerance{Atol: 1e-2, Rtol: 1e-2}
	fx := []equivalence.Fixture{{ID: "dot", Expected: f64Tensor([]int{1}, []float64{exact})}}
	act := map[string]equivalence.Tensor{"dot": f64Tensor([]int{1}, []float64{q1})}
	v, err := equivalence.Evaluate("g", fx, act, tol, equivalence.StrictPolicy())
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if v.Level == equivalence.LevelFail {
		t.Fatalf("quantized dot should be EQUIVALENT within tol, got FAIL (exact=%g q=%g absErr=%g)",
			exact, q1, math.Abs(exact-q1))
	}
}

// f64Tensor encodes a float64 slice as a little-endian equivalence.Tensor.
func f64Tensor(shape []int, vals []float64) equivalence.Tensor {
	raw := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(raw[i*8:], math.Float64bits(v))
	}
	return equivalence.Tensor{DType: equivalence.F64, Shape: shape, Raw: raw}
}
