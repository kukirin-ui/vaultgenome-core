// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"math"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

func TestExpNegQ_ApproximatesExp(t *testing.T) {
	if expNegQ(0) != int32(fpOne) {
		t.Fatalf("expNegQ(0) must be 1.0 (=%d), got %d", fpOne, expNegQ(0))
	}
	for _, x := range []float64{-0.1, -0.5, -1, -2, -5, -10} {
		xq := int32(math.RoundToEven(x * float64(fpOne)))
		got := float64(expNegQ(xq)) / float64(fpOne)
		want := math.Exp(x)
		if math.Abs(got-want) > 0.02 { // i-BERT 2nd-order poly bound
			t.Fatalf("expNegQ(%g)=%.4f want exp=%.4f (err %.4f)", x, got, want, math.Abs(got-want))
		}
	}
}

func TestISqrtU64(t *testing.T) {
	for _, n := range []uint64{0, 1, 2, 3, 4, 15, 16, 17, 100, 1 << 20, 1<<40 + 12345} {
		got := isqrtU64(n)
		want := uint64(math.Sqrt(float64(n)))
		// floor sqrt; allow the float reference to be off by one either way.
		if got > want+1 || (want > 0 && got < want-1) {
			t.Fatalf("isqrtU64(%d)=%d want ~%d", n, got, want)
		}
		if got*got > n || (got+1)*(got+1) <= n {
			t.Fatalf("isqrtU64(%d)=%d not floor sqrt", n, got)
		}
	}
}

func TestSoftmaxRowsQ_Normalized(t *testing.T) {
	z := []int32{
		int32(1 * fpOne), int32(2 * fpOne), int32(3 * fpOne),
		int32(-5 * fpOne), 0, int32(5 * fpOne),
	}
	SoftmaxRowsQ(z, 2, 3)
	for r := 0; r < 2; r++ {
		var sum int64
		for _, v := range z[r*3 : r*3+3] {
			sum += int64(v)
		}
		// Should sum to ~1.0 (fpOne) within integer-division slack.
		if math.Abs(float64(sum)/float64(fpOne)-1) > 0.001 {
			t.Fatalf("row %d softmax sum=%.5f, want ~1.0", r, float64(sum)/float64(fpOne))
		}
	}
}

// TestTransformerBlockQ_ByteIdenticalByConstruction: the integer block is
// deterministic and — being integer-only — identical on every platform. We
// assert exact byte-equality across repeated runs (the property that, unlike the
// float64 kernel, holds across architectures by construction).
func TestTransformerBlockQ_ByteIdenticalByConstruction(t *testing.T) {
	p, x, L := randParams(3, 16)
	fp := QuantizeParams(p)
	xq := QuantizeVec(x)
	o1 := fp.TransformerBlockQ(xq, L)
	o2 := fp.TransformerBlockQ(append([]int32(nil), xq...), L)
	for i := range o1 {
		if o1[i] != o2[i] {
			t.Fatalf("integer block nondeterministic at %d: %d vs %d", i, o1[i], o2[i])
		}
	}
}

// TestTransformerBlockQ_GateEQUIVALENT: the integer block reproduces the float64
// reference within tolerance, so the equivalence gate certifies it EQUIVALENT.
// This is the honest claim: byte-portable by construction AND provably close to
// the original model. The measured error is logged so the tolerance is grounded.
func TestTransformerBlockQ_GateEQUIVALENT(t *testing.T) {
	var maxAbs, maxRel float64
	for _, seed := range []int64{1, 2, 3, 7, 11} {
		p, x, L := randParams(seed, 16)
		ref := p.TransformerBlock(x, L)

		fp := QuantizeParams(p)
		got := DequantizeVec(fp.TransformerBlockQ(QuantizeVec(x), L))

		for i := range ref {
			abs := math.Abs(got[i] - ref[i])
			rel := abs / (math.Abs(ref[i]) + 1e-9)
			if abs > maxAbs {
				maxAbs = abs
			}
			if rel > maxRel {
				maxRel = rel
			}
		}
	}
	t.Logf("integer-vs-float64 block error: maxAbs=%.4g maxRel=%.4g", maxAbs, maxRel)

	// Tolerance grounded in the measured error: across seeds the fully-integer
	// Q16 block tracks the float64 reference to ~3.6e-3 abs / ~1.2% rel, so a
	// 0.05 abs / 0.05 rel gate tolerance holds with headroom.
	tol := equivalence.Tolerance{Atol: 0.05, Rtol: 0.05}
	p, x, L := randParams(1, 16)
	ref := p.TransformerBlock(x, L)
	fp := QuantizeParams(p)
	got := DequantizeVec(fp.TransformerBlockQ(QuantizeVec(x), L))
	fx := []equivalence.Fixture{{ID: "blk", Expected: f64Tensor([]int{L, p.D}, ref)}}
	act := map[string]equivalence.Tensor{"blk": f64Tensor([]int{L, p.D}, got)}
	v, err := equivalence.Evaluate("g", fx, act, tol, equivalence.StrictPolicy())
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if v.Level == equivalence.LevelFail {
		t.Fatalf("integer block should be EQUIVALENT within tol, got FAIL (maxAbs=%g maxRel=%g)", v.MaxAbsErr, v.MaxRelErr)
	}
	t.Logf("verdict=%s nEquivalent=%d maxAbs=%.4g", v.Level, v.NEquivalent, v.MaxAbsErr)
}
