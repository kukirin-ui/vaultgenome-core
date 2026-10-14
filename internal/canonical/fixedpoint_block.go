// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import "math"

// This file completes determinism-ladder rung 3: a FULLY INTEGER transformer
// block. Unlike the float64 kernel (rung 2, byte-identical only within a pinned
// toolchain), every operation here is integer, so the output is byte-identical
// on any CPU architecture, under any BLAS, at any thread count — BY CONSTRUCTION.
// This is the guaranteed-availability path for cross-hardware regeneration.
//
// # Representation
//
// Activations flow as int32 in a fixed-point Qf format: the integer v means the
// real number v / 2^Fbits. Weights are quantized the same way. Products
// accumulate in int64 and are rescaled back to Qf by an arithmetic shift with
// round-to-nearest, saturating to int32. The ONLY floats in the whole path are
// (a) the input quantization at the boundary and (b) sealed scalar constants
// (Fbits, epsilon, the exp/LayerNorm polynomial coefficients) that are part of
// the sealed genome and therefore identical on every machine. No float
// arithmetic occurs in the hot path, so nothing can round differently per host.
//
// # Nonlinearities without floats
//
//   - exp: i-BERT-style integer exponential (Kim et al., 2021). Range-reduce
//     x = -(z·ln2 + r) with r in (-ln2, 0], approximate exp(r) by a fixed
//     2nd-order polynomial evaluated in fixed point, then halve z times by an
//     integer shift. Softmax is exp over the row divided by the integer sum.
//   - 1/sqrt: integer Newton isqrt for LayerNorm's normalization; no math.Sqrt.
//
// Approximation error versus the float64 reference is bounded and small; the
// equivalence gate certifies the block EQUIVALENT within a stated tolerance
// (see fixedpoint_block_test.go). The determinism itself is exact.

// Fbits is the fixed-point fractional width. 16 gives ~1.5e-5 resolution and,
// with int32 activations, a real-value range of about ±32768 — ample for the
// normalized activations of a transformer block.
const Fbits = 16

const fpOne = int64(1) << Fbits // 1.0 in Qf

// satInt32 clamps a wide accumulator to int32.
func satInt32(x int64) int32 {
	if x > math.MaxInt32 {
		return math.MaxInt32
	}
	if x < math.MinInt32 {
		return math.MinInt32
	}
	return int32(x)
}

// qRound converts a wide fixed-point-scaled accumulator scaled by 2^shift back
// to Qf, rounding to nearest (half away from zero) and saturating.
func qShiftRound(acc int64, shift uint) int32 {
	if shift == 0 {
		return satInt32(acc)
	}
	half := int64(1) << (shift - 1)
	if acc >= 0 {
		return satInt32((acc + half) >> shift)
	}
	return satInt32(-((-acc + half) >> shift))
}

// QuantizeVec maps a float64 slice to Qf int32 (round-half-to-even at the sealed
// boundary; deterministic and platform-independent), saturating to int32.
func QuantizeVec(x []float64) []int32 {
	out := make([]int32, len(x))
	for i, v := range x {
		out[i] = satInt32(int64(math.RoundToEven(v * float64(fpOne))))
	}
	return out
}

// DequantizeVec maps a Qf int32 slice back to float64.
func DequantizeVec(x []int32) []float64 {
	out := make([]float64, len(x))
	for i, v := range x {
		out[i] = float64(v) / float64(fpOne)
	}
	return out
}

// mulQ multiplies two Qf values, returning a Qf value (integer only).
func mulQ(a, b int32) int32 {
	return qShiftRound(int64(a)*int64(b), Fbits)
}

// GemmQ computes C = A·B in Qf, A is m×k, B is k×n, all row-major, int only.
// Each dot accumulates a·b (Q2f) in int64 and rescales to Qf once.
func GemmQ(a []int32, m, k int, b []int32, n int) []int32 {
	c := make([]int32, m*n)
	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			var acc int64
			for p := 0; p < k; p++ {
				acc += int64(a[i*k+p]) * int64(b[p*n+j])
			}
			c[i*n+j] = qShiftRound(acc, Fbits)
		}
	}
	return c
}

// transposeQ returns the r×c matrix x transposed to c×r.
func transposeQ(x []int32, r, c int) []int32 {
	out := make([]int32, r*c)
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			out[j*r+i] = x[i*c+j]
		}
	}
	return out
}

// ReLUQ applies max(0,x) in place (integer).
func ReLUQ(x []int32) {
	for i := range x {
		if x[i] < 0 {
			x[i] = 0
		}
	}
}

// ---- integer exponential (i-BERT) -----------------------------------------

// ln2Q is ln(2) in Qf.
var ln2Q = int32(math.RoundToEven(math.Ln2 * float64(fpOne)))

// i-BERT exp(r) ≈ c2·(r + c1)^2 + c0 on r ∈ (-ln2, 0], coefficients in Qf.
var (
	ibC1 = int32(math.RoundToEven(1.353 * float64(fpOne)))
	ibC2 = int32(math.RoundToEven(0.3585 * float64(fpOne)))
	ibC0 = int32(math.RoundToEven(0.344 * float64(fpOne)))
)

// expNegQ returns exp(x) in Qf for x <= 0 (integer only). For x > 0 it returns
// fpOne (callers subtract the row max first, so inputs are always <= 0).
func expNegQ(x int32) int32 {
	if x >= 0 {
		return int32(fpOne)
	}
	// z = floor(-x / ln2); r = x + z·ln2  (r ∈ (-ln2, 0])
	z := (-int64(x)) / int64(ln2Q)
	r := x + int32(z)*ln2Q
	// exp(r) ≈ c2·(r+c1)^2 + c0
	t := r + ibC1
	sq := mulQ(t, t)
	er := mulQ(ibC2, sq) + ibC0
	// exp(x) = exp(r) / 2^z  (cap z to avoid shifting to zero prematurely)
	if z >= 31 {
		return 0
	}
	return int32(int64(er) >> uint(z))
}

// SoftmaxRowsQ applies softmax to each row of a rows×cols Qf matrix, in place,
// integer only: subtract the row max, integer exp, divide by the integer sum.
func SoftmaxRowsQ(z []int32, rows, cols int) {
	for i := 0; i < rows; i++ {
		row := z[i*cols : i*cols+cols]
		mx := row[0]
		for _, v := range row {
			if v > mx {
				mx = v
			}
		}
		var sum int64
		exps := make([]int32, cols)
		for j, v := range row {
			exps[j] = expNegQ(v - mx)
			sum += int64(exps[j])
		}
		if sum == 0 {
			sum = 1
		}
		for j := range row {
			// p = exp_j / sum, in Qf: (exp_j << Fbits) / sum
			row[j] = int32((int64(exps[j]) << Fbits) / sum)
		}
	}
}

// ---- integer 1/sqrt and LayerNorm -----------------------------------------

// isqrtU64 returns floor(sqrt(n)) by integer Newton iteration (no float).
func isqrtU64(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	x := n
	y := (x + 1) / 2
	for y < x {
		x = y
		y = (x + n/x) / 2
	}
	return x
}

// LayerNormRowsQ applies (t-mean)/sqrt(var+eps)*g + b per row, integer only.
// gamma/beta are Qf; epsQ is eps in Q(2·Fbits) to match the variance scale.
func LayerNormRowsQ(t []int32, rows, d int, gamma, beta []int32, epsQ int64) {
	for i := 0; i < rows; i++ {
		row := t[i*d : i*d+d]
		// mean in Qf (exact integer average, rounded).
		var s int64
		for _, v := range row {
			s += int64(v)
		}
		mean := qDivRound(s, int64(d))
		// variance in Q(2f): mean of (v-mean)^2, where (v-mean) is Qf so its
		// square is Q2f.
		var vs int64
		for _, v := range row {
			diff := int64(v) - mean
			vs += diff * diff
		}
		variance := vs / int64(d) // Q2f
		// std = sqrt(variance+eps) in Qf: isqrt of a Q2f value is Qf.
		std := int64(isqrtU64(uint64(variance + epsQ)))
		if std == 0 {
			std = 1
		}
		for j := range row {
			// norm = (v-mean)/std, in Qf: ((v-mean) << Fbits) / std
			norm := int32(((int64(row[j]) - mean) << Fbits) / std)
			row[j] = mulQ(norm, gamma[j]) + beta[j]
		}
	}
}

// qDivRound divides a Qf accumulator by an integer count, rounding to nearest.
func qDivRound(num, den int64) int64 {
	if den == 0 {
		return 0
	}
	half := den / 2
	if (num >= 0) == (den >= 0) {
		return (num + half) / den
	}
	return (num - half) / den
}

// FixedParams holds one block's weights already quantized to Qf.
type FixedParams struct {
	D              int
	Wq, Wk, Wv, Wo []int32
	W1, W2         []int32
	G, B           []int32
	EpsQ           int64 // epsilon in Q(2·Fbits)
	InvSqrtDQ      int32 // 1/sqrt(d) in Qf
}

// QuantizeParams converts a float64 Params into a FixedParams (all weights to Qf,
// eps to Q2f, and the attention scale 1/sqrt(d) to Qf). Done once at seal time.
func QuantizeParams(p Params) FixedParams {
	q := func(x []float64) []int32 { return QuantizeVec(x) }
	return FixedParams{
		D:  p.D,
		Wq: q(p.Wq), Wk: q(p.Wk), Wv: q(p.Wv), Wo: q(p.Wo),
		W1: q(p.W1), W2: q(p.W2),
		G: q(p.G), B: q(p.B),
		EpsQ:      int64(math.RoundToEven(p.Eps * float64(fpOne) * float64(fpOne))),
		InvSqrtDQ: int32(math.RoundToEven(1.0 / math.Sqrt(float64(p.D)) * float64(fpOne))),
	}
}

// TransformerBlockQ runs one transformer block entirely in integer arithmetic on
// a Qf input xq (L×d), returning the Qf output (L×d). Byte-identical on every
// platform by construction. Mirrors Params.TransformerBlock op for op.
func (p FixedParams) TransformerBlockQ(xq []int32, L int) []int32 {
	d := p.D
	q := GemmQ(xq, L, d, p.Wq, d)
	k := GemmQ(xq, L, d, p.Wk, d)
	v := GemmQ(xq, L, d, p.Wv, d)

	kT := transposeQ(k, L, d)       // d×L
	scores := GemmQ(q, L, d, kT, L) // L×L
	for i := range scores {
		scores[i] = mulQ(scores[i], p.InvSqrtDQ)
	}
	SoftmaxRowsQ(scores, L, L)

	av := GemmQ(scores, L, L, v, d) // L×d
	avo := GemmQ(av, L, d, p.Wo, d) // L×d
	h := make([]int32, len(xq))
	for i := range h {
		h[i] = satInt32(int64(xq[i]) + int64(avo[i]))
	}
	LayerNormRowsQ(h, L, d, p.G, p.B, p.EpsQ)

	m1 := GemmQ(h, L, d, p.W1, 4*d) // L×4d
	ReLUQ(m1)
	m2 := GemmQ(m1, L, 4*d, p.W2, d) // L×d
	out := make([]int32, len(h))
	for i := range out {
		out[i] = satInt32(int64(h[i]) + int64(m2[i]))
	}
	LayerNormRowsQ(out, L, d, p.G, p.B, p.EpsQ)
	return out
}
