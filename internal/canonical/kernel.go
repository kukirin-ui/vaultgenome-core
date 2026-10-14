// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import "math"

// This file is determinism-ladder rung 2: a BLAS-free, single-threaded,
// fixed-reduction-order float64 reference kernel. Every reduction sums in
// ascending index order, so the result does not depend on thread count or a
// library's tiling. Within a pinned Go toolchain it is bit-identical run to run
// and — because gc does not contract a*b+c into an FMA across statements, uses a
// correctly-rounded hardware SQRTSD, and a software (pure-Go) math.Exp — is
// expected to be byte-identical across CPU architectures. That cross-arch claim
// must still be confirmed on the arch matrix before a reconstruction that used
// this kernel is asserted EXACT in production; see
// docs/testing/cross-hardware-determinism.md.

// Dot is a fixed-order (ascending-index) inner product. The summation order is
// part of the contract and never varies with input, platform, or threads.
func Dot(a, b []float64) float64 {
	var s float64
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

// MatMul computes C = A·B where A is m×k and B is k×n, both row-major, and C is
// m×n row-major. Each element is a fixed-order reduction over the shared k axis.
func MatMul(a []float64, m, k int, b []float64, n int) []float64 {
	c := make([]float64, m*n)
	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			var s float64
			for p := 0; p < k; p++ {
				s += a[i*k+p] * b[p*n+j]
			}
			c[i*n+j] = s
		}
	}
	return c
}

// Transpose returns the r×c row-major matrix x transposed to c×r row-major.
func Transpose(x []float64, r, c int) []float64 {
	out := make([]float64, r*c)
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			out[j*r+i] = x[i*c+j]
		}
	}
	return out
}

// SoftmaxRows applies a numerically-stable softmax independently to each row of
// the rows×cols row-major matrix z (in place): subtract the row max, exponentiate
// in ascending order, divide by the ascending-order sum.
func SoftmaxRows(z []float64, rows, cols int) {
	for i := 0; i < rows; i++ {
		row := z[i*cols : i*cols+cols]
		mx := row[0]
		for _, v := range row {
			if v > mx {
				mx = v
			}
		}
		var sum float64
		for j := range row {
			row[j] = math.Exp(row[j] - mx)
			sum += row[j]
		}
		for j := range row {
			row[j] /= sum
		}
	}
}

// LayerNormRows applies layer normalization independently to each row of the
// rows×d row-major matrix t (in place): (t-mean)/sqrt(var+eps)*g + b. Mean and
// variance reduce in ascending order; var is the population (biased) variance,
// matching the reference transformer.
func LayerNormRows(t []float64, rows, d int, g, b []float64, eps float64) {
	for i := 0; i < rows; i++ {
		row := t[i*d : i*d+d]
		var mean float64
		for _, v := range row {
			mean += v
		}
		mean /= float64(d)
		var variance float64
		for _, v := range row {
			diff := v - mean
			variance += diff * diff
		}
		variance /= float64(d)
		inv := 1.0 / math.Sqrt(variance+eps)
		for j := range row {
			row[j] = (row[j]-mean)*inv*g[j] + b[j]
		}
	}
}

// ReLU applies max(0,x) elementwise, in place.
func ReLU(x []float64) {
	for i := range x {
		if x[i] < 0 {
			x[i] = 0
		}
	}
}

// addInto returns a+b elementwise (a and b are the same length).
func addInto(a, b []float64) []float64 {
	out := make([]float64, len(a))
	for i := range a {
		out[i] = a[i] + b[i]
	}
	return out
}

// Params holds one transformer block's weights, all row-major.
type Params struct {
	D          int       // model dimension
	Wq, Wk, Wv []float64 // d×d projections
	Wo         []float64 // d×d output projection
	W1         []float64 // d×(4d)
	W2         []float64 // (4d)×d
	G, B       []float64 // length-d LayerNorm gain and bias
	Eps        float64   // LayerNorm epsilon
}

// TransformerBlock runs one pre-norm-free reference block on x (L×d row-major)
// and returns the L×d result. It mirrors, operation for operation, the numpy
// block used in the cross-hardware determinism experiments, but computes every
// GEMM through the fixed-order Dot above instead of BLAS — so its output does
// not move when the host's BLAS build or thread count changes.
//
//	q,k,v = x·Wq, x·Wk, x·Wv
//	a     = softmax(q·kᵀ / sqrt(d))
//	h     = LayerNorm(x + (a·v)·Wo)
//	m     = ReLU(h·W1)·W2
//	out   = LayerNorm(h + m)
func (p Params) TransformerBlock(x []float64, L int) []float64 {
	d := p.D
	q := MatMul(x, L, d, p.Wq, d)
	k := MatMul(x, L, d, p.Wk, d)
	v := MatMul(x, L, d, p.Wv, d)

	kT := Transpose(k, L, d)         // d×L
	scores := MatMul(q, L, d, kT, L) // L×L
	scale := 1.0 / math.Sqrt(float64(d))
	for i := range scores {
		scores[i] *= scale
	}
	SoftmaxRows(scores, L, L)

	av := MatMul(scores, L, L, v, d) // L×d
	avo := MatMul(av, L, d, p.Wo, d) // L×d
	h := addInto(x, avo)
	LayerNormRows(h, L, d, p.G, p.B, p.Eps)

	m1 := MatMul(h, L, d, p.W1, 4*d) // L×4d
	ReLU(m1)
	m2 := MatMul(m1, L, 4*d, p.W2, d) // L×d
	out := addInto(h, m2)
	LayerNormRows(out, L, d, p.G, p.B, p.Eps)
	return out
}
