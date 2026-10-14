// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"math"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// This file is determinism-ladder rung 3: the fixed-point foundation. Where the
// float64 kernel (rung 2) is byte-portable in practice, integer arithmetic is
// byte-portable BY CONSTRUCTION — Go's integer operations are exact and defined
// independently of the host, so the same integer program yields the same bytes
// on AMD, Intel, or ARM, under any BLAS, at any thread count. The only way an
// integer kernel can differ across platforms is silent overflow, so the
// primitives here account into a wider type and reject inputs that could
// overflow the declared accumulator.
//
// This provides the guaranteed-availability path: a reconstruction computed with
// these primitives agrees with itself bit-for-bit across hardware, so an
// emergency cross-server failover always comes up. It is only APPROXIMATELY
// equal to the original float64 model (quantization error), which is exactly what
// the equivalence gate's EQUIVALENT verdict certifies. The full fixed-point
// transformer block built on this foundation — including integer softmax and
// LayerNorm — lives in fixedpoint_block.go.

// Quant is an affine (asymmetric) int8 quantization scheme: real ≈ Scale·(q -
// Zero). Scale and Zero are shared parameters, so they are part of the sealed
// canonical genome and identical on every machine.
type Quant struct {
	Scale float64 // must be > 0
	Zero  int32   // zero-point, within int8 range
}

// Quantize maps a real value to int8 with round-half-to-even (the IEEE default,
// deterministic and platform-independent), clamped to the int8 range.
func (q Quant) Quantize(x float64) int8 {
	v := math.RoundToEven(x/q.Scale) + float64(q.Zero)
	if v > math.MaxInt8 {
		return math.MaxInt8
	}
	if v < math.MinInt8 {
		return math.MinInt8
	}
	return int8(v)
}

// DotI8 is an exact int8·int8 inner product accumulated in int64 and returned as
// int32. It is byte-identical on every platform by construction. It returns an
// Operational error if the accumulator leaves the int32 range, because a wrapped
// value would not be portable (real int8 GEMM hardware accumulates in int32).
func DotI8(a, b []int8) (int32, error) {
	if len(a) != len(b) {
		return 0, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"canonical: DotI8 length mismatch", nil)
	}
	var acc int64
	for i := range a {
		acc += int64(a[i]) * int64(b[i])
	}
	if acc > math.MaxInt32 || acc < math.MinInt32 {
		return 0, shared_errors.Operational(
			shared_errors.CodeFieldValueInvalid,
			"canonical: DotI8 int32 accumulator overflow", nil)
	}
	return int32(acc), nil
}

// DotQuant computes an approximate real inner product of a and b by quantizing
// both under qa and qb, doing the exact integer dot, and dequantizing with the
// full asymmetric-affine zero-point correction:
//
//	sum(real_a·real_b) ≈ sa·sb · Σ(qa_i - za)(qb_i - zb)
//
// The integer core is byte-portable by construction, so DotQuant returns the
// same float64 bits on every platform for the same quantized operands. The
// result differs from the exact float64 Dot only by quantization error, which
// the equivalence gate certifies as EQUIVALENT under a suitable tolerance.
func DotQuant(a, b []float64, qa, qb Quant) (float64, error) {
	if len(a) != len(b) {
		return 0, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"canonical: DotQuant length mismatch", nil)
	}
	if qa.Scale <= 0 || qb.Scale <= 0 {
		return 0, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"canonical: DotQuant scales must be positive", nil)
	}
	// Centered integer product Σ(qa_i - za)(qb_i - zb) accumulated in int64.
	var acc int64
	for i := range a {
		ca := int64(qa.Quantize(a[i])) - int64(qa.Zero)
		cb := int64(qb.Quantize(b[i])) - int64(qb.Zero)
		acc += ca * cb
	}
	return float64(acc) * qa.Scale * qb.Scale, nil
}
