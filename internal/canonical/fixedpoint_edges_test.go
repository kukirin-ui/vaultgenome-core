// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"math"
	"testing"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// TestQuantize_RoundsHalfEvenAndSaturates pins the int8 boundary: values
// are rounded half-to-even in units of Scale, offset by Zero, and clamped
// to int8 instead of wrapping.
func TestQuantize_RoundsHalfEvenAndSaturates(t *testing.T) {
	q := Quant{Scale: 0.5, Zero: 10}
	cases := []struct {
		x    float64
		want int8
	}{
		{0, 10},
		{0.25, 10},  // 0.5 units rounds to even (0)
		{0.75, 12},  // 1.5 units rounds to even (2)
		{-0.25, 10}, // -0.5 units rounds to even (0)
		{1, 12},
		{-1, 8},
		{100, math.MaxInt8},    // 200 units + 10 saturates high
		{-100, math.MinInt8},   // -200 units + 10 saturates low
		{58.5, math.MaxInt8},   // exactly 117 + 10 = 127 fits
		{59, math.MaxInt8},     // 118 + 10 = 128 saturates
		{-69, math.MinInt8},    // -138 + 10 = -128 fits
		{-69.5, math.MinInt8},  // -139 + 10 = -129 saturates
		{1e300, math.MaxInt8},  // far beyond range still saturates
		{-1e300, math.MinInt8}, // far beyond range still saturates
	}
	for _, tc := range cases {
		if got := q.Quantize(tc.x); got != tc.want {
			t.Errorf("Quantize(%g)=%d want %d", tc.x, got, tc.want)
		}
	}
}

// TestDotI8_LengthMismatchIsStructural proves that operands of different
// lengths are refused as a caller fault before any arithmetic runs, so a
// shorter vector is never silently zero-padded.
func TestDotI8_LengthMismatchIsStructural(t *testing.T) {
	cases := []struct{ a, b []int8 }{
		{[]int8{1, 2, 3}, []int8{1, 2}},
		{[]int8{}, []int8{1}},
		{nil, []int8{0}},
	}
	for _, tc := range cases {
		got, err := DotI8(tc.a, tc.b)
		if err == nil {
			t.Fatalf("DotI8(len %d, len %d) must refuse, got %d", len(tc.a), len(tc.b), got)
		}
		if shared_errors.CategoryOf(err) != shared_errors.CategoryStructural || shared_errors.CodeOf(err) != shared_errors.CodeFieldValueInvalid {
			t.Fatalf("DotI8 mismatch error = %v, want structural field_value_invalid", err)
		}
		if got != 0 {
			t.Fatalf("DotI8 refused but returned %d", got)
		}
	}
	if got, err := DotI8(nil, nil); err != nil || got != 0 {
		t.Fatalf("DotI8(nil,nil) = %d, %v; want 0, nil", got, err)
	}
}

// TestDotQuant_RefusesBadOperands proves DotQuant refuses mismatched
// lengths and non-positive scales as structural errors, and still
// computes the exact centred product for well-formed operands.
func TestDotQuant_RefusesBadOperands(t *testing.T) {
	ok := Quant{Scale: 0.1, Zero: 0}
	cases := []struct {
		name   string
		a, b   []float64
		qa, qb Quant
	}{
		{"length mismatch", []float64{1, 2}, []float64{1}, ok, ok},
		{"zero scale a", []float64{1}, []float64{1}, Quant{Scale: 0}, ok},
		{"negative scale b", []float64{1}, []float64{1}, ok, Quant{Scale: -0.1}},
	}
	for _, tc := range cases {
		got, err := DotQuant(tc.a, tc.b, tc.qa, tc.qb)
		if err == nil {
			t.Fatalf("%s: must refuse, got %g", tc.name, got)
		}
		if shared_errors.CategoryOf(err) != shared_errors.CategoryStructural || shared_errors.CodeOf(err) != shared_errors.CodeFieldValueInvalid {
			t.Fatalf("%s: error = %v, want structural field_value_invalid", tc.name, err)
		}
		if got != 0 {
			t.Fatalf("%s: refused but returned %g", tc.name, got)
		}
	}

	// With Zero offsets the centred product is exact: (1·1 + 2·3) = 7 in
	// units of 0.1·0.1 after each operand quantizes exactly.
	got, err := DotQuant([]float64{0.1, 0.2}, []float64{0.1, 0.3}, Quant{Scale: 0.1, Zero: 5}, Quant{Scale: 0.1, Zero: -3})
	if err != nil {
		t.Fatal(err)
	}
	if want := 7 * 0.1 * 0.1; math.Abs(got-want) > 1e-12 {
		t.Fatalf("DotQuant = %g want %g", got, want)
	}
}

// TestSatInt32_ClampsBothEnds pins the saturation the whole integer block
// relies on: a wide accumulator beyond int32 lands on the nearest bound
// rather than wrapping.
func TestSatInt32_ClampsBothEnds(t *testing.T) {
	cases := map[int64]int32{
		0:                     0,
		math.MaxInt32:         math.MaxInt32,
		math.MaxInt32 + 1:     math.MaxInt32,
		math.MaxInt64:         math.MaxInt32,
		math.MinInt32:         math.MinInt32,
		math.MinInt32 - 1:     math.MinInt32,
		math.MinInt64:         math.MinInt32,
		-7:                    -7,
		int64(1) << 40:        math.MaxInt32,
		-(int64(1) << 40) - 5: math.MinInt32,
	}
	for in, want := range cases {
		if got := satInt32(in); got != want {
			t.Errorf("satInt32(%d)=%d want %d", in, got, want)
		}
	}
}

// TestQShiftRound_Table pins the rescaling rule: round to nearest, half
// away from zero, symmetric in sign, saturating; a zero shift is a plain
// saturating narrow.
func TestQShiftRound_Table(t *testing.T) {
	cases := []struct {
		acc   int64
		shift uint
		want  int32
	}{
		{5, 0, 5},
		{math.MaxInt64, 0, math.MaxInt32},
		{math.MinInt64, 0, math.MinInt32},
		{4, 1, 2},
		{5, 1, 3},   // 2.5 rounds away from zero
		{-5, 1, -3}, // -2.5 rounds away from zero
		{7, 2, 2},   // 1.75 rounds to 2
		{-7, 2, -2}, // symmetric
		{6, 2, 2},   // 1.5 rounds away from zero
		{-6, 2, -2},
		{1 << 40, 4, math.MaxInt32},
		{-(1 << 40), 4, math.MinInt32},
	}
	for _, tc := range cases {
		if got := qShiftRound(tc.acc, tc.shift); got != tc.want {
			t.Errorf("qShiftRound(%d, %d)=%d want %d", tc.acc, tc.shift, got, tc.want)
		}
	}
}

// TestQDivRound_Table pins the mean's integer division: nearest, half away
// from zero, correct for every sign combination, and zero for a zero
// divisor rather than a fault.
func TestQDivRound_Table(t *testing.T) {
	cases := []struct {
		num, den, want int64
	}{
		{7, 2, 4},
		{-7, 2, -4},
		{7, -2, -4},
		{-7, -2, 4},
		{9, 3, 3},
		{10, 4, 3},   // 2.5 → 3
		{-10, 4, -3}, // -2.5 → -3
		{1, 4, 0},
		{3, 4, 1},
		{5, 0, 0},
		{0, 0, 0},
	}
	for _, tc := range cases {
		if got := qDivRound(tc.num, tc.den); got != tc.want {
			t.Errorf("qDivRound(%d, %d)=%d want %d", tc.num, tc.den, got, tc.want)
		}
	}
}

// TestLayerNormRowsQ_ConstantRowWithoutEpsilon proves the normalization
// has no division by zero: a row of equal values with a zero epsilon has
// zero variance, and the output is exactly the bias.
func TestLayerNormRowsQ_ConstantRowWithoutEpsilon(t *testing.T) {
	const d = 4
	row := []int32{int32(3 * fpOne), int32(3 * fpOne), int32(3 * fpOne), int32(3 * fpOne)}
	gamma := []int32{int32(fpOne), int32(2 * fpOne), int32(fpOne), int32(fpOne)}
	beta := []int32{1, 2, 3, 4}
	LayerNormRowsQ(row, 1, d, gamma, beta, 0)
	for j := range row {
		if row[j] != beta[j] {
			t.Fatalf("row[%d]=%d want beta %d (zero variance normalizes to the bias)", j, row[j], beta[j])
		}
	}

	// The same row with a positive epsilon also normalizes to the bias:
	// the deviation is zero whatever the standard deviation.
	row = []int32{int32(3 * fpOne), int32(3 * fpOne), int32(3 * fpOne), int32(3 * fpOne)}
	LayerNormRowsQ(row, 1, d, gamma, beta, fpOne)
	for j := range row {
		if row[j] != beta[j] {
			t.Fatalf("with epsilon: row[%d]=%d want beta %d", j, row[j], beta[j])
		}
	}
}
