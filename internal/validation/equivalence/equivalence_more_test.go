// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package equivalence

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// A tensor whose bytes cannot be read as its declared type, or whose
// element count does not match the reference, is an outlier with a note,
// never a crash and never a pass; a different rank is a shape mismatch.
func TestEvaluate_UndecodableActualsAreOutliers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expected Tensor
		actual   Tensor
		note     string
	}{
		{"f32 bytes not a multiple of 4", f32t([]int{1}, 1), Tensor{DType: F32, Shape: []int{1}, Raw: []byte{1, 2, 3}}, "decode/length mismatch"},
		{"f64 bytes not a multiple of 8", f64t([]int{1}, 1), Tensor{DType: F64, Shape: []int{1}, Raw: []byte{1, 2, 3, 4}}, "decode/length mismatch"},
		{"unknown dtype", f32t([]int{1}, 1), Tensor{DType: "f16", Shape: []int{1}, Raw: []byte{0, 60}}, "decode/length mismatch"},
		{"undecodable reference", Tensor{DType: "bf16", Shape: []int{1}, Raw: []byte{0, 60}}, f32t([]int{1}, 1), "decode/length mismatch"},
		{"more elements than the shape says", f32t([]int{2}, 1, 2), f32t([]int{2}, 1, 2, 3), "decode/length mismatch"},
		{"different rank", f32t([]int{2}, 1, 2), f32t([]int{1, 2}, 1, 2), "shape mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := []Fixture{{ID: "a", Expected: tc.expected, Critical: true}}
			v, err := Evaluate("g", fx, map[string]Tensor{"a": tc.actual}, looseTol, StrictPolicy())
			require.NoError(t, err)
			require.Equal(t, LevelFail, v.Level)
			require.Equal(t, 1, v.NCriticalMismatch)
			require.Len(t, v.Results, 1)
			require.False(t, v.Results[0].Within)
			require.False(t, v.Results[0].Exact)
			require.Equal(t, tc.note, v.Results[0].Note)
			require.Zero(t, v.Results[0].MaxAbsErr, "no element was compared")
		})
	}
}

// Infinities compare by identity: the same infinity on both sides is no
// error at all, an infinity against anything else is unbounded error.
func TestEvaluate_InfinityHandling(t *testing.T) {
	t.Parallel()
	inf := math.Inf(1)
	fx := []Fixture{
		{ID: "same", Expected: f64t([]int{2}, inf, 1.0)},
		{ID: "sign", Expected: f64t([]int{1}, inf)},
		{ID: "finite", Expected: f64t([]int{1}, inf)},
	}
	act := map[string]Tensor{
		"same":   f64t([]int{2}, inf, 1.0005), // bytes differ, so the elements are compared
		"sign":   f64t([]int{1}, math.Inf(-1)),
		"finite": f64t([]int{1}, 1e300),
	}
	v, err := Evaluate("g", fx, act, looseTol, StrictPolicy())
	require.NoError(t, err)
	require.Equal(t, LevelFail, v.Level)
	byID := map[string]FixtureResult{}
	for _, r := range v.Results {
		byID[r.ID] = r
	}
	require.True(t, byID["same"].Within, "+Inf against +Inf is within any tolerance")
	require.False(t, byID["same"].Exact)
	require.InDelta(t, 0.0005, byID["same"].MaxAbsErr, 1e-9, "the finite element sets the error")
	require.False(t, byID["sign"].Within)
	require.True(t, math.IsInf(byID["sign"].MaxAbsErr, 1))
	require.False(t, byID["finite"].Within)
	require.True(t, math.IsInf(byID["finite"].MaxAbsErr, 1))
	require.True(t, math.IsInf(v.MaxAbsErr, 1))
	require.Equal(t, 1, v.NEquivalent)
	require.Equal(t, 2, v.NMismatch)
}

// Signing needs a usable key and a verdict JSON can carry: a short private
// key is refused, and so is a verdict whose error is infinite (an
// infinity has no JSON encoding), on both the signing and the verifying
// side. A verdict with finite errors round-trips.
func TestSign_RefusesWhatItCannotSign(t *testing.T) {
	t.Parallel()
	pub, priv, err := crypto.GenerateEd25519(nil)
	require.NoError(t, err)
	fx := []Fixture{{ID: "a", Expected: f32t([]int{1}, 1)}}
	finite, err := Evaluate("g", fx, map[string]Tensor{"a": f32t([]int{1}, 1.0004)}, looseTol, StrictPolicy())
	require.NoError(t, err)
	require.Equal(t, LevelEquivalent, finite.Level)

	_, err = Sign(finite, pub, priv[:32])
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.ErrorContains(t, err, "private key must be 64 bytes")

	unbounded, err := Evaluate("g", []Fixture{{ID: "a", Expected: f64t([]int{1}, math.NaN())}},
		map[string]Tensor{"a": f64t([]int{1}, 1)}, looseTol, StrictPolicy())
	require.NoError(t, err)
	require.True(t, math.IsInf(unbounded.MaxAbsErr, 1))
	_, err = unbounded.CanonicalBytes()
	require.ErrorContains(t, err, "unsupported value")
	_, err = Sign(unbounded, pub, priv)
	require.ErrorContains(t, err, "unsupported value")
	err = VerifySigned(SignedVerdict{Verdict: unbounded, SignerPub: pub})
	require.ErrorContains(t, err, "unsupported value")
	require.Equal(t, shared_errors.CategoryUnknown, shared_errors.CategoryOf(err), "an encoding failure is not an integrity failure")

	sv, err := Sign(finite, pub, priv)
	require.NoError(t, err)
	require.NoError(t, VerifySigned(sv))
	sv.SignerPub = pub[:31]
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(VerifySigned(sv)))
}

// Top-1 agreement names which side it could not read: a reference that
// has no largest value, an actual that cannot be decoded, an empty
// tensor. Each counts as a disagreement, critical when the fixture is.
func TestTop1Agreement_NamesTheDefectiveSide(t *testing.T) {
	t.Parallel()
	fixtures := []Fixture{
		{ID: "nan-reference", Critical: true, Expected: f32t([]int{2}, float32(math.NaN()), 1)},
		{ID: "empty-reference", Critical: false, Expected: Tensor{DType: F32, Shape: []int{0}}},
		{ID: "undecodable-actual", Critical: true, Expected: f32t([]int{2}, 1, 2)},
		{ID: "empty-actual", Critical: false, Expected: f32t([]int{2}, 1, 2)},
		{ID: "misaligned-actual", Critical: false, Expected: f64t([]int{1}, 1)},
		{ID: "fine", Critical: true, Expected: f32t([]int{2}, 1, 2)},
	}
	actuals := map[string]Tensor{
		"nan-reference":      f32t([]int{2}, 0, 1),
		"empty-reference":    f32t([]int{1}, 1),
		"undecodable-actual": Tensor{DType: "i8", Shape: []int{2}, Raw: []byte{1, 2}},
		"empty-actual":       Tensor{DType: F32, Shape: []int{2}},
		"misaligned-actual":  Tensor{DType: F64, Shape: []int{1}, Raw: []byte{1, 2, 3}},
		"fine":               f32t([]int{2}, 1, 3),
	}
	rep, err := Top1Agreement(fixtures, actuals)
	require.NoError(t, err)
	require.Equal(t, 6, rep.Total)
	require.Equal(t, 1, rep.Agreed)
	require.Equal(t, 2, rep.CriticalDisagreed)
	require.InDelta(t, 1.0/6.0, rep.Score(), 1e-12)

	notes := map[string]string{}
	for _, r := range rep.Results {
		notes[r.ID] = r.Note
		if r.ID != "fine" {
			require.False(t, r.Agree, r.ID)
			require.Equal(t, -1, r.ExpectedIndex, r.ID)
			require.Equal(t, -1, r.ActualIndex, r.ID)
		}
	}
	require.Equal(t, "reference: NaN at index 0", notes["nan-reference"])
	require.Equal(t, "reference: empty tensor", notes["empty-reference"])
	require.Equal(t, `actual: unknown dtype "i8"`, notes["undecodable-actual"])
	require.Equal(t, "actual: empty tensor", notes["empty-actual"])
	require.Equal(t, "actual: f64 raw not multiple of 8", notes["misaligned-actual"])
	require.Empty(t, notes["fine"])
}
