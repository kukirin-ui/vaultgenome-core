// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package equivalence

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// f32t builds an f32 tensor from float32 values.
func f32t(shape []int, vals ...float32) Tensor {
	raw := make([]byte, len(vals)*4)
	for i, v := range vals {
		binary.LittleEndian.PutUint32(raw[i*4:], math.Float32bits(v))
	}
	return Tensor{DType: F32, Shape: shape, Raw: raw}
}

// f64t builds an f64 tensor from float64 values.
func f64t(shape []int, vals ...float64) Tensor {
	raw := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(raw[i*8:], math.Float64bits(v))
	}
	return Tensor{DType: F64, Shape: shape, Raw: raw}
}

var looseTol = Tolerance{Atol: 1e-3, Rtol: 1e-3}

func TestEvaluate_IdenticalIsExact(t *testing.T) {
	fx := []Fixture{
		{ID: "a", Expected: f32t([]int{3}, 1, 2, 3)},
		{ID: "b", Expected: f64t([]int{2}, 10, 20)},
	}
	act := map[string]Tensor{
		"a": f32t([]int{3}, 1, 2, 3),
		"b": f64t([]int{2}, 10, 20),
	}
	v, err := Evaluate("genome-1", fx, act, looseTol, StrictPolicy())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Level != LevelExact {
		t.Fatalf("want EXACT, got %s (%+v)", v.Level, v)
	}
	if v.NExact != 2 || v.NEquivalent != 0 || v.NMismatch != 0 {
		t.Fatalf("counts wrong: %+v", v)
	}
	if !v.Passed() {
		t.Fatal("EXACT must pass")
	}
	if v.MaxAbsErr != 0 || v.MaxRelErr != 0 {
		t.Fatalf("exact must have zero error, got abs=%g rel=%g", v.MaxAbsErr, v.MaxRelErr)
	}
}

func TestEvaluate_WithinToleranceIsEquivalent(t *testing.T) {
	// 1.0005 vs 1.0: abs err 5e-4 <= atol 1e-3, and the bytes differ, so this is
	// EQUIVALENT (functional match), never EXACT.
	fx := []Fixture{{ID: "a", Expected: f32t([]int{2}, 1.0, 2.0)}}
	act := map[string]Tensor{"a": f32t([]int{2}, 1.0005, 2.0004)}
	v, err := Evaluate("g", fx, act, looseTol, StrictPolicy())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Level != LevelEquivalent {
		t.Fatalf("want EQUIVALENT, got %s (maxAbs=%g)", v.Level, v.MaxAbsErr)
	}
	if v.NEquivalent != 1 || v.NExact != 0 || v.NMismatch != 0 {
		t.Fatalf("counts wrong: %+v", v)
	}
	if !v.Passed() {
		t.Fatal("EQUIVALENT must pass")
	}
}

func TestEvaluate_BeyondToleranceIsFail(t *testing.T) {
	fx := []Fixture{{ID: "a", Expected: f32t([]int{2}, 1.0, 2.0)}}
	act := map[string]Tensor{"a": f32t([]int{2}, 1.5, 2.0)} // abs 0.5 >> tol
	v, err := Evaluate("g", fx, act, looseTol, StrictPolicy())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Level != LevelFail {
		t.Fatalf("want FAIL, got %s", v.Level)
	}
	if v.Passed() {
		t.Fatal("FAIL must not pass")
	}
	if v.MaxAbsErr < 0.49 {
		t.Fatalf("expected maxAbsErr ~0.5, got %g", v.MaxAbsErr)
	}
}

func TestEvaluate_CriticalOutlierAlwaysFails(t *testing.T) {
	// One critical fixture drifts beyond tolerance. Even with a generous policy
	// that tolerates non-critical outliers, a critical outlier must FAIL.
	fx := []Fixture{
		{ID: "crit", Expected: f32t([]int{1}, 1.0), Critical: true},
		{ID: "ok", Expected: f32t([]int{1}, 5.0)},
	}
	act := map[string]Tensor{
		"crit": f32t([]int{1}, 9.0), // way off
		"ok":   f32t([]int{1}, 5.0),
	}
	v, err := Evaluate("g", fx, act, looseTol, Policy{MaxNonCriticalOutliers: 100})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Level != LevelFail {
		t.Fatalf("critical outlier must FAIL, got %s", v.Level)
	}
	if v.NCriticalMismatch != 1 {
		t.Fatalf("want 1 critical mismatch, got %d", v.NCriticalMismatch)
	}
}

func TestEvaluate_NonCriticalOutlierToleratedByPolicy(t *testing.T) {
	// A single non-critical outlier, tolerated by policy → EQUIVALENT (passes),
	// but the mismatch is recorded transparently.
	fx := []Fixture{
		{ID: "a", Expected: f32t([]int{1}, 1.0)},
		{ID: "b", Expected: f32t([]int{1}, 2.0)},
	}
	act := map[string]Tensor{
		"a": f32t([]int{1}, 1.0),
		"b": f32t([]int{1}, 2.9), // outlier
	}
	// Strict: fails.
	if v, _ := Evaluate("g", fx, act, looseTol, StrictPolicy()); v.Level != LevelFail {
		t.Fatalf("strict policy must FAIL on any outlier, got %s", v.Level)
	}
	// Tolerant: 1 non-critical outlier allowed → EQUIVALENT.
	v, err := Evaluate("g", fx, act, looseTol, Policy{MaxNonCriticalOutliers: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Level != LevelEquivalent {
		t.Fatalf("want EQUIVALENT under tolerant policy, got %s", v.Level)
	}
	if v.NMismatch != 1 {
		t.Fatalf("mismatch must still be recorded, got NMismatch=%d", v.NMismatch)
	}
	if !v.Passed() {
		t.Fatal("tolerated EQUIVALENT must pass")
	}
}

func TestEvaluate_ShapeMismatchFails(t *testing.T) {
	fx := []Fixture{{ID: "a", Expected: f32t([]int{3}, 1, 2, 3)}}
	act := map[string]Tensor{"a": f32t([]int{2}, 1, 2)}
	v, err := Evaluate("g", fx, act, looseTol, StrictPolicy())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Level != LevelFail {
		t.Fatalf("shape mismatch must FAIL, got %s", v.Level)
	}
	if v.Results[0].Note != "shape mismatch" {
		t.Fatalf("want shape mismatch note, got %q", v.Results[0].Note)
	}
}

func TestEvaluate_MissingActualIsStructuralError(t *testing.T) {
	fx := []Fixture{{ID: "a", Expected: f32t([]int{1}, 1)}}
	_, err := Evaluate("g", fx, map[string]Tensor{}, looseTol, StrictPolicy())
	if err == nil {
		t.Fatal("expected error for missing actual")
	}
	if !shared_errors.Is(err, shared_errors.CategoryStructural) {
		t.Fatalf("want Structural error, got %v", err)
	}
}

func TestEvaluate_EmptyFixturesRejected(t *testing.T) {
	_, err := Evaluate("g", nil, map[string]Tensor{}, looseTol, StrictPolicy())
	if err == nil || !shared_errors.Is(err, shared_errors.CategoryStructural) {
		t.Fatalf("empty fixtures must be a Structural error, got %v", err)
	}
}

func TestEvaluate_NegativeToleranceRejected(t *testing.T) {
	fx := []Fixture{{ID: "a", Expected: f32t([]int{1}, 1)}}
	act := map[string]Tensor{"a": f32t([]int{1}, 1)}
	if _, err := Evaluate("g", fx, act, Tolerance{Atol: -1}, StrictPolicy()); err == nil {
		t.Fatal("negative atol must be rejected")
	}
	if _, err := Evaluate("g", fx, act, looseTol, Policy{MaxNonCriticalOutliers: -1}); err == nil {
		t.Fatal("negative policy budget must be rejected")
	}
}

func TestEvaluate_NaNHandling(t *testing.T) {
	// NaN matches NaN (both broken the same way is not a divergence signal here),
	// but NaN vs a finite number is an outlier.
	fx := []Fixture{
		{ID: "nan", Expected: f64t([]int{1}, math.NaN())},
		{ID: "mix", Expected: f64t([]int{1}, math.NaN())},
	}
	act := map[string]Tensor{
		"nan": f64t([]int{1}, math.NaN()),
		"mix": f64t([]int{1}, 1.0),
	}
	v, err := Evaluate("g", fx, act, looseTol, StrictPolicy())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Level != LevelFail {
		t.Fatalf("NaN-vs-finite must FAIL, got %s", v.Level)
	}
	// The pure NaN==NaN fixture must not itself be an outlier.
	for _, r := range v.Results {
		if r.ID == "nan" && !r.Within {
			t.Fatal("NaN vs NaN should be within tolerance")
		}
	}
}

func TestSignAndVerify_Roundtrip(t *testing.T) {
	fx := []Fixture{{ID: "a", Expected: f32t([]int{1}, 1)}}
	act := map[string]Tensor{"a": f32t([]int{1}, 1)}
	v, err := Evaluate("genome-xyz", fx, act, looseTol, StrictPolicy())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	pub, priv, err := crypto.GenerateEd25519(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sv, err := Sign(v, pub, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifySigned(sv); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifySigned_DetectsTamper(t *testing.T) {
	fx := []Fixture{{ID: "a", Expected: f32t([]int{1}, 1)}}
	act := map[string]Tensor{"a": f32t([]int{1}, 1)}
	v, _ := Evaluate("g", fx, act, looseTol, StrictPolicy())
	pub, priv, _ := crypto.GenerateEd25519(nil)
	sv, _ := Sign(v, pub, priv)

	// Flip a FAIL onto a signed PASS verdict: signature must no longer verify.
	sv.Verdict.Level = LevelFail
	err := VerifySigned(sv)
	if err == nil {
		t.Fatal("tampered verdict must fail verification")
	}
	if !shared_errors.Is(err, shared_errors.CategoryIntegrity) {
		t.Fatalf("want Integrity error on tamper, got %v", err)
	}
}

func TestFixturesHash_BindsToFixtureSet(t *testing.T) {
	base := []Fixture{{ID: "a", Expected: f32t([]int{1}, 1)}}
	changed := []Fixture{{ID: "a", Expected: f32t([]int{1}, 2)}} // different expected
	added := []Fixture{
		{ID: "a", Expected: f32t([]int{1}, 1)},
		{ID: "b", Expected: f32t([]int{1}, 1)},
	}
	h1 := fixturesHash(base)
	if h1 != fixturesHash(base) {
		t.Fatal("hash must be stable")
	}
	if h1 == fixturesHash(changed) {
		t.Fatal("changing expected output must change the hash")
	}
	if h1 == fixturesHash(added) {
		t.Fatal("adding a fixture must change the hash")
	}
	// Order-independent: same set, different slice order → same hash.
	reordered := []Fixture{added[1], added[0]}
	if fixturesHash(added) != fixturesHash(reordered) {
		t.Fatal("hash must be order-independent")
	}
}

func TestEvaluate_DeterministicVerdictBytes(t *testing.T) {
	// Same inputs → identical canonical bytes (required for reproducible signing).
	fx := []Fixture{
		{ID: "z", Expected: f32t([]int{1}, 3)},
		{ID: "a", Expected: f32t([]int{1}, 1)},
	}
	act := map[string]Tensor{"z": f32t([]int{1}, 3), "a": f32t([]int{1}, 1)}
	v1, _ := Evaluate("g", fx, act, looseTol, StrictPolicy())
	v2, _ := Evaluate("g", fx, act, looseTol, StrictPolicy())
	b1, err1 := v1.CanonicalBytes()
	b2, err2 := v2.CanonicalBytes()
	if err1 != nil || err2 != nil {
		t.Fatalf("canonical bytes error: %v %v", err1, err2)
	}
	if string(b1) != string(b2) {
		t.Fatal("canonical bytes must be deterministic across runs")
	}
}
