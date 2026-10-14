// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package equivalence

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// DType is the element type of a fixture tensor (little-endian in Raw).
type DType string

const (
	F32 DType = "f32"
	F64 DType = "f64"
)

// Tensor is a typed, shaped, little-endian float tensor.
type Tensor struct {
	DType DType  `json:"dtype"`
	Shape []int  `json:"shape"`
	Raw   []byte `json:"-"`
}

// Fixture is one sealed reference: an input id, the expected output, and whether
// it is critical (a critical fixture outside tolerance always fails the gate).
type Fixture struct {
	ID       string
	Expected Tensor
	Critical bool
}

// Tolerance parameterises the allclose test: |a-e| <= Atol + Rtol*|e|.
type Tolerance struct {
	Atol float64 `json:"atol"`
	Rtol float64 `json:"rtol"`
}

// Policy controls how per-fixture outcomes aggregate into a verdict. The zero
// value (StrictPolicy) is fail-closed: any fixture outside tolerance blocks
// release. The knob exists for operators who knowingly accept bounded drift on
// sampled, non-critical references; critical references are never subject to it.
type Policy struct {
	// MaxNonCriticalOutliers is the number of NON-critical fixtures permitted to
	// fall outside tolerance while the verdict may still be EQUIVALENT. A single
	// critical fixture outside tolerance is always FAIL, regardless of this
	// value. Default 0 = strict (any outlier → FAIL).
	MaxNonCriticalOutliers int `json:"max_non_critical_outliers"`
}

// StrictPolicy is the fail-closed default: any fixture outside tolerance → FAIL.
func StrictPolicy() Policy { return Policy{} }

// Level is the gate outcome.
type Level string

const (
	LevelExact      Level = "EXACT"
	LevelEquivalent Level = "EQUIVALENT"
	LevelFail       Level = "FAIL"
)

// FixtureResult is the per-fixture outcome.
type FixtureResult struct {
	ID        string  `json:"id"`
	Critical  bool    `json:"critical"`
	Exact     bool    `json:"exact"`
	Within    bool    `json:"within_tolerance"`
	MaxAbsErr float64 `json:"max_abs_err"`
	MaxRelErr float64 `json:"max_rel_err"`
	Note      string  `json:"note,omitempty"`
}

// Verdict is the aggregate outcome, bound to the fixture set it was computed
// over. It is deterministically serialisable (CanonicalBytes) for signing.
type Verdict struct {
	Level             Level           `json:"level"`
	Tolerance         Tolerance       `json:"tolerance"`
	Policy            Policy          `json:"policy"`
	GenomeID          string          `json:"genome_id,omitempty"`
	FixturesHash      string          `json:"fixtures_hash"`
	NExact            int             `json:"n_exact"`
	NEquivalent       int             `json:"n_equivalent"`
	NMismatch         int             `json:"n_mismatch"`
	NCriticalMismatch int             `json:"n_critical_mismatch"`
	MaxAbsErr         float64         `json:"max_abs_err"`
	MaxRelErr         float64         `json:"max_rel_err"`
	Results           []FixtureResult `json:"results"`
}

// Evaluate runs the gate: for each fixture it looks up the reconstructed output
// in actuals (keyed by fixture ID) and compares under tol, aggregating under
// pol. genomeID is recorded for binding. A missing or malformed actual is a
// Structural error (caller fault); a shape/length mismatch is recorded as a
// per-fixture outlier. Pass StrictPolicy() for the fail-closed default.
func Evaluate(genomeID string, fixtures []Fixture, actuals map[string]Tensor, tol Tolerance, pol Policy) (Verdict, error) {
	if len(fixtures) == 0 {
		return Verdict{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "equivalence: no fixtures", nil)
	}
	if tol.Atol < 0 || tol.Rtol < 0 {
		return Verdict{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "equivalence: tolerance must be non-negative", nil)
	}
	if pol.MaxNonCriticalOutliers < 0 {
		return Verdict{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "equivalence: policy MaxNonCriticalOutliers must be non-negative", nil)
	}

	v := Verdict{Tolerance: tol, Policy: pol, GenomeID: genomeID, FixturesHash: fixturesHash(fixtures)}
	allExact := true
	criticalOutliers, nonCriticalOutliers := 0, 0

	// Deterministic order.
	ordered := append([]Fixture(nil), fixtures...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	for _, f := range ordered {
		act, ok := actuals[f.ID]
		if !ok {
			return Verdict{}, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				fmt.Sprintf("equivalence: no reconstructed output for fixture %q", f.ID), nil)
		}
		res := compare(f, act, tol)
		v.Results = append(v.Results, res)
		if !res.Exact {
			allExact = false
		}
		switch {
		case !res.Within && res.Critical:
			criticalOutliers++
			v.NMismatch++
			v.NCriticalMismatch++
		case !res.Within:
			nonCriticalOutliers++
			v.NMismatch++
		case res.Exact:
			v.NExact++
		default:
			v.NEquivalent++
		}
		if res.MaxAbsErr > v.MaxAbsErr {
			v.MaxAbsErr = res.MaxAbsErr
		}
		if res.MaxRelErr > v.MaxRelErr {
			v.MaxRelErr = res.MaxRelErr
		}
	}

	switch {
	case criticalOutliers > 0 || nonCriticalOutliers > pol.MaxNonCriticalOutliers:
		v.Level = LevelFail
	case allExact:
		v.Level = LevelExact
	default:
		v.Level = LevelEquivalent
	}
	return v, nil
}

func compare(f Fixture, act Tensor, tol Tolerance) FixtureResult {
	r := FixtureResult{ID: f.ID, Critical: f.Critical}
	if act.DType == f.Expected.DType && shapeEqual(act.Shape, f.Expected.Shape) && bytes.Equal(act.Raw, f.Expected.Raw) {
		r.Exact, r.Within = true, true
		return r
	}
	if !shapeEqual(act.Shape, f.Expected.Shape) {
		r.Note = "shape mismatch"
		return r
	}
	exp, err1 := decode(f.Expected)
	got, err2 := decode(act)
	if err1 != nil || err2 != nil || len(exp) != len(got) {
		r.Note = "decode/length mismatch"
		return r
	}
	within := true
	for i := range exp {
		a, e := got[i], exp[i]
		abs, rel := elemErr(a, e)
		if abs > r.MaxAbsErr {
			r.MaxAbsErr = abs
		}
		if rel > r.MaxRelErr {
			r.MaxRelErr = rel
		}
		if !closeElem(a, e, tol.Atol, tol.Rtol) {
			within = false
		}
	}
	r.Within = within
	return r
}

func elemErr(a, e float64) (abs, rel float64) {
	if math.IsNaN(a) || math.IsNaN(e) || math.IsInf(a, 0) || math.IsInf(e, 0) {
		if a == e || (math.IsNaN(a) && math.IsNaN(e)) {
			return 0, 0
		}
		return math.Inf(1), math.Inf(1)
	}
	abs = math.Abs(a - e)
	rel = abs / (math.Abs(e) + 1e-30)
	return abs, rel
}

func closeElem(a, e, atol, rtol float64) bool {
	if math.IsNaN(a) || math.IsNaN(e) {
		return math.IsNaN(a) && math.IsNaN(e)
	}
	if math.IsInf(a, 0) || math.IsInf(e, 0) {
		return a == e
	}
	return math.Abs(a-e) <= atol+rtol*math.Abs(e)
}

func decode(t Tensor) ([]float64, error) {
	switch t.DType {
	case F32:
		if len(t.Raw)%4 != 0 {
			return nil, fmt.Errorf("f32 raw not multiple of 4")
		}
		n := len(t.Raw) / 4
		out := make([]float64, n)
		for i := 0; i < n; i++ {
			out[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(t.Raw[i*4:])))
		}
		return out, nil
	case F64:
		if len(t.Raw)%8 != 0 {
			return nil, fmt.Errorf("f64 raw not multiple of 8")
		}
		n := len(t.Raw) / 8
		out := make([]float64, n)
		for i := 0; i < n; i++ {
			out[i] = math.Float64frombits(binary.LittleEndian.Uint64(t.Raw[i*8:]))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown dtype %q", t.DType)
	}
}

func shapeEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fixturesHash(fixtures []Fixture) string {
	ordered := append([]Fixture(nil), fixtures...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	var buf bytes.Buffer
	for _, f := range ordered {
		buf.WriteString(f.ID)
		buf.WriteByte(0)
		buf.WriteString(string(f.Expected.DType))
		buf.WriteByte(0)
		for _, s := range f.Expected.Shape {
			var b8 [8]byte
			binary.LittleEndian.PutUint64(b8[:], uint64(s))
			buf.Write(b8[:])
		}
		buf.Write(f.Expected.Raw)
		buf.WriteByte(0)
	}
	h := crypto.SHA256(buf.Bytes())
	return fmt.Sprintf("%x", h[:])
}

// CanonicalBytes is the deterministic serialisation signed by the authority.
func (v Verdict) CanonicalBytes() ([]byte, error) {
	return json.Marshal(v)
}

// SignedVerdict binds a verdict to an Ed25519 signature by the release authority.
type SignedVerdict struct {
	Verdict   Verdict `json:"verdict"`
	Signature []byte  `json:"signature"`
	SignerPub []byte  `json:"signer_pub"`
}

// Sign produces a SignedVerdict over the canonical bytes of v.
func Sign(v Verdict, pub crypto.PublicKey, priv crypto.PrivateKey) (SignedVerdict, error) {
	msg, err := v.CanonicalBytes()
	if err != nil {
		return SignedVerdict{}, err
	}
	sig, err := crypto.Sign(priv, msg)
	if err != nil {
		return SignedVerdict{}, err
	}
	return SignedVerdict{Verdict: v, Signature: sig, SignerPub: append([]byte(nil), pub...)}, nil
}

// VerifySigned recomputes the canonical bytes and verifies the signature.
func VerifySigned(sv SignedVerdict) error {
	msg, err := sv.Verdict.CanonicalBytes()
	if err != nil {
		return err
	}
	if err := crypto.Verify(crypto.PublicKey(sv.SignerPub), msg, sv.Signature); err != nil {
		return shared_errors.Integrity(shared_errors.CodeSignatureInvalid, "equivalence: verdict signature invalid", err)
	}
	return nil
}

// Passed reports whether the verdict permits the reconstructed model to go live
// (EXACT or EQUIVALENT). FAIL blocks release.
func (v Verdict) Passed() bool { return v.Level == LevelExact || v.Level == LevelEquivalent }
