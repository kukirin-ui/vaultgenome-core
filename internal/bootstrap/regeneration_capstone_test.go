// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_test

// Capstone — the flagship proven end to end through the REAL receive-side
// authority. It composes every layer built for cross-hardware regeneration:
//
//	orchestrator (Accept wire-hashes → MarkReassembled)
//	    → recvvalidator.ValidationService.Validate WITH behavioral inputs
//	        → reconstruction.Regenerate (determinism-ladder descent)
//	            → canonical kernels (fixed-point door) + equivalence gate
//	    → behavioral DimensionVerdict → OverallVerdict
//	→ MarkValidated / MarkValidationFailed → Decide → ReconstitutionDecision
//
// This is what earlier stages could not assert (see the note atop
// driver_integration_test.go: Stage G was operational-only): a genome that
// recomputes its sealed reference fixtures correctly on the destination is
// reconstituted (Accepted=true / reconstructed_ok); a corrupted one opens no
// ladder door and is blocked fail-closed (Accepted=false / validation_failed).
//
// The ladder door here is backed by the canonical integer kernel over test
// weights; in production the door's RecomputeFunc runs the reassembled weights
// (byte-portable integer path) — the wiring is identical.

import (
	"encoding/binary"
	"math"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/bootstrap"
	"github.com/vault-genome/vaultgenome-core/internal/canonical"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/recvvalidator"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
)

const capL, capD = 8, 16

func capParams(seed int64) canonical.Params {
	r := rand.New(rand.NewSource(seed))
	rv := func(n int) []float64 {
		out := make([]float64, n)
		for i := range out {
			out[i] = r.NormFloat64()
		}
		return out
	}
	d := capD
	return canonical.Params{
		D: d, Wq: rv(d * d), Wk: rv(d * d), Wv: rv(d * d), Wo: rv(d * d),
		W1: rv(d * 4 * d), W2: rv(4 * d * d), G: rv(d), B: rv(d), Eps: 1e-5,
	}
}

func capF64Tensor(shape []int, vals []float64) equivalence.Tensor {
	raw := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(raw[i*8:], math.Float64bits(v))
	}
	return equivalence.Tensor{DType: equivalence.F64, Shape: shape, Raw: raw}
}

type capGenome struct {
	p        canonical.Params
	fixtures []equivalence.Fixture
	inputs   map[string][]float64
}

// capSeal builds a genome and its sealed reference fixtures (input id -> f64
// block output), as an origin node would seal them.
func capSeal(seed int64, n int) capGenome {
	p := capParams(seed)
	g := capGenome{p: p, inputs: map[string][]float64{}}
	for i := 0; i < n; i++ {
		id := string(rune('a' + i))
		r := rand.New(rand.NewSource(seed*100 + int64(i)))
		x := make([]float64, capL*capD)
		for j := range x {
			x[j] = r.NormFloat64()
		}
		g.inputs[id] = x
		g.fixtures = append(g.fixtures, equivalence.Fixture{
			ID:       id,
			Expected: capF64Tensor([]int{capL, capD}, p.TransformerBlock(x, capL)),
			Critical: i == 0,
		})
	}
	return g
}

// capIntegerDoor is the byte-portable fixed-point recompute door over params p.
func capIntegerDoor(p canonical.Params, inputs map[string][]float64) reconstruction.Strategy {
	fp := canonical.QuantizeParams(p)
	return reconstruction.Strategy{
		Rung: 3, Kind: reconstruction.KindFixedPoint, Name: "integer-canonical",
		Tol: equivalence.Tolerance{Atol: 0.05, Rtol: 0.05}, Pol: equivalence.StrictPolicy(),
		Recompute: func(id string) (equivalence.Tensor, error) {
			out := canonical.DequantizeVec(fp.TransformerBlockQ(canonical.QuantizeVec(inputs[id]), capL))
			return capF64Tensor([]int{capL, capD}, out), nil
		},
	}
}

// driveValidationBehavioral mirrors driveValidation but injects the behavioral
// reconstruction inputs so the receive-side validator emits DimensionBehavioral.
func driveValidationBehavioral(t *testing.T, h *driverHarness, svc *recvvalidator.ValidationService, admitted int, behavioral *recvvalidator.BehavioralInputs) *validation_result.ValidationResult {
	t.Helper()
	in := recvvalidator.ValidateInputs{
		OperationalInputs: recvvalidator.OperationalInputs{
			BootstrapManifest: h.bm,
			Attestation:       h.attestation,
			Session:           h.session,
			ActivePolicy:      driverPolicy,
			Coverage: recvvalidator.ReassemblyCoverage{
				Expected: len(h.bm.ExpectedDisclosureIDs),
				Admitted: admitted,
			},
			Resolver: h.store,
		},
		Behavioral: behavioral,
	}
	result, err := svc.Validate(in)
	require.NoError(t, err)
	require.NotNil(t, result)
	return result
}

// driveToValidate runs the orchestrator from Start through MarkReassembled so the
// caller can inject a behavioral validation and Decide.
func driveToValidate(t *testing.T, h *driverHarness) *bootstrap.Orchestrator {
	t.Helper()
	o := newDriverOrchestrator(t, h)
	require.NoError(t, o.Start())
	for i, msg := range h.messages {
		_, err := o.Accept(msg)
		require.NoErrorf(t, err, "Accept #%d", i)
	}
	require.NoError(t, o.MarkReassembled())
	require.Equal(t, bootstrap.StateValidate, o.State())
	return o
}

func TestCapstone_HealthyGenomeReconstitutes(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())
	o := driveToValidate(t, h)

	g := capSeal(1, 4)
	behavioral := &recvvalidator.BehavioralInputs{
		GenomeID:  "genome-capstone",
		Fixtures:  g.fixtures,
		Threshold: 0.99,
		Ladder:    []reconstruction.Strategy{capIntegerDoor(g.p, g.inputs)},
	}

	svc := newDriverValidationService(t, h)
	vr := driveValidationBehavioral(t, h, svc, len(h.messages), behavioral)

	require.Equal(t, validation_result.VerdictPass,
		vr.Dimensions[validation_result.DimensionBehavioral].Verdict,
		"a healthy genome must open a ladder door")
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict)

	require.NoError(t, o.MarkValidated(vr.ValidationResultID))
	require.Equal(t, bootstrap.StateReady, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.True(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReconstructedOK, dec.Reason)
}

func TestCapstone_CorruptedGenomeBlockedFailClosed(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())
	o := driveToValidate(t, h)

	g := capSeal(2, 4)        // sealed reference from the REAL genome
	corrupt := capParams(999) // a completely different ("corrupted") genome
	behavioral := &recvvalidator.BehavioralInputs{
		GenomeID:  "genome-capstone",
		Fixtures:  g.fixtures,
		Threshold: 0.99,
		Ladder:    []reconstruction.Strategy{capIntegerDoor(corrupt, g.inputs)},
	}

	svc := newDriverValidationService(t, h)
	vr := driveValidationBehavioral(t, h, svc, len(h.messages), behavioral)

	require.Equal(t, validation_result.VerdictFail,
		vr.Dimensions[validation_result.DimensionBehavioral].Verdict,
		"a corrupted genome must open no ladder door")
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict,
		"behavioral fail must propagate to overall (validation precedes reconstitution)")

	require.NoError(t, o.MarkValidationFailed(vr.ValidationResultID))
	require.Equal(t, bootstrap.StateRejected, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonValidationFailed, dec.Reason)
}
