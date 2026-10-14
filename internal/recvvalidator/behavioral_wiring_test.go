// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recvvalidator

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
)

// These tests prove the receive-side wire-in: when ValidateInputs carries
// Behavioral inputs, the service runs the determinism-ladder gate and emits a
// behavioral DimensionVerdict that aggregates into OverallVerdict. The
// orchestrator's existing MarkValidated/MarkValidationFailed branch on
// OverallVerdict, so a corrupted genome (no door opens) drives the terminal
// decision to ReasonValidationFailed. The kernels themselves are proven in
// internal/validation/reconstruction and internal/canonical; here the ladder
// doors are trivial fixed outputs so the test isolates the SERVICE integration.

func f64T(vals ...float64) equivalence.Tensor {
	raw := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(raw[i*8:], math.Float64bits(v))
	}
	return equivalence.Tensor{DType: equivalence.F64, Shape: []int{len(vals)}, Raw: raw}
}

func fixedDoor(rung int, name string, out map[string]equivalence.Tensor, tol equivalence.Tolerance) reconstruction.Strategy {
	return reconstruction.Strategy{
		Rung: rung, Name: name, Tol: tol, Pol: equivalence.StrictPolicy(),
		Recompute: func(id string) (equivalence.Tensor, error) { return out[id], nil },
	}
}

func TestValidate_BehavioralDimension_HealthyGenomePasses(t *testing.T) {
	sf := newServiceFixtures(t)
	fx := []equivalence.Fixture{{ID: "a", Expected: f64T(1, 2, 3), Critical: true}}
	good := map[string]equivalence.Tensor{"a": f64T(1, 2, 3)}
	in := ValidateInputs{
		OperationalInputs: sf.recvFixtures.inputs,
		Behavioral: &BehavioralInputs{
			GenomeID:  "g",
			Fixtures:  fx,
			Threshold: 0.99,
			Ladder:    []reconstruction.Strategy{fixedDoor(1, "exact", good, equivalence.Tolerance{})},
		},
	}
	vr, err := sf.service.Validate(in)
	require.NoError(t, err)
	bdim, ok := vr.Dimensions[validation_result.DimensionBehavioral]
	require.True(t, ok, "behavioral dimension must be present when requested")
	require.Equal(t, validation_result.VerdictPass, bdim.Verdict)
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict)
}

func TestValidate_BehavioralDimension_CorruptedGenomeFailsClosed(t *testing.T) {
	sf := newServiceFixtures(t)
	fx := []equivalence.Fixture{{ID: "a", Expected: f64T(1, 2, 3), Critical: true}}
	wrong := map[string]equivalence.Tensor{"a": f64T(9, 9, 9)}
	in := ValidateInputs{
		OperationalInputs: sf.recvFixtures.inputs,
		Behavioral: &BehavioralInputs{
			GenomeID:  "g",
			Fixtures:  fx,
			Threshold: 0.99,
			Ladder: []reconstruction.Strategy{
				fixedDoor(1, "exact", wrong, equivalence.Tolerance{}),
				fixedDoor(3, "integer", wrong, equivalence.Tolerance{Atol: 0.05, Rtol: 0.05}),
			},
		},
	}
	vr, err := sf.service.Validate(in)
	require.NoError(t, err)
	bdim := vr.Dimensions[validation_result.DimensionBehavioral]
	require.Equal(t, validation_result.VerdictFail, bdim.Verdict, "no door opens on a corrupted genome")
	require.NotEmpty(t, bdim.Details, "failed doors must be reported as findings")
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict,
		"behavioral fail must propagate to overall (→ ReasonValidationFailed)")
}

func TestValidate_NoBehavioral_StaysOperationalOnly(t *testing.T) {
	sf := newServiceFixtures(t)
	vr, err := sf.service.Validate(ValidateInputs{OperationalInputs: sf.recvFixtures.inputs})
	require.NoError(t, err)
	_, ok := vr.Dimensions[validation_result.DimensionBehavioral]
	require.False(t, ok, "behavioral dimension must be absent when not requested (operational-only unchanged)")
}
