// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package validation_result

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validPassFixture() ValidationResult {
	return ValidationResult{
		SchemaVersion:      SchemaVersionCurrent,
		ValidationResultID: ids.ValidationResultID("vr-0001"),
		SessionID:          ids.SessionID("sess-0001"),
		ManifestID:         ids.ManifestID("man-0001"),
		Dimensions: map[Dimension]DimensionVerdict{
			DimensionOperational: {Verdict: VerdictPass, Score: 1.0, Threshold: 1.0},
			DimensionSemantic:    {Verdict: VerdictPass, Score: 1.0, Threshold: 1.0},
			DimensionBehavioral:  {Verdict: VerdictPass, Score: 0.98, Threshold: 0.95},
		},
		OverallVerdict: VerdictPass,
		ValidatedAt:    time.Date(2026, 4, 20, 10, 5, 0, 0, time.UTC),
	}
}

func TestValidationResult_Validate_PassOK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validPassFixture().Validate())
}

func TestValidationResult_OperationalMustBePresent(t *testing.T) {
	t.Parallel()
	v := validPassFixture()
	delete(v.Dimensions, DimensionOperational)
	err := v.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestValidationResult_OperationalFailMustPropagateToOverall(t *testing.T) {
	t.Parallel()
	v := validPassFixture()
	v.Dimensions[DimensionOperational] = DimensionVerdict{Verdict: VerdictFail, Score: 0.0, Threshold: 1.0}
	// leave OverallVerdict = pass — this is the inconsistency we detect
	err := v.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	// Now make overall fail too — should validate.
	v.OverallVerdict = VerdictFail
	require.NoError(t, v.Validate())
}

func TestValidationResult_ScoreOutOfRange(t *testing.T) {
	t.Parallel()
	v := validPassFixture()
	v.Dimensions[DimensionBehavioral] = DimensionVerdict{Verdict: VerdictPass, Score: 1.5, Threshold: 0.95}
	err := v.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestValidationResult_UnknownDimensionRejected(t *testing.T) {
	t.Parallel()
	v := validPassFixture()
	v.Dimensions[Dimension("rumor")] = DimensionVerdict{Verdict: VerdictPass, Score: 1, Threshold: 1}
	err := v.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestValidationResult_UnknownVerdictRejected(t *testing.T) {
	t.Parallel()
	v := validPassFixture()
	v.Dimensions[DimensionSemantic] = DimensionVerdict{Verdict: Verdict("maybe"), Score: 1, Threshold: 1}
	err := v.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestValidationResult_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validPassFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got ValidationResult
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.OverallVerdict, got.OverallVerdict)
	require.Equal(t, len(orig.Dimensions), len(got.Dimensions))
}

func TestValidationResult_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"extra":123}`
	var v ValidationResult
	err := v.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
}

func TestValidationResult_FindingSeverityMustBeKnown(t *testing.T) {
	t.Parallel()
	v := validPassFixture()
	v.Dimensions[DimensionBehavioral] = DimensionVerdict{
		Verdict: VerdictPass, Score: 0.97, Threshold: 0.95,
		Details: []Finding{{Code: "probe.001", Severity: Severity("catastrophic"), Message: "x"}},
	}
	err := v.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}
