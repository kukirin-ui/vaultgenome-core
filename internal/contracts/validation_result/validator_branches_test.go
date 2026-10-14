// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package validation_result

import (
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Every shape rule of Validate, one field at a time.
func TestValidationResult_Validate_EveryRule(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		mutate func(*ValidationResult)
		code   string
	}{
		"schema_version below range": {func(v *ValidationResult) { v.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		"validation_result_id":       {func(v *ValidationResult) { v.ValidationResultID = "" }, shared_errors.CodeRequiredFieldMissing},
		"session_id":                 {func(v *ValidationResult) { v.SessionID = "" }, shared_errors.CodeRequiredFieldMissing},
		"manifest_id":                {func(v *ValidationResult) { v.ManifestID = "" }, shared_errors.CodeRequiredFieldMissing},
		"no dimensions":              {func(v *ValidationResult) { v.Dimensions = nil }, shared_errors.CodeRequiredFieldMissing},
		"threshold out of range": {func(v *ValidationResult) {
			d := v.Dimensions[DimensionSemantic]
			d.Threshold = 1.5
			v.Dimensions[DimensionSemantic] = d
		}, shared_errors.CodeFieldValueInvalid},
		"finding without a code": {func(v *ValidationResult) {
			d := v.Dimensions[DimensionSemantic]
			d.Details = []Finding{{Severity: SeverityInfo, Message: "no code"}}
			v.Dimensions[DimensionSemantic] = d
		}, shared_errors.CodeRequiredFieldMissing},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := validPassFixture()
			tc.mutate(&v)
			err := v.Validate()
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err), "%v", err)
		})
	}
}

// CanonicalBytes is deterministic for a valid result and refuses an
// invalid one before encoding anything.
func TestValidationResult_CanonicalBytes(t *testing.T) {
	t.Parallel()
	v := validPassFixture()
	a, err := v.CanonicalBytes()
	require.NoError(t, err)
	w := validPassFixture()
	b, err := w.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, a, b, "the same result encodes to the same bytes")
	require.Contains(t, string(a), `"overall_verdict"`)

	bad := validPassFixture()
	delete(bad.Dimensions, DimensionOperational)
	_, err = bad.CanonicalBytes()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}
