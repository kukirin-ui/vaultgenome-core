// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package validation_result

import (
	"encoding/json"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// unencodableTime lies outside the year range RFC 3339 can express, so
// the canonical encoder refuses it. Validate accepts it (it is not the
// zero time), which is what reaches the encoder's refusal.
var unencodableTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// The verdict-level and evidence rules of Validate: an unknown overall
// verdict, an evidence reference without its audit event id or kind,
// and a missing completion time are each refused as Structural with
// their own code, and the same refusal closes CanonicalBytes. A fully
// named evidence reference is accepted.
func TestValidationResult_Validate_VerdictAndEvidenceRules(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name string
		edit func(v *ValidationResult)
		code string
	}{
		{"unknown overall verdict", func(v *ValidationResult) { v.OverallVerdict = Verdict("maybe") }, shared_errors.CodeFieldValueInvalid},
		{"evidence without an audit event id", func(v *ValidationResult) {
			v.Evidence = []EvidenceRef{{Kind: "VALIDATION_COMPLETED"}}
		}, shared_errors.CodeRequiredFieldMissing},
		{"evidence without a kind", func(v *ValidationResult) {
			v.Evidence = []EvidenceRef{{AuditEventID: ids.AuditEventID("evt-0001")}}
		}, shared_errors.CodeRequiredFieldMissing},
		{"validated at missing", func(v *ValidationResult) { v.ValidatedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			v := validPassFixture()
			row.edit(&v)
			requireRefusal(t, v.Validate(), shared_errors.CategoryStructural, row.code)
			b, err := v.CanonicalBytes()
			requireRefusal(t, err, shared_errors.CategoryStructural, row.code)
			require.Nil(t, b)
		})
	}

	evidenced := validPassFixture()
	evidenced.Evidence = []EvidenceRef{
		{AuditEventID: ids.AuditEventID("evt-0001"), Kind: "VALIDATION_STARTED"},
		{AuditEventID: ids.AuditEventID("evt-0002"), Kind: "VALIDATION_COMPLETED"},
	}
	require.NoError(t, evidenced.Validate())
	b, err := evidenced.CanonicalBytes()
	require.NoError(t, err)
	require.Contains(t, string(b), `"evt-0002"`)
}

// A verdict the canonical encoder cannot express has no bytes: a NaN
// score is neither below 0 nor above 1, and a completion time beyond the
// RFC 3339 year range is not the zero time, so Validate accepts both and
// the refusal comes from the encoder, as Structural with the field code.
func TestValidationResult_CanonicalBytes_RefusesUnencodableValues(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name string
		edit func(v *ValidationResult)
	}{
		{"score is NaN", func(v *ValidationResult) {
			d := v.Dimensions[DimensionBehavioral]
			d.Score = math.NaN()
			v.Dimensions[DimensionBehavioral] = d
		}},
		{"validated at beyond the encodable range", func(v *ValidationResult) { v.ValidatedAt = unencodableTime }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			v := validPassFixture()
			row.edit(&v)
			require.NoError(t, v.Validate())
			b, err := v.CanonicalBytes()
			requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
			require.Nil(t, b)
			require.ErrorContains(t, err, "validation_result: canonical encode failed")
		})
	}
}

// UnmarshalJSON refuses trailing content, an unknown field and a schema
// version outside the supported range, each as Structural with its own
// code. The trailing check is the decoder's own and is reached through
// the method: json.Unmarshal refuses trailing bytes before the method
// runs.
func TestValidationResult_UnmarshalJSON_Refusals(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(validPassFixture())
	require.NoError(t, err)
	rows := []struct {
		name    string
		payload string
		code    string
	}{
		{"trailing value", string(raw) + " null", shared_errors.CodeFieldValueInvalid},
		{"unknown field", `{"schema_version":1,"extra":true}`, shared_errors.CodeFieldValueInvalid},
		{"schema below range", `{"schema_version":` + strconv.Itoa(int(SchemaVersionMin)-1) + `}`, shared_errors.CodeSchemaVersionUnsupported},
		{"schema above range", `{"schema_version":` + strconv.Itoa(int(SchemaVersionMax)+1) + `}`, shared_errors.CodeSchemaVersionUnsupported},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			var v ValidationResult
			requireRefusal(t, v.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the verdict they came from.
	var back ValidationResult
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validPassFixture(), back)
}
