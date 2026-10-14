// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recovery_request

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
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

// A valid request has deterministic canonical bytes that carry every
// field and change with the request; an invalid request has none, and
// neither has one whose timestamp the canonical encoder cannot express:
// Validate accepts that time (it is not zero), and the refusal comes
// from the encoder, as Structural with the field code.
func TestRecoveryRequest_CanonicalBytes(t *testing.T) {
	t.Parallel()
	first := validFixture()
	a, err := first.CanonicalBytes()
	require.NoError(t, err)
	second := validFixture()
	b, err := second.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, a, b, "the same request encodes to the same bytes")
	for _, key := range []string{`"schema_version"`, `"request_id"`, `"genome_id"`, `"policy_profile"`, `"requester_identity"`, `"contour"`, `"created_at"`} {
		require.Contains(t, string(a), key)
	}

	renamed := validFixture()
	renamed.PolicyProfile = "sovereign-ua"
	c, err := renamed.CanonicalBytes()
	require.NoError(t, err)
	require.NotEqual(t, a, c, "a changed field changes the bytes")

	invalid := validFixture()
	invalid.RequestID = ""
	out, err := invalid.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	require.Nil(t, out)

	unencodable := validFixture()
	unencodable.CreatedAt = unencodableTime
	require.NoError(t, unencodable.Validate())
	out, err = unencodable.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, out)
	require.ErrorContains(t, err, "recovery_request: canonical encode failed")
}

// UnmarshalJSON refuses trailing content, an unknown field and a schema
// version outside the supported range, each as Structural with its own
// code. The trailing check is the decoder's own and is reached through
// the method: json.Unmarshal refuses trailing bytes before the method
// runs.
func TestRecoveryRequest_UnmarshalJSON_Refusals(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(validFixture())
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
			var r RecoveryRequest
			requireRefusal(t, r.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the request they came from.
	var back RecoveryRequest
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validFixture(), back)
}
