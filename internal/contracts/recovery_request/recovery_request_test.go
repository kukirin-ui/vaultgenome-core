// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recovery_request

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validFixture() RecoveryRequest {
	return RecoveryRequest{
		SchemaVersion:     SchemaVersionCurrent,
		RequestID:         ids.RequestID("req-0001"),
		GenomeID:          ids.GenomeID("genome-alpha"),
		PolicyProfile:     "research-default",
		RequesterIdentity: "ed25519:fingerprint",
		Contour:           map[string]string{"jurisdiction": "ua", "role": "operator"},
		CreatedAt:         time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
	}
}

func TestRecoveryRequest_Validate_OK(t *testing.T) {
	t.Parallel()
	r := validFixture()
	require.NoError(t, r.Validate())
}

func TestRecoveryRequest_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)

	var got RecoveryRequest
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.SchemaVersion, got.SchemaVersion)
	require.Equal(t, orig.RequestID, got.RequestID)
	require.Equal(t, orig.GenomeID, got.GenomeID)
	require.Equal(t, orig.PolicyProfile, got.PolicyProfile)
	require.Equal(t, orig.RequesterIdentity, got.RequesterIdentity)
	require.Equal(t, orig.Contour, got.Contour)
	require.True(t, orig.CreatedAt.Equal(got.CreatedAt))
}

func TestRecoveryRequest_Validate_NegativeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mutate   func(*RecoveryRequest)
		wantCat  shared_errors.Category
		wantCode string
	}{
		{"schema_version_zero", func(r *RecoveryRequest) { r.SchemaVersion = 0 }, shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported},
		{"schema_version_too_high", func(r *RecoveryRequest) { r.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported},
		{"request_id_missing", func(r *RecoveryRequest) { r.RequestID = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"genome_id_missing", func(r *RecoveryRequest) { r.GenomeID = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"policy_profile_missing", func(r *RecoveryRequest) { r.PolicyProfile = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"requester_identity_missing", func(r *RecoveryRequest) { r.RequesterIdentity = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"created_at_zero", func(r *RecoveryRequest) { r.CreatedAt = time.Time{} }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validFixture()
			tc.mutate(&r)
			err := r.Validate()
			require.Error(t, err)
			require.Equal(t, tc.wantCat, shared_errors.CategoryOf(err))
			require.Equal(t, tc.wantCode, shared_errors.CodeOf(err))
		})
	}
}

func TestRecoveryRequest_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	// Add an unknown "sneaky" field. DisallowUnknownFields must reject.
	payload := `{"schema_version":1,"request_id":"x","genome_id":"g","policy_profile":"p","requester_identity":"r","created_at":"2026-04-20T10:00:00Z","sneaky":"yes"}`
	var r RecoveryRequest
	err := r.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestRecoveryRequest_UnmarshalJSON_SchemaVersionGate(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":2,"request_id":"x","genome_id":"g","policy_profile":"p","requester_identity":"r","created_at":"2026-04-20T10:00:00Z"}`
	var r RecoveryRequest
	err := r.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestRecoveryRequest_CanonicalBytes_OmitsSignature(t *testing.T) {
	t.Parallel()
	// recovery_request has no signature field; this tests that CanonicalBytes
	// refuses to produce bytes for an invalid contract.
	var r RecoveryRequest
	_, err := r.CanonicalBytes()
	require.Error(t, err, "CanonicalBytes must reject invalid contract")
}
