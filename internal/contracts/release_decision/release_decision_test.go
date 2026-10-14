// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package release_decision

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validPassFixture() ReleaseDecision {
	return ReleaseDecision{
		SchemaVersion:      SchemaVersionCurrent,
		DecisionID:         ids.DecisionID("dec-0001"),
		SessionID:          ids.SessionID("sess-0001"),
		ManifestID:         ids.ManifestID("man-0001"),
		ValidationResultID: ids.ValidationResultID("vr-0001"),
		Release:            true,
		Reason:             ReasonValidationPass,
		DecidedAt:          time.Date(2026, 4, 20, 10, 5, 0, 0, time.UTC),
		SigningKeyID:       ids.KeyID("vault-key-1"),
		Signature:          []byte{0xFF},
		AuditEventID:       ids.AuditEventID("evt-0001"),
	}
}

func TestReleaseDecision_Validate_PassOK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validPassFixture().Validate())
}

func TestReleaseDecision_PassRequiresReleaseTrue(t *testing.T) {
	t.Parallel()
	r := validPassFixture()
	r.Release = false
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestReleaseDecision_FailRequiresReleaseFalse(t *testing.T) {
	t.Parallel()
	r := validPassFixture()
	r.Reason = ReasonValidationFail
	r.Release = true
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	r.Release = false
	require.NoError(t, r.Validate())
}

func TestReleaseDecision_ConditionalFailRequiresReleaseFalse(t *testing.T) {
	t.Parallel()
	r := validPassFixture()
	r.Reason = ReasonConditionalFailRequiresReview
	r.Release = true
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	r.Release = false
	require.NoError(t, r.Validate())
}

func TestReleaseDecision_UnknownReasonRejected(t *testing.T) {
	t.Parallel()
	r := validPassFixture()
	r.Reason = Reason("vibes")
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestReleaseDecision_AuditEventIDRequired(t *testing.T) {
	t.Parallel()
	r := validPassFixture()
	r.AuditEventID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestReleaseDecision_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validPassFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got ReleaseDecision
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.Reason, got.Reason)
	require.Equal(t, orig.Release, got.Release)
	require.Equal(t, orig.AuditEventID, got.AuditEventID)
}

func TestReleaseDecision_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"extra":"x"}`
	var r ReleaseDecision
	err := r.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
}

func TestReleaseDecision_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	r := validPassFixture()
	b, err := r.CanonicalBytes()
	require.NoError(t, err)
	require.NotContains(t, string(b), `"signature":"`)
}

func validTrustDeniedFixture() ReleaseDecision {
	return ReleaseDecision{
		SchemaVersion: SchemaVersionCurrent,
		DecisionID:    ids.DecisionID("dec-0002"),
		AttestationID: ids.AttestationID("att-0002"),
		Release:       false,
		Reason:        ReasonTrustDenied,
		DecidedAt:     time.Date(2026, 9, 16, 10, 5, 0, 0, time.UTC),
		SigningKeyID:  ids.KeyID("vault-key-1"),
		Signature:     []byte{0xFF},
		AuditEventID:  ids.AuditEventID("evt-0002"),
	}
}

// Schema v2: a denial at Trust Admission is a release decision without a
// session — it cites the attestation and nothing downstream.
func TestReleaseDecision_TrustDenied_V2(t *testing.T) {
	t.Parallel()
	require.NoError(t, validTrustDeniedFixture().Validate())

	r := validTrustDeniedFixture()
	r.Release = true
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(r.Validate()))

	r = validTrustDeniedFixture()
	r.AttestationID = ""
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(r.Validate()))

	r = validTrustDeniedFixture()
	r.SessionID = "sess-0001"
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(r.Validate()))

	r = validTrustDeniedFixture()
	r.SchemaVersion = 1
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(r.Validate()))

	// A v1 decision is still a valid decision, and the validation reasons
	// still need every id.
	v1 := validPassFixture()
	v1.SchemaVersion = 1
	require.NoError(t, v1.Validate())
	v1.SessionID = ""
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(v1.Validate()))

	data, err := json.Marshal(validTrustDeniedFixture())
	require.NoError(t, err)
	require.NotContains(t, string(data), `"attestation_id":""`)
	var back ReleaseDecision
	require.NoError(t, json.Unmarshal(data, &back))
	require.Equal(t, validTrustDeniedFixture(), back)
}
