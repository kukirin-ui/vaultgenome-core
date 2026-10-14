// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cross_cloud_handshake_request

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func validFixture() CrossCloudHandshakeRequest {
	nonce := make([]byte, HandshakeNonceMinBytes)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	measurement := make([]byte, 32)
	for i := range measurement {
		measurement[i] = byte(0x42)
	}
	return CrossCloudHandshakeRequest{
		SchemaVersion:       SchemaVersionCurrent,
		RequestID:           ids.RequestID("xcc-req-0001"),
		DecisionID:          ids.DecisionID("dec-0001"),
		DestinationTEEKind:  tee.ProviderAWSNitro,
		DestinationEndpoint: "https://acp-bootstrap.example.com:8443",
		HandshakeNonce:      nonce,
		SourceMeasurement:   measurement,
		InitiatedAt:         time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
		SigningKeyID:        ids.KeyID("vault-key-1"),
		Signature:           []byte{0xFF},
		AuditEventID:        ids.AuditEventID("evt-xcc-0001"),
	}
}

func TestCrossCloudHandshakeRequest_Validate_OK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validFixture().Validate())
}

func TestCrossCloudHandshakeRequest_Validate_OK_WithoutSourceEvidence(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.SourceEvidence = nil
	r.SourceMeasurement = nil
	require.NoError(t, r.Validate(), "mutual attestation is optional; absence of source_evidence + source_measurement is permitted")
}

func TestCrossCloudHandshakeRequest_SchemaVersionOutOfRange(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.SchemaVersion = SchemaVersionMax + 1
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_RequestIDRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.RequestID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_DecisionIDRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.DecisionID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_DestinationTEEKindRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.DestinationTEEKind = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_UnknownDestinationTEEKindRejected(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.DestinationTEEKind = tee.Provider("vibes-tee")
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_DestinationEndpointRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.DestinationEndpoint = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_HandshakeNonceTooShortRejected(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.HandshakeNonce = make([]byte, HandshakeNonceMinBytes-1)
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_SourceMeasurementWrongLengthRejected(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.SourceMeasurement = make([]byte, 31) // too short, but non-empty
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))

	r.SourceMeasurement = make([]byte, 48) // a whole SEV-SNP / Nitro measurement
	require.NoError(t, r.Validate())
}

func TestCrossCloudHandshakeRequest_InitiatedAtRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.InitiatedAt = time.Time{}
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_SigningKeyIDRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.SigningKeyID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_SignatureRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.Signature = nil
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_AuditEventIDRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.AuditEventID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_AllProvidersAccepted(t *testing.T) {
	t.Parallel()
	for _, p := range tee.AllProviders() {
		t.Run(string(p), func(t *testing.T) {
			r := validFixture()
			r.DestinationTEEKind = p
			require.NoError(t, r.Validate(), "every Provider in factory.go must be a valid destination_tee_kind")
		})
	}
}

func TestCrossCloudHandshakeRequest_JSON_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	b, err := json.Marshal(orig)
	require.NoError(t, err)

	var decoded CrossCloudHandshakeRequest
	require.NoError(t, json.Unmarshal(b, &decoded))
	require.Equal(t, orig.SchemaVersion, decoded.SchemaVersion)
	require.Equal(t, orig.RequestID, decoded.RequestID)
	require.Equal(t, orig.DecisionID, decoded.DecisionID)
	require.Equal(t, orig.DestinationTEEKind, decoded.DestinationTEEKind)
	require.Equal(t, orig.DestinationEndpoint, decoded.DestinationEndpoint)
	require.Equal(t, orig.HandshakeNonce, decoded.HandshakeNonce)
	require.Equal(t, orig.SourceMeasurement, decoded.SourceMeasurement)
	require.True(t, orig.InitiatedAt.Equal(decoded.InitiatedAt))
	require.Equal(t, orig.SigningKeyID, decoded.SigningKeyID)
	require.Equal(t, orig.Signature, decoded.Signature)
	require.Equal(t, orig.AuditEventID, decoded.AuditEventID)
}

func TestCrossCloudHandshakeRequest_UnmarshalJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	bad := []byte(`{"schema_version":1,"request_id":"x","mystery_field":"hi"}`)
	var r CrossCloudHandshakeRequest
	err := r.UnmarshalJSON(bad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_UnmarshalJSON_RejectsSchemaOutOfRange(t *testing.T) {
	t.Parallel()
	bad := []byte(`{"schema_version":99}`)
	var r CrossCloudHandshakeRequest
	err := r.UnmarshalJSON(bad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestCrossCloudHandshakeRequest_CanonicalBytes_StableAcrossInvocations(t *testing.T) {
	t.Parallel()
	r := validFixture()
	b1, err := r.CanonicalBytes()
	require.NoError(t, err)
	b2, err := r.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, b1, b2, "CanonicalBytes must be deterministic")
}

func TestCrossCloudHandshakeRequest_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	r1 := validFixture()
	r2 := validFixture()
	r2.Signature = []byte{0xAA, 0xBB, 0xCC}
	b1, err := r1.CanonicalBytes()
	require.NoError(t, err)
	b2, err := r2.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, b1, b2, "Signature must NOT contribute to its own cover-bytes")
}

func TestCrossCloudHandshakeRequest_CanonicalBytes_ChangesWithFields(t *testing.T) {
	t.Parallel()
	r1 := validFixture()
	r2 := validFixture()
	r2.RequestID = ids.RequestID("different-request")
	b1, err := r1.CanonicalBytes()
	require.NoError(t, err)
	b2, err := r2.CanonicalBytes()
	require.NoError(t, err)
	require.NotEqual(t, b1, b2, "CanonicalBytes must reflect every signed field")
}
