// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package key_release_token

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validFixture() KeyReleaseToken {
	measurement := make([]byte, 32)
	for i := range measurement {
		measurement[i] = byte(0x42)
	}
	return KeyReleaseToken{
		SchemaVersion:          SchemaVersionCurrent,
		TokenID:                ids.DecisionID("xcc-tok-0001"),
		DecisionID:             ids.DecisionID("dec-0001"),
		RequestID:              ids.RequestID("xcc-req-0001"),
		DestinationMeasurement: measurement,
		Wrapped: []WrappedKey{
			{
				KeyID:      ids.KeyID("seal-key-1"),
				Purpose:    PurposeSealing,
				Ciphertext: []byte{0x01, 0x02, 0x03, 0x04},
				AAD:        []byte{0xAA, 0xBB, 0xCC},
			},
		},
		PolicyVersion: "policy-v1",
		AuthorizedAt:  time.Date(2026, 5, 9, 12, 5, 0, 0, time.UTC),
		SigningKeyID:  ids.KeyID("vault-key-1"),
		Signature:     []byte{0xFF},
		AuditEventID:  ids.AuditEventID("evt-xcc-rel-0001"),
	}
}

func TestKeyReleaseToken_Validate_OK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validFixture().Validate())
}

func TestKeyReleaseToken_SchemaVersionOutOfRange(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.SchemaVersion = SchemaVersionMax + 1
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_TokenIDRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.TokenID = ""
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_DecisionIDRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.DecisionID = ""
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_RequestIDRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.RequestID = ""
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_DestinationMeasurementWrongSize(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 31, 33, 47, 49, 63, 65, 128} {
		tok := validFixture()
		tok.DestinationMeasurement = make([]byte, n)
		err := tok.Validate()
		require.Error(t, err, "%d-byte measurement accepted", n)
		require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	}
}

// Real hardware measurements are pinned whole: SEV-SNP MEASUREMENT and
// Nitro PCR0 are 48 bytes (ADR 0007), SHA-512 digests 64.
func TestKeyReleaseToken_DestinationMeasurementHardwareSizes(t *testing.T) {
	t.Parallel()
	for _, n := range []int{32, 48, 64} {
		tok := validFixture()
		tok.DestinationMeasurement = make([]byte, n)
		require.NoError(t, tok.Validate(), "%d-byte measurement rejected", n)
	}
}

func TestKeyReleaseToken_DestinationMeasurementMissing(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.DestinationMeasurement = nil
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_WrappedEmptyRejected(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.Wrapped = nil
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))

	tok.Wrapped = []WrappedKey{}
	err = tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_WrappedKeyKeyIDRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.Wrapped[0].KeyID = ""
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_WrappedKeyWrongPurposeRejected(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.Wrapped[0].Purpose = 1 // PurposeSigningAuthority — not allowed in Phase 4 wrap
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_WrappedKeyCiphertextRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.Wrapped[0].Ciphertext = nil
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_WrappedKeyAADRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.Wrapped[0].AAD = nil
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_PolicyVersionRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.PolicyVersion = ""
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_AuthorizedAtRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.AuthorizedAt = time.Time{}
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_SigningKeyIDRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.SigningKeyID = ""
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_SignatureRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.Signature = nil
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_AuditEventIDRequired(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.AuditEventID = ""
	err := tok.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_MultipleWrappedKeysOK(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.Wrapped = []WrappedKey{
		{KeyID: ids.KeyID("k1"), Purpose: PurposeSealing, Ciphertext: []byte{1}, AAD: []byte{1}},
		{KeyID: ids.KeyID("k2"), Purpose: PurposeSealing, Ciphertext: []byte{2}, AAD: []byte{2}},
		{KeyID: ids.KeyID("k3"), Purpose: PurposeSealing, Ciphertext: []byte{3}, AAD: []byte{3}},
	}
	require.NoError(t, tok.Validate())
}

func TestKeyReleaseToken_JSON_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	b, err := json.Marshal(orig)
	require.NoError(t, err)

	var decoded KeyReleaseToken
	require.NoError(t, json.Unmarshal(b, &decoded))
	require.Equal(t, orig.SchemaVersion, decoded.SchemaVersion)
	require.Equal(t, orig.TokenID, decoded.TokenID)
	require.Equal(t, orig.DecisionID, decoded.DecisionID)
	require.Equal(t, orig.RequestID, decoded.RequestID)
	require.Equal(t, orig.DestinationMeasurement, decoded.DestinationMeasurement)
	require.Equal(t, len(orig.Wrapped), len(decoded.Wrapped))
	require.Equal(t, orig.Wrapped[0].KeyID, decoded.Wrapped[0].KeyID)
	require.Equal(t, orig.Wrapped[0].Purpose, decoded.Wrapped[0].Purpose)
	require.Equal(t, orig.PolicyVersion, decoded.PolicyVersion)
	require.True(t, orig.AuthorizedAt.Equal(decoded.AuthorizedAt))
	require.Equal(t, orig.AuditEventID, decoded.AuditEventID)
}

func TestKeyReleaseToken_UnmarshalJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	bad := []byte(`{"schema_version":1,"mystery_field":"hi"}`)
	var tok KeyReleaseToken
	err := tok.UnmarshalJSON(bad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_UnmarshalJSON_RejectsSchemaOutOfRange(t *testing.T) {
	t.Parallel()
	bad := []byte(`{"schema_version":99}`)
	var tok KeyReleaseToken
	err := tok.UnmarshalJSON(bad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestKeyReleaseToken_CanonicalBytes_StableAcrossInvocations(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	b1, err := tok.CanonicalBytes()
	require.NoError(t, err)
	b2, err := tok.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, b1, b2)
}

func TestKeyReleaseToken_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	t1 := validFixture()
	t2 := validFixture()
	t2.Signature = []byte{0xAA, 0xBB, 0xCC}
	b1, err := t1.CanonicalBytes()
	require.NoError(t, err)
	b2, err := t2.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, b1, b2, "Signature must NOT contribute to its own cover-bytes")
}

func TestKeyReleaseToken_CanonicalBytes_ChangesWithFields(t *testing.T) {
	t.Parallel()
	t1 := validFixture()
	t2 := validFixture()
	t2.PolicyVersion = "policy-v2"
	b1, err := t1.CanonicalBytes()
	require.NoError(t, err)
	b2, err := t2.CanonicalBytes()
	require.NoError(t, err)
	require.NotEqual(t, b1, b2, "CanonicalBytes must reflect every signed field")
}
