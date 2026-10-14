// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_object

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validFixture() SessionObject {
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	return SessionObject{
		SchemaVersion: SchemaVersionCurrent,
		SessionID:     ids.SessionID("sess-0001"),
		RequestID:     ids.RequestID("req-0001"),
		GenomeID:      ids.GenomeID("genome-alpha"),
		PolicyVersion: ids.PolicyVersion("v1"),
		IssuedAt:      now,
		ExpiresAt:     now.Add(5 * time.Minute),
		State:         StateActive,
		SigningKeyID:  ids.KeyID("vault-key-1"),
		Signature:     []byte{0x01, 0x02, 0x03},
	}
}

func TestSessionObject_Validate_OK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validFixture().Validate())
}

func TestSessionObject_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)

	var got SessionObject
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.SchemaVersion, got.SchemaVersion)
	require.Equal(t, orig.SessionID, got.SessionID)
	require.Equal(t, orig.State, got.State)
	require.Equal(t, orig.Signature, got.Signature)
	require.True(t, orig.IssuedAt.Equal(got.IssuedAt))
	require.True(t, orig.ExpiresAt.Equal(got.ExpiresAt))
}

func TestSessionObject_Validate_NegativeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mutate   func(*SessionObject)
		wantCode string
	}{
		{"schema_zero", func(s *SessionObject) { s.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"session_id_missing", func(s *SessionObject) { s.SessionID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"request_id_missing", func(s *SessionObject) { s.RequestID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"genome_id_missing", func(s *SessionObject) { s.GenomeID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"policy_version_missing", func(s *SessionObject) { s.PolicyVersion = "" }, shared_errors.CodeRequiredFieldMissing},
		{"issued_at_zero", func(s *SessionObject) { s.IssuedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"expires_at_zero", func(s *SessionObject) { s.ExpiresAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"expires_before_issued", func(s *SessionObject) { s.ExpiresAt = s.IssuedAt.Add(-time.Second) }, shared_errors.CodeCrossFieldInconsistent},
		{"state_invalid", func(s *SessionObject) { s.State = State("zombie") }, shared_errors.CodeFieldValueInvalid},
		{"signing_key_missing", func(s *SessionObject) { s.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature_empty", func(s *SessionObject) { s.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validFixture()
			tc.mutate(&s)
			err := s.Validate()
			require.Error(t, err)
			require.Equal(t, tc.wantCode, shared_errors.CodeOf(err))
		})
	}
}

func TestSessionObject_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"session_id":"s","request_id":"r","genome_id":"g","policy_version":"v","issued_at":"2026-04-20T10:00:00Z","expires_at":"2026-04-20T10:05:00Z","state":"active","signing_key_id":"k","signature":"AQID","sneaky":"no"}`
	var s SessionObject
	err := s.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestSessionObject_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	s := validFixture()
	b, err := s.CanonicalBytes()
	require.NoError(t, err)
	// The literal Signature bytes [0x01, 0x02, 0x03] must not appear in
	// canonical form. JSON encodes them as base64 "AQID" — check that too.
	require.NotContains(t, string(b), `"AQID"`)
}
