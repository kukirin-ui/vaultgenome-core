// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package attestation_result

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validAllow() AttestationResult {
	return AttestationResult{
		SchemaVersion: SchemaVersionCurrent,
		AttestationID: ids.AttestationID("att-0001"),
		RequestID:     ids.RequestID("req-0001"),
		Outcome:       OutcomeAllow,
		IssuedAt:      time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		TTL:           DefaultTTL,
		SigningKeyID:  ids.KeyID("trust-key-1"),
		Signature:     []byte{0xAA, 0xBB},
	}
}

func TestAttestationResult_Validate_AllowOK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validAllow().Validate())
}

func TestAttestationResult_Validate_DenyRequiresReason(t *testing.T) {
	t.Parallel()
	a := validAllow()
	a.Outcome = OutcomeDeny
	err := a.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	a.Reason = "trust.peer_unknown"
	require.NoError(t, a.Validate())
}

func TestAttestationResult_Validate_RestrictRequiresReason(t *testing.T) {
	t.Parallel()
	a := validAllow()
	a.Outcome = OutcomeRestrict
	err := a.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestAttestationResult_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validAllow()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got AttestationResult
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.Outcome, got.Outcome)
	require.Equal(t, orig.TTL, got.TTL)
}

func TestAttestationResult_Validate_NegativeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mutate   func(*AttestationResult)
		wantCode string
	}{
		{"schema_zero", func(a *AttestationResult) { a.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"attestation_id_missing", func(a *AttestationResult) { a.AttestationID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"request_id_missing", func(a *AttestationResult) { a.RequestID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"unknown_outcome", func(a *AttestationResult) { a.Outcome = Outcome("maybe") }, shared_errors.CodeFieldValueInvalid},
		{"ttl_zero", func(a *AttestationResult) { a.TTL = 0 }, shared_errors.CodeFieldValueInvalid},
		{"ttl_negative", func(a *AttestationResult) { a.TTL = -time.Second }, shared_errors.CodeFieldValueInvalid},
		{"issued_at_zero", func(a *AttestationResult) { a.IssuedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"signing_key_missing", func(a *AttestationResult) { a.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature_empty", func(a *AttestationResult) { a.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAllow()
			tc.mutate(&a)
			err := a.Validate()
			require.Error(t, err)
			require.Equal(t, tc.wantCode, shared_errors.CodeOf(err))
		})
	}
}

func TestAttestationResult_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"attestation_id":"a","request_id":"r","outcome":"allow","issued_at":"2026-04-20T10:00:00Z","ttl":300000000000,"signing_key_id":"k","signature":"qqo=","sneaky":1}`
	var a AttestationResult
	err := a.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}
