// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_object

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// unencodableTime lies outside the year range RFC 3339 can express, so
// the canonical encoder refuses it. Validate accepts it as an expiry
// (it is not the zero time and it is after issued_at), which is what
// reaches the encoder's refusal.
var unencodableTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// newAuditOnlyStore holds kid under the audit purpose only, so a session
// — an authority artifact — can neither be signed nor verified through it.
func newAuditOnlyStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)
	return s
}

// Every shape rule of Validate, one field at a time: each defect is
// refused as Structural with its own code, and the same refusal closes
// CanonicalBytes and VerifySignature, which run Validate first.
func TestSessionObject_Validate_RefusesEachDefect(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newSignedStore(t, kid)
	rows := []struct {
		name string
		edit func(s *SessionObject)
		code string
	}{
		{"schema below range", func(s *SessionObject) { s.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"schema above range", func(s *SessionObject) { s.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		{"session id missing", func(s *SessionObject) { s.SessionID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"request id missing", func(s *SessionObject) { s.RequestID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"genome id missing", func(s *SessionObject) { s.GenomeID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"policy version missing", func(s *SessionObject) { s.PolicyVersion = "" }, shared_errors.CodeRequiredFieldMissing},
		{"issued at missing", func(s *SessionObject) { s.IssuedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"expires at missing", func(s *SessionObject) { s.ExpiresAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"expires when issued", func(s *SessionObject) { s.ExpiresAt = s.IssuedAt }, shared_errors.CodeCrossFieldInconsistent},
		{"unknown state", func(s *SessionObject) { s.State = State("zombie") }, shared_errors.CodeFieldValueInvalid},
		{"signing key missing", func(s *SessionObject) { s.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(s *SessionObject) { s.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			s := validFixture()
			row.edit(&s)
			requireRefusal(t, s.Validate(), shared_errors.CategoryStructural, row.code)
			b, err := s.CanonicalBytes()
			requireRefusal(t, err, shared_errors.CategoryStructural, row.code)
			require.Nil(t, b)
			requireRefusal(t, s.VerifySignature(store), shared_errors.CategoryStructural, row.code)
		})
	}
}

// A session whose expiry the canonical encoder cannot express has no
// cover-bytes: Validate accepts it (the expiry is set and after
// issued_at), and the refusal comes from the encoder, as Structural with
// the field code.
func TestSessionObject_CanonicalBytes_RefusesUnencodableTimestamp(t *testing.T) {
	t.Parallel()
	s := validFixture()
	s.ExpiresAt = unencodableTime
	require.NoError(t, s.Validate())
	b, err := s.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "session_object: canonical encode failed")
}

// SignWith refuses what it cannot sign — a nil receiver, a missing key
// id and a timestamp the canonical encoder cannot express, all as
// Structural — and passes the signer's own refusal through unchanged:
// Authority for a key the store does not hold, Integrity for the key id
// held under another purpose. The session stays unsigned in every case.
func TestSessionObject_SignWith_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newSignedStore(t, kid)
	auditOnly := newAuditOnlyStore(t, kid)

	var nilSession *SessionObject
	requireRefusal(t, nilSession.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		edit     func(s *SessionObject)
		signer   keys.Signer
		category shared_errors.Category
		code     string
	}{
		{"signing key id missing", func(s *SessionObject) { s.SigningKeyID = "" }, store, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"expires at beyond the encodable range", func(s *SessionObject) { s.ExpiresAt = unencodableTime }, store, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"key the store does not hold", func(s *SessionObject) { s.SigningKeyID = "nobody" }, store, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"key held under the audit purpose", func(*SessionObject) {}, auditOnly, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			s := validFixture()
			s.SigningKeyID = kid
			s.Signature = nil
			row.edit(&s)
			requireRefusal(t, s.SignWith(row.signer), row.category, row.code)
			require.Empty(t, s.Signature)
		})
	}

	// The same session signs under the key it names.
	s := validFixture()
	s.SigningKeyID = kid
	s.Signature = nil
	require.NoError(t, s.SignWith(store))
	require.NoError(t, s.VerifySignature(store))
}

// VerifySignature refuses a nil resolver as Structural before any key is
// looked up, passes the resolver's refusal through for a signed session
// (Authority when it does not hold the kid), and refuses as Integrity a
// signature that does not cover these bytes under this key: the same kid
// under another key, a flipped bit.
func TestSessionObject_VerifySignature_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newSignedStore(t, kid)
	signed := validFixture()
	signed.SigningKeyID = kid
	signed.Signature = nil
	require.NoError(t, signed.SignWith(store))
	require.NoError(t, signed.VerifySignature(store))

	requireRefusal(t, signed.VerifySignature(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	empty := keys.NewInMemoryStore(shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)))
	requireRefusal(t, signed.VerifySignature(empty), shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, signed.VerifySignature(newSignedStore(t, kid)), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	flipped := signed
	flipped.Signature = append([]byte(nil), signed.Signature...)
	flipped.Signature[0] ^= 0x01
	requireRefusal(t, flipped.VerifySignature(store), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
}

// UnmarshalJSON refuses trailing content, an unknown field and a schema
// version outside the supported range, each as Structural with its own
// code. The trailing check is the decoder's own and is reached through
// the method: json.Unmarshal refuses trailing bytes before the method
// runs.
func TestSessionObject_UnmarshalJSON_Refusals(t *testing.T) {
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
			var s SessionObject
			requireRefusal(t, s.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the session they came from.
	var back SessionObject
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validFixture(), back)
}
