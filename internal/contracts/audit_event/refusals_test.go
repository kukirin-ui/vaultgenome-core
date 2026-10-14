// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_event

import (
	"bytes"
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
// the canonical encoder refuses it. Validate accepts it (it is not the
// zero time), which is what reaches the encoder's refusal.
var unencodableTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// newAuthorityOnlyStore holds kid under the authority purpose only, so an
// audit event — sealed under the audit purpose — can neither be signed
// nor verified through it.
func newAuthorityOnlyStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

// Every shape rule of Validate, one field at a time: each defect is
// refused as Structural with its own code, and the same refusal closes
// CanonicalBytes and VerifySignature, which run Validate first.
func TestAuditEvent_Validate_RefusesEachDefect(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)
	rows := []struct {
		name string
		edit func(e *AuditEvent)
		code string
	}{
		{"schema below range", func(e *AuditEvent) { e.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"schema above range", func(e *AuditEvent) { e.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		{"event id missing", func(e *AuditEvent) { e.EventID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"unknown kind", func(e *AuditEvent) { e.Kind = Kind("GOSSIP") }, shared_errors.CodeFieldValueInvalid},
		{"occurred at missing", func(e *AuditEvent) { e.OccurredAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"payload missing", func(e *AuditEvent) { e.Payload = nil }, shared_errors.CodeRequiredFieldMissing},
		{"prev hash short", func(e *AuditEvent) { e.PrevHash = e.PrevHash[:HashSize-1] }, shared_errors.CodeFieldValueInvalid},
		{"hash long", func(e *AuditEvent) { e.Hash = bytes.Repeat([]byte{0xAA}, HashSize+1) }, shared_errors.CodeFieldValueInvalid},
		{"signing key missing", func(e *AuditEvent) { e.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(e *AuditEvent) { e.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			e := validFixture()
			row.edit(&e)
			requireRefusal(t, e.Validate(), shared_errors.CategoryStructural, row.code)
			b, err := e.CanonicalBytes()
			requireRefusal(t, err, shared_errors.CategoryStructural, row.code)
			require.Nil(t, b)
			requireRefusal(t, e.VerifySignature(store), shared_errors.CategoryStructural, row.code)
		})
	}
}

// An event whose timestamp the canonical encoder cannot express has no
// cover-bytes: Validate accepts it (the time is not zero), and the
// refusal comes from the encoder, as Structural with the field code.
func TestAuditEvent_CanonicalBytes_RefusesUnencodableTimestamp(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.OccurredAt = unencodableTime
	require.NoError(t, e.Validate())
	b, err := e.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "audit_event: canonical encode failed")
}

// SignWith refuses what it cannot seal — a nil receiver, a missing key id
// and a timestamp the canonical encoder cannot express, all as
// Structural — and passes the signer's own refusal through unchanged:
// Authority for a key the store does not hold, Integrity for the key id
// held under the authority purpose instead of the audit purpose. The
// event stays unsigned in every case.
func TestAuditEvent_SignWith_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)
	authorityOnly := newAuthorityOnlyStore(t, kid)

	var nilEvent *AuditEvent
	requireRefusal(t, nilEvent.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		edit     func(e *AuditEvent)
		signer   keys.Signer
		category shared_errors.Category
		code     string
	}{
		{"signing key id missing", func(e *AuditEvent) { e.SigningKeyID = "" }, store, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"occurred at beyond the encodable range", func(e *AuditEvent) { e.OccurredAt = unencodableTime }, store, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"key the store does not hold", func(e *AuditEvent) { e.SigningKeyID = "nobody" }, store, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"key held under the authority purpose", func(*AuditEvent) {}, authorityOnly, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			e := unsignedFixture()
			e.SigningKeyID = kid
			row.edit(&e)
			requireRefusal(t, e.SignWith(row.signer), row.category, row.code)
			require.Empty(t, e.Signature)
		})
	}

	// The same event seals under the key it names.
	e := unsignedFixture()
	e.SigningKeyID = kid
	require.NoError(t, e.SignWith(store))
	require.NoError(t, e.VerifySignature(store))
}

// VerifySignature refuses a nil resolver as Structural before any key is
// looked up, and passes the resolver's refusal through for a sealed
// event: Authority when the resolver does not hold the kid. The same
// event still verifies under the key that sealed it.
func TestAuditEvent_VerifySignature_ResolverRefusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)
	e := unsignedFixture()
	e.SigningKeyID = kid
	require.NoError(t, e.SignWith(store))

	requireRefusal(t, e.VerifySignature(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	empty := keys.NewInMemoryStore(shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)))
	requireRefusal(t, e.VerifySignature(empty), shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing)

	require.NoError(t, e.VerifySignature(store))
}

// UnmarshalJSON refuses trailing content, an unknown field and a schema
// version outside the supported range, each as Structural with its own
// code. The trailing check is the decoder's own and is reached through
// the method: json.Unmarshal refuses trailing bytes before the method
// runs.
func TestAuditEvent_UnmarshalJSON_Refusals(t *testing.T) {
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
			var e AuditEvent
			requireRefusal(t, e.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the event they came from.
	var back AuditEvent
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validFixture(), back)
}
