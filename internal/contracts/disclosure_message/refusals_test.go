// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_message

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
// the canonical encoder refuses it. Validate accepts it (it is not the
// zero time), which is what reaches the encoder's refusal.
var unencodableTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// newAuditOnlyStore holds kid under the audit purpose only, so a
// disclosure — an authority artifact — can neither be signed nor
// verified through it.
func newAuditOnlyStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)
	return s
}

// A disclosure whose timestamp the canonical encoder cannot express has
// no cover-bytes: Validate accepts it (the time is not zero), and the
// refusal comes from the encoder, as Structural with the field code.
func TestDisclosureMessage_CanonicalBytes_RefusesUnencodableTimestamp(t *testing.T) {
	t.Parallel()
	d := validFixture()
	d.AuthorizedAt = unencodableTime
	require.NoError(t, d.Validate())
	b, err := d.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "disclosure_message: canonical encode failed")
}

// SignWith refuses what it cannot sign — a nil receiver, a missing key
// id and a timestamp the canonical encoder cannot express, all as
// Structural — and passes the signer's own refusal through unchanged:
// Authority for a key the store does not hold, Integrity for the key id
// held under another purpose. The disclosure stays unsigned in every
// case.
func TestDisclosureMessage_SignWith_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	auditOnly := newAuditOnlyStore(t, kid)

	var nilMessage *DisclosureMessage
	requireRefusal(t, nilMessage.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		edit     func(d *DisclosureMessage)
		signer   keys.Signer
		category shared_errors.Category
		code     string
	}{
		{"signing key id missing", func(d *DisclosureMessage) { d.SigningKeyID = "" }, store, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"authorized at beyond the encodable range", func(d *DisclosureMessage) { d.AuthorizedAt = unencodableTime }, store, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"key the store does not hold", func(d *DisclosureMessage) { d.SigningKeyID = "nobody" }, store, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"key held under the audit purpose", func(*DisclosureMessage) {}, auditOnly, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			d := validFixture()
			d.SigningKeyID = kid
			d.Signature = nil
			row.edit(&d)
			requireRefusal(t, d.SignWith(row.signer), row.category, row.code)
			require.Empty(t, d.Signature)
		})
	}

	// The same disclosure signs under the key it names.
	d := validFixture()
	d.SigningKeyID = kid
	d.Signature = nil
	require.NoError(t, d.SignWith(store))
	require.NoError(t, d.VerifySignature(store))
}

// VerifySignature passes the resolver's refusal through for a signed
// disclosure (Authority when it does not hold the kid, Integrity when it
// holds the kid under another purpose) and refuses the same kid under a
// different key as Integrity with the signature code. The disclosure
// still verifies under the key that signed it.
func TestDisclosureMessage_VerifySignature_ResolverRefusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	signed := validFixture()
	signed.SigningKeyID = kid
	signed.Signature = nil
	require.NoError(t, signed.SignWith(store))

	empty := keys.NewInMemoryStore(shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)))
	requireRefusal(t, signed.VerifySignature(empty), shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, signed.VerifySignature(newAuditOnlyStore(t, kid)), shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid)
	requireRefusal(t, signed.VerifySignature(newAuthStore(t, kid)), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	require.NoError(t, signed.VerifySignature(store))
}

// UnmarshalJSON refuses trailing content, an unknown field and a schema
// version outside the supported range, each as Structural with its own
// code. The trailing check is the decoder's own and is reached through
// the method: json.Unmarshal refuses trailing bytes before the method
// runs.
func TestDisclosureMessage_UnmarshalJSON_Refusals(t *testing.T) {
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
			var d DisclosureMessage
			requireRefusal(t, d.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the disclosure they came from.
	var back DisclosureMessage
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validFixture(), back)
}
