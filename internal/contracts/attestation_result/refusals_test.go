// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package attestation_result

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

// newAuditOnlyStore holds kid under the audit purpose only, so a Trust
// Admission outcome — an authority artifact — can neither be signed nor
// verified through it.
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
func TestAttestationResult_Validate_RefusesEachDefect(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("trust-key-1")
	store := newAuthStore(t, kid)
	rows := []struct {
		name string
		edit func(a *AttestationResult)
		code string
	}{
		{"schema below range", func(a *AttestationResult) { a.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"schema above range", func(a *AttestationResult) { a.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		{"attestation id missing", func(a *AttestationResult) { a.AttestationID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"request id missing", func(a *AttestationResult) { a.RequestID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"unknown outcome", func(a *AttestationResult) { a.Outcome = Outcome("maybe") }, shared_errors.CodeFieldValueInvalid},
		{"issued at missing", func(a *AttestationResult) { a.IssuedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"ttl zero", func(a *AttestationResult) { a.TTL = 0 }, shared_errors.CodeFieldValueInvalid},
		{"signing key missing", func(a *AttestationResult) { a.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(a *AttestationResult) { a.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
		{"deny without a reason", func(a *AttestationResult) { a.Outcome = OutcomeDeny }, shared_errors.CodeCrossFieldInconsistent},
		{"restrict without a reason", func(a *AttestationResult) { a.Outcome = OutcomeRestrict }, shared_errors.CodeCrossFieldInconsistent},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			a := validAllow()
			row.edit(&a)
			requireRefusal(t, a.Validate(), shared_errors.CategoryStructural, row.code)
			b, err := a.CanonicalBytes()
			requireRefusal(t, err, shared_errors.CategoryStructural, row.code)
			require.Nil(t, b)
			requireRefusal(t, a.VerifySignature(store), shared_errors.CategoryStructural, row.code)
		})
	}
}

// An outcome whose timestamp the canonical encoder cannot express has no
// cover-bytes: Validate accepts it (the time is not zero), and the
// refusal comes from the encoder, as Structural with the field code.
func TestAttestationResult_CanonicalBytes_RefusesUnencodableTimestamp(t *testing.T) {
	t.Parallel()
	a := validAllow()
	a.IssuedAt = unencodableTime
	require.NoError(t, a.Validate())
	b, err := a.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "attestation_result: canonical encode failed")
}

// SignWith refuses what it cannot sign — a nil receiver, a missing key
// id and a timestamp the canonical encoder cannot express, all as
// Structural — and passes the signer's own refusal through unchanged:
// Authority for a key the store does not hold, Integrity for the key id
// held under another purpose. The outcome stays unsigned in every case.
func TestAttestationResult_SignWith_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("trust-key-1")
	store := newAuthStore(t, kid)
	auditOnly := newAuditOnlyStore(t, kid)

	var nilResult *AttestationResult
	requireRefusal(t, nilResult.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		edit     func(a *AttestationResult)
		signer   keys.Signer
		category shared_errors.Category
		code     string
	}{
		{"signing key id missing", func(a *AttestationResult) { a.SigningKeyID = "" }, store, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"issued at beyond the encodable range", func(a *AttestationResult) { a.IssuedAt = unencodableTime }, store, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"key the store does not hold", func(a *AttestationResult) { a.SigningKeyID = "nobody" }, store, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"key held under the audit purpose", func(*AttestationResult) {}, auditOnly, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			a := validAllow()
			a.SigningKeyID = kid
			a.Signature = nil
			row.edit(&a)
			requireRefusal(t, a.SignWith(row.signer), row.category, row.code)
			require.Empty(t, a.Signature)
		})
	}

	// The same outcome signs under the key it names.
	a := validAllow()
	a.SigningKeyID = kid
	a.Signature = nil
	require.NoError(t, a.SignWith(store))
	require.NoError(t, a.VerifySignature(store))
}

// VerifySignature refuses a nil resolver as Structural before any key is
// looked up, passes the resolver's refusal through for a signed outcome
// (Authority when it does not hold the kid, Integrity when it holds the
// kid under another purpose), and refuses as Integrity a signature that
// does not cover these bytes under this key: the same kid under another
// key, a flipped bit, a truncated signature.
func TestAttestationResult_VerifySignature_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("trust-key-1")
	store := newAuthStore(t, kid)
	signed := validAllow()
	signed.SigningKeyID = kid
	signed.Signature = nil
	require.NoError(t, signed.SignWith(store))
	require.NoError(t, signed.VerifySignature(store))

	requireRefusal(t, signed.VerifySignature(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	empty := keys.NewInMemoryStore(shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)))
	requireRefusal(t, signed.VerifySignature(empty), shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, signed.VerifySignature(newAuditOnlyStore(t, kid)), shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid)
	requireRefusal(t, signed.VerifySignature(newAuthStore(t, kid)), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	flipped := signed
	flipped.Signature = append([]byte(nil), signed.Signature...)
	flipped.Signature[0] ^= 0x01
	requireRefusal(t, flipped.VerifySignature(store), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	truncated := signed
	truncated.Signature = signed.Signature[:len(signed.Signature)-1]
	requireRefusal(t, truncated.VerifySignature(store), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
}

// UnmarshalJSON refuses trailing content, an unknown field and a schema
// version outside the supported range, each as Structural with its own
// code. The trailing check is the decoder's own and is reached through
// the method: json.Unmarshal refuses trailing bytes before the method
// runs.
func TestAttestationResult_UnmarshalJSON_Refusals(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(validAllow())
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
			var a AttestationResult
			requireRefusal(t, a.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the outcome they came from.
	var back AttestationResult
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validAllow(), back)
}
