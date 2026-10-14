// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package key_release_token

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

// newStore holds kid under purpose, on a fake clock so the key's
// creation time is deterministic.
func newStore(t *testing.T, kid ids.KeyID, purpose keys.Purpose) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, purpose)
	require.NoError(t, err)
	return s
}

// newAuthStore holds kid as a release-side authority signing key.
func newAuthStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	return newStore(t, kid, keys.PurposeSigningAuthority)
}

// signedFixture returns a token signed under kid through store.
func signedFixture(t *testing.T, store *keys.InMemoryStore, kid ids.KeyID) KeyReleaseToken {
	t.Helper()
	tok := validFixture()
	tok.SigningKeyID = kid
	tok.Signature = nil
	require.NoError(t, tok.SignWith(store))
	require.NotEmpty(t, tok.Signature)
	return tok
}

// A token signed under its authority key verifies under the same key,
// and nothing covered by the signature can change afterwards: a touched
// measurement, released key, policy version or decision id is refused
// as Integrity, as is a flipped or truncated signature.
func TestKeyReleaseToken_SignAndVerify(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	signed := signedFixture(t, store, kid)
	require.NoError(t, signed.VerifySignature(store))
	require.NoError(t, signed.Validate())

	rows := []struct {
		name string
		edit func(tok *KeyReleaseToken)
	}{
		{"destination measurement", func(tok *KeyReleaseToken) {
			tok.DestinationMeasurement = append([]byte(nil), tok.DestinationMeasurement...)
			tok.DestinationMeasurement[0] ^= 0xFF
		}},
		{"released key id", func(tok *KeyReleaseToken) {
			tok.Wrapped = append([]WrappedKey(nil), tok.Wrapped...)
			tok.Wrapped[0].KeyID = "seal-key-forged"
		}},
		{"policy version", func(tok *KeyReleaseToken) { tok.PolicyVersion = "policy-v2" }},
		{"decision id", func(tok *KeyReleaseToken) { tok.DecisionID = "dec-0002" }},
		{"signature bit", func(tok *KeyReleaseToken) {
			tok.Signature = append([]byte(nil), tok.Signature...)
			tok.Signature[0] ^= 0x01
		}},
		{"signature truncated", func(tok *KeyReleaseToken) { tok.Signature = tok.Signature[:len(tok.Signature)-1] }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			tok := signed
			row.edit(&tok)
			requireRefusal(t, tok.VerifySignature(store), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
		})
	}
}

// Every shape rule of Validate is refused as Structural with its own
// code, and the same refusal closes CanonicalBytes and VerifySignature,
// which run Validate first: an invalid token has no cover-bytes and
// nothing to verify.
func TestKeyReleaseToken_Validate_RefusalClosesCanonicalBytesAndVerify(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	rows := []struct {
		name string
		edit func(tok *KeyReleaseToken)
		code string
	}{
		{"schema above range", func(tok *KeyReleaseToken) { tok.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		{"token id missing", func(tok *KeyReleaseToken) { tok.TokenID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"measurement of 31 bytes", func(tok *KeyReleaseToken) { tok.DestinationMeasurement = tok.DestinationMeasurement[:31] }, shared_errors.CodeFieldValueInvalid},
		{"no wrapped keys", func(tok *KeyReleaseToken) { tok.Wrapped = nil }, shared_errors.CodeRequiredFieldMissing},
		{"wrapped key for another purpose", func(tok *KeyReleaseToken) {
			tok.Wrapped = append([]WrappedKey(nil), tok.Wrapped...)
			tok.Wrapped[0].Purpose = PurposeSealing + 1
		}, shared_errors.CodeFieldValueInvalid},
		{"policy version missing", func(tok *KeyReleaseToken) { tok.PolicyVersion = "" }, shared_errors.CodeRequiredFieldMissing},
		{"authorized at missing", func(tok *KeyReleaseToken) { tok.AuthorizedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(tok *KeyReleaseToken) { tok.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
		{"audit event id missing", func(tok *KeyReleaseToken) { tok.AuditEventID = "" }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			tok := validFixture()
			row.edit(&tok)
			requireRefusal(t, tok.Validate(), shared_errors.CategoryStructural, row.code)
			b, err := tok.CanonicalBytes()
			requireRefusal(t, err, shared_errors.CategoryStructural, row.code)
			require.Nil(t, b)
			requireRefusal(t, tok.VerifySignature(store), shared_errors.CategoryStructural, row.code)
		})
	}
}

// A token whose timestamp the canonical encoder cannot express has no
// cover-bytes: Validate accepts it (the time is not zero), and the
// refusal comes from the encoder, as Structural with the field code.
func TestKeyReleaseToken_CanonicalBytes_RefusesUnencodableTimestamp(t *testing.T) {
	t.Parallel()
	tok := validFixture()
	tok.AuthorizedAt = unencodableTime
	require.NoError(t, tok.Validate())
	b, err := tok.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "key_release_token: canonical encode failed")
}

// SignWith refuses what it cannot sign — a nil receiver, a missing key
// id and a timestamp the canonical encoder cannot express, all as
// Structural — and passes the signer's own refusal through unchanged:
// Authority for a key the store does not hold, Integrity for the key id
// held under another purpose. The token stays unsigned in every case.
func TestKeyReleaseToken_SignWith_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	auditOnly := newStore(t, kid, keys.PurposeSigningAudit)

	var nilToken *KeyReleaseToken
	requireRefusal(t, nilToken.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		edit     func(tok *KeyReleaseToken)
		signer   keys.Signer
		category shared_errors.Category
		code     string
	}{
		{"signing key id missing", func(tok *KeyReleaseToken) { tok.SigningKeyID = "" }, store, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"authorized at beyond the encodable range", func(tok *KeyReleaseToken) { tok.AuthorizedAt = unencodableTime }, store, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"key the store does not hold", func(tok *KeyReleaseToken) { tok.SigningKeyID = "nobody" }, store, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"key held under the audit purpose", func(*KeyReleaseToken) {}, auditOnly, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			tok := validFixture()
			tok.SigningKeyID = kid
			tok.Signature = nil
			row.edit(&tok)
			requireRefusal(t, tok.SignWith(row.signer), row.category, row.code)
			require.Empty(t, tok.Signature)
		})
	}
}

// VerifySignature refuses a nil resolver as Structural before any key is
// looked up, and passes the resolver's refusal through for a signed
// token: Authority when it does not hold the kid, Integrity when it
// holds the kid under another purpose, and Integrity with the signature
// code when it holds the same kid under a different key.
func TestKeyReleaseToken_VerifySignature_ResolverRefusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	signed := signedFixture(t, store, kid)

	requireRefusal(t, signed.VerifySignature(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	empty := keys.NewInMemoryStore(shared_time.NewFakeClock(time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)))
	requireRefusal(t, signed.VerifySignature(empty), shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, signed.VerifySignature(newStore(t, kid, keys.PurposeSigningAudit)), shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid)
	requireRefusal(t, signed.VerifySignature(newAuthStore(t, kid)), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	require.NoError(t, signed.VerifySignature(store))
}

// UnmarshalJSON refuses trailing content, an unknown field and a schema
// version outside the supported range, each as Structural with its own
// code. The trailing check is the decoder's own and is reached through
// the method: json.Unmarshal refuses trailing bytes before the method
// runs.
func TestKeyReleaseToken_UnmarshalJSON_Refusals(t *testing.T) {
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
			var tok KeyReleaseToken
			requireRefusal(t, tok.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the token they came from.
	var back KeyReleaseToken
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validFixture(), back)
}
