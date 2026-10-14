// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cross_cloud_handshake_request

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
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

// signedFixture returns a request signed under kid through store.
func signedFixture(t *testing.T, store *keys.InMemoryStore, kid ids.KeyID) CrossCloudHandshakeRequest {
	t.Helper()
	r := validFixture()
	r.SigningKeyID = kid
	r.Signature = nil
	require.NoError(t, r.SignWith(store))
	require.NotEmpty(t, r.Signature)
	return r
}

// A request signed under its authority key verifies under the same key,
// and nothing covered by the signature can change afterwards: a touched
// nonce, destination, decision id or source measurement is refused as
// Integrity, as is a flipped or truncated signature.
func TestCrossCloudHandshakeRequest_SignAndVerify(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	signed := signedFixture(t, store, kid)
	require.NoError(t, signed.VerifySignature(store))
	require.NoError(t, signed.Validate())

	rows := []struct {
		name string
		edit func(r *CrossCloudHandshakeRequest)
	}{
		{"handshake nonce", func(r *CrossCloudHandshakeRequest) {
			r.HandshakeNonce = append([]byte(nil), r.HandshakeNonce...)
			r.HandshakeNonce[0] ^= 0xFF
		}},
		{"destination endpoint", func(r *CrossCloudHandshakeRequest) { r.DestinationEndpoint = "https://elsewhere.example.com:8443" }},
		{"destination tee kind", func(r *CrossCloudHandshakeRequest) {
			for _, p := range tee.AllProviders() {
				if p != r.DestinationTEEKind {
					r.DestinationTEEKind = p
					return
				}
			}
		}},
		{"decision id", func(r *CrossCloudHandshakeRequest) { r.DecisionID = "dec-0002" }},
		{"source measurement dropped", func(r *CrossCloudHandshakeRequest) { r.SourceMeasurement = nil }},
		{"signature bit", func(r *CrossCloudHandshakeRequest) {
			r.Signature = append([]byte(nil), r.Signature...)
			r.Signature[0] ^= 0x01
		}},
		{"signature truncated", func(r *CrossCloudHandshakeRequest) { r.Signature = r.Signature[:len(r.Signature)-1] }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			r := signed
			row.edit(&r)
			requireRefusal(t, r.VerifySignature(store), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
		})
	}
}

// Every shape rule of Validate is refused as Structural with its own
// code, and the same refusal closes CanonicalBytes and VerifySignature,
// which run Validate first: an invalid request has no cover-bytes and
// nothing to verify.
func TestCrossCloudHandshakeRequest_Validate_RefusalClosesCanonicalBytesAndVerify(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	rows := []struct {
		name string
		edit func(r *CrossCloudHandshakeRequest)
		code string
	}{
		{"schema above range", func(r *CrossCloudHandshakeRequest) { r.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		{"request id missing", func(r *CrossCloudHandshakeRequest) { r.RequestID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"destination tee kind missing", func(r *CrossCloudHandshakeRequest) { r.DestinationTEEKind = "" }, shared_errors.CodeRequiredFieldMissing},
		{"unknown destination tee kind", func(r *CrossCloudHandshakeRequest) { r.DestinationTEEKind = tee.Provider("abacus") }, shared_errors.CodeFieldValueInvalid},
		{"destination endpoint missing", func(r *CrossCloudHandshakeRequest) { r.DestinationEndpoint = "" }, shared_errors.CodeRequiredFieldMissing},
		{"handshake nonce short", func(r *CrossCloudHandshakeRequest) { r.HandshakeNonce = r.HandshakeNonce[:HandshakeNonceMinBytes-1] }, shared_errors.CodeFieldValueInvalid},
		{"source measurement of 31 bytes", func(r *CrossCloudHandshakeRequest) { r.SourceMeasurement = r.SourceMeasurement[:31] }, shared_errors.CodeFieldValueInvalid},
		{"initiated at missing", func(r *CrossCloudHandshakeRequest) { r.InitiatedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(r *CrossCloudHandshakeRequest) { r.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
		{"audit event id missing", func(r *CrossCloudHandshakeRequest) { r.AuditEventID = "" }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			r := validFixture()
			row.edit(&r)
			requireRefusal(t, r.Validate(), shared_errors.CategoryStructural, row.code)
			b, err := r.CanonicalBytes()
			requireRefusal(t, err, shared_errors.CategoryStructural, row.code)
			require.Nil(t, b)
			requireRefusal(t, r.VerifySignature(store), shared_errors.CategoryStructural, row.code)
		})
	}
}

// A request whose timestamp the canonical encoder cannot express has no
// cover-bytes: Validate accepts it (the time is not zero), and the
// refusal comes from the encoder, as Structural with the field code.
func TestCrossCloudHandshakeRequest_CanonicalBytes_RefusesUnencodableTimestamp(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.InitiatedAt = unencodableTime
	require.NoError(t, r.Validate())
	b, err := r.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "cross_cloud_handshake_request: canonical encode failed")
}

// SignWith refuses what it cannot sign — a nil receiver, a missing key
// id and a timestamp the canonical encoder cannot express, all as
// Structural — and passes the signer's own refusal through unchanged:
// Authority for a key the store does not hold, Integrity for the key id
// held under another purpose. The request stays unsigned in every case.
func TestCrossCloudHandshakeRequest_SignWith_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)
	auditOnly := newStore(t, kid, keys.PurposeSigningAudit)

	var nilRequest *CrossCloudHandshakeRequest
	requireRefusal(t, nilRequest.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		edit     func(r *CrossCloudHandshakeRequest)
		signer   keys.Signer
		category shared_errors.Category
		code     string
	}{
		{"signing key id missing", func(r *CrossCloudHandshakeRequest) { r.SigningKeyID = "" }, store, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"initiated at beyond the encodable range", func(r *CrossCloudHandshakeRequest) { r.InitiatedAt = unencodableTime }, store, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"key the store does not hold", func(r *CrossCloudHandshakeRequest) { r.SigningKeyID = "nobody" }, store, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"key held under the audit purpose", func(*CrossCloudHandshakeRequest) {}, auditOnly, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			r := validFixture()
			r.SigningKeyID = kid
			r.Signature = nil
			row.edit(&r)
			requireRefusal(t, r.SignWith(row.signer), row.category, row.code)
			require.Empty(t, r.Signature)
		})
	}
}

// VerifySignature refuses a nil resolver as Structural before any key is
// looked up, and passes the resolver's refusal through for a signed
// request: Authority when it does not hold the kid, Integrity when it
// holds the kid under another purpose, and Integrity with the signature
// code when it holds the same kid under a different key.
func TestCrossCloudHandshakeRequest_VerifySignature_ResolverRefusals(t *testing.T) {
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
func TestCrossCloudHandshakeRequest_UnmarshalJSON_Refusals(t *testing.T) {
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
			var r CrossCloudHandshakeRequest
			requireRefusal(t, r.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the request they came from.
	var back CrossCloudHandshakeRequest
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validFixture(), back)
}
