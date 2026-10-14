// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package release_decision

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

// newAuditOnlyStore holds kid under the audit purpose only, so a release
// decision — an authority artifact — can neither be signed nor verified
// through it.
func newAuditOnlyStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)
	return s
}

// Every shape rule of Validate, one field at a time and for both reason
// families: each defect is refused as Structural with its own code, and
// the same refusal closes CanonicalBytes and VerifySignature, which run
// Validate first.
func TestReleaseDecision_Validate_RefusesEachDefect(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("authority-signer-1")
	store := newAuthStore(t, kid)
	rows := []struct {
		name string
		base func() ReleaseDecision
		edit func(r *ReleaseDecision)
		code string
	}{
		{"schema below range", validPassFixture, func(r *ReleaseDecision) { r.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"schema above range", validPassFixture, func(r *ReleaseDecision) { r.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		{"decision id missing", validPassFixture, func(r *ReleaseDecision) { r.DecisionID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"session id missing", validPassFixture, func(r *ReleaseDecision) { r.SessionID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"manifest id missing", validPassFixture, func(r *ReleaseDecision) { r.ManifestID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"validation result id missing", validPassFixture, func(r *ReleaseDecision) { r.ValidationResultID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"decided at missing", validPassFixture, func(r *ReleaseDecision) { r.DecidedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"signing key missing", validPassFixture, func(r *ReleaseDecision) { r.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", validPassFixture, func(r *ReleaseDecision) { r.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
		{"audit event id missing", validPassFixture, func(r *ReleaseDecision) { r.AuditEventID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"trust denied citing a manifest", validTrustDeniedFixture, func(r *ReleaseDecision) { r.ManifestID = "man-0001" }, shared_errors.CodeCrossFieldInconsistent},
		{"trust denied citing a validation result", validTrustDeniedFixture, func(r *ReleaseDecision) { r.ValidationResultID = "vr-0001" }, shared_errors.CodeCrossFieldInconsistent},
		{"trust denied with decided at missing", validTrustDeniedFixture, func(r *ReleaseDecision) { r.DecidedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			r := row.base()
			row.edit(&r)
			requireRefusal(t, r.Validate(), shared_errors.CategoryStructural, row.code)
			b, err := r.CanonicalBytes()
			requireRefusal(t, err, shared_errors.CategoryStructural, row.code)
			require.Nil(t, b)
			requireRefusal(t, r.VerifySignature(store), shared_errors.CategoryStructural, row.code)
		})
	}
}

// A decision whose timestamp the canonical encoder cannot express has no
// cover-bytes: Validate accepts it (the time is not zero), and the
// refusal comes from the encoder, as Structural with the field code.
func TestReleaseDecision_CanonicalBytes_RefusesUnencodableTimestamp(t *testing.T) {
	t.Parallel()
	r := validPassFixture()
	r.DecidedAt = unencodableTime
	require.NoError(t, r.Validate())
	b, err := r.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "release_decision: canonical encode failed")
}

// SignWith refuses what it cannot sign — a nil receiver, a missing key
// id and a timestamp the canonical encoder cannot express, all as
// Structural — and passes the signer's own refusal through unchanged:
// Authority for a key the store does not hold, Integrity for the key id
// held under another purpose. The decision stays unsigned in every case.
func TestReleaseDecision_SignWith_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("authority-signer-1")
	store := newAuthStore(t, kid)
	auditOnly := newAuditOnlyStore(t, kid)

	var nilDecision *ReleaseDecision
	requireRefusal(t, nilDecision.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		edit     func(r *ReleaseDecision)
		signer   keys.Signer
		category shared_errors.Category
		code     string
	}{
		{"signing key id missing", func(r *ReleaseDecision) { r.SigningKeyID = "" }, store, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"decided at beyond the encodable range", func(r *ReleaseDecision) { r.DecidedAt = unencodableTime }, store, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"key the store does not hold", func(r *ReleaseDecision) { r.SigningKeyID = "nobody" }, store, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"key held under the audit purpose", func(*ReleaseDecision) {}, auditOnly, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			r := validPassFixture()
			r.SigningKeyID = kid
			r.Signature = nil
			row.edit(&r)
			requireRefusal(t, r.SignWith(row.signer), row.category, row.code)
			require.Empty(t, r.Signature)
		})
	}

	// The same decision signs under the key it names.
	r := validPassFixture()
	r.SigningKeyID = kid
	r.Signature = nil
	require.NoError(t, r.SignWith(store))
	require.NoError(t, r.VerifySignature(store))
}

// UnmarshalJSON refuses trailing content, an unknown field and a schema
// version outside the supported range, each as Structural with its own
// code. The trailing check is the decoder's own and is reached through
// the method: json.Unmarshal refuses trailing bytes before the method
// runs.
func TestReleaseDecision_UnmarshalJSON_Refusals(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(validPassFixture())
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
			var r ReleaseDecision
			requireRefusal(t, r.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the decision they came from.
	var back ReleaseDecision
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validPassFixture(), back)
}
