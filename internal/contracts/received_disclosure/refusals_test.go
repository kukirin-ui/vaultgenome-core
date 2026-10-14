// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package received_disclosure

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

// newWitnessOnlyStore holds kid under the witness purpose only, so a
// receive-side record — signed under the authority purpose — can neither
// be signed nor verified through it.
func newWitnessOnlyStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)
	return s
}

// A record whose timestamp the canonical encoder cannot express has no
// cover-bytes: Validate accepts it (the time is not zero), and the
// refusal comes from the encoder, as Structural with the field code.
func TestReceivedDisclosure_CanonicalBytes_RefusesUnencodableTimestamp(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.ReceivedAt = unencodableTime
	require.NoError(t, r.Validate())
	b, err := r.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "received_disclosure: canonical encode failed")
}

// SignWith refuses what it cannot sign — a nil receiver, a missing key
// id and a timestamp the canonical encoder cannot express, all as
// Structural — and passes the signer's own refusal through unchanged:
// Authority for a key the store does not hold, Integrity for the key id
// held under another purpose. The record stays unsigned in every case.
func TestReceivedDisclosure_SignWith_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvStore(t, kid)
	witnessOnly := newWitnessOnlyStore(t, kid)

	var nilRecord *ReceivedDisclosure
	requireRefusal(t, nilRecord.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		edit     func(r *ReceivedDisclosure)
		signer   keys.Signer
		category shared_errors.Category
		code     string
	}{
		{"signing key id missing", func(r *ReceivedDisclosure) { r.SigningKeyID = "" }, store, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"received at beyond the encodable range", func(r *ReceivedDisclosure) { r.ReceivedAt = unencodableTime }, store, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"key the store does not hold", func(r *ReceivedDisclosure) { r.SigningKeyID = "nobody" }, store, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"key held under the witness purpose", func(*ReceivedDisclosure) {}, witnessOnly, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
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

	// The same record signs under the key it names.
	r := validFixture()
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
func TestReceivedDisclosure_UnmarshalJSON_Refusals(t *testing.T) {
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
			var r ReceivedDisclosure
			requireRefusal(t, r.UnmarshalJSON([]byte(row.payload)), shared_errors.CategoryStructural, row.code)
		})
	}

	// The same bytes without the defect decode to the record they came from.
	var back ReceivedDisclosure
	require.NoError(t, back.UnmarshalJSON(raw))
	require.Equal(t, validFixture(), back)
}
