// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package received_disclosure

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Every shape rule of Validate, one field at a time.
func TestReceivedDisclosure_Validate_EveryRule(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		mutate func(*ReceivedDisclosure)
		code   string
	}{
		"schema_version above range": {func(r *ReceivedDisclosure) { r.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		"received_id":                {func(r *ReceivedDisclosure) { r.ReceivedID = "" }, shared_errors.CodeRequiredFieldMissing},
		"session_id":                 {func(r *ReceivedDisclosure) { r.SessionID = "" }, shared_errors.CodeRequiredFieldMissing},
		"disclosure_id":              {func(r *ReceivedDisclosure) { r.DisclosureID = "" }, shared_errors.CodeRequiredFieldMissing},
		"component_id":               {func(r *ReceivedDisclosure) { r.ComponentID = "" }, shared_errors.CodeRequiredFieldMissing},
		"received_at":                {func(r *ReceivedDisclosure) { r.ReceivedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		"signing_key_id":             {func(r *ReceivedDisclosure) { r.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		"signature":                  {func(r *ReceivedDisclosure) { r.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := validFixture()
			tc.mutate(&r)
			err := r.Validate()
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err), "%v", err)
			require.ErrorContains(t, err, "received_disclosure:")
		})
	}
}

// VerifySignature refuses what it cannot check: no resolver, a receipt
// that fails its own shape rules, a key the resolver does not hold.
func TestReceivedDisclosure_VerifySignature_RefusesWhatItCannotCheck(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-signer-1")
	store := newRecvStore(t, kid)
	r := validFixture()
	r.SigningKeyID = kid
	require.NoError(t, r.SignWith(store))

	err := r.VerifySignature(nil)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))

	malformed := r
	malformed.WireHash = nil
	err = malformed.VerifySignature(store)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err), "%v", err)

	stranger := newRecvStore(t, ids.KeyID("someone-else"))
	require.Error(t, r.VerifySignature(stranger), "a resolver without the key cannot vouch for the signature")

	other := newRecvStore(t, kid)
	require.Error(t, r.VerifySignature(other), "the same key id under another key is not the signer")
	_ = keys.PurposeSigningAuthority
}
