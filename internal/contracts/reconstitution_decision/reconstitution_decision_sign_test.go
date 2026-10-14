// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstitution_decision

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

func newRecvAuthStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

func TestReconstitutionDecision_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvAuthStore(t, kid)

	r := validAcceptFixture()
	r.SigningKeyID = kid
	r.Signature = nil

	require.NoError(t, r.SignWith(store))
	require.NotEmpty(t, r.Signature)

	require.NoError(t, r.VerifySignature(store))
}

func TestReconstitutionDecision_VerifySignature_TamperedAcceptedFlagRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvAuthStore(t, kid)

	r := validAcceptFixture()
	r.SigningKeyID = kid
	r.Signature = nil
	require.NoError(t, r.SignWith(store))

	// Flip Accepted from true to false (and adjust Reason to keep
	// Validate happy). The signature was bound to Accepted=true;
	// verification must reject.
	r.Accepted = false
	r.Reason = ReasonValidationFailed
	err := r.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestReconstitutionDecision_SignWith_NilReceiver(t *testing.T) {
	t.Parallel()
	var r *ReconstitutionDecision
	err := r.SignWith(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestReconstitutionDecision_SignWith_MissingSigningKeyID(t *testing.T) {
	t.Parallel()
	store := newRecvAuthStore(t, ids.KeyID("recv-key-1"))
	r := validAcceptFixture()
	r.SigningKeyID = ""
	err := r.SignWith(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// A verifier handed no key resolver is a malformed call, refused up front
// as Structural — never a nil dereference inside the signature check.
func TestReconstitutionDecision_VerifySignature_NilResolverRefused(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("nil-resolver-key")
	store := newRecvAuthStore(t, kid)
	r := validAcceptFixture()
	r.SigningKeyID = kid
	r.Signature = nil
	require.NoError(t, r.SignWith(store))

	err := r.VerifySignature(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.NoError(t, r.VerifySignature(store))
}
