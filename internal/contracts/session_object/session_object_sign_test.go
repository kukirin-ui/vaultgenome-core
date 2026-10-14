// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_object

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// newSignedStore boots an InMemoryStore with a single authority signing
// key registered under kid. The fake clock keeps CreatedAt deterministic.
func newSignedStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

func TestSessionObject_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newSignedStore(t, kid)

	s := validFixture()
	s.SigningKeyID = kid
	s.Signature = nil // force SignWith to populate it

	require.NoError(t, s.SignWith(store))
	require.NotEmpty(t, s.Signature, "SignWith must populate Signature")

	require.NoError(t, s.VerifySignature(store))
}

func TestSessionObject_VerifySignature_TamperedPayloadRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newSignedStore(t, kid)

	s := validFixture()
	s.SigningKeyID = kid
	s.Signature = nil
	require.NoError(t, s.SignWith(store))

	// Flip a covered field after signing — signature must no longer verify.
	s.ExpiresAt = s.ExpiresAt.Add(time.Second)
	err := s.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestSessionObject_VerifySignature_WrongPurposeRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-audit-1")
	// Key is registered under the AUDIT purpose, but SessionObject insists
	// on PurposeSigningAuthority. Resolve must reject the cross-purpose lookup
	// as an Integrity error before Verify is ever called.
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(fc)
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)

	s := validFixture()
	s.SigningKeyID = kid
	// Signature content is irrelevant; the purpose gate fires first.
	err = s.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestSessionObject_CanonicalBytes_Deterministic(t *testing.T) {
	t.Parallel()
	// Identical inputs across independent calls must produce identical
	// cover-bytes — canonical JSON determinism is the property that makes
	// a signature verifiable on a different machine.
	s1 := validFixture()
	s2 := validFixture()
	b1, err := s1.CanonicalBytes()
	require.NoError(t, err)
	b2, err := s2.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, b1, b2)
}
