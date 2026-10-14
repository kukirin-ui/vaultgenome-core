// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_manifest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

func newRecvStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

func TestBootstrapManifest_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvStore(t, kid)

	b := validFixture()
	b.SigningKeyID = kid
	b.Signature = nil

	require.NoError(t, b.SignWith(store))
	require.NotEmpty(t, b.Signature)

	require.NoError(t, b.VerifySignature(store))
}

func TestBootstrapManifest_VerifySignature_TamperedExpectedDisclosuresRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvStore(t, kid)

	b := validFixture()
	b.SigningKeyID = kid
	b.Signature = nil
	require.NoError(t, b.SignWith(store))

	// Flip one ExpectedDisclosureID after signing. The signature was
	// bound to the original list; verification must reject.
	b.ExpectedDisclosureIDs[0] = ids.DisclosureID("disc-forged")
	err := b.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestBootstrapManifest_SignWith_NilReceiver(t *testing.T) {
	t.Parallel()
	var b *BootstrapManifest
	err := b.SignWith(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_SignWith_MissingSigningKeyID(t *testing.T) {
	t.Parallel()
	store := newRecvStore(t, ids.KeyID("recv-key-1"))
	b := validFixture()
	b.SigningKeyID = ""
	err := b.SignWith(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// A verifier handed no key resolver is a malformed call, refused up front
// as Structural — never a nil dereference inside the signature check.
func TestBootstrapManifest_VerifySignature_NilResolverRefused(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("nil-resolver-key")
	store := newRecvStore(t, kid)
	b := validFixture()
	b.SigningKeyID = kid
	b.Signature = nil
	require.NoError(t, b.SignWith(store))

	err := b.VerifySignature(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.NoError(t, b.VerifySignature(store))
}
