// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction_job_manifest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

func newAuthStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

func TestManifest_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)

	m := validFixture()
	m.SigningKeyID = kid
	m.Signature = nil

	require.NoError(t, m.SignWith(store))
	require.NotEmpty(t, m.Signature)

	require.NoError(t, m.VerifySignature(store))
}

func TestManifest_VerifySignature_TamperedDisclosureListRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)

	m := validFixture()
	m.SigningKeyID = kid
	m.Signature = nil
	require.NoError(t, m.SignWith(store))

	// Swap out a disclosure reference after signing — the op.manifest_integrity
	// check would catch this on the external-compute side via hash mismatch,
	// and the direct signature check must catch it here.
	m.DisclosureIDs = append([]ids.DisclosureID(nil), m.DisclosureIDs...)
	m.DisclosureIDs[0] = "disc-forged"
	err := m.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestManifest_VerifySignature_DeadlineTamperRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)

	m := validFixture()
	m.SigningKeyID = kid
	m.Signature = nil
	require.NoError(t, m.SignWith(store))

	// Push the deadline out to buy the adversary more time — verifier
	// must reject.
	m.Deadline = m.Deadline.Add(time.Hour)
	err := m.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// A verifier handed no key resolver is a malformed call, refused up front
// as Structural — never a nil dereference inside the signature check.
func TestManifest_VerifySignature_NilResolverRefused(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("nil-resolver-key")
	store := newAuthStore(t, kid)
	m := validFixture()
	m.SigningKeyID = kid
	m.Signature = nil
	require.NoError(t, m.SignWith(store))

	err := m.VerifySignature(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.NoError(t, m.VerifySignature(store))
}
