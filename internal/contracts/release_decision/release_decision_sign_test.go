// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package release_decision

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

func TestReleaseDecision_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)

	r := validPassFixture()
	r.SigningKeyID = kid
	r.Signature = nil

	require.NoError(t, r.SignWith(store))
	require.NotEmpty(t, r.Signature)

	require.NoError(t, r.VerifySignature(store))
}

func TestReleaseDecision_VerifySignature_TamperedReleaseFlagRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)

	r := validPassFixture()
	r.SigningKeyID = kid
	r.Signature = nil
	require.NoError(t, r.SignWith(store))

	// Flipping Release from true to false (and adjusting Reason to keep
	// Validate happy) must NOT verify — the original signature was bound
	// to Release=true.
	r.Release = false
	r.Reason = ReasonValidationFail
	err := r.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}
