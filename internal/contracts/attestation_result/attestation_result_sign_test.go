// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package attestation_result

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

func TestAttestationResult_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("trust-key-1")
	store := newAuthStore(t, kid)

	a := validAllow()
	a.SigningKeyID = kid
	a.Signature = nil

	require.NoError(t, a.SignWith(store))
	require.NotEmpty(t, a.Signature)

	require.NoError(t, a.VerifySignature(store))
}

func TestAttestationResult_VerifySignature_TamperedOutcomeRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("trust-key-1")
	store := newAuthStore(t, kid)

	a := validAllow()
	a.SigningKeyID = kid
	a.Signature = nil
	require.NoError(t, a.SignWith(store))

	// An allow becomes a deny after signing — the verifier must reject it.
	a.Outcome = OutcomeDeny
	a.Reason = "trust.peer_unknown"
	err := a.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}
