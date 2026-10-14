// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package received_disclosure

import (
	"bytes"
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

func TestReceivedDisclosure_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvStore(t, kid)

	r := validFixture()
	r.SigningKeyID = kid
	r.Signature = nil

	require.NoError(t, r.SignWith(store))
	require.NotEmpty(t, r.Signature)

	require.NoError(t, r.VerifySignature(store))
}

func TestReceivedDisclosure_VerifySignature_TamperedWireHashRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvStore(t, kid)

	r := validFixture()
	r.SigningKeyID = kid
	r.Signature = nil
	require.NoError(t, r.SignWith(store))

	// Flip the wire hash. The signature was bound to the original
	// hash; verification must reject.
	r.WireHash = bytes.Repeat([]byte{0xCD}, WireHashSize)
	err := r.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestReceivedDisclosure_SignWith_NilReceiver(t *testing.T) {
	t.Parallel()
	var r *ReceivedDisclosure
	err := r.SignWith(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestReceivedDisclosure_SignWith_MissingSigningKeyID(t *testing.T) {
	t.Parallel()
	store := newRecvStore(t, ids.KeyID("recv-key-1"))
	r := validFixture()
	r.SigningKeyID = ""
	err := r.SignWith(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}
