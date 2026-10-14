// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// workerKey generates a worker signing key and returns its public half.
func workerKey(t *testing.T, kid ids.KeyID, purpose keys.Purpose) keys.VerifyingKey {
	t.Helper()
	store := keys.NewInMemoryStore(shared_time.NewFakeClock(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)))
	vk, err := store.GenerateSigning(kid, purpose)
	require.NoError(t, err)
	return vk
}

// TestPublicKeyResolver_SeededEntriesResolve proves keys handed to the
// constructor resolve under their purpose, and that the seed map is
// copied rather than shared with the caller.
func TestPublicKeyResolver_SeededEntriesResolve(t *testing.T) {
	t.Parallel()
	vk := workerKey(t, "worker-1", keys.PurposeSigningAuthority)
	seed := map[ids.KeyID]keys.VerifyingKey{"worker-1": vk}
	r := NewPublicKeyResolver(seed)

	got, err := r.Resolve("worker-1", keys.PurposeSigningAuthority)
	require.NoError(t, err)
	require.Equal(t, vk.PublicKey, got.PublicKey)

	delete(seed, "worker-1")
	_, err = r.Resolve("worker-1", keys.PurposeSigningAuthority)
	require.NoError(t, err, "the resolver owns its own copy of the seed map")
}

// TestPublicKeyResolver_RegisterRefusals proves Register insists on a
// key ID and a public key, and that a successful Register overwrites
// an earlier entry under the same ID.
func TestPublicKeyResolver_RegisterRefusals(t *testing.T) {
	t.Parallel()
	vk := workerKey(t, "worker-1", keys.PurposeSigningAuthority)
	r := NewPublicKeyResolver(nil)

	cases := []struct {
		name string
		kid  ids.KeyID
		vk   keys.VerifyingKey
		want string
	}{
		{"zero key id", "", vk, "zero KeyID"},
		{"nil public key", "worker-1", keys.VerifyingKey{Purpose: keys.PurposeSigningAuthority}, "nil PublicKey"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := r.Register(tc.kid, tc.vk)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), tc.want)
		})
	}

	require.NoError(t, r.Register("worker-1", vk))
	replacement := workerKey(t, "worker-1", keys.PurposeSigningAuthority)
	require.NoError(t, r.Register("worker-1", replacement))
	got, err := r.Resolve("worker-1", keys.PurposeSigningAuthority)
	require.NoError(t, err)
	require.Equal(t, replacement.PublicKey, got.PublicKey, "a later Register replaces the entry")
}

// TestPublicKeyResolver_ResolveRefusals proves an unknown ID is an
// authority refusal and a purpose mismatch an integrity one, matching
// the in-memory keystore's classification.
func TestPublicKeyResolver_ResolveRefusals(t *testing.T) {
	t.Parallel()
	r := NewPublicKeyResolver(map[ids.KeyID]keys.VerifyingKey{
		"worker-1": workerKey(t, "worker-1", keys.PurposeSigningAuthority),
	})
	cases := []struct {
		name     string
		kid      ids.KeyID
		want     keys.Purpose
		wantCat  shared_errors.Category
		wantCode string
	}{
		{"unknown key id", "worker-9", keys.PurposeSigningAuthority, shared_errors.CategoryAuthority, shared_errors.CodeRequiredFieldMissing},
		{"purpose mismatch", "worker-1", keys.PurposeSigningAudit, shared_errors.CategoryIntegrity, shared_errors.CodeFieldValueInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			vk, err := r.Resolve(tc.kid, tc.want)
			require.Error(t, err)
			require.Nil(t, vk.PublicKey)
			require.Equal(t, tc.wantCat, shared_errors.CategoryOf(err))
			require.Equal(t, tc.wantCode, shared_errors.CodeOf(err))
		})
	}
}
