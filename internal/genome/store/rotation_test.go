// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/store"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// rotatingResolver resolves through whichever key store is current, the
// way a deployment whose authority key was rotated under a reused KeyID
// would: the same descriptor body, re-signed by the new key, verifies.
type rotatingResolver struct {
	mu      sync.Mutex
	current keys.Resolver
}

func (r *rotatingResolver) Resolve(kid ids.KeyID, want keys.Purpose) (keys.VerifyingKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current.Resolve(kid, want)
}

func (r *rotatingResolver) rotate(to keys.Resolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = to
}

// TestInMemoryStore_Put_ResignedDescriptorIsACollision proves the
// collision tripwire through the public API: a descriptor re-signed under
// a rotated authority key keeps its content-addressed ID but not its
// bytes, and the store refuses to rewrite the stored object — an
// Incident, with the original bytes left in place.
func TestInMemoryStore_Put_ResignedDescriptorIsACollision(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	before := newAuthorityStore(t, kid)
	after := newAuthorityStore(t, kid)
	resolver := &rotatingResolver{current: before}
	s, err := store.NewInMemoryStore(resolver)
	require.NoError(t, err)

	g1 := descriptorWithFamily(t, before, kid, "continuity-llm")
	id, err := s.Put(&g1)
	require.NoError(t, err)

	resolver.rotate(after)
	g2 := descriptorWithFamily(t, after, kid, "continuity-llm")
	require.Equal(t, g1.GenomeID, g2.GenomeID, "same body, same content-addressed ID")
	require.NotEqual(t, g1.Signature, g2.Signature, "a different key gives different bytes")
	require.NoError(t, g2.VerifySignature(resolver), "the re-signed descriptor verifies under the rotated key")

	got, err := s.Put(&g2)
	require.Error(t, err)
	require.Empty(t, got)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeTamperSignal, shared_errors.CodeOf(err))

	require.Equal(t, 1, s.Size())
	stored, err := s.Get(id)
	require.NoError(t, err)
	require.Equal(t, g1.Signature, stored.Signature, "the original object is untouched")
}
