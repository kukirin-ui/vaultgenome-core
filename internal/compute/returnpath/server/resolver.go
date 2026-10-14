// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"sync"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// PublicKeyResolver is a read-only keys.Resolver backed by a static
// map of KeyID → VerifyingKey. The vault side uses it to register
// worker public keys that were exchanged out-of-band (in Phase 1 via
// operator config; in Phase 3 via a TEE attestation appraisal policy
// that binds worker pubkeys to measurements).
//
// The type exists because vault/keys.InMemoryStore is write-generating
// — its GenerateSigning produces a fresh key pair under a caller-
// supplied KeyID and owns the private half. The vault has no private
// half for a worker's key; it only needs the public half to Verify.
// PublicKeyResolver fills exactly that gap without duplicating any of
// InMemoryStore's private-key machinery.
//
// Safe for concurrent use (read-only after construction, but Register
// is mutex-guarded so callers can extend the map at runtime).
type PublicKeyResolver struct {
	mu      sync.RWMutex
	entries map[ids.KeyID]keys.VerifyingKey
}

// NewPublicKeyResolver constructs a resolver seeded with the given
// entries. A nil entries map is accepted; callers can then Register at
// runtime. The resolver does not validate purposes on insertion — that
// is the caller's responsibility — but it DOES validate purpose on
// Resolve, matching vault/keys.InMemoryStore semantics exactly.
func NewPublicKeyResolver(entries map[ids.KeyID]keys.VerifyingKey) *PublicKeyResolver {
	r := &PublicKeyResolver{entries: make(map[ids.KeyID]keys.VerifyingKey, len(entries))}
	for k, v := range entries {
		r.entries[k] = v
	}
	return r
}

// Register adds or overwrites one entry. Returns a Structural error if
// kid is zero or vk.PublicKey is nil.
func (r *PublicKeyResolver) Register(kid ids.KeyID, vk keys.VerifyingKey) error {
	if kid.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/server: PublicKeyResolver.Register called with zero KeyID", nil)
	}
	if vk.PublicKey == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/server: PublicKeyResolver.Register called with nil PublicKey", nil)
	}
	r.mu.Lock()
	r.entries[kid] = vk
	r.mu.Unlock()
	return nil
}

// Resolve implements keys.Resolver.
func (r *PublicKeyResolver) Resolve(kid ids.KeyID, want keys.Purpose) (keys.VerifyingKey, error) {
	r.mu.RLock()
	vk, ok := r.entries[kid]
	r.mu.RUnlock()
	if !ok {
		return keys.VerifyingKey{}, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/server: unknown worker kid on Resolve", nil)
	}
	if vk.Purpose != want {
		return keys.VerifyingKey{}, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"returnpath/server: purpose mismatch on PublicKeyResolver.Resolve", nil)
	}
	return vk, nil
}

// Compile-time interface assertion.
var _ keys.Resolver = (*PublicKeyResolver)(nil)
