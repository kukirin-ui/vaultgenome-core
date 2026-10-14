// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"encoding/json"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Store is the read/write interface to an AGD content-addressed store.
//
// The interface is deliberately narrow: the rest of the platform depends
// on these five methods, not on any particular backing technology. A
// production deployment replaces InMemoryStore with a store that persists
// sealed bytes to disk; nothing else changes.
type Store interface {
	// Put writes g to the store after enforcing the full integrity
	// invariant chain (see package doc). Returns the content-addressed
	// GenomeID of the accepted descriptor.
	//
	// Idempotence: if g's GenomeID is already present AND the stored
	// bytes byte-equal the incoming bytes, Put is a successful no-op.
	// If the GenomeID is present but the bytes differ, Put returns an
	// Incident-classified error.
	Put(g *genome_descriptor.GenomeDescriptor) (ids.GenomeID, error)

	// Get returns a fresh copy of the descriptor stored under id. The
	// returned pointer is owned by the caller; mutating it does not
	// affect the store.
	//
	// Get re-derives the GenomeID from the loaded descriptor and fails
	// with an Integrity error if it disagrees with id — a backing-store
	// corruption tripwire.
	Get(id ids.GenomeID) (*genome_descriptor.GenomeDescriptor, error)

	// Exists is a fast O(1) presence check. It does NOT decode or
	// validate the stored bytes; callers that need guaranteed
	// loadability should Get.
	Exists(id ids.GenomeID) bool

	// Size returns the number of descriptors currently in the store.
	Size() int

	// Each invokes visit on every stored descriptor. Iteration halts
	// on the first visit that returns a non-nil error, which is then
	// returned from Each. Order is unspecified and MUST NOT be relied
	// on by callers — use an explicit cursor/list layered above.
	Each(visit func(id ids.GenomeID, g *genome_descriptor.GenomeDescriptor) error) error
}

// ---- in-memory implementation ----------------------------------------------

// InMemoryStore is the MVP Store. It holds JSON-serialized descriptor
// bytes in a map under a mutex. Production deployments replace this
// with a disk-backed store that seals its bytes under the TEE's sealing
// key.
type InMemoryStore struct {
	mu       sync.RWMutex
	entries  map[ids.GenomeID][]byte
	resolver keys.Resolver
}

// NewInMemoryStore constructs an empty store. resolver is required — the
// store uses it at Put time to verify authority signatures; it does not
// retain any private key material.
func NewInMemoryStore(resolver keys.Resolver) (*InMemoryStore, error) {
	if resolver == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"store: resolver required",
			nil,
		)
	}
	return &InMemoryStore{
		entries:  make(map[ids.GenomeID][]byte),
		resolver: resolver,
	}, nil
}

// Put implements Store.Put.
func (s *InMemoryStore) Put(g *genome_descriptor.GenomeDescriptor) (ids.GenomeID, error) {
	if g == nil {
		return "", shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"store: nil descriptor",
			nil,
		)
	}
	// Validate enforces structural invariants AND the R-14 content-
	// addressing check. A mismatch surfaces as Integrity.
	if err := g.Validate(); err != nil {
		return "", err
	}
	// Signature must verify under the Authority key — this is the
	// cryptographic authenticity gate. Validate's R-14 check alone is
	// not enough: an attacker with no key could fabricate a descriptor
	// whose ID matches its body. Signature verification prevents that.
	if err := g.VerifySignature(s.resolver); err != nil {
		return "", err
	}
	// Serialize to canonical storage bytes. encoding/json (not the
	// canonical encoder) is used so Signature round-trips with the
	// body. Any future backing store can treat these bytes as opaque.
	enc, err := json.Marshal(g)
	if err != nil {
		return "", shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"store: descriptor encode failed",
			err,
		)
	}

	id := g.GenomeID

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.entries[id]; ok {
		if bytes.Equal(existing, enc) {
			// Exact same bytes — idempotent no-op.
			return id, nil
		}
		// Same ID, different bytes. Under SHA-256 this should be
		// cryptographically impossible without a pre-image break;
		// in practice it means the caller is attempting to rewrite
		// a content-addressed object (a tamper signal).
		return "", shared_errors.Incident(
			shared_errors.CodeTamperSignal,
			"store: same GenomeID, different bytes — collision attempt",
			nil,
		)
	}
	s.entries[id] = enc
	return id, nil
}

// Get implements Store.Get.
func (s *InMemoryStore) Get(id ids.GenomeID) (*genome_descriptor.GenomeDescriptor, error) {
	if id.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"store: GenomeID required",
			nil,
		)
	}
	s.mu.RLock()
	enc, ok := s.entries[id]
	s.mu.RUnlock()
	if !ok {
		return nil, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"store: unknown GenomeID",
			nil,
		)
	}
	var g genome_descriptor.GenomeDescriptor
	if err := json.Unmarshal(enc, &g); err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			"store: descriptor decode failed — backing corruption",
			err,
		)
	}
	// Tripwire: re-derive the ID from the loaded bytes and compare
	// against the key. A mismatch means the backing store has been
	// tampered with.
	derived, err := g.DeriveID()
	if err != nil {
		return nil, err
	}
	if derived != id {
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"store: loaded descriptor's derived ID disagrees with lookup key",
			nil,
		)
	}
	return &g, nil
}

// Exists implements Store.Exists.
func (s *InMemoryStore) Exists(id ids.GenomeID) bool {
	if id.IsZero() {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.entries[id]
	return ok
}

// Size implements Store.Size.
func (s *InMemoryStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Each implements Store.Each.
func (s *InMemoryStore) Each(visit func(id ids.GenomeID, g *genome_descriptor.GenomeDescriptor) error) error {
	if visit == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"store: visit function required",
			nil,
		)
	}
	// Snapshot the key list under the read lock so we don't hold the
	// lock across arbitrary visitor logic (visitors may be slow, or
	// may themselves touch the store via other methods).
	s.mu.RLock()
	keysSnap := make([]ids.GenomeID, 0, len(s.entries))
	for k := range s.entries {
		keysSnap = append(keysSnap, k)
	}
	s.mu.RUnlock()

	for _, id := range keysSnap {
		g, err := s.Get(id)
		if err != nil {
			// A key present in the snapshot that no longer exists
			// between snapshot and Get is benign — skip. Any other
			// error is surfaced.
			if shared_errors.CategoryOf(err) == shared_errors.CategoryAuthority {
				continue
			}
			return err
		}
		if err := visit(id, g); err != nil {
			return err
		}
	}
	return nil
}

// Compile-time interface assertion.
var _ Store = (*InMemoryStore)(nil)
