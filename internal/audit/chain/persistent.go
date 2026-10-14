// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

import (
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Persister is where a PersistentChain keeps its events, in order.
// store.BBoltStore implements it.
type Persister interface {
	Append(evt audit_event.AuditEvent) error
	Load() ([]audit_event.AuditEvent, error)
}

// PersistentChain is a Chain whose events survive the process: an event
// is durably persisted before Append returns it, and a chain reopened
// later continues where it stopped.
//
// Opening verifies the whole stored chain first — every hash link and
// every signature — and refuses a log that was edited, reordered,
// spliced, or signed by another key. What a chain cannot detect by
// itself is its tail being cut off; compare Tip() against a value
// recorded elsewhere (the crosscloud-restore report prints it) to catch
// that.
type PersistentChain struct {
	mu     sync.RWMutex
	store  Persister
	events []audit_event.AuditEvent
	tip    []byte
}

// OpenPersistentChain loads every event from store and verifies the chain
// under resolver before accepting appends.
func OpenPersistentChain(store Persister, resolver keys.Resolver) (*PersistentChain, error) {
	if store == nil || resolver == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
			"audit/chain: persistent chain needs a store and a resolver", nil)
	}
	events, err := store.Load()
	if err != nil {
		return nil, err
	}
	if err := verifyEvents(events, resolver); err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
			"audit/chain: the stored audit log does not verify; refusing to extend it", err)
	}
	tip := make([]byte, audit_event.HashSize)
	if len(events) > 0 {
		tip = append([]byte(nil), events[len(events)-1].Hash...)
	}
	return &PersistentChain{store: store, events: events, tip: tip}, nil
}

// Append seals evt against the current tip and persists it; only then
// does the chain advance. If persisting fails, nothing changes and the
// caller must treat the decision the event describes as not taken.
func (c *PersistentChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	if signer == nil {
		return audit_event.AuditEvent{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing, "audit/chain: signer required", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	sealed, err := seal(evt, c.tip, signer)
	if err != nil {
		return audit_event.AuditEvent{}, err
	}
	if err := c.store.Append(sealed); err != nil {
		return audit_event.AuditEvent{}, shared_errors.Operational(shared_errors.CodeResourceExhausted,
			"audit/chain: persisting the event failed; the chain did not advance", err)
	}
	c.events = append(c.events, sealed)
	c.tip = append([]byte(nil), sealed.Hash...)
	return cloneEvent(sealed), nil
}

// Verify implements Chain.
func (c *PersistentChain) Verify(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit/chain: resolver required", nil)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return verifyEvents(c.events, resolver)
}

// Tip implements Chain.
func (c *PersistentChain) Tip() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.tip...)
}

// Len implements Chain.
func (c *PersistentChain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.events)
}

// EventAt implements Chain.
func (c *PersistentChain) EventAt(idx int) (audit_event.AuditEvent, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if idx < 0 || idx >= len(c.events) {
		return audit_event.AuditEvent{}, false
	}
	return cloneEvent(c.events[idx]), true
}

// Events implements Chain.
func (c *PersistentChain) Events() []audit_event.AuditEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]audit_event.AuditEvent, len(c.events))
	for i := range c.events {
		out[i] = cloneEvent(c.events[i])
	}
	return out
}

var _ Chain = (*PersistentChain)(nil)
