// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Chain is the append-only, hash-linked audit log abstraction.
//
// # Doctrinal role
//
// Every decision the vault emits produces an AuditEvent that is signed
// under keys.PurposeSigningAudit and chained by SHA-256(canonical-form of
// prior event). Integrity of the chain is verifiable offline: any auditor
// with the audit verifying key and a read of the events can independently
// replay the chain and detect tampering — without ever touching authority
// keys or session material.
//
// Genesis convention: the first event's PrevHash is 32 zero bytes. Empty
// chain ⇒ Tip() returns 32 zero bytes.
type Chain interface {
	// Append seals evt into the chain:
	//
	//  1. Sets evt.PrevHash = Tip().
	//  2. Zeroes evt.Hash and evt.Signature.
	//  3. Calls evt.SignWith(signer), which computes Hash and Signature.
	//  4. Runs a full static Validate() as a post-condition.
	//  5. Advances the tip.
	//
	// Returns the sealed event (with PrevHash / Hash / Signature populated).
	// Concurrent appends serialize on the chain's internal mutex.
	Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error)

	// Verify walks every event in order and checks:
	//
	//  - PrevHash of event i equals Hash of event i-1 (genesis equals zero).
	//  - Hash equals SHA-256 of canonical pre-image.
	//  - Signature verifies under SigningKeyID bound to PurposeSigningAudit.
	//
	// The first failure short-circuits with an Integrity-classified error.
	Verify(resolver keys.Resolver) error

	// Tip returns a fresh copy of the current chain tip (32 bytes). For an
	// empty chain it returns 32 zero bytes.
	Tip() []byte

	// Len returns the number of events currently in the chain.
	Len() int

	// EventAt returns a copy of the event at index idx. The second return
	// value is false if idx is out of range.
	EventAt(idx int) (audit_event.AuditEvent, bool)

	// Events returns a copy of every event in insertion order. Intended for
	// export and bulk verification; for large chains prefer streaming.
	Events() []audit_event.AuditEvent
}

// ---- in-memory chain ------------------------------------------------------

// InMemoryChain is the MVP chain. Events live in process memory; a crash
// loses state. Production wraps bbolt (or equivalent) behind the same
// interface and seals persisted state under the TEE's sealing key.
type InMemoryChain struct {
	mu     sync.RWMutex
	events []audit_event.AuditEvent
	tip    []byte // exactly audit_event.HashSize bytes
}

// NewInMemoryChain constructs an empty chain with the genesis tip
// (32 zero bytes).
func NewInMemoryChain() *InMemoryChain {
	return &InMemoryChain{
		tip: make([]byte, audit_event.HashSize),
	}
}

// Append implements Chain.
func (c *InMemoryChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	if signer == nil {
		return audit_event.AuditEvent{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"audit/chain: signer required",
			nil,
		)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	evt, err := seal(evt, c.tip, signer)
	if err != nil {
		return audit_event.AuditEvent{}, err
	}
	c.events = append(c.events, evt)
	c.tip = append([]byte(nil), evt.Hash...)
	return evt, nil
}

// seal links evt to tip and signs it: PrevHash = tip, Hash and Signature
// recomputed by SignWith, then a full static Validate as a
// post-condition — a malformed skeleton is refused, never inserted.
func seal(evt audit_event.AuditEvent, tip []byte, signer keys.Signer) (audit_event.AuditEvent, error) {
	// A fresh copy, so callers can't mutate stored events through a
	// shared backing array.
	evt.PrevHash = append([]byte(nil), tip...)
	// Clear any stale values — SignWith is the authority on Hash/Signature.
	evt.Hash = nil
	evt.Signature = nil
	if err := evt.SignWith(signer); err != nil {
		return audit_event.AuditEvent{}, err
	}
	if err := evt.Validate(); err != nil {
		return audit_event.AuditEvent{}, err
	}
	return evt, nil
}

// Verify implements Chain.
func (c *InMemoryChain) Verify(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"audit/chain: resolver required",
			nil,
		)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	return verifyEvents(c.events, resolver)
}

// verifyEvents walks events in order: each links to the previous event's
// hash (genesis: zeros) and carries a valid audit signature.
func verifyEvents(events []audit_event.AuditEvent, resolver keys.Resolver) error {
	expectedPrev := make([]byte, audit_event.HashSize) // genesis
	for i := range events {
		evt := events[i]
		if !bytes.Equal(evt.PrevHash, expectedPrev) {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("audit/chain: event #%d: prev_hash does not link to the previous event", i),
				nil,
			)
		}
		if err := evt.VerifySignature(resolver); err != nil {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("audit/chain: event #%d does not verify", i),
				err,
			)
		}
		expectedPrev = evt.Hash
	}
	return nil
}

// Tip implements Chain.
func (c *InMemoryChain) Tip() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.tip...)
}

// Len implements Chain.
func (c *InMemoryChain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.events)
}

// EventAt implements Chain.
func (c *InMemoryChain) EventAt(idx int) (audit_event.AuditEvent, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if idx < 0 || idx >= len(c.events) {
		return audit_event.AuditEvent{}, false
	}
	return cloneEvent(c.events[idx]), true
}

// Events implements Chain.
func (c *InMemoryChain) Events() []audit_event.AuditEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]audit_event.AuditEvent, len(c.events))
	for i := range c.events {
		out[i] = cloneEvent(c.events[i])
	}
	return out
}

// cloneEvent returns a deep copy of evt. The PrevHash, Hash, Signature,
// and Payload slices are copied so external mutation of the returned value
// cannot corrupt chain state.
func cloneEvent(evt audit_event.AuditEvent) audit_event.AuditEvent {
	cp := evt
	cp.PrevHash = append([]byte(nil), evt.PrevHash...)
	cp.Hash = append([]byte(nil), evt.Hash...)
	cp.Signature = append([]byte(nil), evt.Signature...)
	cp.Payload = append([]byte(nil), evt.Payload...)
	return cp
}

// Compile-time interface assertion.
var _ Chain = (*InMemoryChain)(nil)
