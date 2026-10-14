// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// chainAuditEmitter implements kms.AuditEmitter by appending each
// emit to a chain.Chain, signed under an audit-purpose Ed25519 key.
//
// # Construction
//
// Use newChainAuditEmitter; it bundles the chain handle, the
// audit-signing keystore, and the audit-signing kid. Callers do not
// see these internals — the emitter only exposes the kms.AuditEmitter
// surface.
//
// # Audit-first-class discipline
//
// chain.Append fills PrevHash, Hash, and Signature in one transaction;
// the sealed event is durable on disk (or in memory for MVP) before
// Emit returns. This satisfies Doctrinal Invariant #8: the audit
// record exists BEFORE the caller's outward action becomes visible.
//
// EventID is generated as <prefix><monotonic counter, hex>; the prefix
// makes cross-chain correlation easy when an operator merges the
// release-side and receive-side chains in evidence bundles.
type chainAuditEmitter struct {
	chain     chain.Chain
	signer    keys.Signer
	signerKID ids.KeyID
	clock     shared_time.Clock

	mu      sync.Mutex
	counter uint64
	prefix  string
}

func newChainAuditEmitter(
	c chain.Chain,
	signer keys.Signer,
	signerKID ids.KeyID,
	clock shared_time.Clock,
	prefix string,
) (*chainAuditEmitter, error) {
	if c == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud emitter: chain required", nil)
	}
	if signer == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud emitter: signer required", nil)
	}
	if signerKID.IsZero() {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud emitter: signerKID required", nil)
	}
	if clock == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud emitter: clock required", nil)
	}
	if prefix == "" {
		prefix = "xcc-evt-"
	}
	return &chainAuditEmitter{
		chain:     c,
		signer:    signer,
		signerKID: signerKID,
		clock:     clock,
		prefix:    prefix,
	}, nil
}

// Emit builds an AuditEvent with the supplied (kind, payload,
// correlators), appends to the chain (which fills PrevHash/Hash/
// Signature), and returns the sealed event's ID.
//
// Returns an Operational error if the chain refuses the append (chain
// hash mismatch, signature failure, etc); callers MUST treat that as
// audit-first-class violation and abort their decision flow.
func (e *chainAuditEmitter) Emit(
	kind audit_event.Kind,
	payload []byte,
	sessionID ids.SessionID,
	manifestID ids.ManifestID,
	requestID ids.RequestID,
) (ids.AuditEventID, error) {
	e.mu.Lock()
	e.counter++
	counter := e.counter
	e.mu.Unlock()

	now := e.clock.Now().UTC()
	skel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(fmt.Sprintf("%s%016x", e.prefix, counter)),
		Kind:          kind,
		OccurredAt:    now,
		SessionID:     sessionID,
		ManifestID:    manifestID,
		RequestID:     requestID,
		Payload:       payload,
		SigningKeyID:  e.signerKID,
	}
	sealed, err := e.chain.Append(skel, e.signer)
	if err != nil {
		return "", err
	}
	return sealed.EventID, nil
}

// --- ID generator ---------------------------------------------------

// cryptoRandIDGenerator implements kms.IDGenerator using crypto/rand
// for fresh RequestID and DecisionID values. Each ID is a 16-byte
// random value, hex-encoded with a stable prefix so operator log
// scans are easy.
type cryptoRandIDGenerator struct {
	requestPrefix  string
	decisionPrefix string
}

func newCryptoRandIDGenerator(requestPrefix, decisionPrefix string) *cryptoRandIDGenerator {
	if requestPrefix == "" {
		requestPrefix = "xcc-req-"
	}
	if decisionPrefix == "" {
		decisionPrefix = "xcc-dec-"
	}
	return &cryptoRandIDGenerator{
		requestPrefix:  requestPrefix,
		decisionPrefix: decisionPrefix,
	}
}

func (g *cryptoRandIDGenerator) NewRequestID() (ids.RequestID, error) {
	hex16, err := freshHex(16)
	if err != nil {
		return "", shared_errors.Operational(shared_errors.CodeResourceExhausted, "crosscloud idgen: fresh request id", err)
	}
	return ids.RequestID(g.requestPrefix + hex16), nil
}

func (g *cryptoRandIDGenerator) NewDecisionID() (ids.DecisionID, error) {
	hex16, err := freshHex(16)
	if err != nil {
		return "", shared_errors.Operational(shared_errors.CodeResourceExhausted, "crosscloud idgen: fresh decision id", err)
	}
	return ids.DecisionID(g.decisionPrefix + hex16), nil
}

func freshHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// freshNonceSource returns a NonceSource backed by crypto/rand.
// Suitable for production handshake nonces.
func freshNonceSource() kms.NonceSource {
	return func(n int) ([]byte, error) {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		return b, nil
	}
}
