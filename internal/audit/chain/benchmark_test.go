// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

// Benchmarks for the audit chain's hot path: Append (which signs +
// hash-links an event) and Verify (which replays the chain).
//
// Used by the Performance Regression CI workflow to surface when an
// audit-side change measurably slows down the daemon's per-decision
// path. Audit Append runs once per release decision; if it grows
// from O(microseconds) to O(milliseconds) we want to know before
// shipping.

import (
	"bytes"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

func benchmarkAuditFixture(b *testing.B) (*InMemoryChain, keys.Signer, ids.KeyID) {
	b.Helper()
	store := keys.NewInMemoryStore(shared_time.NewSystemClock())
	kid := ids.KeyID("bench-audit-signing")
	seed := bytes.Repeat([]byte{0xC0}, crypto.Ed25519SeedSize)
	if _, err := store.RegisterSigningFromSeed(kid, keys.PurposeSigningAudit, seed); err != nil {
		b.Fatal(err)
	}
	return NewInMemoryChain(), store, kid
}

func benchmarkAuditEvent(i int, kid ids.KeyID) audit_event.AuditEvent {
	return audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID("bench-evt"),
		Kind:          audit_event.KindReleaseDecided,
		OccurredAt:    time.Unix(0, int64(i)*1_000_000),
		SessionID:     ids.SessionID("bench-sess"),
		ManifestID:    ids.ManifestID("bench-man"),
		Payload:       []byte(`{"i":0}`),
		SigningKeyID:  kid,
	}
}

// BenchmarkChain_Append — measures the per-event Append cost
// (canonical-form serialise + SHA-256 + Ed25519 sign + chain link).
func BenchmarkChain_Append(b *testing.B) {
	c, signer, kid := benchmarkAuditFixture(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evt := benchmarkAuditEvent(i, kid)
		if _, err := c.Append(evt, signer); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkChain_Verify_100 — measures Verify cost over a 100-event
// chain. Operators run this on every restart (Phase 2) and on every
// `acpctl audit verify` invocation; latency matters when the chain
// grows.
func BenchmarkChain_Verify_100(b *testing.B) {
	c, signer, kid := benchmarkAuditFixture(b)
	for i := 0; i < 100; i++ {
		if _, err := c.Append(benchmarkAuditEvent(i, kid), signer); err != nil {
			b.Fatal(err)
		}
	}
	resolver := signer.(*keys.InMemoryStore)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.Verify(resolver); err != nil {
			b.Fatal(err)
		}
	}
}
