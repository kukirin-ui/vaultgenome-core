// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_event

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// newAuditStore registers a single audit-signing key and returns the store.
func newAuditStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)
	return s
}

// unsignedFixture is a valid AuditEvent except for Hash and Signature —
// those are what SignWith is about to produce.
func unsignedFixture() AuditEvent {
	prev := bytes.Repeat([]byte{0x00}, HashSize)
	return AuditEvent{
		SchemaVersion: SchemaVersionCurrent,
		EventID:       ids.AuditEventID("evt-0001"),
		Kind:          KindRequestReceived,
		OccurredAt:    time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SessionID:     ids.SessionID("sess-0001"),
		RequestID:     ids.RequestID("req-0001"),
		Payload:       []byte(`{"note":"entry point"}`),
		PrevHash:      prev,
		SigningKeyID:  ids.KeyID("audit-key-1"),
	}
}

func TestAuditEvent_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)

	e := unsignedFixture()
	require.Empty(t, e.Hash)
	require.Empty(t, e.Signature)

	require.NoError(t, e.SignWith(store))

	// SignWith populates both Hash and Signature.
	require.Len(t, e.Hash, HashSize, "SignWith must populate a full 32-byte hash")
	require.NotEmpty(t, e.Signature, "SignWith must populate Signature")

	// Re-derive the pre-image the same way SignWith does and confirm Hash
	// is SHA-256 of it.
	cp := e
	cp.Hash = nil
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	require.NoError(t, err)
	h := crypto.SHA256(cb)
	require.Equal(t, h[:], e.Hash, "Hash must equal SHA-256 of canonical bytes")

	// Full signature verification goes through the resolver.
	require.NoError(t, e.VerifySignature(store))
}

func TestAuditEvent_VerifySignature_TamperedHashRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)

	e := unsignedFixture()
	require.NoError(t, e.SignWith(store))

	// Flip a bit of Hash — re-derivation will disagree with the stored Hash.
	e.Hash[0] ^= 0x01
	err := e.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestAuditEvent_VerifySignature_TamperedPayloadRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)

	e := unsignedFixture()
	require.NoError(t, e.SignWith(store))

	// Mutate a covered field — Hash no longer matches canonical bytes.
	e.Payload = []byte(`{"note":"forged"}`)
	err := e.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestAuditEvent_VerifySignature_WrongPurposeRejected(t *testing.T) {
	t.Parallel()
	// Sign in the correct AUDIT-purpose store, then verify through a
	// different store that has the same KID registered under AUTHORITY.
	// The Resolver-side purpose gate must reject the lookup even though the
	// stored Hash and Signature are internally consistent.
	kid := ids.KeyID("audit-key-1")
	signStore := newAuditStore(t, kid)

	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	verifyStore := keys.NewInMemoryStore(fc)
	_, err := verifyStore.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	e := unsignedFixture()
	require.NoError(t, e.SignWith(signStore))

	err = e.VerifySignature(verifyStore)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}
