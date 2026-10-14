// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

func newAuditStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)
	return s
}

// skeleton returns a pre-sign AuditEvent template — PrevHash, Hash, and
// Signature are left to the chain / SignWith to populate. EventID is a
// parameter so tests can insert multiple distinct events.
func skeleton(eventID string, kid ids.KeyID) audit_event.AuditEvent {
	return audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(eventID),
		Kind:          audit_event.KindRequestReceived,
		OccurredAt:    time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SessionID:     ids.SessionID("sess-0001"),
		RequestID:     ids.RequestID("req-0001"),
		Payload:       []byte(`{"note":"` + eventID + `"}`),
		SigningKeyID:  kid,
	}
}

func TestInMemoryChain_Genesis(t *testing.T) {
	t.Parallel()
	c := NewInMemoryChain()
	require.Equal(t, 0, c.Len())
	require.Equal(t, bytes.Repeat([]byte{0x00}, audit_event.HashSize), c.Tip())
}

func TestInMemoryChain_AppendAndVerify(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)
	c := NewInMemoryChain()

	first, err := c.Append(skeleton("evt-1", kid), store)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0x00}, audit_event.HashSize), first.PrevHash,
		"genesis event PrevHash must be zero")
	require.Len(t, first.Hash, audit_event.HashSize)
	require.NotEmpty(t, first.Signature)
	require.Equal(t, 1, c.Len())
	require.Equal(t, first.Hash, c.Tip())

	// Second event links to the first.
	second, err := c.Append(skeleton("evt-2", kid), store)
	require.NoError(t, err)
	require.Equal(t, first.Hash, second.PrevHash)
	require.NotEqual(t, first.Hash, second.Hash)
	require.Equal(t, 2, c.Len())
	require.Equal(t, second.Hash, c.Tip())

	// Third event, just to exercise a longer chain.
	third, err := c.Append(skeleton("evt-3", kid), store)
	require.NoError(t, err)
	require.Equal(t, second.Hash, third.PrevHash)
	require.Equal(t, 3, c.Len())

	// Full chain must verify.
	require.NoError(t, c.Verify(store))

	// Spot-check EventAt and Events.
	e0, ok := c.EventAt(0)
	require.True(t, ok)
	require.Equal(t, first.EventID, e0.EventID)

	_, ok = c.EventAt(99)
	require.False(t, ok)

	all := c.Events()
	require.Len(t, all, 3)
}

func TestInMemoryChain_Verify_TamperedEventRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)
	c := NewInMemoryChain()

	_, err := c.Append(skeleton("evt-1", kid), store)
	require.NoError(t, err)
	_, err = c.Append(skeleton("evt-2", kid), store)
	require.NoError(t, err)

	// Reach into the chain and mutate the first event's payload.
	c.events[0].Payload = []byte(`{"note":"forged"}`)

	err = c.Verify(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestInMemoryChain_Verify_BrokenLinkRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)
	c := NewInMemoryChain()

	_, err := c.Append(skeleton("evt-1", kid), store)
	require.NoError(t, err)
	_, err = c.Append(skeleton("evt-2", kid), store)
	require.NoError(t, err)

	// Replace the second event's PrevHash with random bytes — the chain
	// no longer links, even if the signature over that (wrong) pre-image
	// would be internally consistent.
	c.events[1].PrevHash = bytes.Repeat([]byte{0xEE}, audit_event.HashSize)

	err = c.Verify(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestInMemoryChain_Verify_WrongPurposeKeyRejected(t *testing.T) {
	t.Parallel()
	// Chain is built against the audit-purpose store. Verification against
	// a store that registers the same KID under authority purpose must fail.
	kid := ids.KeyID("audit-key-1")
	auditStore := newAuditStore(t, kid)
	c := NewInMemoryChain()
	_, err := c.Append(skeleton("evt-1", kid), auditStore)
	require.NoError(t, err)

	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	wrongStore := keys.NewInMemoryStore(fc)
	_, err = wrongStore.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	err = c.Verify(wrongStore)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestInMemoryChain_Events_AreDefensiveCopies(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	store := newAuditStore(t, kid)
	c := NewInMemoryChain()

	_, err := c.Append(skeleton("evt-1", kid), store)
	require.NoError(t, err)

	snap := c.Events()
	require.Len(t, snap, 1)

	// Mutate the copy — the chain must not be affected.
	snap[0].Payload[0] = 'X'
	snap[0].Hash[0] ^= 0xFF

	// Chain still verifies because internal state wasn't touched.
	require.NoError(t, c.Verify(store))
}

func TestInMemoryChain_Append_NilSigner(t *testing.T) {
	t.Parallel()
	c := NewInMemoryChain()
	kid := ids.KeyID("audit-key-1")
	_, err := c.Append(skeleton("evt-1", kid), nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestInMemoryChain_Verify_NilResolver(t *testing.T) {
	t.Parallel()
	c := NewInMemoryChain()
	err := c.Verify(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}
