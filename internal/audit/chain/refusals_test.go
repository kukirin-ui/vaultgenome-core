// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// sealRefusal is one skeleton the chain must refuse to seal: either the
// signer cannot sign it, or the signed event fails the static
// post-condition. Both chain kinds share the seal step, so both are held
// to the same table.
type sealRefusal struct {
	name     string
	mutate   func(e *audit_event.AuditEvent)
	category shared_errors.Category
	code     string
}

func sealRefusals() []sealRefusal {
	return []sealRefusal{
		{
			name:     "no signing key id",
			mutate:   func(e *audit_event.AuditEvent) { e.SigningKeyID = "" },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeRequiredFieldMissing,
		},
		{
			name:     "key registered for another purpose",
			mutate:   func(e *audit_event.AuditEvent) { e.SigningKeyID = "witness-key" },
			category: shared_errors.CategoryIntegrity,
			code:     shared_errors.CodeFieldValueInvalid,
		},
		{
			name:     "unknown key id",
			mutate:   func(e *audit_event.AuditEvent) { e.SigningKeyID = "never-registered" },
			category: shared_errors.CategoryAuthority,
			code:     shared_errors.CodeRequiredFieldMissing,
		},
		{
			name:     "empty payload",
			mutate:   func(e *audit_event.AuditEvent) { e.Payload = nil },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeRequiredFieldMissing,
		},
		{
			name:     "unknown kind",
			mutate:   func(e *audit_event.AuditEvent) { e.Kind = "NOT_A_KIND" },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeFieldValueInvalid,
		},
		{
			name:     "zero occurred_at",
			mutate:   func(e *audit_event.AuditEvent) { e.OccurredAt = time.Time{} },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeRequiredFieldMissing,
		},
		{
			name:     "missing event id",
			mutate:   func(e *audit_event.AuditEvent) { e.EventID = "" },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeRequiredFieldMissing,
		},
		{
			name:     "unsupported schema version",
			mutate:   func(e *audit_event.AuditEvent) { e.SchemaVersion = audit_event.SchemaVersionMax + 1 },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeSchemaVersionUnsupported,
		},
	}
}

// signerWithStrayKey returns an audit key store that also holds a key
// registered for witness signing, so a purpose mismatch can be provoked.
func signerWithStrayKey(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	s := newAuditStore(t, kid)
	_, err := s.GenerateSigning("witness-key", keys.PurposeSigningWitness)
	require.NoError(t, err)
	return s
}

// TestInMemoryChain_Append_RefusesWhatItCannotSeal proves that a skeleton
// the signer refuses, or one that fails the static post-condition after
// signing, is never inserted: the error carries the contract's category
// and code, and the chain's length and tip do not move.
func TestInMemoryChain_Append_RefusesWhatItCannotSeal(t *testing.T) {
	t.Parallel()
	for _, tc := range sealRefusals() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kid := ids.KeyID("audit-key-1")
			signer := signerWithStrayKey(t, kid)
			c := NewInMemoryChain()
			first, err := c.Append(skeleton("evt-ok", kid), signer)
			require.NoError(t, err)

			bad := skeleton("evt-bad", kid)
			tc.mutate(&bad)
			sealed, err := c.Append(bad, signer)
			require.Error(t, err)
			require.Equal(t, audit_event.AuditEvent{}, sealed)
			require.Equal(t, tc.category, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))

			require.Equal(t, 1, c.Len())
			require.Equal(t, first.Hash, c.Tip())
			require.NoError(t, c.Verify(signer))
		})
	}
}

// TestPersistentChain_Append_RefusesWhatItCannotSeal proves the same for
// the persistent chain, and additionally that a refused event never
// reaches the persister.
func TestPersistentChain_Append_RefusesWhatItCannotSeal(t *testing.T) {
	t.Parallel()
	for _, tc := range sealRefusals() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kid := ids.KeyID("audit-key-1")
			signer := signerWithStrayKey(t, kid)
			p := &memPersister{}
			c, err := OpenPersistentChain(p, signer)
			require.NoError(t, err)
			first, err := c.Append(skeleton("evt-ok", kid), signer)
			require.NoError(t, err)

			bad := skeleton("evt-bad", kid)
			tc.mutate(&bad)
			sealed, err := c.Append(bad, signer)
			require.Error(t, err)
			require.Equal(t, audit_event.AuditEvent{}, sealed)
			require.Equal(t, tc.category, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))

			require.Equal(t, 1, c.Len())
			require.Equal(t, first.Hash, c.Tip())
			require.Len(t, p.events, 1, "a refused event is never persisted")
		})
	}
}

// loadFailingPersister is a Persister whose log cannot be read.
type loadFailingPersister struct{}

func (loadFailingPersister) Append(audit_event.AuditEvent) error { return nil }

func (loadFailingPersister) Load() ([]audit_event.AuditEvent, error) {
	return nil, errors.New("log unreadable")
}

// TestOpenPersistentChain_LoadFailureSurfaces proves that a log that
// cannot be read is not silently treated as empty: the store's error is
// returned and no chain is handed out.
func TestOpenPersistentChain_LoadFailureSurfaces(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	c, err := OpenPersistentChain(loadFailingPersister{}, newAuditStore(t, kid))
	require.Nil(t, c)
	require.EqualError(t, err, "log unreadable")
}

// TestPersistentChain_Verify_NilResolver proves the persistent chain
// refuses to verify without a resolver, as the in-memory chain does.
func TestPersistentChain_Verify_NilResolver(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	c, err := OpenPersistentChain(&memPersister{}, newAuditStore(t, kid))
	require.NoError(t, err)
	err = c.Verify(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// TestPersistentChain_EventAtAndEvents proves the persistent chain's read
// side: EventAt answers only in-range indexes, Events returns every event
// in insertion order, and what either hands out is a copy — mutating it
// does not touch the chain or what Verify sees.
func TestPersistentChain_EventAtAndEvents(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	signer := newAuditStore(t, kid)
	c, err := OpenPersistentChain(&memPersister{}, signer)
	require.NoError(t, err)
	var sealed []audit_event.AuditEvent
	for _, id := range []string{"evt-1", "evt-2", "evt-3"} {
		e, err := c.Append(skeleton(id, kid), signer)
		require.NoError(t, err)
		sealed = append(sealed, e)
	}

	for _, idx := range []int{-1, 3, 42} {
		_, ok := c.EventAt(idx)
		require.Falsef(t, ok, "index %d must be out of range", idx)
	}
	got, ok := c.EventAt(1)
	require.True(t, ok)
	require.Equal(t, sealed[1], got)
	got.Payload[0] = 'X'
	got.Hash[0] ^= 0xff
	again, ok := c.EventAt(1)
	require.True(t, ok)
	require.Equal(t, sealed[1], again, "EventAt hands out a copy")

	all := c.Events()
	require.Equal(t, sealed, all)
	all[0].Signature[0] ^= 0xff
	all[2].PrevHash[0] ^= 0xff
	require.Equal(t, sealed, c.Events(), "Events hands out copies")
	require.NoError(t, c.Verify(signer))
}
