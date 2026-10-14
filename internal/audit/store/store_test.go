// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store_test

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// E2E tests for /internal/audit/store.
//
// The bbolt-backed store is the evidence substrate the audit chain
// depends on. These tests pin the three properties the chain layer
// relies on:
//
//   1. Round-trip: what goes in comes back byte-identical.
//   2. Crash + re-open survivorship: closing and re-opening the store
//      preserves insertion order and all events.
//   3. Concurrent-append ordering: NextSequence guarantees monotonic
//      keys even across process restarts.
//
// Tests use t.TempDir() so the bbolt file is wiped automatically on
// test completion. No process-wide state persists between tests.

// sampleEvent constructs a deterministic AuditEvent for persistence
// testing. The returned event is NOT signed — the store is content-
// neutral and stores whatever bytes it is handed. SignWith / Chain
// integration is tested in /internal/audit/chain.
func sampleEvent(i int) audit_event.AuditEvent {
	return audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(fmt.Sprintf("evt-persist-%04d", i)),
		Kind:          audit_event.KindRequestReceived,
		OccurredAt:    time.Date(2026, 4, 20, 10, 0, i, 0, time.UTC),
		SessionID:     ids.SessionID(fmt.Sprintf("sess-%04d", i)),
		RequestID:     ids.RequestID(fmt.Sprintf("req-%04d", i)),
		Payload:       fmt.Appendf(nil, `{"i":%d}`, i),
		PrevHash:      bytes.Repeat([]byte{byte(i)}, audit_event.HashSize),
		Hash:          bytes.Repeat([]byte{byte(i + 1)}, audit_event.HashSize),
		SigningKeyID:  ids.KeyID("audit-key-1"),
		Signature:     bytes.Repeat([]byte{byte(i + 2)}, 64),
	}
}

func TestBBoltStore_OpenEmptyAndClose(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")

	s, err := store.Open(path)
	require.NoError(t, err)

	n, err := s.Len()
	require.NoError(t, err)
	require.Equal(t, 0, n)

	events, err := s.Load()
	require.NoError(t, err)
	require.Empty(t, events)

	require.NoError(t, s.Close())
	// Second Close is a no-op.
	require.NoError(t, s.Close())
}

func TestBBoltStore_AppendAndLoadRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")

	s, err := store.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	const n = 10
	originals := make([]audit_event.AuditEvent, n)
	for i := 0; i < n; i++ {
		originals[i] = sampleEvent(i)
		require.NoError(t, s.Append(originals[i]), "append %d", i)
	}

	got, err := s.Load()
	require.NoError(t, err)
	require.Len(t, got, n)

	for i := 0; i < n; i++ {
		require.Equal(t, originals[i].EventID, got[i].EventID, "event %d EventID differs", i)
		require.Equal(t, originals[i].Kind, got[i].Kind)
		require.Equal(t, originals[i].SessionID, got[i].SessionID)
		require.Equal(t, originals[i].RequestID, got[i].RequestID)
		require.True(t, originals[i].OccurredAt.Equal(got[i].OccurredAt),
			"event %d OccurredAt differs: want=%v got=%v",
			i, originals[i].OccurredAt, got[i].OccurredAt)
		require.Equal(t, originals[i].Payload, got[i].Payload)
		require.Equal(t, originals[i].PrevHash, got[i].PrevHash)
		require.Equal(t, originals[i].Hash, got[i].Hash)
		require.Equal(t, originals[i].Signature, got[i].Signature)
		require.Equal(t, originals[i].SigningKeyID, got[i].SigningKeyID)
	}

	l, err := s.Len()
	require.NoError(t, err)
	require.Equal(t, n, l)
}

// TestBBoltStore_CrashAndReopen_PreservesAllEvents is the core persistence
// contract test: write events, close the store (simulating a clean shutdown
// or crash — bbolt's file format is crash-consistent on close), open a
// fresh handle against the same path, and assert every event comes back
// in the same order with the same bytes.
//
// This is the property the audit chain's offline-verifiability promise
// rests on: if Load after Close returns a different sequence than
// Append fed in, the hash-link graph no longer reassembles and the
// chain is effectively destroyed.
func TestBBoltStore_CrashAndReopen_PreservesAllEvents(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")

	// ---- Session 1: append the first batch. -------------------------------
	s1, err := store.Open(path)
	require.NoError(t, err)

	const batch1 = 7
	originals := make([]audit_event.AuditEvent, 0, batch1*2)
	for i := 0; i < batch1; i++ {
		e := sampleEvent(i)
		originals = append(originals, e)
		require.NoError(t, s1.Append(e))
	}

	// Simulate a crash + shutdown — Close flushes any pending writes
	// to the OS. bbolt's mmap guarantees that all completed Update
	// transactions are durable before Close returns.
	require.NoError(t, s1.Close())

	// ---- Session 2: re-open and verify first batch survived. --------------
	s2, err := store.Open(path)
	require.NoError(t, err)

	got1, err := s2.Load()
	require.NoError(t, err)
	require.Len(t, got1, batch1, "first batch lost after re-open")

	for i := 0; i < batch1; i++ {
		require.Equal(t, originals[i].EventID, got1[i].EventID,
			"batch1 event %d EventID changed after re-open", i)
		require.Equal(t, originals[i].Hash, got1[i].Hash,
			"batch1 event %d Hash changed after re-open", i)
	}

	// ---- Session 2 continues: append a second batch and verify sequence
	// numbers continue monotonically after re-open. --------------------------
	const batch2 = 5
	for i := batch1; i < batch1+batch2; i++ {
		e := sampleEvent(i)
		originals = append(originals, e)
		require.NoError(t, s2.Append(e))
	}

	got2, err := s2.Load()
	require.NoError(t, err)
	require.Len(t, got2, batch1+batch2)

	// Order invariant: events appended before the restart appear before
	// events appended after.
	for i := 0; i < batch1+batch2; i++ {
		require.Equal(t, originals[i].EventID, got2[i].EventID,
			"event %d ordering broken across re-open boundary", i)
	}

	require.NoError(t, s2.Close())

	// ---- Session 3: one more re-open to confirm the full sequence
	// survives the second close. --------------------------------------
	s3, err := store.Open(path)
	require.NoError(t, err)
	defer func() { _ = s3.Close() }()

	got3, err := s3.Load()
	require.NoError(t, err)
	require.Len(t, got3, batch1+batch2)

	for i := 0; i < batch1+batch2; i++ {
		require.Equal(t, originals[i].EventID, got3[i].EventID,
			"event %d lost across second re-open", i)
	}
}

// TestBBoltStore_AppendMonotonicKeysAfterReopen asserts the append
// sequence continues monotonically from where the previous session left
// off. Without this, a restart would let the next Append collide with
// an existing key, silently overwriting an audit record.
func TestBBoltStore_AppendMonotonicKeysAfterReopen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")

	s1, err := store.Open(path)
	require.NoError(t, err)
	for i := 0; i < 4; i++ {
		require.NoError(t, s1.Append(sampleEvent(i)))
	}
	require.NoError(t, s1.Close())

	s2, err := store.Open(path)
	require.NoError(t, err)
	defer func() { _ = s2.Close() }()

	// Append one more; total should be 5, not overwrite one of the
	// first 4.
	require.NoError(t, s2.Append(sampleEvent(99)))

	n, err := s2.Len()
	require.NoError(t, err)
	require.Equal(t, 5, n, "re-opened store did not preserve monotonic key sequence")

	all, err := s2.Load()
	require.NoError(t, err)
	require.Len(t, all, 5)
	require.Equal(t, ids.AuditEventID("evt-persist-0099"), all[4].EventID,
		"newly-appended event was not stored at the tail")
}

// TestBBoltStore_OpsOnClosedStoreFail asserts the Close contract: every
// op on a closed store returns a classified Operational error wrapping
// ErrStoreClosed. Callers MUST be able to distinguish "handle is dead"
// from other failure modes, so this contract is load-bearing for
// higher layers (e.g. the chain's Append failure handler).
func TestBBoltStore_OpsOnClosedStoreFail(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")

	s, err := store.Open(path)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// Append on closed store.
	err = s.Append(sampleEvent(0))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.True(t, errors.Is(err, store.ErrStoreClosed),
		"Append on closed store did not surface ErrStoreClosed (err=%v)", err)

	// Load on closed store.
	_, err = s.Load()
	require.Error(t, err)
	require.True(t, errors.Is(err, store.ErrStoreClosed))

	// Len on closed store.
	_, err = s.Len()
	require.Error(t, err)
	require.True(t, errors.Is(err, store.ErrStoreClosed))
}

// TestBBoltStore_EmptyPathRejected asserts the input-validation gate.
// A zero-value path is a structural defect (caller bug) rather than an
// operational failure, so the returned error is Structural.
func TestBBoltStore_EmptyPathRejected(t *testing.T) {
	t.Parallel()
	_, err := store.Open("")
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// TestBBoltStore_SecondOpenLockedOut asserts bbolt's single-writer
// invariant: opening the same path twice while the first handle is
// live returns an Operational error (file lock conflict). The vault
// relies on this to guarantee single-writer ownership of its audit
// file across cold-start races.
func TestBBoltStore_SecondOpenLockedOut(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")

	first, err := store.Open(path)
	require.NoError(t, err)
	defer func() { _ = first.Close() }()

	// Second Open on the same path should fail within the open timeout.
	start := time.Now()
	_, err = store.Open(path)
	require.Error(t, err,
		"second concurrent Open on %q unexpectedly succeeded", path)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	// Sanity: must not hang forever — the timeout is 5s; allow generous
	// slack for slow CI runners.
	require.Less(t, time.Since(start), 30*time.Second,
		"second Open hung beyond configured timeout")
}
