// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// These tests damage a store's database from inside the package — the
// bucket dropped, foreign keys and values written, the handle closed
// underneath — to prove the store reports corruption as Integrity or
// Operational refusals rather than returning partial or invented events.

func openStore(t *testing.T) *BBoltStore {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func event(i int) audit_event.AuditEvent {
	return audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID("evt-internal-" + string(rune('a'+i))),
		Kind:          audit_event.KindRequestReceived,
		OccurredAt:    time.Date(2026, 4, 20, 10, 0, i, 0, time.UTC),
		SessionID:     ids.SessionID("sess-internal"),
		RequestID:     ids.RequestID("req-internal"),
		Payload:       []byte(`{}`),
		PrevHash:      bytes.Repeat([]byte{byte(i)}, audit_event.HashSize),
		Hash:          bytes.Repeat([]byte{byte(i + 1)}, audit_event.HashSize),
		SigningKeyID:  ids.KeyID("audit-key-1"),
		Signature:     bytes.Repeat([]byte{byte(i + 2)}, 64),
	}
}

// TestAppend_UnencodableEventIsStructural proves that an event the JSON
// encoder refuses (a timestamp outside the years JSON can carry) is a
// structural refusal and leaves the store untouched.
func TestAppend_UnencodableEventIsStructural(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	evt := event(0)
	evt.OccurredAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)

	err := s.Append(evt)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))

	n, err := s.Len()
	require.NoError(t, err)
	require.Zero(t, n)
}

// TestBucketDropped_AppendRefusedReadsEmpty proves that when the audit
// bucket has been removed from the database, Append refuses to write
// anywhere else, while Load and Len report an empty store rather than
// failing — the file is still a valid database with nothing in it.
func TestBucketDropped_AppendRefusedReadsEmpty(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	require.NoError(t, s.Append(event(0)))
	require.NoError(t, s.db.Update(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket([]byte(bucketName))
	}))

	err := s.Append(event(1))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeResourceExhausted, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), "audit bucket missing")

	events, err := s.Load()
	require.NoError(t, err)
	require.Empty(t, events)

	n, err := s.Len()
	require.NoError(t, err)
	require.Zero(t, n)
}

// TestLoad_CorruptedRecordsAreIntegrityRefusals proves that a record the
// store did not write — a key that is not an 8-byte sequence number, or
// a value that is not an audit event — makes Load refuse the whole store
// as an Integrity failure, naming the damage, instead of skipping it.
func TestLoad_CorruptedRecordsAreIntegrityRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		key, value []byte
		want       string
	}{
		"short key":        {[]byte("abc"), []byte(`{}`), "malformed key length=3"},
		"long key":         {bytes.Repeat([]byte{1}, 9), []byte(`{}`), "malformed key length=9"},
		"value not json":   {[]byte{0, 0, 0, 0, 0, 0, 0, 9}, []byte("not json"), "unmarshal seq=9 failed"},
		"value wrong type": {[]byte{0, 0, 0, 0, 0, 0, 0, 7}, []byte(`{"schema_version":"x"}`), "unmarshal seq=7 failed"},
		"unknown field":    {[]byte{0, 0, 0, 0, 0, 0, 0, 5}, []byte(`{"schema_version":1,"injected":true}`), "unmarshal seq=5 failed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := openStore(t)
			require.NoError(t, s.Append(event(0)))
			require.NoError(t, s.db.Update(func(tx *bbolt.Tx) error {
				return tx.Bucket([]byte(bucketName)).Put(tc.key, tc.value)
			}))

			events, err := s.Load()
			require.Error(t, err)
			require.Nil(t, events)
			require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestLoad_SortsBySequenceNotInsertion proves that Load orders events by
// their sequence key: a record written under a lower key after a higher
// one is still returned first.
func TestLoad_SortsBySequenceNotInsertion(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	require.NoError(t, s.Append(event(0)))
	require.NoError(t, s.Append(event(1)))
	require.NoError(t, s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		early := event(2)
		raw, err := json.Marshal(&early)
		if err != nil {
			return err
		}
		return b.Put([]byte{0, 0, 0, 0, 0, 0, 0, 0}, raw)
	}))

	events, err := s.Load()
	require.NoError(t, err)
	require.Len(t, events, 3)
	require.Equal(t, event(2).EventID, events[0].EventID)
	require.Equal(t, event(0).EventID, events[1].EventID)
	require.Equal(t, event(1).EventID, events[2].EventID)
}

// TestHandleClosedUnderneath_OpsFailThenCloseIsClean proves that when the
// database handle is closed behind the store's back, every operation
// surfaces bbolt's not-open error instead of succeeding on a dead handle,
// and that Close afterwards is still clean.
func TestHandleClosedUnderneath_OpsFailThenCloseIsClean(t *testing.T) {
	t.Parallel()
	s := openStore(t)
	require.NoError(t, s.Append(event(0)))
	require.NoError(t, s.db.Close())

	_, err := s.Len()
	require.True(t, errors.Is(err, berrors.ErrDatabaseNotOpen), "Len: %v", err)
	_, err = s.Load()
	require.True(t, errors.Is(err, berrors.ErrDatabaseNotOpen), "Load: %v", err)
	err = s.Append(event(1))
	require.True(t, errors.Is(err, berrors.ErrDatabaseNotOpen), "Append: %v", err)

	require.NoError(t, s.Close())
	require.Nil(t, s.db)
}
