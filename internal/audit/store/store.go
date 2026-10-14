// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"go.etcd.io/bbolt"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Doctrinal role (implementation layer)
//
// The audit Store is the evidence substrate the vault appends to after
// every decision. It MUST survive crash and re-open without losing
// events or rearranging their order — the audit chain in
// /internal/audit/chain relies on insertion order to reconstruct the
// hash-link graph offline.
//
// MVP implementation: bbolt (https://github.com/etcd-io/bbolt). One
// bucket "audit_events"; keys are 8-byte big-endian uint64 sequence
// numbers; values are JSON-encoded AuditEvent bytes. Sequence numbers
// are allocated from bbolt's bucket-level sequence counter so
// concurrent appends never collide, and so that the native
// `Bucket.ForEach` iteration order (lexicographic over the 8-byte
// fixed-width keys) matches insertion order exactly.
//
// Dependency on bbolt: governed by docs/doctrine/ci-security-policy.md §3.1/§3.3
// (allowlist) and docs/dependencies/bbolt.md (justification).

// Store is the append-only persistence interface for audit events.
//
// Implementations MUST:
//
//   - Preserve insertion order across Close/Open cycles.
//   - Reject nil/zero events at Append time (structural rejection).
//   - Return a defensive copy on Load — callers must be free to mutate
//     returned slices without corrupting stored state.
type Store interface {
	// Append persists evt. The event's canonical form (including the
	// chain's PrevHash / Hash / Signature fields, already populated by
	// the chain's Append path) is written as an opaque JSON blob. The
	// store does not re-validate the event — it trusts the chain layer
	// above to have done so.
	Append(evt audit_event.AuditEvent) error

	// Load returns all persisted events in insertion order. The returned
	// slice and every event's []byte fields are defensive copies.
	Load() ([]audit_event.AuditEvent, error)

	// Len returns the current number of events in the store.
	Len() (int, error)

	// Close releases the underlying file handle / OS resources. After
	// Close, all further calls MUST return an error classified as
	// Operational with Code equal to CodeResourceExhausted (see
	// shared/errors for the canonical taxonomy).
	Close() error
}

// bucketName is the only bucket the bbolt-backed store writes to. It is
// fixed and MUST NOT be renamed — existing databases on disk are keyed
// by this name.
const bucketName = "audit_events"

// openTimeout bounds how long Open waits for an OS-level exclusive file
// lock on the bbolt database. A real crash-recovery scenario should
// never require more than this; if the lock can't be taken within this
// window something stale is still holding the previous handle.
const openTimeout = 5 * time.Second

// BBoltStore is the bbolt-backed implementation of Store.
//
// Concurrency: bbolt itself is concurrency-safe (one writer, many readers
// coordinated by an internal mmap + sync.RWMutex). The BBoltStore wrapper
// adds no further locks — all writes go through Append which takes a
// single bbolt write transaction, and all reads go through Load / Len
// which use bbolt read transactions.
type BBoltStore struct {
	db   *bbolt.DB
	path string
}

// Open opens or creates a bbolt-backed audit store at path. The parent
// directory MUST exist; Open does not create intermediate directories.
// Open takes the bbolt file lock, so a second Open on the same path
// while the first is live returns an Operational error.
func Open(path string) (*BBoltStore, error) {
	if path == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"audit/store: path required",
			nil,
		)
	}

	// 0600 — the audit file is vault-private. A broader mode would let
	// the host OS user leak evidence.
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			fmt.Sprintf("audit/store: open %q failed", filepath.Clean(path)),
			err,
		)
	}

	// Ensure the bucket exists. Idempotent — bbolt returns nil if it
	// already does. Done eagerly so the first Append doesn't race with
	// another thread attempting to create it.
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"audit/store: bucket initialisation failed",
			err,
		)
	}

	return &BBoltStore{db: db, path: path}, nil
}

// Append implements Store.Append.
func (s *BBoltStore) Append(evt audit_event.AuditEvent) error {
	if s.db == nil {
		return shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"audit/store: append on closed store",
			ErrStoreClosed,
		)
	}

	// Serialise the event as plain JSON. The store is content-neutral —
	// the canonical-form invariant is owned by the chain layer; the
	// store just needs to preserve bytes and order.
	buf, err := json.Marshal(&evt)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"audit/store: marshal failed",
			err,
		)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return shared_errors.Operational(
				shared_errors.CodeResourceExhausted,
				"audit/store: audit bucket missing",
				nil,
			)
		}

		// Allocate a fresh monotonic sequence number. bbolt guarantees
		// NextSequence is strictly increasing within the bucket's
		// lifetime, which is exactly the ordering contract the chain
		// layer relies on.
		seq, err := b.NextSequence()
		if err != nil {
			return shared_errors.Operational(
				shared_errors.CodeResourceExhausted,
				"audit/store: next sequence failed",
				err,
			)
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], seq)

		if err := b.Put(key[:], buf); err != nil {
			return shared_errors.Operational(
				shared_errors.CodeResourceExhausted,
				"audit/store: put failed",
				err,
			)
		}
		return nil
	})
}

// Load implements Store.Load.
func (s *BBoltStore) Load() ([]audit_event.AuditEvent, error) {
	if s.db == nil {
		return nil, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"audit/store: load on closed store",
			ErrStoreClosed,
		)
	}

	// We collect (seq, bytes) pairs inside the transaction and decode
	// after closing it, so decode errors don't hold the read lock.
	type entry struct {
		seq  uint64
		data []byte
	}
	var entries []entry

	if err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil // empty store
		}
		return b.ForEach(func(k, v []byte) error {
			if len(k) != 8 {
				return shared_errors.Integrity(
					shared_errors.CodeFieldValueInvalid,
					fmt.Sprintf("audit/store: malformed key length=%d", len(k)),
					nil,
				)
			}
			seq := binary.BigEndian.Uint64(k)
			// Defensive copy — bbolt's []byte values are only valid
			// for the lifetime of the transaction.
			cp := make([]byte, len(v))
			copy(cp, v)
			entries = append(entries, entry{seq: seq, data: cp})
			return nil
		})
	}); err != nil {
		return nil, err
	}

	// bbolt.ForEach already walks keys in lexicographic (i.e. numeric
	// big-endian) order, but we sort defensively to document the
	// invariant and to make the code independent of bbolt iteration
	// guarantees should they ever change.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].seq < entries[j].seq
	})

	out := make([]audit_event.AuditEvent, 0, len(entries))
	for _, e := range entries {
		var evt audit_event.AuditEvent
		if err := json.Unmarshal(e.data, &evt); err != nil {
			return nil, shared_errors.Integrity(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("audit/store: unmarshal seq=%d failed", e.seq),
				err,
			)
		}
		out = append(out, evt)
	}
	return out, nil
}

// Len implements Store.Len.
func (s *BBoltStore) Len() (int, error) {
	if s.db == nil {
		return 0, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"audit/store: len on closed store",
			ErrStoreClosed,
		)
	}

	var n int
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil
		}
		// Stats().KeyN is O(1) against the bucket metadata — avoids a
		// full iteration for the common Len() use case.
		n = b.Stats().KeyN
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Close implements Store.Close. Idempotent — a second Close is a no-op
// that returns nil.
func (s *BBoltStore) Close() error {
	if s.db == nil {
		return nil
	}
	db := s.db
	s.db = nil
	if err := db.Close(); err != nil {
		return shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"audit/store: close failed",
			err,
		)
	}
	return nil
}

// Compile-time interface assertion.
var _ Store = (*BBoltStore)(nil)

// ErrStoreClosed is returned by operations on a closed store. Kept as a
// named error so callers can use errors.Is for explicit closed-state
// detection instead of string matching.
var ErrStoreClosed = errors.New("audit/store: closed")
