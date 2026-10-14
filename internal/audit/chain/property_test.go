// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Property tests for /internal/audit/chain.
//
// These tests extend the hand-rolled unit tests in chain_test.go with
// population-scale assertions over the hash-link integrity contract:
//
//   - Append produces a strictly linked chain for arbitrary event
//     sequences (property: every PrevHash[i] == Hash[i-1]).
//   - Verify accepts any honestly-built chain and rejects every
//     single-byte mutation of a stored field.
//   - Verify rejects any reordering of a valid chain (ordering is a
//     load-bearing part of the commitment — reordering breaks the hash
//     link even without touching individual event bytes).
//
// Doctrinal binding: the audit chain is the offline-verifiable integrity
// contract. A regression in any of the properties below silently lets
// tampered or reordered events survive Verify, which breaks the auditor-
// without-keys promise.
//
// Budget: each property iterates 32 seeds × small random chain lengths
// (3..12). Small by fuzz standards but exhaustive enough over the
// mutation surface (PrevHash / Hash / Signature / Payload) to pin the
// integrity contract.

// randomKinds rotates through the release-side Kinds that a real pipeline
// actually emits — the kind-set must stay within SchemaVersion 1 so the
// default fixture SchemaVersion (=1) is valid for every event.
var randomKinds = []audit_event.Kind{
	audit_event.KindRequestReceived,
	audit_event.KindTrustEvaluated,
	audit_event.KindSessionIssued,
	audit_event.KindValidationStarted,
	audit_event.KindValidationCompleted,
	audit_event.KindReleaseDecided,
}

// randomSkeleton returns a pre-sign event template drawn from the seeded
// RNG. Every tuple field varies so the canonical pre-image differs per
// event, which is a necessary condition for the Hash column to change.
func randomSkeleton(r *rand.Rand, idx int, kid ids.KeyID) audit_event.AuditEvent {
	eventID := fmt.Sprintf("evt-%08d-%04d", r.Int31(), idx)
	sessionID := fmt.Sprintf("sess-%04d", r.Intn(16))
	requestID := fmt.Sprintf("req-%04d-%04d", r.Intn(16), idx)
	payload := fmt.Appendf(nil, `{"i":%d,"n":%d}`, idx, r.Int31())
	// OccurredAt advances by 1..4 seconds per event so ordering is
	// monotonically plausible; random within that window to ensure the
	// canonical form differs per event.
	occ := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC).
		Add(time.Duration(idx)*time.Second + time.Duration(r.Intn(500))*time.Millisecond)

	return audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(eventID),
		Kind:          randomKinds[r.Intn(len(randomKinds))],
		OccurredAt:    occ,
		SessionID:     ids.SessionID(sessionID),
		RequestID:     ids.RequestID(requestID),
		Payload:       payload,
		SigningKeyID:  kid,
	}
}

// buildRandomChain appends n random events to a fresh InMemoryChain and
// returns both the chain and the store so callers can run Verify. Each
// seed gets its own KeyID so property subtests running under t.Parallel()
// hold independent per-seed stores and never race on a shared one.
func buildRandomChain(t *testing.T, seed int64, n int) (*InMemoryChain, *keys.InMemoryStore, ids.KeyID) {
	t.Helper()
	kid := ids.KeyID(fmt.Sprintf("audit-key-%d", seed))
	store := newAuditStore(t, kid)
	c := NewInMemoryChain()

	r := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i++ {
		_, err := c.Append(randomSkeleton(r, i, kid), store)
		require.NoError(t, err, "append event %d failed", i)
	}
	return c, store, kid
}

// TestProperty_AppendLinksEveryEvent asserts the structural link contract:
// for every random chain of 1..12 events, PrevHash[i] == Hash[i-1] and
// PrevHash[0] is 32 zero bytes. A regression here means Append forgot to
// snapshot the tip before signing, which would silently let an adversary
// forge events outside the chain.
func TestProperty_AppendLinksEveryEvent(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 32; seed++ {
		seed := seed
		for _, n := range []int{1, 2, 3, 5, 8, 12} {
			n := n
			t.Run(fmt.Sprintf("seed=%d/n=%d", seed, n), func(t *testing.T) {
				t.Parallel()
				c, _, _ := buildRandomChain(t, seed, n)

				events := c.Events()
				require.Len(t, events, n)

				// Genesis: first event's PrevHash is all zero.
				require.Equal(t,
					bytes.Repeat([]byte{0x00}, audit_event.HashSize),
					events[0].PrevHash,
					"genesis event PrevHash must be zero")

				// Every subsequent event's PrevHash == previous event's Hash.
				for i := 1; i < n; i++ {
					require.Equal(t, events[i-1].Hash, events[i].PrevHash,
						"chain link broken at index %d", i)
				}

				// Tip == last Hash.
				require.Equal(t, events[n-1].Hash, c.Tip())

				// Hashes are unique — a duplicate would indicate the
				// canonical pre-image isn't including the chain-link
				// (PrevHash) component, which would catastrophically
				// break integrity.
				seen := map[string]bool{}
				for i, e := range events {
					key := string(e.Hash)
					require.False(t, seen[key],
						"duplicate Hash at index %d — pre-image is not including PrevHash or EventID", i)
					seen[key] = true
				}
			})
		}
	}
}

// TestProperty_VerifyAcceptsHonestChain asserts the positive case: any
// random chain built through Append MUST verify end-to-end. This is the
// property the vault relies on to export audit trails — the auditor MUST
// be able to recompute every hash and verify every signature offline.
func TestProperty_VerifyAcceptsHonestChain(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 32; seed++ {
		seed := seed
		n := 3 + int(seed%10) // chain length 3..12
		t.Run(fmt.Sprintf("seed=%d/n=%d", seed, n), func(t *testing.T) {
			t.Parallel()
			c, store, _ := buildRandomChain(t, seed, n)
			require.NoError(t, c.Verify(store),
				"honest chain of length %d failed to verify (seed=%d)", n, seed)
		})
	}
}

// TestProperty_AnyFieldMutationRejected asserts the negative half of the
// integrity contract: mutating any single byte of PrevHash, Hash,
// Signature, or Payload in any event of the chain MUST cause Verify to
// fail with an Integrity-classified error.
//
// The test picks a middle event (so both before/after siblings must
// still verify honestly) and mutates each field independently with a
// fresh chain per mutation.
func TestProperty_AnyFieldMutationRejected(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 16; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			const n = 5

			mutations := []struct {
				name string
				mut  func(*audit_event.AuditEvent)
			}{
				{
					name: "PrevHash[0]",
					mut:  func(e *audit_event.AuditEvent) { e.PrevHash[0] ^= 0x01 },
				},
				{
					name: "Hash[0]",
					mut:  func(e *audit_event.AuditEvent) { e.Hash[0] ^= 0x01 },
				},
				{
					name: "Signature[0]",
					mut:  func(e *audit_event.AuditEvent) { e.Signature[0] ^= 0x01 },
				},
				{
					name: "Payload",
					mut:  func(e *audit_event.AuditEvent) { e.Payload = []byte(`{"note":"forged"}`) },
				},
			}

			for _, m := range mutations {
				m := m
				t.Run(m.name, func(t *testing.T) {
					t.Parallel()
					c, store, _ := buildRandomChain(t, seed, n)

					// Mutate the middle event in place. We reach into the
					// unexported slice because the chain is the system
					// under test — an auditor or adversary would see the
					// stored bytes exactly this way.
					m.mut(&c.events[n/2])

					err := c.Verify(store)
					require.Error(t, err,
						"chain verified despite %s mutation at middle event", m.name)
					require.Equal(t, shared_errors.CategoryIntegrity,
						shared_errors.CategoryOf(err),
						"mutation %s surfaced as %v, expected Integrity",
						m.name, shared_errors.CategoryOf(err))
				})
			}
		})
	}
}

// TestProperty_ReorderingBreaksVerify asserts the ordering contract: any
// swap of two adjacent events (that actually changes positions — skip
// trivial no-op swaps where events might happen to be equal, which does
// not occur in our random corpus) breaks Verify. This is the property
// that makes the chain an ordered commitment, not just a set commitment.
func TestProperty_ReorderingBreaksVerify(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 16; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			const n = 5
			c, store, _ := buildRandomChain(t, seed, n)

			// Sanity: honest chain verifies.
			require.NoError(t, c.Verify(store))

			// Swap events at indices 1 and 2. Their PrevHash fields are
			// not re-computed, so the link chain is now broken at both
			// positions.
			c.events[1], c.events[2] = c.events[2], c.events[1]

			err := c.Verify(store)
			require.Error(t, err,
				"chain verified despite adjacent-event reordering (seed=%d)", seed)
			require.Equal(t, shared_errors.CategoryIntegrity,
				shared_errors.CategoryOf(err),
				"reordering surfaced as %v, expected Integrity",
				shared_errors.CategoryOf(err))
		})
	}
}

// TestProperty_TipMatchesLastHashAfterEveryAppend asserts a stepwise
// invariant: after each Append, Tip() == last event's Hash. This is
// what subsequent Append calls rely on to compute PrevHash for the next
// event, so a regression here silently desynchronises the link chain.
func TestProperty_TipMatchesLastHashAfterEveryAppend(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 32; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			kid := ids.KeyID(fmt.Sprintf("audit-key-tip-%d", seed))
			store := newAuditStore(t, kid)
			c := NewInMemoryChain()

			// Genesis tip is all zero.
			require.Equal(t,
				bytes.Repeat([]byte{0x00}, audit_event.HashSize),
				c.Tip())

			r := rand.New(rand.NewSource(seed))
			for i := 0; i < 8; i++ {
				sealed, err := c.Append(randomSkeleton(r, i, kid), store)
				require.NoError(t, err)
				require.Equal(t, sealed.Hash, c.Tip(),
					"Tip() out of sync with last event Hash at step %d", i)
			}
		})
	}
}
