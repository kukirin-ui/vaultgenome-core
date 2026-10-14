// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// -------------------------------------------------------------------
// Small byte helpers
// -------------------------------------------------------------------

// repeat returns a fresh []byte of length n, every byte set to b.
// Mirrors the helper pattern used in probe_battery_test; intentionally
// kept local to this _test package so the two test suites do not
// couple to each other.
func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// zeros32 returns a freshly-allocated 32-byte zero slice.
func zeros32() []byte {
	return make([]byte, crypto.HashSize)
}

// -------------------------------------------------------------------
// Keystore helpers
// -------------------------------------------------------------------

// newWitnessStore constructs an in-memory keystore with a witness-
// purpose signing key registered under kid.
func newWitnessStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	store := keys.NewInMemoryStore(nil)
	_, err := store.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)
	return store
}

// -------------------------------------------------------------------
// LogEntry construction helpers
// -------------------------------------------------------------------

// defaultBaseTime is a fixed reference point so every test is
// deterministic in time — matches the 2026-04-20 anchor used across
// the rest of the project's test fixtures.
func defaultBaseTime() time.Time {
	return time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
}

// buildEntryUnderIndex builds a well-formed LogEntry at the given
// index with the given PrevLeafHash and a few distinguishing payload
// bytes derived from index — enough to produce a unique LeafHash per
// entry without requiring the caller to supply them.
//
// The caller is responsible for threading PrevLeafHash correctly from
// the previous entry's LeafHash; buildChain does this automatically.
func buildEntryUnderIndex(t *testing.T, index uint64, prevLeafHash []byte, ts time.Time) *witness.LogEntry {
	t.Helper()
	entry := &witness.LogEntry{
		SchemaVersion:     witness.SchemaVersionCurrent,
		Index:             index,
		PrevLeafHash:      append([]byte(nil), prevLeafHash...),
		Timestamp:         ts,
		GenomeID:          ids.GenomeID("gen:witness-entry-" + itoa(index)),
		AttestationRoot:   repeat(byte(0x10+byte(index&0xFF)), crypto.HashSize),
		BatteryMerkleRoot: repeat(byte(0x20+byte(index&0xFF)), crypto.HashSize),
		ScorecardRoot:     repeat(byte(0x30+byte(index&0xFF)), crypto.HashSize),
	}
	// Succession-edge payload on every entry except the first: makes
	// the covered payload non-trivial in the common test case.
	if index > 0 {
		entry.ParentGenomeID = ids.GenomeID("gen:witness-entry-" + itoa(index-1))
		entry.DerivationMethod = genome_descriptor.DerivationFineTune
	}
	leaf, entryID, err := entry.DeriveLeafHashAndID()
	require.NoError(t, err)
	entry.LeafHash = leaf
	entry.EntryID = entryID
	return entry
}

// buildChain builds a valid chain of n entries, correctly threading
// PrevLeafHash → LeafHash and monotonically advancing timestamps by
// one second per entry.
func buildChain(t *testing.T, n int) []witness.LogEntry {
	t.Helper()
	entries := make([]witness.LogEntry, 0, n)
	prev := zeros32()
	base := defaultBaseTime()
	for i := 0; i < n; i++ {
		e := buildEntryUnderIndex(t, uint64(i), prev, base.Add(time.Duration(i)*time.Second))
		entries = append(entries, *e)
		prev = append([]byte(nil), e.LeafHash...)
	}
	return entries
}

// leafHashes extracts the LeafHash slice from a chain — useful as the
// input to proof builders and ComputeMerkleRoot.
func leafHashes(entries []witness.LogEntry) [][]byte {
	out := make([][]byte, len(entries))
	for i := range entries {
		out[i] = append([]byte(nil), entries[i].LeafHash...)
	}
	return out
}

// -------------------------------------------------------------------
// Merkle proof builders — independent references matching RFC 6962
// -------------------------------------------------------------------

// buildInclusionPath returns the audit path from leaf m to the root
// of the tree over leaves. Used by tests to construct valid proofs
// that witness.VerifyInclusion MUST accept.
func buildInclusionPath(t *testing.T, leaves [][]byte, m int) [][]byte {
	t.Helper()
	require.Less(t, m, len(leaves), "leaf index out of range")
	if len(leaves) == 1 {
		return nil
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	index := m
	var path [][]byte
	for len(level) > 1 {
		var sibling []byte
		if index%2 == 1 {
			sibling = append([]byte(nil), level[index-1]...)
		} else if index+1 < len(level) {
			sibling = append([]byte(nil), level[index+1]...)
		}
		if sibling != nil {
			path = append(path, sibling)
		}
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			h, err := witness.CombineNodes(level[i], level[i+1])
			require.NoError(t, err)
			next = append(next, h)
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
		index /= 2
	}
	return path
}

// buildConsistencyPath returns the RFC 6962 PROOF(m, D[n]) that a
// tree of size m grew legitimately into a tree of size n=len(leaves).
// Implementation follows the RFC recursion SUBPROOF(m, D, b).
func buildConsistencyPath(t *testing.T, leaves [][]byte, m int) [][]byte {
	t.Helper()
	require.LessOrEqual(t, m, len(leaves), "old size > new size")
	if m == 0 || m == len(leaves) {
		return nil
	}
	return subproof(t, m, leaves, true)
}

func subproof(t *testing.T, m int, leaves [][]byte, isFirst bool) [][]byte {
	t.Helper()
	n := len(leaves)
	if m == n {
		if isFirst {
			return nil
		}
		r, err := witness.ComputeMerkleRoot(leaves)
		require.NoError(t, err)
		return [][]byte{r}
	}
	k := largestPow2Less(n)
	if m <= k {
		r, err := witness.ComputeMerkleRoot(leaves[k:])
		require.NoError(t, err)
		sub := subproof(t, m, leaves[:k], isFirst)
		return append(sub, r)
	}
	r, err := witness.ComputeMerkleRoot(leaves[:k])
	require.NoError(t, err)
	sub := subproof(t, m-k, leaves[k:], false)
	return append(sub, r)
}

// largestPow2Less returns the largest power of 2 strictly less than n.
// Precondition: n >= 2.
func largestPow2Less(n int) int {
	if n <= 1 {
		return 0
	}
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// -------------------------------------------------------------------
// STH construction helpers
// -------------------------------------------------------------------

// coverTime is when an STH over entries is issued in these fixtures:
// the newest entry's timestamp, since a head cannot predate what it
// commits to (WitnessReceipt.Validate refuses one that does). Empty
// entries fall back to the base time.
func coverTime(entries []witness.LogEntry) time.Time {
	if len(entries) == 0 {
		return defaultBaseTime()
	}
	return entries[len(entries)-1].Timestamp
}

// newSignedSTH builds a SignedTreeHead covering the given entries,
// signs it under kid, and returns the populated struct. Empty entries
// is legal — produces an empty-tree STH.
func newSignedSTH(
	t *testing.T,
	store *keys.InMemoryStore,
	kid ids.KeyID,
	entries []witness.LogEntry,
	ts time.Time,
) *witness.SignedTreeHead {
	t.Helper()
	sth := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      uint64(len(entries)),
		Timestamp:     ts,
		SigningKeyID:  kid,
	}
	if len(entries) == 0 {
		sth.TreeHash = zeros32()
		sth.TreeChainHead = zeros32()
	} else {
		root, err := witness.ComputeMerkleRoot(leafHashes(entries))
		require.NoError(t, err)
		sth.TreeHash = root
		sth.TreeChainHead = append([]byte(nil), entries[len(entries)-1].LeafHash...)
	}
	require.NoError(t, sth.SignWith(store))
	return sth
}

// -------------------------------------------------------------------
// Dependency-free uint→decimal — avoids dragging strconv into tests
// for a single call-site per entry.
// -------------------------------------------------------------------

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
