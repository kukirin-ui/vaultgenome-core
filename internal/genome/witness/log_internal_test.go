// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	contract "github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// These tests reach the guards that the public Log interface keeps out of
// reach by construction: a head requested past the committed tail, and the
// corruption guards that fire when the log's own leaf cache no longer holds
// 32-byte hashes. They live in the package so they can call the internals
// directly and corrupt the cache on purpose.

func filled(b byte) []byte {
	out := make([]byte, crypto.HashSize)
	for i := range out {
		out[i] = b
	}
	return out
}

func newInternalLog(t *testing.T) *InMemoryLog {
	t.Helper()
	kid := ids.KeyID("witness-internal")
	store := keys.NewInMemoryStore(nil)
	_, err := store.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)
	log, err := NewInMemoryLog(store, kid, shared_time.NewFakeClock(time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)))
	require.NoError(t, err)
	return log
}

func appendOne(t *testing.T, log *InMemoryLog, seed byte) {
	t.Helper()
	_, err := log.Append(contract.LogEntry{
		Timestamp:         time.Date(2026, 4, 20, 12, 0, int(seed), 0, time.UTC),
		GenomeID:          ids.GenomeID("gen:internal"),
		AttestationRoot:   filled(0x10 + seed),
		BatteryMerkleRoot: filled(0x20 + seed),
		ScorecardRoot:     filled(0x30 + seed),
	})
	require.NoError(t, err)
}

// TestHeadLocked_SizePastTailRefused proves that an STH can only cover
// entries that exist: asking for a head over more entries than were
// committed is an Operational refusal, not a head over phantom leaves.
func TestHeadLocked_SizePastTailRefused(t *testing.T) {
	t.Parallel()
	log := newInternalLog(t)
	appendOne(t, log, 0)

	log.mu.RLock()
	defer log.mu.RUnlock()
	sth, err := log.headLocked(2)
	require.Error(t, err)
	require.Nil(t, sth)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Equal(t, "witness_log_tree_size_out_of_range", shared_errors.CodeOf(err))

	sth, err = log.headLocked(1)
	require.NoError(t, err)
	require.Equal(t, uint64(1), sth.TreeSize)
}

// TestHeadLocked_CorruptLeafCacheRefused proves that a leaf cache entry
// that is no longer a 32-byte hash cannot be signed into a head: the
// Merkle root computation refuses it and the refusal is surfaced instead
// of an STH over corrupted memory.
func TestHeadLocked_CorruptLeafCacheRefused(t *testing.T) {
	t.Parallel()
	log := newInternalLog(t)
	appendOne(t, log, 0)
	appendOne(t, log, 1)
	log.mu.Lock()
	log.leaves[1] = []byte{0xde, 0xad}
	log.mu.Unlock()

	sth, err := log.Head()
	require.Error(t, err)
	require.Nil(t, sth)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

// TestCloneEntry_NilStaysNil proves the copier passes a nil entry through
// instead of manufacturing an empty one.
func TestCloneEntry_NilStaysNil(t *testing.T) {
	t.Parallel()
	require.Nil(t, cloneEntry(nil))

	src := &contract.LogEntry{PrevLeafHash: filled(1), LeafHash: filled(2), AttestationRoot: filled(3)}
	out := cloneEntry(src)
	out.PrevLeafHash[0] = 0xff
	require.Equal(t, byte(1), src.PrevLeafHash[0], "the copy must not alias the source")
}

// TestLargestPow2Less_Table pins the RFC 6962 split point for tree sizes
// around powers of two, including the degenerate sizes below two.
func TestLargestPow2Less_Table(t *testing.T) {
	t.Parallel()
	cases := map[int]int{0: 0, 1: 0, 2: 1, 3: 2, 4: 2, 5: 4, 8: 4, 9: 8, 17: 16, 1024: 512, 1025: 1024}
	for n, want := range cases {
		require.Equalf(t, want, largestPow2Less(n), "n=%d", n)
	}
}

// TestProofBuilders_PanicOnCorruptOwnLeaves proves that the proof builders
// treat a non-32-byte leaf in the log's own cache as memory corruption and
// stop with the documented message rather than emitting a proof that
// verifiers would reject or, worse, accept.
func TestProofBuilders_PanicOnCorruptOwnLeaves(t *testing.T) {
	t.Parallel()
	good := filled(0xaa)
	bad := []byte{0x01}
	_, combineErr := contract.CombineNodes(good, bad)
	require.Error(t, combineErr)
	_, rootErr := contract.ComputeMerkleRoot([][]byte{bad})
	require.Error(t, rootErr)
	combineMsg := "witness-log: CombineNodes failed on own leaves: " + combineErr.Error()
	rootMsg := "witness-log: ComputeMerkleRoot failed on own leaves: " + rootErr.Error()

	cases := []struct {
		name string
		run  func()
		msg  string
	}{
		{
			name: "inclusion path combine",
			run:  func() { buildInclusionPathInternal([][]byte{good, bad}, 0) },
			msg:  combineMsg,
		},
		{
			name: "subproof whole-tree root",
			run:  func() { subproofInternal(1, [][]byte{bad}, false) },
			msg:  rootMsg,
		},
		{
			name: "subproof right-subtree root",
			run:  func() { subproofInternal(1, [][]byte{good, good, bad}, true) },
			msg:  rootMsg,
		},
		{
			name: "subproof left-subtree root",
			run:  func() { subproofInternal(3, [][]byte{bad, good, good, good}, true) },
			msg:  rootMsg,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.PanicsWithValue(t, tc.msg, tc.run)
		})
	}
}
