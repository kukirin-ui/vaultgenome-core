// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	contract "github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/genome/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// -------------------------------------------------------------------
// Local byte helpers — kept private to this _test package.
// -------------------------------------------------------------------

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func zeros32() []byte { return make([]byte, crypto.HashSize) }

// -------------------------------------------------------------------
// Fixture helpers
// -------------------------------------------------------------------

func defaultBaseTime() time.Time {
	return time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
}

// newLog constructs an in-memory log bound to a freshly-generated
// witness key. The key store is returned alongside so tests can
// resolve signatures.
func newLog(t *testing.T) (*witness.InMemoryLog, *keys.InMemoryStore, ids.KeyID) {
	t.Helper()
	kid := ids.KeyID("witness-op-1")
	store := keys.NewInMemoryStore(nil)
	_, err := store.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)
	log, err := witness.NewInMemoryLog(store, kid, shared_time.NewFakeClock(defaultBaseTime()))
	require.NoError(t, err)
	return log, store, kid
}

// samplePayload returns a LogEntry with only the payload fields set —
// the log will assign Index/PrevLeafHash and derive LeafHash/EntryID.
func samplePayload(seed byte, ts time.Time) contract.LogEntry {
	return contract.LogEntry{
		Timestamp:         ts,
		GenomeID:          ids.GenomeID("gen:log-" + string(rune('A'+int(seed)))),
		AttestationRoot:   repeatByte(0x10+seed, crypto.HashSize),
		BatteryMerkleRoot: repeatByte(0x20+seed, crypto.HashSize),
		ScorecardRoot:     repeatByte(0x30+seed, crypto.HashSize),
	}
}

// appendN commits n entries at one-second cadence. Returns the
// committed copies.
func appendN(t *testing.T, log *witness.InMemoryLog, n int) []*contract.LogEntry {
	t.Helper()
	out := make([]*contract.LogEntry, 0, n)
	base := defaultBaseTime()
	for i := 0; i < n; i++ {
		committed, err := log.Append(samplePayload(byte(i), base.Add(time.Duration(i)*time.Second)))
		require.NoError(t, err)
		out = append(out, committed)
	}
	return out
}

// -------------------------------------------------------------------
// Constructor tests
// -------------------------------------------------------------------

func TestNewInMemoryLog_RejectsNilSigner(t *testing.T) {
	t.Parallel()
	_, err := witness.NewInMemoryLog(nil, ids.KeyID("k"), nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestNewInMemoryLog_RejectsZeroKid(t *testing.T) {
	t.Parallel()
	store := keys.NewInMemoryStore(nil)
	_, err := witness.NewInMemoryLog(store, ids.KeyID(""), nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewInMemoryLog_NilClockUsesSystemClock(t *testing.T) {
	t.Parallel()
	store := keys.NewInMemoryStore(nil)
	kid := ids.KeyID("k1")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)
	// nil clock → SystemClock; construction must succeed.
	log, err := witness.NewInMemoryLog(store, kid, nil)
	require.NoError(t, err)
	require.Zero(t, log.Size())
}

// -------------------------------------------------------------------
// Append tests
// -------------------------------------------------------------------

func TestAppend_GenesisAssignsZeroPrevLeafHash(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	e, err := log.Append(samplePayload(0, defaultBaseTime()))
	require.NoError(t, err)
	require.Equal(t, uint64(0), e.Index)
	require.Len(t, e.PrevLeafHash, crypto.HashSize)
	require.True(t, bytes.Equal(e.PrevLeafHash, zeros32()))
	require.Len(t, e.LeafHash, crypto.HashSize)
	require.NotEmpty(t, e.EntryID)
	// Entry must self-validate.
	require.NoError(t, e.Validate())
}

func TestAppend_ThreadsPrevLeafHashAcrossChain(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	entries := appendN(t, log, 5)
	for i := 1; i < len(entries); i++ {
		require.True(t, bytes.Equal(entries[i].PrevLeafHash, entries[i-1].LeafHash),
			"entry %d PrevLeafHash must equal entry %d LeafHash", i, i-1)
		require.Equal(t, uint64(i), entries[i].Index)
	}
}

func TestAppend_IgnoresCallerSuppliedAuthorityFields(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	payload := samplePayload(0, defaultBaseTime())
	// Callers may accidentally set these; the log MUST overwrite.
	payload.Index = 999
	payload.PrevLeafHash = repeatByte(0xAA, crypto.HashSize)
	payload.LeafHash = repeatByte(0xBB, crypto.HashSize)
	payload.EntryID = contract.EntryID("log:deadbeef")

	e, err := log.Append(payload)
	require.NoError(t, err)
	require.Equal(t, uint64(0), e.Index)
	require.True(t, bytes.Equal(e.PrevLeafHash, zeros32()))
	require.NotEqual(t, contract.EntryID("log:deadbeef"), e.EntryID)
}

func TestAppend_RejectsNonMonotonicTimestamp(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	base := defaultBaseTime()
	_, err := log.Append(samplePayload(0, base.Add(time.Minute)))
	require.NoError(t, err)
	// Second entry with strictly-earlier timestamp — Incident.
	_, err = log.Append(samplePayload(1, base))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeTamperSignal, shared_errors.CodeOf(err))
	// Log size must not have advanced past the rejected entry.
	require.Equal(t, uint64(1), log.Size())
}

func TestAppend_AllowsEqualTimestamp(t *testing.T) {
	t.Parallel()
	// Same-instant batching is legitimate — we only reject strictly
	// earlier timestamps.
	log, _, _ := newLog(t)
	ts := defaultBaseTime()
	_, err := log.Append(samplePayload(0, ts))
	require.NoError(t, err)
	_, err = log.Append(samplePayload(1, ts))
	require.NoError(t, err)
	require.Equal(t, uint64(2), log.Size())
}

func TestAppend_ReturnsIndependentCopy(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	e, err := log.Append(samplePayload(0, defaultBaseTime()))
	require.NoError(t, err)
	// Mutating the returned copy MUST NOT drift the stored entry.
	e.LeafHash[0] ^= 0xFF
	fresh, err := log.Entry(0)
	require.NoError(t, err)
	require.False(t, bytes.Equal(fresh.LeafHash, e.LeafHash))
}

// -------------------------------------------------------------------
// Entry / Size / Head
// -------------------------------------------------------------------

func TestEntry_OutOfRangeRejected(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	appendN(t, log, 3)
	_, err := log.Entry(5)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
}

func TestSize_TracksAppendCount(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	require.Zero(t, log.Size())
	appendN(t, log, 4)
	require.Equal(t, uint64(4), log.Size())
}

func TestHead_EmptyLogYieldsZeroTreeSTH(t *testing.T) {
	t.Parallel()
	log, store, _ := newLog(t)
	sth, err := log.Head()
	require.NoError(t, err)
	require.Equal(t, uint64(0), sth.TreeSize)
	require.True(t, bytes.Equal(sth.TreeHash, zeros32()))
	require.True(t, bytes.Equal(sth.TreeChainHead, zeros32()))
	require.NoError(t, sth.Validate())
	require.NoError(t, sth.VerifySignature(store))
}

func TestHead_PopulatedLogMatchesMerkleRoot(t *testing.T) {
	t.Parallel()
	log, store, _ := newLog(t)
	entries := appendN(t, log, 5)

	sth, err := log.Head()
	require.NoError(t, err)
	require.Equal(t, uint64(5), sth.TreeSize)
	require.NoError(t, sth.Validate())
	require.NoError(t, sth.VerifySignature(store))

	// Cross-check TreeChainHead equals the tail LeafHash.
	require.True(t, bytes.Equal(sth.TreeChainHead, entries[4].LeafHash))

	// Cross-check TreeHash equals ComputeMerkleRoot over the leaves.
	leaves := make([][]byte, len(entries))
	for i := range entries {
		leaves[i] = append([]byte(nil), entries[i].LeafHash...)
	}
	expectedRoot, err := contract.ComputeMerkleRoot(leaves)
	require.NoError(t, err)
	require.True(t, bytes.Equal(sth.TreeHash, expectedRoot))
}

// -------------------------------------------------------------------
// InclusionProof round-trip + out-of-range
// -------------------------------------------------------------------

func TestInclusionProof_RoundTripAcrossSizes(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	entries := appendN(t, log, 6)

	// For every attainable (size, leafIndex) pair, the returned proof
	// must verify against the log's corresponding STH.
	for size := uint64(1); size <= uint64(len(entries)); size++ {
		leaves := make([][]byte, size)
		for i := uint64(0); i < size; i++ {
			leaves[i] = append([]byte(nil), entries[i].LeafHash...)
		}
		root, err := contract.ComputeMerkleRoot(leaves)
		require.NoError(t, err)

		for idx := uint64(0); idx < size; idx++ {
			proof, err := log.InclusionProof(idx, size)
			require.NoError(t, err, "size=%d idx=%d", size, idx)
			require.Equal(t, idx, proof.LeafIndex)
			require.Equal(t, size, proof.TreeSize)
			require.NoError(t, contract.VerifyInclusion(leaves[idx], proof, root),
				"size=%d idx=%d", size, idx)
		}
	}
}

func TestInclusionProof_RejectsOutOfRange(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	appendN(t, log, 3)

	_, err := log.InclusionProof(0, 0)
	require.Error(t, err)

	_, err = log.InclusionProof(0, 99)
	require.Error(t, err)

	_, err = log.InclusionProof(5, 3)
	require.Error(t, err)
}

// -------------------------------------------------------------------
// ConsistencyProof round-trip + edge cases
// -------------------------------------------------------------------

func TestConsistencyProof_RoundTripAcrossSizes(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	entries := appendN(t, log, 6)

	for newSize := uint64(1); newSize <= uint64(len(entries)); newSize++ {
		leavesNew := make([][]byte, newSize)
		for i := uint64(0); i < newSize; i++ {
			leavesNew[i] = append([]byte(nil), entries[i].LeafHash...)
		}
		rootNew, err := contract.ComputeMerkleRoot(leavesNew)
		require.NoError(t, err)

		for oldSize := uint64(1); oldSize <= newSize; oldSize++ {
			leavesOld := leavesNew[:oldSize]
			rootOld, err := contract.ComputeMerkleRoot(leavesOld)
			require.NoError(t, err)

			proof, err := log.ConsistencyProof(oldSize, newSize)
			require.NoError(t, err, "old=%d new=%d", oldSize, newSize)
			require.Equal(t, oldSize, proof.OldSize)
			require.Equal(t, newSize, proof.NewSize)
			require.NoError(t, contract.VerifyConsistency(rootOld, rootNew, proof),
				"old=%d new=%d", oldSize, newSize)
		}
	}
}

func TestConsistencyProof_EmptyOldTree(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	appendN(t, log, 3)
	proof, err := log.ConsistencyProof(0, 3)
	require.NoError(t, err)
	require.Equal(t, uint64(0), proof.OldSize)
	require.Equal(t, uint64(3), proof.NewSize)
	require.Empty(t, proof.Path)
}

func TestConsistencyProof_RejectsOldGreaterThanNew(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	appendN(t, log, 3)
	_, err := log.ConsistencyProof(4, 2)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestConsistencyProof_RejectsNewOutOfRange(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	appendN(t, log, 3)
	_, err := log.ConsistencyProof(2, 99)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
}

// -------------------------------------------------------------------
// Receipt end-to-end
// -------------------------------------------------------------------

func TestReceipt_RoundTripVerify(t *testing.T) {
	t.Parallel()
	log, store, _ := newLog(t)
	entries := appendN(t, log, 5)

	for i := range entries {
		receipt, err := log.Receipt(uint64(i))
		require.NoError(t, err, "idx=%d", i)
		require.NoError(t, receipt.Verify(store), "idx=%d", i)
		require.Equal(t, entries[i].EntryID, receipt.Entry.EntryID)
	}
}

func TestReceipt_OutOfRangeRejected(t *testing.T) {
	t.Parallel()
	log, _, _ := newLog(t)
	appendN(t, log, 2)
	_, err := log.Receipt(99)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
}

// -------------------------------------------------------------------
// End-to-end fork detection across two divergent logs
// -------------------------------------------------------------------

func TestTwoLogs_DifferentContent_DetectedAsFork(t *testing.T) {
	t.Parallel()
	// Two operators under the SAME signing kid (simulates a compromised
	// witness key that has been used to sign a second, divergent
	// history). In our threat model this is the textbook fork signal
	// DetectFork must catch.
	kid := ids.KeyID("witness-op-shared")
	store := keys.NewInMemoryStore(nil)
	_, err := store.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)

	clockA := shared_time.NewFakeClock(defaultBaseTime())
	clockB := shared_time.NewFakeClock(defaultBaseTime().Add(time.Hour))
	logA, err := witness.NewInMemoryLog(store, kid, clockA)
	require.NoError(t, err)
	logB, err := witness.NewInMemoryLog(store, kid, clockB)
	require.NoError(t, err)

	base := defaultBaseTime()
	// A's history: seeds 0, 1, 2.
	_, err = logA.Append(samplePayload(0, base))
	require.NoError(t, err)
	_, err = logA.Append(samplePayload(1, base.Add(time.Second)))
	require.NoError(t, err)
	_, err = logA.Append(samplePayload(2, base.Add(2*time.Second)))
	require.NoError(t, err)

	// B's history: different payload at index 0 (seed 7).
	_, err = logB.Append(samplePayload(7, base))
	require.NoError(t, err)
	_, err = logB.Append(samplePayload(1, base.Add(time.Second)))
	require.NoError(t, err)
	_, err = logB.Append(samplePayload(2, base.Add(2*time.Second)))
	require.NoError(t, err)

	sthA, err := logA.Head()
	require.NoError(t, err)
	sthB, err := logB.Head()
	require.NoError(t, err)

	ev, err := contract.DetectFork(sthA, sthB, nil)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, contract.ForkKindSameSizeDifferentRoot, ev.Kind)
	require.True(t, ev.Kind.IsIncident())

	// AsError routes to CategoryIncident.
	err = ev.AsError()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeTamperSignal, shared_errors.CodeOf(err))
}

// -------------------------------------------------------------------
// Concurrency smoke — the log must stay self-consistent under a
// single writer and many concurrent readers.
// -------------------------------------------------------------------

func TestInMemoryLog_ConcurrentReadsStayConsistent(t *testing.T) {
	t.Parallel()
	log, store, _ := newLog(t)
	appendN(t, log, 8)

	var wg sync.WaitGroup
	const readers = 16
	wg.Add(readers)
	errCh := make(chan error, readers)

	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				sth, err := log.Head()
				if err != nil {
					errCh <- err
					return
				}
				if err := sth.VerifySignature(store); err != nil {
					errCh <- err
					return
				}
				for idx := uint64(0); idx < log.Size(); idx++ {
					receipt, err := log.Receipt(idx)
					if err != nil {
						errCh <- err
						return
					}
					if err := receipt.Verify(store); err != nil {
						errCh <- err
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}
