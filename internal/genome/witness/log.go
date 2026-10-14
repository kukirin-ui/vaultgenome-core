// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness

import (
	"sync"

	contract "github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Log is the operator-facing interface to a witness transparency log.
//
// Implementations are the single source of truth for Index ordering,
// PrevLeafHash threading, and STH signing. Receivers of receipts issued
// by a Log need only the /internal/contracts/witness package to verify
// them — Log is never reachable across a trust boundary.
type Log interface {
	// Append commits a new entry at the tail. The caller supplies the
	// payload fields (Timestamp, GenomeID, the three roots, and
	// optionally ParentGenomeID + DerivationMethod). The log assigns
	// Index, PrevLeafHash, and SchemaVersion (if unset), derives
	// LeafHash and EntryID, and returns a fresh copy of the committed
	// entry.
	//
	// Append rejects an entry whose Timestamp is strictly earlier than
	// the previous entry's Timestamp (Incident — time rollback).
	Append(entry contract.LogEntry) (*contract.LogEntry, error)

	// Head returns a freshly-signed STH covering the current tree.
	// Timestamp is the Log's clock at call time, and never earlier than
	// the newest entry the STH covers: a head cannot predate what it
	// commits to, and the receipt contract refuses one that does.
	Head() (*contract.SignedTreeHead, error)

	// Size returns the number of entries committed.
	Size() uint64

	// Entry returns a fresh copy of the entry at the given index.
	// Out-of-range index returns Operational.
	Entry(index uint64) (*contract.LogEntry, error)

	// InclusionProof builds an inclusion proof for the leaf at
	// leafIndex within the tree snapshot of size treeSize.
	// Requirements: leafIndex < treeSize <= Size().
	InclusionProof(leafIndex, treeSize uint64) (*contract.InclusionProof, error)

	// ConsistencyProof builds an RFC 6962 consistency proof bridging
	// oldSize and newSize. Requirements: oldSize <= newSize <= Size().
	// oldSize == 0 is legal — the proof is empty.
	ConsistencyProof(oldSize, newSize uint64) (*contract.ConsistencyProof, error)

	// Receipt is a convenience: builds a WitnessReceipt for the entry
	// at index against a freshly-issued STH covering the current tree.
	Receipt(index uint64) (*contract.WitnessReceipt, error)
}

// ---- in-memory implementation ---------------------------------------------

// InMemoryLog is the MVP Log. It keeps entries and their derived
// LeafHashes in process memory under a mutex. Production deployments
// replace it with a sealed, disk-backed implementation whose bytes
// are additionally protected by a TEE-scoped sealing key.
//
// Concurrency: safe for any number of concurrent readers and a single
// writer. Append holds a write-lock for the duration of the commit;
// all other methods take the read-lock.
type InMemoryLog struct {
	mu     sync.RWMutex
	signer keys.Signer
	kid    ids.KeyID
	clock  shared_time.Clock

	// entries holds the committed sequence. entries[i].Index == i.
	entries []contract.LogEntry
	// leaves is the parallel LeafHash slice, cached so proof builders
	// don't re-derive from raw payloads on every query.
	leaves [][]byte
}

// NewInMemoryLog constructs an empty log. signer is required; kid must
// refer to a signing key registered under PurposeSigningWitness in the
// signer's underlying keystore. clock may be nil — the system clock is
// used then.
//
// The constructor does NOT eagerly verify the signer accepts kid with
// PurposeSigningWitness. That check happens on the first Head()/STH
// signing attempt; a misconfigured key surfaces as Integrity there.
func NewInMemoryLog(signer keys.Signer, kid ids.KeyID, clock shared_time.Clock) (*InMemoryLog, error) {
	if signer == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"witness-log: signer required",
			nil,
		)
	}
	if kid.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"witness-log: signing key id required",
			nil,
		)
	}
	if clock == nil {
		clock = shared_time.SystemClock{}
	}
	return &InMemoryLog{
		signer: signer,
		kid:    kid,
		clock:  clock,
	}, nil
}

// Append implements Log.Append.
func (l *InMemoryLog) Append(entry contract.LogEntry) (*contract.LogEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	index := uint64(len(l.entries))
	// Caller-supplied Index/LeafHash/EntryID/PrevLeafHash are ignored;
	// the log is the authority on those four fields.
	entry.Index = index
	entry.LeafHash = nil
	entry.EntryID = ""
	if entry.SchemaVersion == 0 {
		entry.SchemaVersion = contract.SchemaVersionCurrent
	}

	// Threading: genesis ⇒ all-zero PrevLeafHash; otherwise ⇒ previous
	// entry's LeafHash.
	if index == 0 {
		entry.PrevLeafHash = make([]byte, crypto.HashSize)
	} else {
		prev := l.leaves[index-1]
		entry.PrevLeafHash = append([]byte(nil), prev...)
	}

	// Monotonic time gate: reject a strictly-earlier Timestamp as an
	// Incident. We do NOT force equality — operators may legitimately
	// batch entries under one wall-clock tick.
	if index > 0 {
		prevTs := l.entries[index-1].Timestamp
		if entry.Timestamp.Before(prevTs) {
			return nil, shared_errors.Incident(
				shared_errors.CodeTamperSignal,
				"witness-log: non-monotonic timestamp at append",
				nil,
			)
		}
	}

	leaf, entryID, err := entry.DeriveLeafHashAndID()
	if err != nil {
		return nil, err
	}
	entry.LeafHash = leaf
	entry.EntryID = entryID

	// Defense in depth: entry MUST pass its own Validate before we
	// commit. A pass here means the committed tail is self-consistent.
	if err := entry.Validate(); err != nil {
		return nil, err
	}

	l.entries = append(l.entries, entry)
	l.leaves = append(l.leaves, append([]byte(nil), leaf...))

	// Return a caller-owned copy.
	copied := cloneEntry(&entry)
	return copied, nil
}

// Head implements Log.Head.
func (l *InMemoryLog) Head() (*contract.SignedTreeHead, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.headLocked(uint64(len(l.entries)))
}

// Size implements Log.Size.
func (l *InMemoryLog) Size() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return uint64(len(l.entries))
}

// Entry implements Log.Entry.
func (l *InMemoryLog) Entry(index uint64) (*contract.LogEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index >= uint64(len(l.entries)) {
		return nil, shared_errors.Operational(
			"witness_log_index_out_of_range",
			"witness-log: entry index out of range",
			nil,
		)
	}
	return cloneEntry(&l.entries[index]), nil
}

// InclusionProof implements Log.InclusionProof.
func (l *InMemoryLog) InclusionProof(leafIndex, treeSize uint64) (*contract.InclusionProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	size := uint64(len(l.entries))
	if treeSize == 0 || treeSize > size {
		return nil, shared_errors.Operational(
			"witness_log_tree_size_out_of_range",
			"witness-log: inclusion proof tree_size out of range",
			nil,
		)
	}
	if leafIndex >= treeSize {
		return nil, shared_errors.Operational(
			"witness_log_leaf_index_out_of_range",
			"witness-log: inclusion proof leaf_index out of range",
			nil,
		)
	}

	snapshot := cloneLeaves(l.leaves[:treeSize])
	path := buildInclusionPathInternal(snapshot, int(leafIndex))
	return &contract.InclusionProof{
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
		Path:      path,
	}, nil
}

// ConsistencyProof implements Log.ConsistencyProof.
func (l *InMemoryLog) ConsistencyProof(oldSize, newSize uint64) (*contract.ConsistencyProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	size := uint64(len(l.entries))
	if newSize > size {
		return nil, shared_errors.Operational(
			"witness_log_tree_size_out_of_range",
			"witness-log: consistency proof new_size out of range",
			nil,
		)
	}
	if oldSize > newSize {
		return nil, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"witness-log: consistency proof old_size > new_size",
			nil,
		)
	}

	var path [][]byte
	if oldSize != 0 && oldSize != newSize {
		snapshot := cloneLeaves(l.leaves[:newSize])
		path = subproofInternal(int(oldSize), snapshot, true)
	}
	return &contract.ConsistencyProof{
		OldSize: oldSize,
		NewSize: newSize,
		Path:    path,
	}, nil
}

// Receipt implements Log.Receipt.
func (l *InMemoryLog) Receipt(index uint64) (*contract.WitnessReceipt, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	size := uint64(len(l.entries))
	if index >= size {
		return nil, shared_errors.Operational(
			"witness_log_index_out_of_range",
			"witness-log: receipt index out of range",
			nil,
		)
	}

	sth, err := l.headLocked(size)
	if err != nil {
		return nil, err
	}

	snapshot := cloneLeaves(l.leaves[:size])
	path := buildInclusionPathInternal(snapshot, int(index))

	return &contract.WitnessReceipt{
		SchemaVersion: contract.SchemaVersionCurrent,
		Entry:         *cloneEntry(&l.entries[index]),
		InclusionProof: contract.InclusionProof{
			LeafIndex: index,
			TreeSize:  size,
			Path:      path,
		},
		STH: *sth,
	}, nil
}

// ---- internals -------------------------------------------------------------

// headLocked builds and signs an STH covering the first size entries.
// Caller MUST hold at least the read lock.
func (l *InMemoryLog) headLocked(size uint64) (*contract.SignedTreeHead, error) {
	if size > uint64(len(l.entries)) {
		return nil, shared_errors.Operational(
			"witness_log_tree_size_out_of_range",
			"witness-log: STH size out of range",
			nil,
		)
	}

	// The STH's timestamp is the clock's, and never earlier than the
	// newest entry it covers: an entry may carry a caller-supplied
	// timestamp ahead of this log's clock (a batch stamped by the
	// producer, a clock that lags), and a head that claims to predate
	// what it commits to is nonsensical — the receipt contract refuses
	// it. Entries are monotonic at Append, so the newest is the latest.
	ts := l.clock.Now().UTC()
	if size > 0 {
		if newest := l.entries[size-1].Timestamp.UTC(); newest.After(ts) {
			ts = newest
		}
	}
	sth := &contract.SignedTreeHead{
		SchemaVersion: contract.SchemaVersionCurrent,
		TreeSize:      size,
		Timestamp:     ts,
		SigningKeyID:  l.kid,
	}
	if size == 0 {
		sth.TreeHash = make([]byte, crypto.HashSize)
		sth.TreeChainHead = make([]byte, crypto.HashSize)
	} else {
		snapshot := cloneLeaves(l.leaves[:size])
		root, err := contract.ComputeMerkleRoot(snapshot)
		if err != nil {
			return nil, err
		}
		sth.TreeHash = root
		sth.TreeChainHead = append([]byte(nil), l.leaves[size-1]...)
	}
	if err := sth.SignWith(l.signer); err != nil {
		return nil, err
	}
	return sth, nil
}

// cloneEntry returns a deep copy whose byte slices are independent of
// the argument's. Used to hand out caller-owned views of stored entries.
func cloneEntry(e *contract.LogEntry) *contract.LogEntry {
	if e == nil {
		return nil
	}
	out := *e
	out.PrevLeafHash = append([]byte(nil), e.PrevLeafHash...)
	out.LeafHash = append([]byte(nil), e.LeafHash...)
	out.AttestationRoot = append([]byte(nil), e.AttestationRoot...)
	out.BatteryMerkleRoot = append([]byte(nil), e.BatteryMerkleRoot...)
	out.ScorecardRoot = append([]byte(nil), e.ScorecardRoot...)
	return &out
}

// cloneLeaves returns an independent copy of a []byte slice-of-slices.
// The outer slice AND every inner slice are fresh — modifications to
// either don't affect the source.
func cloneLeaves(src [][]byte) [][]byte {
	out := make([][]byte, len(src))
	for i := range src {
		out[i] = append([]byte(nil), src[i]...)
	}
	return out
}

// buildInclusionPathInternal mirrors the RFC 6962 audit-path builder.
// Kept internal so the operator side and the tests-side helper remain
// independent — a bug in one will not silently agree with the same bug
// in the other.
func buildInclusionPathInternal(leaves [][]byte, m int) [][]byte {
	if len(leaves) <= 1 {
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
			h, err := contract.CombineNodes(level[i], level[i+1])
			if err != nil {
				// All leaves come from our own store; a wrong-size
				// slice here means memory corruption. Panic — the
				// log's invariants have been violated.
				panic("witness-log: CombineNodes failed on own leaves: " + err.Error())
			}
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

// subproofInternal implements RFC 6962 SUBPROOF(m, D, b). See §2.1.2.
func subproofInternal(m int, leaves [][]byte, isFirst bool) [][]byte {
	n := len(leaves)
	if m == n {
		if isFirst {
			return nil
		}
		r, err := contract.ComputeMerkleRoot(leaves)
		if err != nil {
			panic("witness-log: ComputeMerkleRoot failed on own leaves: " + err.Error())
		}
		return [][]byte{r}
	}
	k := largestPow2Less(n)
	if m <= k {
		r, err := contract.ComputeMerkleRoot(leaves[k:])
		if err != nil {
			panic("witness-log: ComputeMerkleRoot failed on own leaves: " + err.Error())
		}
		sub := subproofInternal(m, leaves[:k], isFirst)
		return append(sub, r)
	}
	r, err := contract.ComputeMerkleRoot(leaves[:k])
	if err != nil {
		panic("witness-log: ComputeMerkleRoot failed on own leaves: " + err.Error())
	}
	sub := subproofInternal(m-k, leaves[k:], false)
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

// Statically ensure InMemoryLog satisfies Log. The blank reference
// keeps a compile-time guard without a runtime cost.
var _ Log = (*InMemoryLog)(nil)
