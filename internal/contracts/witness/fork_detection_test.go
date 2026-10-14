// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// -------------------------------------------------------------------
// Construction helpers local to the fork-detection suite
// -------------------------------------------------------------------

// handSTH builds a SignedTreeHead with caller-specified roots and
// signs it under kid. It deliberately bypasses the Merkle-root
// computation so tests can construct STHs whose TreeHash /
// TreeChainHead are fabricated — the only way to exercise
// same-size-different-root and same-size-different-chain-head
// branches without a hash collision.
func handSTH(
	t *testing.T,
	store *keys.InMemoryStore,
	kid ids.KeyID,
	treeSize uint64,
	treeHash, treeChainHead []byte,
	ts time.Time,
) *witness.SignedTreeHead {
	t.Helper()
	sth := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      treeSize,
		TreeHash:      append([]byte(nil), treeHash...),
		TreeChainHead: append([]byte(nil), treeChainHead...),
		Timestamp:     ts,
		SigningKeyID:  kid,
	}
	require.NoError(t, sth.SignWith(store))
	return sth
}

// -------------------------------------------------------------------
// Argument-validation gates
// -------------------------------------------------------------------

func TestDetectFork_RejectsNilA(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	b := newSignedSTH(t, store, kid, buildChain(t, 2), defaultBaseTime())

	_, err := witness.DetectFork(nil, b, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestDetectFork_RejectsNilB(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	a := newSignedSTH(t, store, kid, buildChain(t, 2), defaultBaseTime())

	_, err := witness.DetectFork(a, nil, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestDetectFork_PropagatesInvalidSTHValidation(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	valid := newSignedSTH(t, store, kid, buildChain(t, 2), defaultBaseTime())

	// Invalid singleton: TreeHash != TreeChainHead — Validate() rejects.
	invalid := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      1,
		TreeHash:      repeat(0xAA, crypto.HashSize),
		TreeChainHead: repeat(0xBB, crypto.HashSize),
		Timestamp:     defaultBaseTime(),
		SigningKeyID:  kid,
		Signature:     []byte{1, 2, 3},
	}
	_, err := witness.DetectFork(valid, invalid, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

// -------------------------------------------------------------------
// Happy paths — no fork
// -------------------------------------------------------------------

func TestDetectFork_SameSizeSameContents_NoFork(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 4)

	// Two STHs at the same tree size with IDENTICAL roots and chain
	// heads, but different issuance timestamps — consistent re-publish.
	a := newSignedSTH(t, store, kid, entries, defaultBaseTime())
	b := newSignedSTH(t, store, kid, entries, defaultBaseTime().Add(time.Hour))

	ev, err := witness.DetectFork(a, b, nil)
	require.NoError(t, err)
	require.Nil(t, ev)
}

func TestDetectFork_HonestAppend_WithValidProof(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)

	// buildChain is deterministic per index, so entriesNew extends
	// entriesOld byte-for-byte in the shared prefix.
	entriesOld := buildChain(t, 3)
	entriesNew := buildChain(t, 5)

	a := newSignedSTH(t, store, kid, entriesOld, defaultBaseTime())
	b := newSignedSTH(t, store, kid, entriesNew, defaultBaseTime().Add(time.Minute))

	path := buildConsistencyPath(t, leafHashes(entriesNew), 3)
	proof := &witness.ConsistencyProof{OldSize: 3, NewSize: 5, Path: path}

	ev, err := witness.DetectFork(a, b, proof)
	require.NoError(t, err)
	require.Nil(t, ev)
}

func TestDetectFork_ArgumentOrderIndependent(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entriesOld := buildChain(t, 3)
	entriesNew := buildChain(t, 5)

	a := newSignedSTH(t, store, kid, entriesOld, defaultBaseTime())
	b := newSignedSTH(t, store, kid, entriesNew, defaultBaseTime().Add(time.Minute))
	path := buildConsistencyPath(t, leafHashes(entriesNew), 3)
	proof := &witness.ConsistencyProof{OldSize: 3, NewSize: 5, Path: path}

	// (a, b) reports no fork.
	ev, err := witness.DetectFork(a, b, proof)
	require.NoError(t, err)
	require.Nil(t, ev)

	// (b, a) — reversed argument order — MUST agree.
	ev, err = witness.DetectFork(b, a, proof)
	require.NoError(t, err)
	require.Nil(t, ev)
}

// -------------------------------------------------------------------
// Fork kind — same size, different root
// -------------------------------------------------------------------

func TestDetectFork_SameSizeDifferentRoot(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 3)

	a := newSignedSTH(t, store, kid, entries, defaultBaseTime())
	// Fabricate an alternate history at the same size — different root.
	b := handSTH(t, store, kid, 3,
		repeat(0xCC, crypto.HashSize), // bogus tree hash
		repeat(0xDD, crypto.HashSize), // bogus chain head
		defaultBaseTime().Add(time.Second),
	)

	ev, err := witness.DetectFork(a, b, nil)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindSameSizeDifferentRoot, ev.Kind)
	require.True(t, ev.Kind.IsIncident())
	// Normalized ordering: A has TreeSize <= B.TreeSize.
	require.LessOrEqual(t, ev.A.TreeSize, ev.B.TreeSize)
}

// -------------------------------------------------------------------
// Fork kind — same size, same root, different chain head
// -------------------------------------------------------------------

func TestDetectFork_SameSizeDifferentChainHead(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)

	// Fabricate both STHs with the SAME TreeHash but DIFFERENT
	// TreeChainHead. Cryptographically impossible in practice, but
	// defensive-in-depth: DetectFork must still catch it.
	commonRoot := repeat(0xAA, crypto.HashSize)
	a := handSTH(t, store, kid, 3, commonRoot, repeat(0xBB, crypto.HashSize), defaultBaseTime())
	b := handSTH(t, store, kid, 3, commonRoot, repeat(0xCC, crypto.HashSize), defaultBaseTime().Add(time.Second))

	ev, err := witness.DetectFork(a, b, nil)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindSameSizeDifferentChainHead, ev.Kind)
	require.True(t, ev.Kind.IsIncident())
}

// -------------------------------------------------------------------
// Fork kind — timestamp non-monotonic
// -------------------------------------------------------------------

func TestDetectFork_TimestampNonMonotonic(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entriesOld := buildChain(t, 3)
	entriesNew := buildChain(t, 5)

	// The LARGER tree is issued BEFORE the smaller one — impossible
	// for an honest append-only log.
	a := newSignedSTH(t, store, kid, entriesOld, defaultBaseTime().Add(time.Hour))
	b := newSignedSTH(t, store, kid, entriesNew, defaultBaseTime()) // earlier

	path := buildConsistencyPath(t, leafHashes(entriesNew), 3)
	proof := &witness.ConsistencyProof{OldSize: 3, NewSize: 5, Path: path}

	ev, err := witness.DetectFork(a, b, proof)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindTimestampNonMonotonic, ev.Kind)
	require.True(t, ev.Kind.IsIncident())
	require.LessOrEqual(t, ev.A.TreeSize, ev.B.TreeSize)
}

// -------------------------------------------------------------------
// Fork kind — inconsistent proof (4 variants)
// -------------------------------------------------------------------

func TestDetectFork_InconsistentProof_MissingWhenSizesDiffer(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	a := newSignedSTH(t, store, kid, buildChain(t, 3), defaultBaseTime())
	b := newSignedSTH(t, store, kid, buildChain(t, 5), defaultBaseTime().Add(time.Minute))

	// No proof supplied for differing sizes — Incident.
	ev, err := witness.DetectFork(a, b, nil)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindInconsistentProof, ev.Kind)
	require.True(t, ev.Kind.IsIncident())
}

func TestDetectFork_InconsistentProof_SizesDisagreeWithSTHs(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entriesOld := buildChain(t, 3)
	entriesNew := buildChain(t, 5)
	a := newSignedSTH(t, store, kid, entriesOld, defaultBaseTime())
	b := newSignedSTH(t, store, kid, entriesNew, defaultBaseTime().Add(time.Minute))

	// Proof carries (2, 4) — doesn't match (3, 5).
	path := buildConsistencyPath(t, leafHashes(entriesNew), 2)
	proof := &witness.ConsistencyProof{OldSize: 2, NewSize: 4, Path: path}

	ev, err := witness.DetectFork(a, b, proof)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindInconsistentProof, ev.Kind)
	require.True(t, ev.Kind.IsIncident())
}

func TestDetectFork_InconsistentProof_TamperedPath(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entriesOld := buildChain(t, 3)
	entriesNew := buildChain(t, 5)
	a := newSignedSTH(t, store, kid, entriesOld, defaultBaseTime())
	b := newSignedSTH(t, store, kid, entriesNew, defaultBaseTime().Add(time.Minute))

	path := buildConsistencyPath(t, leafHashes(entriesNew), 3)
	require.NotEmpty(t, path, "fixture must yield a non-empty path")
	path[0] = append([]byte(nil), path[0]...)
	path[0][0] ^= 0xFF

	proof := &witness.ConsistencyProof{OldSize: 3, NewSize: 5, Path: path}

	ev, err := witness.DetectFork(a, b, proof)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindInconsistentProof, ev.Kind)
	require.True(t, ev.Kind.IsIncident())
}

func TestDetectFork_InconsistentProof_ForksWithForgedNewRoot(t *testing.T) {
	t.Parallel()
	// Operator signs a NEW STH that CAN'T be reached from the old
	// one — classic split-brain. We forge b's TreeHash to a random
	// value; VerifyConsistency will reject it.
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entriesOld := buildChain(t, 3)
	a := newSignedSTH(t, store, kid, entriesOld, defaultBaseTime())

	forgedNewHash := repeat(0xEE, crypto.HashSize)
	forgedChainHead := repeat(0xFE, crypto.HashSize)
	b := handSTH(t, store, kid, 5, forgedNewHash, forgedChainHead, defaultBaseTime().Add(time.Minute))

	// Caller supplies any path — the sizes match the STHs, so we get
	// past the size gate, then VerifyConsistency fails against the
	// forged root.
	path := buildConsistencyPath(t, leafHashes(buildChain(t, 5)), 3)
	proof := &witness.ConsistencyProof{OldSize: 3, NewSize: 5, Path: path}

	ev, err := witness.DetectFork(a, b, proof)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindInconsistentProof, ev.Kind)
	require.True(t, ev.Kind.IsIncident())
}

// -------------------------------------------------------------------
// Fork kind — different signers
// -------------------------------------------------------------------

func TestDetectFork_DifferentSigners_StructuralNotIncident(t *testing.T) {
	t.Parallel()
	// Two different operators legitimately sign different STHs. This
	// is NOT an incident — it is a caller-level book-keeping error.
	kid1 := ids.KeyID("witness-op-alpha")
	kid2 := ids.KeyID("witness-op-beta")

	store := keys.NewInMemoryStore(nil)
	_, err := store.GenerateSigning(kid1, keys.PurposeSigningWitness)
	require.NoError(t, err)
	_, err = store.GenerateSigning(kid2, keys.PurposeSigningWitness)
	require.NoError(t, err)

	entries := buildChain(t, 3)

	a := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      uint64(len(entries)),
		Timestamp:     defaultBaseTime(),
		SigningKeyID:  kid1,
	}
	root, err := witness.ComputeMerkleRoot(leafHashes(entries))
	require.NoError(t, err)
	a.TreeHash = root
	a.TreeChainHead = append([]byte(nil), entries[len(entries)-1].LeafHash...)
	require.NoError(t, a.SignWith(store))

	b := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      uint64(len(entries)),
		Timestamp:     defaultBaseTime().Add(time.Second),
		SigningKeyID:  kid2,
	}
	b.TreeHash = append([]byte(nil), root...)
	b.TreeChainHead = append([]byte(nil), entries[len(entries)-1].LeafHash...)
	require.NoError(t, b.SignWith(store))

	ev, err := witness.DetectFork(a, b, nil)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindDifferentSigners, ev.Kind)
	require.False(t, ev.Kind.IsIncident())
}

func TestDetectFork_DifferentSigners_GateFiresBeforeRootCheck(t *testing.T) {
	t.Parallel()
	// Even when the two STHs would OTHERWISE look like a
	// same-size-different-root fork, the different-signers gate must
	// fire FIRST — otherwise cross-operator comparisons get
	// mis-routed to Incident.
	kid1 := ids.KeyID("witness-op-alpha")
	kid2 := ids.KeyID("witness-op-beta")

	store := keys.NewInMemoryStore(nil)
	_, err := store.GenerateSigning(kid1, keys.PurposeSigningWitness)
	require.NoError(t, err)
	_, err = store.GenerateSigning(kid2, keys.PurposeSigningWitness)
	require.NoError(t, err)

	a := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      3,
		TreeHash:      repeat(0xAA, crypto.HashSize),
		TreeChainHead: repeat(0xAB, crypto.HashSize),
		Timestamp:     defaultBaseTime(),
		SigningKeyID:  kid1,
	}
	require.NoError(t, a.SignWith(store))

	b := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      3,
		TreeHash:      repeat(0xCC, crypto.HashSize), // different root
		TreeChainHead: repeat(0xCD, crypto.HashSize),
		Timestamp:     defaultBaseTime().Add(time.Second),
		SigningKeyID:  kid2,
	}
	require.NoError(t, b.SignWith(store))

	ev, err := witness.DetectFork(a, b, nil)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindDifferentSigners, ev.Kind)
}

// -------------------------------------------------------------------
// ForkKind.IsIncident matrix
// -------------------------------------------------------------------

func TestForkKind_IsIncident_Matrix(t *testing.T) {
	t.Parallel()
	require.True(t, witness.ForkKindSameSizeDifferentRoot.IsIncident())
	require.True(t, witness.ForkKindSameSizeDifferentChainHead.IsIncident())
	require.True(t, witness.ForkKindTimestampNonMonotonic.IsIncident())
	require.True(t, witness.ForkKindInconsistentProof.IsIncident())
	require.False(t, witness.ForkKindDifferentSigners.IsIncident())
	// Unknown/garbage kinds are NOT incidents.
	require.False(t, witness.ForkKind("").IsIncident())
	require.False(t, witness.ForkKind("not_a_kind").IsIncident())
}

// -------------------------------------------------------------------
// ForkEvidence.AsError routing
// -------------------------------------------------------------------

func TestForkEvidence_AsError_Incident(t *testing.T) {
	t.Parallel()
	for _, kind := range []witness.ForkKind{
		witness.ForkKindSameSizeDifferentRoot,
		witness.ForkKindSameSizeDifferentChainHead,
		witness.ForkKindTimestampNonMonotonic,
		witness.ForkKindInconsistentProof,
	} {
		ev := &witness.ForkEvidence{Kind: kind, Detail: "t"}
		err := ev.AsError()
		require.Error(t, err, "kind=%s", kind)
		require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err), "kind=%s", kind)
		require.Equal(t, shared_errors.CodeTamperSignal, shared_errors.CodeOf(err), "kind=%s", kind)
	}
}

func TestForkEvidence_AsError_DifferentSignersIsStructural(t *testing.T) {
	t.Parallel()
	ev := &witness.ForkEvidence{Kind: witness.ForkKindDifferentSigners, Detail: "t"}
	err := ev.AsError()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestForkEvidence_AsError_NilReceiver(t *testing.T) {
	t.Parallel()
	var ev *witness.ForkEvidence
	require.NoError(t, ev.AsError())
}
