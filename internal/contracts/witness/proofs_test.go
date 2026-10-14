// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// TestVerifyInclusion_RoundTripAcrossSizes exercises inclusion-proof
// correctness at every leaf index for every tree size from 1 to 10.
// Covers singleton, power-of-two, odd, and ragged right-spine cases.
func TestVerifyInclusion_RoundTripAcrossSizes(t *testing.T) {
	t.Parallel()
	for size := 1; size <= 10; size++ {
		entries := buildChain(t, size)
		leaves := leafHashes(entries)
		root, err := witness.ComputeMerkleRoot(leaves)
		require.NoError(t, err)

		for idx := 0; idx < size; idx++ {
			path := buildInclusionPath(t, leaves, idx)
			proof := &witness.InclusionProof{
				LeafIndex: uint64(idx),
				TreeSize:  uint64(size),
				Path:      path,
			}
			err := witness.VerifyInclusion(leaves[idx], proof, root)
			require.NoError(t, err, "size=%d idx=%d", size, idx)
		}
	}
}

func TestVerifyInclusion_RejectsTamperedLeaf(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 5)
	leaves := leafHashes(entries)
	root, err := witness.ComputeMerkleRoot(leaves)
	require.NoError(t, err)

	idx := 3
	path := buildInclusionPath(t, leaves, idx)
	tampered := append([]byte(nil), leaves[idx]...)
	tampered[0] ^= 0xFF

	proof := &witness.InclusionProof{
		LeafIndex: uint64(idx),
		TreeSize:  uint64(len(leaves)),
		Path:      path,
	}
	err = witness.VerifyInclusion(tampered, proof, root)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_RejectsWrongRoot(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 5)
	leaves := leafHashes(entries)
	idx := 2
	path := buildInclusionPath(t, leaves, idx)
	bogusRoot := repeat(0xEE, crypto.HashSize)

	proof := &witness.InclusionProof{
		LeafIndex: uint64(idx),
		TreeSize:  uint64(len(leaves)),
		Path:      path,
	}
	err := witness.VerifyInclusion(leaves[idx], proof, bogusRoot)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_PathTooLong(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 3)
	leaves := leafHashes(entries)
	root, err := witness.ComputeMerkleRoot(leaves)
	require.NoError(t, err)
	idx := 2
	path := buildInclusionPath(t, leaves, idx)
	path = append(path, repeat(0xAA, crypto.HashSize))

	proof := &witness.InclusionProof{
		LeafIndex: uint64(idx),
		TreeSize:  uint64(len(leaves)),
		Path:      path,
	}
	err = witness.VerifyInclusion(leaves[idx], proof, root)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_PathTooShort(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 5)
	leaves := leafHashes(entries)
	root, err := witness.ComputeMerkleRoot(leaves)
	require.NoError(t, err)
	idx := 2
	path := buildInclusionPath(t, leaves, idx)
	if len(path) > 0 {
		path = path[:len(path)-1]
	}
	proof := &witness.InclusionProof{
		LeafIndex: uint64(idx),
		TreeSize:  uint64(len(leaves)),
		Path:      path,
	}
	err = witness.VerifyInclusion(leaves[idx], proof, root)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestInclusionProof_Validate_SingletonEmptyPath(t *testing.T) {
	t.Parallel()
	// Good case: singleton tree with empty path.
	p := &witness.InclusionProof{
		LeafIndex: 0,
		TreeSize:  1,
		Path:      nil,
	}
	require.NoError(t, p.Validate())

	// Bad case: singleton tree with non-empty path.
	p.Path = [][]byte{repeat(0xAA, crypto.HashSize)}
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestInclusionProof_Validate_NonSingletonRequiresPath(t *testing.T) {
	t.Parallel()
	p := &witness.InclusionProof{
		LeafIndex: 0,
		TreeSize:  2,
		Path:      nil,
	}
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestInclusionProof_Validate_LeafIndexOutOfRange(t *testing.T) {
	t.Parallel()
	p := &witness.InclusionProof{
		LeafIndex: 5,
		TreeSize:  3,
		Path:      [][]byte{repeat(0xAA, crypto.HashSize)},
	}
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

// TestVerifyConsistency_RoundTripAcrossSizes exercises consistency-
// proof correctness for every (oldSize, newSize) pair in [1..8],
// catching both power-of-two and non-power-of-two seed paths.
func TestVerifyConsistency_RoundTripAcrossSizes(t *testing.T) {
	t.Parallel()
	for newSize := 1; newSize <= 8; newSize++ {
		entriesNew := buildChain(t, newSize)
		leavesNew := leafHashes(entriesNew)
		rootNew, err := witness.ComputeMerkleRoot(leavesNew)
		require.NoError(t, err)

		for oldSize := 1; oldSize <= newSize; oldSize++ {
			leavesOld := leavesNew[:oldSize]
			rootOld, err := witness.ComputeMerkleRoot(leavesOld)
			require.NoError(t, err)

			path := buildConsistencyPath(t, leavesNew, oldSize)
			proof := &witness.ConsistencyProof{
				OldSize: uint64(oldSize),
				NewSize: uint64(newSize),
				Path:    path,
			}
			err = witness.VerifyConsistency(rootOld, rootNew, proof)
			require.NoError(t, err, "oldSize=%d newSize=%d", oldSize, newSize)
		}
	}
}

func TestVerifyConsistency_EmptyOldTree(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 3)
	leaves := leafHashes(entries)
	rootNew, err := witness.ComputeMerkleRoot(leaves)
	require.NoError(t, err)
	proof := &witness.ConsistencyProof{OldSize: 0, NewSize: 3, Path: nil}
	require.NoError(t, witness.VerifyConsistency(zeros32(), rootNew, proof))
}

func TestVerifyConsistency_SameSize_RequiresMatchingRoots(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 4)
	leaves := leafHashes(entries)
	root, err := witness.ComputeMerkleRoot(leaves)
	require.NoError(t, err)
	proof := &witness.ConsistencyProof{OldSize: 4, NewSize: 4, Path: nil}
	require.NoError(t, witness.VerifyConsistency(root, root, proof))

	// Mismatched roots at same size — fork.
	bogus := repeat(0xEE, crypto.HashSize)
	err = witness.VerifyConsistency(root, bogus, proof)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyConsistency_RejectsTamperedProof(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 5)
	leavesNew := leafHashes(entries)
	rootNew, err := witness.ComputeMerkleRoot(leavesNew)
	require.NoError(t, err)

	leavesOld := leavesNew[:3]
	rootOld, err := witness.ComputeMerkleRoot(leavesOld)
	require.NoError(t, err)

	path := buildConsistencyPath(t, leavesNew, 3)
	// Corrupt a proof element.
	path[0] = append([]byte(nil), path[0]...)
	path[0][0] ^= 0xFF

	proof := &witness.ConsistencyProof{OldSize: 3, NewSize: 5, Path: path}
	err = witness.VerifyConsistency(rootOld, rootNew, proof)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestConsistencyProof_Validate_OldSizeGreater(t *testing.T) {
	t.Parallel()
	p := &witness.ConsistencyProof{OldSize: 5, NewSize: 3}
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestConsistencyProof_Validate_TrivialMustHaveEmptyPath(t *testing.T) {
	t.Parallel()
	// Same size with extra path elements.
	p := &witness.ConsistencyProof{
		OldSize: 3,
		NewSize: 3,
		Path:    [][]byte{repeat(0xAA, crypto.HashSize)},
	}
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	// Empty old tree with extra path elements.
	p = &witness.ConsistencyProof{
		OldSize: 0,
		NewSize: 3,
		Path:    [][]byte{repeat(0xAA, crypto.HashSize)},
	}
	err = p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}
