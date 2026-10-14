// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package componenttree

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// hashOf is a test helper: SHA-256(s) as a 32-byte slice.
func hashOf(s string) []byte {
	h := crypto.SHA256([]byte(s))
	return append([]byte(nil), h[:]...)
}

// componentsFor synthesizes n deterministic tensor components.
func componentsFor(n int) []Component {
	out := make([]Component, n)
	for i := 0; i < n; i++ {
		out[i] = Component{
			Path:     fmt.Sprintf("layer.%04d.weight", i),
			Kind:     KindTensor,
			ByteSize: uint64(1024 * (i + 1)),
			Hash:     hashOf(fmt.Sprintf("content-%d", i)),
		}
	}
	return out
}

// -------- BuildTree ---------------------------------------------------------

func TestBuildTree_EmptyRejected(t *testing.T) {
	t.Parallel()
	_, err := BuildTree(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestBuildTree_EmptyPathRejected(t *testing.T) {
	t.Parallel()
	_, err := BuildTree([]Component{{Path: "", Kind: KindTensor, ByteSize: 1, Hash: hashOf("x")}})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestBuildTree_UnknownKindRejected(t *testing.T) {
	t.Parallel()
	_, err := BuildTree([]Component{{Path: "p", Kind: Kind("mystery"), ByteSize: 1, Hash: hashOf("x")}})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestBuildTree_BadHashSizeRejected(t *testing.T) {
	t.Parallel()
	_, err := BuildTree([]Component{{Path: "p", Kind: KindTensor, ByteSize: 1, Hash: []byte{0x01, 0x02}}})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestBuildTree_DuplicatePathRejected(t *testing.T) {
	t.Parallel()
	cs := []Component{
		{Path: "a", Kind: KindTensor, ByteSize: 1, Hash: hashOf("1")},
		{Path: "b", Kind: KindTensor, ByteSize: 1, Hash: hashOf("2")},
		{Path: "a", Kind: KindTensor, ByteSize: 1, Hash: hashOf("3")},
	}
	_, err := BuildTree(cs)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestBuildTree_SingleLeafRootIsLeafHash(t *testing.T) {
	t.Parallel()
	c := Component{Path: "only", Kind: KindTensor, ByteSize: 42, Hash: hashOf("a")}
	tree, err := BuildTree([]Component{c})
	require.NoError(t, err)
	require.Equal(t, 1, tree.Size())

	root := tree.Root()
	expectedLeaf := leafHash(c)
	require.Equal(t, expectedLeaf, root[:])
}

func TestBuildTree_DeterministicOverInputOrder(t *testing.T) {
	t.Parallel()
	// Two orderings of the same components must produce identical roots
	// because BuildTree sorts by Path internally.
	cs := []Component{
		{Path: "b", Kind: KindTensor, ByteSize: 2, Hash: hashOf("B")},
		{Path: "a", Kind: KindTensor, ByteSize: 1, Hash: hashOf("A")},
		{Path: "c", Kind: KindTensor, ByteSize: 3, Hash: hashOf("C")},
	}
	t1, err := BuildTree(cs)
	require.NoError(t, err)
	t2, err := BuildTree([]Component{cs[2], cs[0], cs[1]})
	require.NoError(t, err)
	require.Equal(t, t1.Root(), t2.Root())
}

func TestBuildTree_DefensivelyCopiesInputs(t *testing.T) {
	t.Parallel()
	cs := componentsFor(2)
	tree, err := BuildTree(cs)
	require.NoError(t, err)

	// Mutate the caller's slice after BuildTree — the tree must be unaffected.
	original := tree.Root()
	cs[0].Hash[0] ^= 0xFF
	cs[1].Path = "changed"

	require.Equal(t, original, tree.Root())
}

// -------- Odd/even sizes + promoted nodes ----------------------------------

func TestBuildTree_OddSizedTree_DifferentFromEven(t *testing.T) {
	t.Parallel()
	// Promoted-node semantics means an odd tree is not equivalent to an
	// even tree with the last leaf duplicated. Verify.
	cs3 := componentsFor(3)
	t3, err := BuildTree(cs3)
	require.NoError(t, err)

	cs4Dup := append(componentsFor(3), Component{
		Path: cs3[2].Path + "-dup", Kind: KindTensor, ByteSize: cs3[2].ByteSize, Hash: cs3[2].Hash,
	})
	t4, err := BuildTree(cs4Dup)
	require.NoError(t, err)

	r3 := t3.Root()
	r4 := t4.Root()
	require.NotEqual(t, r3[:], r4[:],
		"promoted-node tree must NOT equal a duplicate-last-leaf tree of size+1")
}

// -------- InclusionProof / VerifyInclusion ---------------------------------

func TestInclusionProof_RoundTripAllSizes(t *testing.T) {
	t.Parallel()
	// Exercise every leaf position for sizes 1..11 — spans balanced and
	// unbalanced (odd) levels and every promoted-node path.
	for size := 1; size <= 11; size++ {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			cs := componentsFor(size)
			tree, err := BuildTree(cs)
			require.NoError(t, err)
			rootSlice := tree.RootSlice()

			for idx := 0; idx < size; idx++ {
				sorted := tree.Components()
				target := sorted[idx]
				proof, err := tree.ProofFor(target.Path)
				require.NoError(t, err)
				require.Equal(t, uint64(idx), proof.LeafIndex)
				require.Equal(t, uint64(size), proof.TreeSize)

				require.NoError(t, VerifyInclusion(target, proof, rootSlice),
					"size=%d idx=%d", size, idx)
			}
		})
	}
}

func TestInclusionProof_UnknownPathRejected(t *testing.T) {
	t.Parallel()
	tree, err := BuildTree(componentsFor(4))
	require.NoError(t, err)
	_, err = tree.ProofFor("does-not-exist")
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_TamperedHashRejected(t *testing.T) {
	t.Parallel()
	cs := componentsFor(5)
	tree, err := BuildTree(cs)
	require.NoError(t, err)

	target := tree.Components()[2]
	proof, err := tree.ProofFor(target.Path)
	require.NoError(t, err)

	// Flip one bit in the component's hash — verification must reject.
	target.Hash[0] ^= 0x01
	err = VerifyInclusion(target, proof, tree.RootSlice())
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_TamperedPathRejected(t *testing.T) {
	t.Parallel()
	cs := componentsFor(5)
	tree, err := BuildTree(cs)
	require.NoError(t, err)

	target := tree.Components()[2]
	proof, err := tree.ProofFor(target.Path)
	require.NoError(t, err)

	// Path is part of the leaf pre-image; altering it produces a
	// different leaf hash that won't root to the signed root.
	target.Path = "some.other.path"
	err = VerifyInclusion(target, proof, tree.RootSlice())
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_TamperedByteSizeRejected(t *testing.T) {
	t.Parallel()
	cs := componentsFor(5)
	tree, err := BuildTree(cs)
	require.NoError(t, err)

	target := tree.Components()[2]
	proof, err := tree.ProofFor(target.Path)
	require.NoError(t, err)

	// ByteSize is covered by the leaf hash — altering it must fail verify.
	target.ByteSize++
	err = VerifyInclusion(target, proof, tree.RootSlice())
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_TamperedProofRejected(t *testing.T) {
	t.Parallel()
	cs := componentsFor(6)
	tree, err := BuildTree(cs)
	require.NoError(t, err)

	target := tree.Components()[3]
	proof, err := tree.ProofFor(target.Path)
	require.NoError(t, err)
	require.Greater(t, len(proof.AuditPath), 0)

	// Flip a bit somewhere in the audit path.
	proof.AuditPath[0] = append([]byte(nil), proof.AuditPath[0]...)
	proof.AuditPath[0][0] ^= 0x01

	err = VerifyInclusion(target, proof, tree.RootSlice())
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_WrongRootRejected(t *testing.T) {
	t.Parallel()
	cs := componentsFor(4)
	tree, err := BuildTree(cs)
	require.NoError(t, err)

	target := tree.Components()[1]
	proof, err := tree.ProofFor(target.Path)
	require.NoError(t, err)

	wrongRoot := bytes.Repeat([]byte{0xAB}, crypto.HashSize)
	err = VerifyInclusion(target, proof, wrongRoot)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerifyInclusion_InvalidArgsRejected(t *testing.T) {
	t.Parallel()
	c := Component{Path: "p", Kind: KindTensor, ByteSize: 1, Hash: hashOf("x")}
	valid := make([]byte, crypto.HashSize)

	// Non-32-byte root
	err := VerifyInclusion(c, InclusionProof{TreeSize: 1}, valid[:10])
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// Non-32-byte component hash
	bad := c
	bad.Hash = []byte{0x01}
	err = VerifyInclusion(bad, InclusionProof{TreeSize: 1}, valid)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// Unknown kind
	bad = c
	bad.Kind = Kind("mystery")
	err = VerifyInclusion(bad, InclusionProof{TreeSize: 1}, valid)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// Empty tree size
	err = VerifyInclusion(c, InclusionProof{TreeSize: 0}, valid)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// LeafIndex out of range
	err = VerifyInclusion(c, InclusionProof{LeafIndex: 5, TreeSize: 3}, valid)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// -------- ComponentByPath / Components -------------------------------------

func TestComponentByPath_Found(t *testing.T) {
	t.Parallel()
	cs := componentsFor(5)
	tree, err := BuildTree(cs)
	require.NoError(t, err)

	found, ok := tree.ComponentByPath("layer.0002.weight")
	require.True(t, ok)
	require.Equal(t, "layer.0002.weight", found.Path)

	_, ok = tree.ComponentByPath("not-there")
	require.False(t, ok)
}

func TestComponents_ReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()
	tree, err := BuildTree(componentsFor(3))
	require.NoError(t, err)

	snap := tree.Components()
	require.Len(t, snap, 3)

	// Mutate the copy — the tree must not be affected.
	snap[0].Hash[0] ^= 0xFF
	snap[0].Path = "hacked"

	// Re-fetch; must match original.
	fresh := tree.Components()
	require.NotEqual(t, snap[0].Hash, fresh[0].Hash)
	require.NotEqual(t, snap[0].Path, fresh[0].Path)
}

// -------- Cross-check: encodeComponent stability --------------------------

func TestEncodeComponent_ByteExact(t *testing.T) {
	t.Parallel()
	// Freeze the exact byte-form for a known component. If this test
	// ever fails, every AGD ever signed is being invalidated — treat as
	// a breaking-change alarm, not a test fix.
	c := Component{
		Path:     "a",        // 1 byte
		Kind:     KindTensor, // "tensor" 6 bytes
		ByteSize: 0x0102,
		Hash:     bytes.Repeat([]byte{0xAA}, crypto.HashSize),
	}
	got := encodeComponent(c)

	// kind-len=6, kind="tensor", path-len=1, path="a", bytesize=0x0102,
	// hash=32×0xAA  => total = 4+6+4+1+8+32 = 55 bytes.
	require.Len(t, got, 55)

	// Spot-check the leading bytes.
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x06}, got[0:4])
	require.Equal(t, []byte("tensor"), got[4:10])
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x01}, got[10:14])
	require.Equal(t, []byte("a"), got[14:15])
	// ByteSize big-endian 0x0000000000000102
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0x01, 0x02}, got[15:23])
	// Last 32 bytes: the hash.
	require.Equal(t, bytes.Repeat([]byte{0xAA}, 32), got[23:55])
}
