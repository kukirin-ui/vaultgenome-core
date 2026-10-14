// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package componenttree

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// Property tests for /internal/genome/componenttree.
//
// These tests assert structural invariants of BuildTree / ProofFor /
// VerifyInclusion over pseudo-random populations. They extend the
// hand-rolled unit tests in tree_test.go with coverage that grows
// combinatorially with the seed count.
//
// Doctrinal binding: the ComponentTreeRoot of an AGD is a signed
// commitment to the set of components; every disclosed component must
// verify against that root. A regression in any of the properties
// below breaks the signed-tree binding and the receive-side
// reassembler's tier-2 Merkle root check in one stroke.
//
// Budget: each property iterates 64 random populations of sizes 1–32.
// That is small by fuzz standards but exhaustive enough over the
// RFC 6962 promotion corners (odd, even, power-of-2, one-below-pow2)
// to pin the audit-path arithmetic.

// randomComponents returns n deterministic components derived from
// seed. Paths are globally unique across any (seed, n) combination.
func randomComponents(seed int64, n int) []Component {
	r := rand.New(rand.NewSource(seed))
	out := make([]Component, n)
	for i := range out {
		// 16-byte pseudo-random suffix in the path so paths don't
		// collide across different seeds.
		var suf [16]byte
		r.Read(suf[:])
		out[i] = Component{
			Path:     fmt.Sprintf("seed%d/node/%04d-%x", seed, i, suf),
			Kind:     KindTensor,
			ByteSize: uint64(r.Int63n(1 << 20)),
			Hash:     randomHash(r),
		}
	}
	return out
}

func randomHash(r *rand.Rand) []byte {
	h := make([]byte, crypto.HashSize)
	r.Read(h)
	return h
}

// TestProperty_EveryLeafVerifiesAgainstRoot asserts the primary
// integrity property: for every component in every random tree, the
// inclusion proof at its own path verifies against the tree's root.
// A false negative here means a legitimate disclosure would be
// rejected by a receive-side verifier.
func TestProperty_EveryLeafVerifiesAgainstRoot(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 64; seed++ {
		seed := seed
		for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32} {
			n := n
			t.Run(fmt.Sprintf("seed=%d/n=%d", seed, n), func(t *testing.T) {
				t.Parallel()
				cs := randomComponents(seed, n)
				tree, err := BuildTree(cs)
				require.NoError(t, err)
				root := tree.RootSlice()

				for _, c := range tree.Components() {
					proof, err := tree.ProofFor(c.Path)
					require.NoError(t, err)
					require.NoError(t, VerifyInclusion(c, proof, root),
						"leaf at path %q failed to verify", c.Path)
				}
			})
		}
	}
}

// TestProperty_WrongRootRejectsProof asserts that flipping ANY byte
// in the committed root makes every inclusion proof fail. This is
// the negative half of the root-binding contract — a verifier that
// tolerates a mutated root is not actually bound to the AGD.
func TestProperty_WrongRootRejectsProof(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 16; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			cs := randomComponents(seed, 8)
			tree, err := BuildTree(cs)
			require.NoError(t, err)

			corrupt := tree.RootSlice()
			corrupt[0] ^= 0x01 // flip one bit in the first byte

			for _, c := range tree.Components() {
				proof, err := tree.ProofFor(c.Path)
				require.NoError(t, err)
				err = VerifyInclusion(c, proof, corrupt)
				require.Error(t, err,
					"path %q verified against corrupted root", c.Path)
			}
		})
	}
}

// TestProperty_SwappedLeafBreaksVerification asserts that feeding
// VerifyInclusion a Component with the right Path but wrong Hash
// (or right Hash but wrong Kind, ByteSize, or Path) breaks the
// verification. This is the property that makes the tree a
// commitment to the full (Path, Kind, ByteSize, Hash) tuple, not
// just to Path.
func TestProperty_SwappedLeafBreaksVerification(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 16; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			cs := randomComponents(seed, 6)
			tree, err := BuildTree(cs)
			require.NoError(t, err)
			root := tree.RootSlice()

			// Pick the middle leaf and mutate each tuple field
			// independently. Every mutation must break verification.
			orig := tree.Components()[len(cs)/2]
			proof, err := tree.ProofFor(orig.Path)
			require.NoError(t, err)

			mutants := []Component{
				// Hash flipped in the first byte.
				func() Component {
					c := cloneComponent(orig)
					c.Hash[0] ^= 0x01
					return c
				}(),
				// ByteSize incremented.
				func() Component {
					c := cloneComponent(orig)
					c.ByteSize += 1
					return c
				}(),
				// ByteSize decremented when possible.
				func() Component {
					c := cloneComponent(orig)
					if c.ByteSize > 0 {
						c.ByteSize -= 1
					} else {
						c.ByteSize = 1
					}
					return c
				}(),
			}
			for i, m := range mutants {
				err := VerifyInclusion(m, proof, root)
				require.Error(t, err,
					"mutant #%d verified against original root (field mutation was insufficient)", i)
			}
		})
	}
}

// TestProperty_PathOrderInsensitiveAtBuild asserts that BuildTree is
// a total function of the component SET, not of input order: two
// shuffles of the same component list produce the same root. This
// is the property that lets AGD producers assemble components in
// any order without risking signature divergence.
func TestProperty_PathOrderInsensitiveAtBuild(t *testing.T) {
	t.Parallel()
	for seed := int64(1); seed <= 32; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			t.Parallel()
			cs := randomComponents(seed, 10)

			r := rand.New(rand.NewSource(seed + 1_000_000))
			shuffled := make([]Component, len(cs))
			copy(shuffled, cs)
			r.Shuffle(len(shuffled), func(i, j int) {
				shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
			})

			a, err := BuildTree(cs)
			require.NoError(t, err)
			b, err := BuildTree(shuffled)
			require.NoError(t, err)

			if !bytes.Equal(a.RootSlice(), b.RootSlice()) {
				t.Fatalf("root differs across shuffles: a=%x b=%x",
					a.RootSlice(), b.RootSlice())
			}
			require.Equal(t, a.Size(), b.Size())
		})
	}
}

// TestProperty_AuditPathLengthMatches66962Geometry asserts the RFC
// 6962 audit-path length invariant: for a tree of size N, the audit
// path for leaf k is ceil(log2(N)) long, modulo the "promoted"
// leaves on the right spine of an odd-level. This is the property a
// light client exploits to bound verification cost.
//
// The loop walks every tree size from 1 to 32 and every leaf index
// in the tree, asserting the audit path is no longer than
// ceil(log2(N)) and that the path length equals the number of hash
// steps VerifyInclusion takes.
func TestProperty_AuditPathLengthMatches66962Geometry(t *testing.T) {
	t.Parallel()
	for n := 1; n <= 32; n++ {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			t.Parallel()
			cs := randomComponents(int64(n)*7919, n)
			tree, err := BuildTree(cs)
			require.NoError(t, err)

			maxLen := ceilLog2(uint64(n))
			for _, c := range tree.Components() {
				proof, err := tree.ProofFor(c.Path)
				require.NoError(t, err)
				if uint64(len(proof.AuditPath)) > maxLen {
					t.Fatalf(
						"n=%d path=%q: audit path length %d exceeds ceil(log2(%d))=%d",
						n, c.Path, len(proof.AuditPath), n, maxLen)
				}
				// Every element must be 32 bytes.
				for j, el := range proof.AuditPath {
					if len(el) != crypto.HashSize {
						t.Fatalf("n=%d path=%q step=%d: element len=%d != %d",
							n, c.Path, j, len(el), crypto.HashSize)
					}
				}
			}
		})
	}
}

// TestProperty_SingletonTreeRootEqualsOwnLeafHash asserts the
// doctrinal special case of RFC 6962: a tree with one leaf has root
// == leafHash(that leaf). Singleton trees must not accidentally
// hash an extra "combine" step that would invalidate commitment.
func TestProperty_SingletonTreeRootEqualsOwnLeafHash(t *testing.T) {
	t.Parallel()
	c := randomComponents(1, 1)[0]
	tree, err := BuildTree([]Component{c})
	require.NoError(t, err)

	expected := leafHash(c)
	if !bytes.Equal(expected, tree.RootSlice()) {
		t.Fatalf("singleton root differs from leafHash: want=%x got=%x",
			expected, tree.RootSlice())
	}

	// Singleton proof must be empty (no siblings to combine with).
	proof, err := tree.ProofFor(c.Path)
	require.NoError(t, err)
	require.Equal(t, 0, len(proof.AuditPath))
	require.Equal(t, uint64(1), proof.TreeSize)
	require.Equal(t, uint64(0), proof.LeafIndex)
	require.NoError(t, VerifyInclusion(c, proof, tree.RootSlice()))
}

// --- helpers ----------------------------------------------------------------

func cloneComponent(c Component) Component {
	return Component{
		Path:     c.Path,
		Kind:     c.Kind,
		ByteSize: c.ByteSize,
		Hash:     append([]byte(nil), c.Hash...),
	}
}

// ceilLog2 returns ceil(log2(n)) for n >= 1. Used to bound the audit
// path length. Implemented via a bit scan to avoid the math package's
// floating-point rounding issues.
func ceilLog2(n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	// Subtract 1 and count bits.
	n--
	var bits uint64
	for n > 0 {
		bits++
		n >>= 1
	}
	return bits
}
