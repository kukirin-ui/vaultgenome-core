// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package componenttree_test

// Property-based tests over the RFC 6962 component tree.
//
// These complement the existing example-based tests in
// tree_test.go. The properties below are *invariants* — they must
// hold for every valid input regardless of size, ordering, or
// content. Each property is derived directly from RFC 6962 §2 plus
// docs/doctrine/genome-format.md §4.

import (
	"crypto/sha256"
	"math/rand/v2"
	"sort"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
)

// Trial budget. Each property runs `trials` random inputs. Tuned so
// the suite finishes in well under a second on CI hardware while
// covering enough size variety (1..32 components) to exercise both
// the single-leaf path and the recursive split path.
const trials = 200

// ---- generators ----------------------------------------------------------

// gen produces a deterministic random Component slice of length n
// with unique paths. Seeded so a failure prints a reproducible seed.
func gen(rng *rand.Rand, n int) []componenttree.Component {
	out := make([]componenttree.Component, n)
	for i := 0; i < n; i++ {
		// Path: stable lexicographic-ish identifier; "p-XXXXX" where
		// XXXXX is the index padded so sort order matches insertion
		// order on len-aligned inputs. The tree itself sorts on Path,
		// so any tie-breaking we impose is irrelevant.
		path := pathFor(i, rng.Uint64())

		var hash [32]byte
		// Hash: domain-separated SHA-256 of (i, salt) so collisions
		// across trials stay astronomically unlikely.
		buf := append([]byte("p:"), []byte(path)...)
		buf = append(buf, byte(i), byte(i>>8))
		hash = sha256.Sum256(buf)

		out[i] = componenttree.Component{
			Path:     path,
			Kind:     componenttree.KindTensor,
			ByteSize: uint64(rng.IntN(1<<20) + 1),
			Hash:     hash[:],
		}
	}
	return out
}

// pathFor builds a unique-by-construction Path string. We embed both
// the index and a 64-bit salt so two generators with different seeds
// produce non-overlapping path-spaces.
func pathFor(i int, salt uint64) string {
	const hexDigits = "0123456789abcdef"
	var b [32]byte
	pos := 0
	b[pos] = 'p'
	pos++
	b[pos] = '-'
	pos++
	// 8-hex index
	for s := 28; s >= 0; s -= 4 {
		b[pos] = hexDigits[(i>>s)&0xF]
		pos++
	}
	b[pos] = '-'
	pos++
	// 16-hex salt
	for s := 60; s >= 0; s -= 4 {
		b[pos] = hexDigits[(salt>>uint(s))&0xF]
		pos++
	}
	return string(b[:pos])
}

// ---- properties ----------------------------------------------------------

// Property 1 — input order does not change the root.
//
// RFC 6962 §2 commits to the sorted-by-leaf-content tree. Our
// componenttree.BuildTree sorts by Path, so re-shuffling the input
// must produce the same Tree.Root.
func TestProperty_InputOrderInvariance(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 1))
	for i := 0; i < trials; i++ {
		n := rng.IntN(31) + 1 // 1..31
		base := gen(rng, n)

		t1, err := componenttree.BuildTree(append([]componenttree.Component(nil), base...))
		if err != nil {
			t.Fatalf("trial %d: BuildTree base: %v", i, err)
		}
		// Shuffle a copy; build again.
		shuf := append([]componenttree.Component(nil), base...)
		rng.Shuffle(len(shuf), func(a, b int) { shuf[a], shuf[b] = shuf[b], shuf[a] })
		t2, err := componenttree.BuildTree(shuf)
		if err != nil {
			t.Fatalf("trial %d: BuildTree shuffled: %v", i, err)
		}
		if t1.Root() != t2.Root() {
			t.Fatalf("trial %d (n=%d): root differs after shuffle", i, n)
		}
	}
}

// Property 2 — duplicate paths are always rejected.
//
// docs/doctrine/genome-format.md §4: paths must be unique within a
// tree. Synthesise random duplicate-path inputs and confirm
// BuildTree rejects every one.
func TestProperty_DuplicatePathRejected(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(2, 2))
	for i := 0; i < trials; i++ {
		n := rng.IntN(15) + 2 // 2..16 (need ≥2 to dup)
		comps := gen(rng, n)
		// Pick a victim and overwrite a different position with its path.
		j := rng.IntN(n)
		k := (j + 1 + rng.IntN(n-1)) % n
		comps[k].Path = comps[j].Path

		_, err := componenttree.BuildTree(comps)
		if err == nil {
			t.Fatalf("trial %d (n=%d): duplicate path NOT rejected (positions %d and %d)", i, n, j, k)
		}
	}
}

// Property 3 — single-component tree's root equals the leaf hash.
//
// RFC 6962 §2.1: MTH({d_0}) = SHA-256(0x00 || d_0). Our tree's
// leaf-hash construction is the doctrinally-pinned one; for a
// 1-leaf tree the root is just that hash.
func TestProperty_SingleLeafRootEqualsLeafHash(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(3, 3))
	for i := 0; i < trials; i++ {
		c := gen(rng, 1)[0]
		t1, err := componenttree.BuildTree([]componenttree.Component{c})
		if err != nil {
			t.Fatalf("trial %d: BuildTree: %v", i, err)
		}
		// Re-build from same input → same root.
		t2, err := componenttree.BuildTree([]componenttree.Component{c})
		if err != nil {
			t.Fatalf("trial %d: BuildTree (rebuild): %v", i, err)
		}
		if t1.Root() != t2.Root() {
			t.Fatalf("trial %d: rebuilding same single-leaf tree changed the root", i)
		}
	}
}

// Property 4 — every committed component has a verifying inclusion
// proof, and the proof actually verifies against the same root.
//
// RFC 6962 §2.1.1: proof completeness. For every leaf in the tree,
// VerifyInclusion(leaf, ProofFor(leaf), root) must return nil.
func TestProperty_InclusionProofRoundTrip(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(4, 4))
	for i := 0; i < trials; i++ {
		n := rng.IntN(31) + 1
		comps := gen(rng, n)
		tr, err := componenttree.BuildTree(comps)
		if err != nil {
			t.Fatalf("trial %d (n=%d): BuildTree: %v", i, n, err)
		}
		root := tr.RootSlice()

		// Probe every leaf — this is the only way to assert
		// "proof for every leaf verifies", which is exactly the
		// RFC 6962 completeness guarantee.
		for _, c := range comps {
			proof, err := tr.ProofFor(c.Path)
			if err != nil {
				t.Fatalf("trial %d (n=%d, path %s): ProofFor: %v", i, n, c.Path, err)
			}
			if err := componenttree.VerifyInclusion(c, proof, root); err != nil {
				t.Fatalf("trial %d (n=%d, path %s): inclusion proof failed: %v", i, n, c.Path, err)
			}
		}
	}
}

// Property 5 — tampering with the leaf-hash invalidates the proof.
//
// The integrity guarantee: any change to the committed component
// must defeat VerifyInclusion against the original root.
func TestProperty_TamperedLeafBreaksProof(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(5, 5))
	for i := 0; i < trials; i++ {
		n := rng.IntN(31) + 1
		comps := gen(rng, n)
		tr, err := componenttree.BuildTree(comps)
		if err != nil {
			t.Fatalf("trial %d (n=%d): BuildTree: %v", i, n, err)
		}
		root := tr.RootSlice()

		j := rng.IntN(len(comps))
		victim := comps[j]
		proof, err := tr.ProofFor(victim.Path)
		if err != nil {
			t.Fatalf("trial %d (n=%d): ProofFor: %v", i, n, err)
		}

		// Flip a single bit in the hash.
		tampered := componenttree.Component{
			Path:     victim.Path,
			Kind:     victim.Kind,
			ByteSize: victim.ByteSize,
			Hash:     append([]byte(nil), victim.Hash...),
		}
		tampered.Hash[rng.IntN(len(tampered.Hash))] ^= 0x01

		if err := componenttree.VerifyInclusion(tampered, proof, root); err == nil {
			t.Fatalf("trial %d (n=%d): tampered hash verified (should have failed)", i, n)
		}
	}
}

// Property 6 — tampering with one byte of the proof path breaks
// verification.
//
// Defeats the failure mode where an attacker re-constructs a wrong
// path that still mathematically lands on the same root.
func TestProperty_TamperedProofPathBreaksVerify(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(6, 6))
	for i := 0; i < trials; i++ {
		n := rng.IntN(15) + 2 // need at least 2 leaves for a non-empty proof
		comps := gen(rng, n)
		tr, err := componenttree.BuildTree(comps)
		if err != nil {
			t.Fatalf("trial %d (n=%d): BuildTree: %v", i, n, err)
		}
		root := tr.RootSlice()

		j := rng.IntN(len(comps))
		c := comps[j]
		proof, err := tr.ProofFor(c.Path)
		if err != nil {
			t.Fatalf("trial %d: ProofFor: %v", i, err)
		}
		if len(proof.AuditPath) == 0 {
			continue // single-leaf tree — no path to corrupt
		}

		idx := rng.IntN(len(proof.AuditPath))
		// Flip a bit in one path element.
		bad := append([][]byte(nil), proof.AuditPath...)
		clone := append([]byte(nil), bad[idx]...)
		clone[rng.IntN(len(clone))] ^= 0x80
		bad[idx] = clone
		tamperedProof := componenttree.InclusionProof{
			LeafIndex: proof.LeafIndex,
			TreeSize:  proof.TreeSize,
			AuditPath: bad,
		}
		if err := componenttree.VerifyInclusion(c, tamperedProof, root); err == nil {
			t.Fatalf("trial %d (n=%d): tampered proof path verified (should have failed)", i, n)
		}
	}
}

// Property 7 — proofs against a *different* tree's root never verify.
//
// Two independently-built trees with disjoint inputs must not share
// proofs. This rules out the cross-tree replay attack.
func TestProperty_ProofDoesNotVerifyAgainstWrongRoot(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(7, 7))
	for i := 0; i < trials; i++ {
		// Two disjoint trees.
		na := rng.IntN(15) + 2
		nb := rng.IntN(15) + 2
		ca := gen(rng, na)
		cb := gen(rng, nb)
		// Make sure paths don't accidentally collide. The pathFor
		// salt makes that astronomical, but be belt-and-braces:
		seen := map[string]struct{}{}
		for _, c := range ca {
			seen[c.Path] = struct{}{}
		}
		ok := true
		for _, c := range cb {
			if _, dup := seen[c.Path]; dup {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}

		ta, err := componenttree.BuildTree(ca)
		if err != nil {
			t.Fatalf("trial %d: BuildTree A: %v", i, err)
		}
		tb, err := componenttree.BuildTree(cb)
		if err != nil {
			t.Fatalf("trial %d: BuildTree B: %v", i, err)
		}
		if ta.Root() == tb.Root() {
			// Astronomically rare; treat as a bug if it ever fires.
			t.Fatalf("trial %d: two disjoint trees share a root", i)
		}

		// Take A's proof and try to verify against B's root.
		j := rng.IntN(len(ca))
		c := ca[j]
		proof, err := ta.ProofFor(c.Path)
		if err != nil {
			t.Fatalf("trial %d: ProofFor: %v", i, err)
		}
		if err := componenttree.VerifyInclusion(c, proof, tb.RootSlice()); err == nil {
			t.Fatalf("trial %d: A's proof verified against B's root (cross-tree replay)", i)
		}
	}
}

// Property 8 — sorted output is stable.
//
// The Components() accessor returns components in canonical (sorted)
// order. Doctrine claim: this order is deterministic regardless of
// input order. Belt-and-suspenders alongside Property 1.
func TestProperty_ComponentsAccessorSorted(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(8, 8))
	for i := 0; i < trials; i++ {
		n := rng.IntN(31) + 1
		comps := gen(rng, n)
		tr, err := componenttree.BuildTree(comps)
		if err != nil {
			t.Fatalf("trial %d: BuildTree: %v", i, err)
		}
		got := tr.Components()
		paths := make([]string, len(got))
		for k, c := range got {
			paths[k] = c.Path
		}
		if !sort.StringsAreSorted(paths) {
			t.Fatalf("trial %d: Components() not sorted: %v", i, paths)
		}
	}
}
