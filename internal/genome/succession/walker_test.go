// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package succession_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/genome/store"
	"github.com/vault-genome/vaultgenome-core/internal/genome/succession"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- fixtures --------------------------------------------------------------

func fixedHash(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

func newAuthorityKS(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

// baseDescriptor returns a fully-populated, valid descriptor with the
// given family and generation. The caller must still set GenomeID,
// DerivedFrom, and Signature.
func baseDescriptor(family string, generation uint64) genome_descriptor.GenomeDescriptor {
	issued := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	produced := time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC)
	return genome_descriptor.GenomeDescriptor{
		SchemaVersion: genome_descriptor.SchemaVersionCurrent,
		FamilyName:    family,
		Generation:    generation,
		Kind:          genome_descriptor.KindTransformer,
		Architecture: genome_descriptor.ArchitectureDescriptor{
			Framework:      "pytorch-2.1",
			ModelClass:     "transformer-decoder",
			ParameterCount: 7_000_000_000,
			PrecisionBits:  16,
			ConfigHash:     fixedHash(0xA1),
		},
		ComponentTreeRoot: fixedHash(0xB2),
		ComponentCount:    512,
		TotalBytes:        14_000_000_000,
		Provenance: genome_descriptor.ProvenanceRecord{
			ProducerIdentity:   "producer:alpha-lab",
			ProducedAt:         produced,
			TrainingDataRoot:   fixedHash(0xC3),
			TrainingRecipeHash: fixedHash(0xD4),
		},
		BehavioralFingerprint: genome_descriptor.ProbeBatteryRoot{
			BatteryID:            "llm-reasoning-v3",
			BatterySchemaVersion: 1,
			BatteryMerkleRoot:    fixedHash(0xE5),
			CanonicalScoresRoot:  fixedHash(0xF6),
			ProbeCount:           256,
			MinPassingScore:      0.85,
		},
		PolicyLabels: map[string]string{"classification": "research"},
		IssuedAt:     issued,
	}
}

// signAndPut derives the ID, signs, and writes the descriptor to the
// given Store. Returns the derived ID.
func signAndPut(
	t *testing.T,
	s store.Store,
	ks *keys.InMemoryStore,
	kid ids.KeyID,
	g *genome_descriptor.GenomeDescriptor,
) ids.GenomeID {
	t.Helper()
	g.SigningKeyID = kid
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	require.NoError(t, g.SignWith(ks))
	putID, err := s.Put(g)
	require.NoError(t, err)
	require.Equal(t, id, putID)
	return id
}

// buildChain constructs and stores a linear ancestry of depth N:
// gen-0, gen-1 with DerivedFrom=[gen-0], gen-2 with DerivedFrom=[gen-1],
// ... gen-(N-1). Returns all IDs in generation order (root → leaf).
func buildChain(
	t *testing.T,
	s store.Store,
	ks *keys.InMemoryStore,
	kid ids.KeyID,
	n int,
	family string,
) []ids.GenomeID {
	t.Helper()
	var out []ids.GenomeID
	// Generation 0 root.
	g0 := baseDescriptor(family, 0)
	out = append(out, signAndPut(t, s, ks, kid, &g0))
	// Each subsequent generation cites the previous as parent.
	for gen := uint64(1); gen < uint64(n); gen++ {
		g := baseDescriptor(family, gen)
		g.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
			{ParentGenomeID: out[gen-1], Method: genome_descriptor.DerivationFineTune},
		}
		out = append(out, signAndPut(t, s, ks, kid, &g))
	}
	return out
}

// ---- fakeStore -------------------------------------------------------------

// fakeStore is a test-only Store that bypasses all integrity gates so
// we can inject adversarial graphs (cycles, generation inversions) that
// would be rejected by the real Put pipeline.
//
// It implements store.Store but only Get and Exists carry real logic;
// the rest are no-ops sufficient for tests.
type fakeStore struct {
	entries map[ids.GenomeID]*genome_descriptor.GenomeDescriptor
}

func newFakeStore() *fakeStore {
	return &fakeStore{entries: make(map[ids.GenomeID]*genome_descriptor.GenomeDescriptor)}
}

func (f *fakeStore) inject(id ids.GenomeID, g *genome_descriptor.GenomeDescriptor) {
	// Force the stored descriptor's GenomeID to match the key so that
	// the real store.Get's re-derivation tripwire (if ever ported
	// here) wouldn't fire. We only call through succession.Walk,
	// which reads Get's returned descriptor as-is.
	cp := *g
	cp.GenomeID = id
	f.entries[id] = &cp
}

func (f *fakeStore) Put(_ *genome_descriptor.GenomeDescriptor) (ids.GenomeID, error) {
	return "", shared_errors.Structural("test", "fakeStore: Put not implemented", nil)
}

func (f *fakeStore) Get(id ids.GenomeID) (*genome_descriptor.GenomeDescriptor, error) {
	g, ok := f.entries[id]
	if !ok {
		return nil, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"fakeStore: unknown id",
			nil,
		)
	}
	// Return a copy so caller mutation doesn't bleed back.
	cp := *g
	return &cp, nil
}

func (f *fakeStore) Exists(id ids.GenomeID) bool {
	_, ok := f.entries[id]
	return ok
}

func (f *fakeStore) Size() int { return len(f.entries) }

func (f *fakeStore) Each(visit func(ids.GenomeID, *genome_descriptor.GenomeDescriptor) error) error {
	for id, g := range f.entries {
		cp := *g
		if err := visit(id, &cp); err != nil {
			return err
		}
	}
	return nil
}

// ---- constructor guards ----------------------------------------------------

func TestWalk_RejectsNilStore(t *testing.T) {
	t.Parallel()
	err := succession.Walk(ids.GenomeID("gen:abc"), nil, succession.Options{}, func(*succession.Node) error { return nil })
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestWalk_RejectsNilVisit(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)
	err = succession.Walk(ids.GenomeID("gen:abc"), s, succession.Options{}, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestWalk_RejectsZeroRoot(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)
	err = succession.Walk("", s, succession.Options{}, func(*succession.Node) error { return nil })
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestVerifyWithSignatures_RejectsMissingResolver(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)
	err = succession.VerifyWithSignatures(ids.GenomeID("gen:abc"), s, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// ---- happy paths -----------------------------------------------------------

func TestWalk_LinearChain_VisitsAllInPreOrder(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	chain := buildChain(t, s, ks, kid, 4, "continuity-llm") // [gen0, gen1, gen2, gen3]
	leaf := chain[3]

	var order []ids.GenomeID
	var depths []int
	require.NoError(t, succession.Walk(leaf, s, succession.Options{}, func(n *succession.Node) error {
		order = append(order, n.GenomeID)
		depths = append(depths, n.Depth)
		return nil
	}))
	// Pre-order DFS from leaf visits leaf → gen2 → gen1 → gen0.
	require.Equal(t, []ids.GenomeID{chain[3], chain[2], chain[1], chain[0]}, order)
	require.Equal(t, []int{0, 1, 2, 3}, depths)
}

func TestVerify_LinearChainOK(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	chain := buildChain(t, s, ks, kid, 3, "continuity-llm")
	require.NoError(t, succession.Verify(chain[2], s))
}

func TestVerifyWithSignatures_LinearChainOK(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	chain := buildChain(t, s, ks, kid, 3, "continuity-llm")
	require.NoError(t, succession.VerifyWithSignatures(chain[2], s, ks))
}

func TestWalk_DiamondMerge_VisitsCommonAncestorTwice(t *testing.T) {
	t.Parallel()
	// gen-0 root; two gen-1 children (distinct via FamilyName so they
	// get distinct IDs); gen-2 merge-child citing both. Walk from
	// merge-child MUST visit the gen-0 root TWICE (once per path) —
	// the walker is path-aware, not set-based.
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g0 := baseDescriptor("family-root", 0)
	id0 := signAndPut(t, s, ks, kid, &g0)

	g1a := baseDescriptor("family-left", 1)
	g1a.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: id0, Method: genome_descriptor.DerivationFineTune},
	}
	id1a := signAndPut(t, s, ks, kid, &g1a)

	g1b := baseDescriptor("family-right", 1)
	g1b.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: id0, Method: genome_descriptor.DerivationDistill},
	}
	id1b := signAndPut(t, s, ks, kid, &g1b)

	g2 := baseDescriptor("family-merge", 2)
	g2.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: id1a, Method: genome_descriptor.DerivationMerge},
		{ParentGenomeID: id1b, Method: genome_descriptor.DerivationMerge},
	}
	id2 := signAndPut(t, s, ks, kid, &g2)

	visits := make(map[ids.GenomeID]int)
	require.NoError(t, succession.Walk(id2, s, succession.Options{}, func(n *succession.Node) error {
		visits[n.GenomeID]++
		return nil
	}))
	require.Equal(t, 1, visits[id2])
	require.Equal(t, 1, visits[id1a])
	require.Equal(t, 1, visits[id1b])
	require.Equal(t, 2, visits[id0], "common ancestor reached via both merge-paths")
}

func TestAncestors_DedupsDiamondMerge(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g0 := baseDescriptor("family-root", 0)
	id0 := signAndPut(t, s, ks, kid, &g0)

	g1a := baseDescriptor("family-left", 1)
	g1a.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: id0, Method: genome_descriptor.DerivationFineTune},
	}
	id1a := signAndPut(t, s, ks, kid, &g1a)

	g1b := baseDescriptor("family-right", 1)
	g1b.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: id0, Method: genome_descriptor.DerivationDistill},
	}
	id1b := signAndPut(t, s, ks, kid, &g1b)

	g2 := baseDescriptor("family-merge", 2)
	g2.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: id1a, Method: genome_descriptor.DerivationMerge},
		{ParentGenomeID: id1b, Method: genome_descriptor.DerivationMerge},
	}
	id2 := signAndPut(t, s, ks, kid, &g2)

	anc, err := succession.Ancestors(id2, s)
	require.NoError(t, err)
	require.Len(t, anc, 3, "root + two left/right parents, deduplicated")
	// Self should not appear.
	for _, a := range anc {
		require.NotEqual(t, id2, a, "Ancestors must exclude root itself")
	}
	// id0 appears once despite two paths.
	count0 := 0
	for _, a := range anc {
		if a == id0 {
			count0++
		}
	}
	require.Equal(t, 1, count0)
}

// ---- operational: missing ancestor -----------------------------------------

func TestWalk_MissingRoot_IsStructural(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	err = succession.Verify(ids.GenomeID(genome_descriptor.GenomeIDPrefix+"absent"), s)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err),
		"missing ROOT is a caller mistake, not a chain gap")
}

func TestWalk_MissingAncestor_IsOperational(t *testing.T) {
	t.Parallel()
	// Build a gen-1 child citing a parent that is NOT in the store.
	// The child itself is stored, so the walk starts fine, but the
	// descent into the parent fails with Operational.
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	ghost := ids.GenomeID(genome_descriptor.GenomeIDPrefix +
		"0000000000000000000000000000000000000000000000000000000000000000")

	g1 := baseDescriptor("orphan", 1)
	g1.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: ghost, Method: genome_descriptor.DerivationFineTune},
	}
	id1 := signAndPut(t, s, ks, kid, &g1)

	err = succession.Verify(id1, s)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Equal(t, "succession_ancestor_missing", shared_errors.CodeOf(err))
}

// ---- incident: cycle -------------------------------------------------------

func TestWalk_CycleDetected_IsIncident(t *testing.T) {
	t.Parallel()
	// A↔B mutual-descent cycle. Not constructible through a real Put
	// pipeline under SHA-256, so we inject via fakeStore to simulate
	// what we'd see if a backing store were compromised.
	idA := ids.GenomeID(genome_descriptor.GenomeIDPrefix + "aa")
	idB := ids.GenomeID(genome_descriptor.GenomeIDPrefix + "bb")

	gA := baseDescriptor("A", 2)
	gA.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: idB, Method: genome_descriptor.DerivationFineTune},
	}
	gB := baseDescriptor("B", 1)
	gB.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: idA, Method: genome_descriptor.DerivationFineTune},
	}

	f := newFakeStore()
	f.inject(idA, &gA)
	f.inject(idB, &gB)

	err := succession.Verify(idA, f)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeTamperSignal, shared_errors.CodeOf(err))
}

func TestWalk_SelfCycle_IsIncident(t *testing.T) {
	t.Parallel()
	// Single-node self-loop.
	id := ids.GenomeID(genome_descriptor.GenomeIDPrefix + "ff")
	g := baseDescriptor("selfloop", 1)
	g.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: id, Method: genome_descriptor.DerivationFineTune},
	}
	f := newFakeStore()
	f.inject(id, &g)

	err := succession.Verify(id, f)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))
}

// ---- incident: generation monotonicity -------------------------------------

func TestWalk_GenerationInversion_IsIncident(t *testing.T) {
	t.Parallel()
	// Child claims Generation=1, parent claims Generation=5 — parent
	// cannot be older-with-higher-number. Inject via fakeStore because
	// the real Validate would reject gen=0-with-parents but not the
	// inversion itself.
	idChild := ids.GenomeID(genome_descriptor.GenomeIDPrefix + "11")
	idParent := ids.GenomeID(genome_descriptor.GenomeIDPrefix + "22")

	gChild := baseDescriptor("child", 1)
	gChild.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: idParent, Method: genome_descriptor.DerivationFineTune},
	}
	gParent := baseDescriptor("parent", 5) // inverted
	// parent itself has no parents — it's a "root" in the gen=0 sense
	// but with gen=5 label (a forged continuity claim).

	f := newFakeStore()
	f.inject(idChild, &gChild)
	f.inject(idParent, &gParent)

	err := succession.Verify(idChild, f)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeTamperSignal, shared_errors.CodeOf(err))
}

func TestWalk_GenerationEqual_IsIncident(t *testing.T) {
	t.Parallel()
	// Strict < is required. A parent with equal Generation is still
	// a forged succession claim.
	idChild := ids.GenomeID(genome_descriptor.GenomeIDPrefix + "11")
	idParent := ids.GenomeID(genome_descriptor.GenomeIDPrefix + "22")

	gChild := baseDescriptor("child", 3)
	gChild.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: idParent, Method: genome_descriptor.DerivationFineTune},
	}
	gParent := baseDescriptor("parent", 3) // equal!

	f := newFakeStore()
	f.inject(idChild, &gChild)
	f.inject(idParent, &gParent)

	err := succession.Verify(idChild, f)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))
}

// ---- options: MaxDepth -----------------------------------------------------

func TestWalk_MaxDepthExceeded_IsOperational(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	chain := buildChain(t, s, ks, kid, 5, "continuity-llm") // depths 0..4
	leaf := chain[4]

	err = succession.Walk(leaf, s, succession.Options{MaxDepth: 2}, func(*succession.Node) error { return nil })
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Equal(t, "succession_depth_exceeded", shared_errors.CodeOf(err))
}

func TestWalk_MaxDepthExact_OK(t *testing.T) {
	t.Parallel()
	// Chain has depths 0..3 from leaf. MaxDepth=3 permits the last node
	// (gen-0 root at depth 3); MaxDepth=2 does not.
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	chain := buildChain(t, s, ks, kid, 4, "continuity-llm")
	leaf := chain[3]

	require.NoError(t, succession.Walk(leaf, s, succession.Options{MaxDepth: 3}, func(*succession.Node) error { return nil }))
}

// ---- visitor: early exit ---------------------------------------------------

func TestWalk_VisitorEarlyExit_PropagatesError(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	chain := buildChain(t, s, ks, kid, 4, "continuity-llm")
	leaf := chain[3]

	sentinel := shared_errors.Operational("test", "stop", nil)
	visited := 0
	err = succession.Walk(leaf, s, succession.Options{}, func(n *succession.Node) error {
		visited++
		if visited == 2 {
			return sentinel
		}
		return nil
	})
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 2, visited, "visitor halts on first error")
}

// ---- VerifyWithSignatures: tamper -----------------------------------------

func TestVerifyWithSignatures_DetectsCorruptedAncestor(t *testing.T) {
	t.Parallel()
	// Build a real signed chain, then inject a tampered ancestor via
	// fakeStore that seeds it under the same IDs. VerifyWithSignatures
	// should fail at the point it re-verifies the tampered node.
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityKS(t, kid)
	realStore, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)
	chain := buildChain(t, realStore, ks, kid, 3, "continuity-llm") // gen-0, gen-1, gen-2
	leaf := chain[2]

	// Load the real descriptors, tamper with gen-1's signature, then
	// serve from fakeStore.
	g0, err := realStore.Get(chain[0])
	require.NoError(t, err)
	g1, err := realStore.Get(chain[1])
	require.NoError(t, err)
	g2, err := realStore.Get(leaf)
	require.NoError(t, err)

	// Flip one bit of gen-1's signature. The body is still self-
	// consistent (R-14 still holds) but the signature is no longer
	// valid — VerifyWithSignatures must catch it.
	g1.Signature[0] ^= 0x01

	f := newFakeStore()
	f.inject(chain[0], g0)
	f.inject(chain[1], g1)
	f.inject(leaf, g2)

	err = succession.VerifyWithSignatures(leaf, f, ks)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}
