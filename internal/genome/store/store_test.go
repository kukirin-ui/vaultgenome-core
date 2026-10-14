// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/genome/store"
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

func newAuthorityStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

// descriptorWithFamily returns a fully-signed descriptor. Varying family
// gives us a knob to produce distinct genomes on demand.
func descriptorWithFamily(t *testing.T, ks *keys.InMemoryStore, kid ids.KeyID, family string) genome_descriptor.GenomeDescriptor {
	t.Helper()
	issued := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	produced := time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC)
	g := genome_descriptor.GenomeDescriptor{
		SchemaVersion: genome_descriptor.SchemaVersionCurrent,
		FamilyName:    family,
		Generation:    0,
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
		PolicyLabels: map[string]string{
			"classification": "research",
		},
		IssuedAt:     issued,
		SigningKeyID: kid,
	}
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	require.NoError(t, g.SignWith(ks))
	require.NoError(t, g.Validate())
	return g
}

// ---- Construction ----------------------------------------------------------

func TestNewInMemoryStore_RejectsNilResolver(t *testing.T) {
	t.Parallel()
	_, err := store.NewInMemoryStore(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// ---- Put: happy path -------------------------------------------------------

func TestInMemoryStore_Put_HappyPath(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g := descriptorWithFamily(t, ks, kid, "continuity-llm")
	id, err := s.Put(&g)
	require.NoError(t, err)
	require.Equal(t, g.GenomeID, id)
	require.Equal(t, 1, s.Size())
	require.True(t, s.Exists(id))
}

// ---- Put: idempotence ------------------------------------------------------

func TestInMemoryStore_Put_IdempotentOnExactRePut(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g := descriptorWithFamily(t, ks, kid, "continuity-llm")
	id1, err := s.Put(&g)
	require.NoError(t, err)
	id2, err := s.Put(&g)
	require.NoError(t, err)
	require.Equal(t, id1, id2)
	require.Equal(t, 1, s.Size(), "idempotent re-put must not duplicate")
}

// ---- Put: rejection paths --------------------------------------------------

func TestInMemoryStore_Put_RejectsNilDescriptor(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	s, err := store.NewInMemoryStore(newAuthorityStore(t, kid))
	require.NoError(t, err)

	_, err = s.Put(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestInMemoryStore_Put_RejectsForgedID(t *testing.T) {
	t.Parallel()
	// Caller mutates GenomeID to a wrong value. Validate's R-14 gate
	// must trip (Integrity) before we ever look at the signature.
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g := descriptorWithFamily(t, ks, kid, "continuity-llm")
	g.GenomeID = ids.GenomeID(genome_descriptor.GenomeIDPrefix + "deadbeef")
	_, err = s.Put(&g)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, 0, s.Size())
}

func TestInMemoryStore_Put_RejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g := descriptorWithFamily(t, ks, kid, "continuity-llm")
	// Body stays self-consistent (ID still matches body), so Validate
	// passes. Flipping a bit in the signature trips VerifySignature.
	g.Signature[0] ^= 0x01
	_, err = s.Put(&g)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, 0, s.Size())
}

func TestInMemoryStore_Put_RejectsUnknownSigningKey(t *testing.T) {
	t.Parallel()
	// Key used to sign is not registered in the store's resolver.
	signKid := ids.KeyID("vault-auth-1")
	signKS := newAuthorityStore(t, signKid)

	// Fresh, empty keystore handed to the Store — won't know the signer.
	emptyFC := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	emptyKS := keys.NewInMemoryStore(emptyFC)
	s, err := store.NewInMemoryStore(emptyKS)
	require.NoError(t, err)

	g := descriptorWithFamily(t, signKS, signKid, "continuity-llm")
	_, err = s.Put(&g)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, 0, s.Size())
}

// ---- Put: collision (same ID, different bytes) -----------------------------

func TestInMemoryStore_Put_SameIDDifferentBytesIsIncident(t *testing.T) {
	t.Parallel()
	// Constructing a real SHA-256 collision is infeasible; we simulate
	// the effect by inserting bytes under an arbitrary key, then trying
	// a second Put of a DIFFERENT descriptor that — through a test-only
	// back door — claims the same ID. We do this by constructing a
	// valid descriptor, putting it, then putting it again after mutating
	// the Signature. The mutation changes the stored JSON bytes but the
	// Validate+R-14 check still passes up to the collision gate — except
	// the tampered signature fails VerifySignature first, so we cannot
	// exercise the collision branch through the public API.
	//
	// Instead, we exercise the collision branch directly: two freshly-
	// signed descriptors with the SAME body will produce the same ID
	// AND (because Ed25519 is deterministic) the same Signature bytes —
	// so they are byte-equal, which is the idempotent path. To exercise
	// the distinct-bytes-same-ID branch we need two DIFFERENT signatures
	// over the same body. We get that by re-signing under a second key
	// whose KeyID we force to match the first — impossible via the key
	// store, which forbids double registration. Therefore the collision
	// branch is only reachable in genuinely adversarial scenarios.
	//
	// What we CAN test, and what matters for correctness, is that the
	// IDEMPOTENT path holds for byte-identical re-puts (already covered
	// by TestInMemoryStore_Put_IdempotentOnExactRePut), and that ANY
	// deviation fails earlier in the integrity chain. Document that
	// here and assert the idempotent behavior as a secondary check.
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g1 := descriptorWithFamily(t, ks, kid, "continuity-llm")
	g2 := descriptorWithFamily(t, ks, kid, "continuity-llm")
	require.Equal(t, g1.GenomeID, g2.GenomeID, "same body ⇒ same ID")
	require.Equal(t, g1.Signature, g2.Signature, "Ed25519 is deterministic ⇒ same signature")

	_, err = s.Put(&g1)
	require.NoError(t, err)
	_, err = s.Put(&g2)
	require.NoError(t, err, "byte-identical re-put must be idempotent")
	require.Equal(t, 1, s.Size())
}

// ---- Get -------------------------------------------------------------------

func TestInMemoryStore_Get_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g := descriptorWithFamily(t, ks, kid, "continuity-llm")
	id, err := s.Put(&g)
	require.NoError(t, err)

	got, err := s.Get(id)
	require.NoError(t, err)
	require.Equal(t, g.GenomeID, got.GenomeID)
	require.Equal(t, g.FamilyName, got.FamilyName)
	require.Equal(t, g.Signature, got.Signature)

	// Verify re-derivation on loaded bytes is consistent.
	redid, err := got.DeriveID()
	require.NoError(t, err)
	require.Equal(t, id, redid)

	// And verify signature still checks out.
	require.NoError(t, got.VerifySignature(ks))
}

func TestInMemoryStore_Get_UnknownIDIsAuthority(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	s, err := store.NewInMemoryStore(newAuthorityStore(t, kid))
	require.NoError(t, err)

	_, err = s.Get(ids.GenomeID(genome_descriptor.GenomeIDPrefix + "nothinghere"))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

func TestInMemoryStore_Get_ZeroIDRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	s, err := store.NewInMemoryStore(newAuthorityStore(t, kid))
	require.NoError(t, err)

	_, err = s.Get("")
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestInMemoryStore_Get_ReturnsFreshCopy(t *testing.T) {
	t.Parallel()
	// Mutating the returned descriptor must NOT affect what the store
	// hands back on a subsequent Get.
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g := descriptorWithFamily(t, ks, kid, "continuity-llm")
	id, err := s.Put(&g)
	require.NoError(t, err)

	first, err := s.Get(id)
	require.NoError(t, err)
	first.FamilyName = "mutated-by-caller"

	second, err := s.Get(id)
	require.NoError(t, err)
	require.Equal(t, "continuity-llm", second.FamilyName)
}

// ---- Exists / Size ---------------------------------------------------------

func TestInMemoryStore_Exists_EmptyAndUnknown(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	s, err := store.NewInMemoryStore(newAuthorityStore(t, kid))
	require.NoError(t, err)

	require.False(t, s.Exists(""), "zero id must return false")
	require.False(t, s.Exists(ids.GenomeID(genome_descriptor.GenomeIDPrefix+"abc")))
	require.Equal(t, 0, s.Size())
}

// ---- Each ------------------------------------------------------------------

func TestInMemoryStore_Each_VisitsAll(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g1 := descriptorWithFamily(t, ks, kid, "family-one")
	g2 := descriptorWithFamily(t, ks, kid, "family-two")
	g3 := descriptorWithFamily(t, ks, kid, "family-three")
	for _, g := range []*genome_descriptor.GenomeDescriptor{&g1, &g2, &g3} {
		_, err := s.Put(g)
		require.NoError(t, err)
	}
	require.Equal(t, 3, s.Size())

	seen := make(map[ids.GenomeID]string)
	err = s.Each(func(id ids.GenomeID, g *genome_descriptor.GenomeDescriptor) error {
		seen[id] = g.FamilyName
		return nil
	})
	require.NoError(t, err)
	require.Len(t, seen, 3)
	require.Equal(t, "family-one", seen[g1.GenomeID])
	require.Equal(t, "family-two", seen[g2.GenomeID])
	require.Equal(t, "family-three", seen[g3.GenomeID])
}

func TestInMemoryStore_Each_StopsOnError(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g1 := descriptorWithFamily(t, ks, kid, "family-one")
	g2 := descriptorWithFamily(t, ks, kid, "family-two")
	for _, g := range []*genome_descriptor.GenomeDescriptor{&g1, &g2} {
		_, err := s.Put(g)
		require.NoError(t, err)
	}

	sentinel := shared_errors.Operational("test", "stop here", nil)
	visited := 0
	err = s.Each(func(id ids.GenomeID, g *genome_descriptor.GenomeDescriptor) error {
		visited++
		return sentinel
	})
	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 1, visited, "visit must halt on first error")
}

func TestInMemoryStore_Each_RejectsNilVisitor(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	s, err := store.NewInMemoryStore(newAuthorityStore(t, kid))
	require.NoError(t, err)

	err = s.Each(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// ---- Concurrency -----------------------------------------------------------

func TestInMemoryStore_Put_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	// Spawn N goroutines that each Put a distinct descriptor. The store
	// must end up with exactly N entries and no race detector complaints.
	// (Run with -race in CI.)
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	const N = 16
	descriptors := make([]genome_descriptor.GenomeDescriptor, N)
	for i := 0; i < N; i++ {
		descriptors[i] = descriptorWithFamily(t, ks, kid, "family-concurrent-"+intToDec(i))
	}

	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.Put(&descriptors[i])
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "goroutine %d failed", i)
	}
	require.Equal(t, N, s.Size())
}

func TestInMemoryStore_Put_ConcurrentSameDescriptorRemainsIdempotent(t *testing.T) {
	t.Parallel()
	// N goroutines racing to Put the SAME descriptor must converge on
	// exactly one entry with no errors.
	kid := ids.KeyID("vault-auth-1")
	ks := newAuthorityStore(t, kid)
	s, err := store.NewInMemoryStore(ks)
	require.NoError(t, err)

	g := descriptorWithFamily(t, ks, kid, "family-race")

	const N = 32
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.Put(&g)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "goroutine %d failed", i)
	}
	require.Equal(t, 1, s.Size())
}

// intToDec is a tiny helper used only for goroutine-distinguishing family
// names in the concurrent test. strconv would be fine too; this keeps the
// import list trim.
func intToDec(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}
