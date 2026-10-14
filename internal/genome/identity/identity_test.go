// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package identity_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/genome/identity"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// fixedHash returns a deterministic 32-byte hash filled with b.
func fixedHash(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

// makeDescriptor returns a valid generation-0 descriptor. Kept local to
// this test file so we do not depend on the contract package's test
// helpers (which live in its _test.go files and are not exported).
func makeDescriptor() genome_descriptor.GenomeDescriptor {
	issued := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	produced := time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC)
	return genome_descriptor.GenomeDescriptor{
		SchemaVersion: genome_descriptor.SchemaVersionCurrent,
		FamilyName:    "continuity-llm",
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
			"jurisdiction":   "XX",
		},
		IssuedAt:     issued,
		SigningKeyID: ids.KeyID("vault-auth-1"),
	}
}

// ---- Derive: basic properties ---------------------------------------------

func TestDerive_NilReturnsStructural(t *testing.T) {
	t.Parallel()
	_, err := identity.Derive(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestDerive_MatchesMethod(t *testing.T) {
	t.Parallel()
	// identity.Derive MUST be observationally identical to calling
	// DeriveID on the descriptor directly. If the two ever diverge,
	// somebody has forked the derivation rule — which is exactly the
	// failure mode this package exists to prevent.
	g := makeDescriptor()
	viaMethod, err := g.DeriveID()
	require.NoError(t, err)
	viaPackage, err := identity.Derive(&g)
	require.NoError(t, err)
	require.Equal(t, viaMethod, viaPackage)
}

func TestDerive_DoesNotMutate(t *testing.T) {
	t.Parallel()
	// Derive must be side-effect-free. In particular, it must not
	// populate the caller's GenomeID or clear their Signature.
	g := makeDescriptor()
	g.GenomeID = ids.GenomeID(identity.Prefix + "deadbeef") // a wrong id
	g.Signature = []byte{0xAA, 0xBB}                        // a placeholder
	before := g

	_, err := identity.Derive(&g)
	require.NoError(t, err)

	require.Equal(t, before.GenomeID, g.GenomeID, "Derive must not touch GenomeID")
	require.Equal(t, before.Signature, g.Signature, "Derive must not touch Signature")
}

func TestDerive_PrefixAndHexShape(t *testing.T) {
	t.Parallel()
	g := makeDescriptor()
	id, err := identity.Derive(&g)
	require.NoError(t, err)
	s := id.String()
	require.True(t, strings.HasPrefix(s, identity.Prefix), "id %q missing prefix", s)
	require.Equal(t, 64, len(s)-len(identity.Prefix), "expected 64 hex chars after prefix")
	for _, c := range s[len(identity.Prefix):] {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		require.Truef(t, isHex, "non-hex rune %q in derived id", c)
	}
}

// ---- Derive: idempotence ---------------------------------------------------

func TestDerive_Idempotent(t *testing.T) {
	t.Parallel()
	// Calling Derive twice on the same descriptor returns the same ID.
	g := makeDescriptor()
	a, err := identity.Derive(&g)
	require.NoError(t, err)
	b, err := identity.Derive(&g)
	require.NoError(t, err)
	require.Equal(t, a, b)
}

func TestDerive_StableWhenStoredIDIsPresent(t *testing.T) {
	t.Parallel()
	// Assigning the derived ID back onto the descriptor and re-deriving
	// must return the same value. This is the property that makes
	// content-addressing self-consistent: a producer who runs
	//
	//     g.GenomeID, _ = identity.Derive(&g)
	//
	// creates a descriptor that from then on identifies itself.
	g := makeDescriptor()
	a, err := identity.Derive(&g)
	require.NoError(t, err)
	g.GenomeID = a
	b, err := identity.Derive(&g)
	require.NoError(t, err)
	require.Equal(t, a, b)
}

// ---- Derive: JSON round-trip invariant -------------------------------------

func TestDerive_InvariantOverJSONRoundTrip(t *testing.T) {
	t.Parallel()
	// The core round-trip invariant: encoding a descriptor to JSON and
	// decoding it back must not shift its GenomeID. If this test ever
	// fails, the canonical form is non-deterministic — a fatal bug,
	// because no two machines would agree on a GenomeID.
	orig := makeDescriptor()
	idOrig, err := identity.Derive(&orig)
	require.NoError(t, err)
	orig.GenomeID = idOrig // populate before encoding so the wire form is realistic

	data, err := json.Marshal(&orig)
	require.NoError(t, err)

	var round genome_descriptor.GenomeDescriptor
	require.NoError(t, json.Unmarshal(data, &round))

	idRound, err := identity.Derive(&round)
	require.NoError(t, err)
	require.Equal(t, idOrig, idRound,
		"GenomeID must be invariant across JSON round-trip")
}

// ---- Verify ----------------------------------------------------------------

func TestVerify_AcceptsConsistentDescriptor(t *testing.T) {
	t.Parallel()
	g := makeDescriptor()
	id, err := identity.Derive(&g)
	require.NoError(t, err)
	g.GenomeID = id
	require.NoError(t, identity.Verify(&g))
}

func TestVerify_RejectsMissingID(t *testing.T) {
	t.Parallel()
	g := makeDescriptor()
	// g.GenomeID is zero.
	err := identity.Verify(&g)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerify_RejectsMutatedBody(t *testing.T) {
	t.Parallel()
	g := makeDescriptor()
	id, err := identity.Derive(&g)
	require.NoError(t, err)
	g.GenomeID = id
	// Mutate a covered field after derivation — Verify must flag it.
	g.FamilyName = "renamed-after-derivation"
	err = identity.Verify(&g)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerify_RejectsForgedID(t *testing.T) {
	t.Parallel()
	g := makeDescriptor()
	g.GenomeID = ids.GenomeID(identity.Prefix + "0000000000000000000000000000000000000000000000000000000000000000")
	err := identity.Verify(&g)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestVerify_NilReturnsStructural(t *testing.T) {
	t.Parallel()
	err := identity.Verify(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// ---- Derive: content-sensitivity spot check --------------------------------

func TestDerive_AnyCoveredFieldChangeShiftsID(t *testing.T) {
	t.Parallel()
	// The contract package has the exhaustive sensitivity matrix; here
	// we only verify that the wrapper preserves the property end-to-end.
	base := makeDescriptor()
	baseID, err := identity.Derive(&base)
	require.NoError(t, err)

	mutated := makeDescriptor()
	mutated.Architecture.ParameterCount = 1 // smallest possible covered change
	got, err := identity.Derive(&mutated)
	require.NoError(t, err)
	require.NotEqual(t, baseID, got)
}

func TestDerive_SignatureDoesNotShiftID(t *testing.T) {
	t.Parallel()
	// Signature is excluded from the pre-image by construction. Stamping
	// one in MUST NOT shift the ID — otherwise signing a descriptor
	// would alter its identity, and the whole point of content-
	// addressing collapses.
	before := makeDescriptor()
	beforeID, err := identity.Derive(&before)
	require.NoError(t, err)

	after := makeDescriptor()
	after.Signature = []byte{0x01, 0x02, 0x03}
	afterID, err := identity.Derive(&after)
	require.NoError(t, err)

	require.Equal(t, beforeID, afterID)
}
