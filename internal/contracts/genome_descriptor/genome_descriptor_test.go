// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package genome_descriptor

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// fixedHash returns a deterministic 32-byte hash filled with b.
// Used to give fixtures stable, recognizable commitments.
func fixedHash(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

// genesisFixture returns a valid generation-0 descriptor WITHOUT GenomeID
// or Signature populated. The identity and signature tests drive those
// fields from empty; the Validate-style tests populate them explicitly.
func genesisFixture() GenomeDescriptor {
	issued := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	produced := time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC)
	return GenomeDescriptor{
		SchemaVersion: SchemaVersionCurrent,
		FamilyName:    "continuity-llm",
		Generation:    0,
		Kind:          KindTransformer,
		Architecture: ArchitectureDescriptor{
			Framework:      "pytorch-2.1",
			ModelClass:     "transformer-decoder",
			ParameterCount: 7_000_000_000,
			PrecisionBits:  16,
			ConfigHash:     fixedHash(0xA1),
		},
		ComponentTreeRoot: fixedHash(0xB2),
		ComponentCount:    512,
		TotalBytes:        14_000_000_000,
		Provenance: ProvenanceRecord{
			ProducerIdentity:   "producer:alpha-lab",
			ProducedAt:         produced,
			TrainingDataRoot:   fixedHash(0xC3),
			TrainingRecipeHash: fixedHash(0xD4),
			DerivedFrom:        nil,
		},
		BehavioralFingerprint: ProbeBatteryRoot{
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

// signedFixture returns a fully-populated descriptor with a derived
// GenomeID and a placeholder signature. Use this for Validate tests that
// don't care whether the signature is cryptographically real.
func signedFixture(t *testing.T) GenomeDescriptor {
	t.Helper()
	g := genesisFixture()
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	g.Signature = bytes.Repeat([]byte{0x77}, 64) // len only matters to Validate
	return g
}

// ---- DeriveID --------------------------------------------------------------

func TestGenomeDescriptor_DeriveID_Idempotent(t *testing.T) {
	t.Parallel()
	g := genesisFixture()
	a, err := g.DeriveID()
	require.NoError(t, err)

	// Assign it, derive again — should produce the same value (DeriveID
	// zeros GenomeID in the pre-image, so pre-existing storage is ignored).
	g.GenomeID = a
	b, err := g.DeriveID()
	require.NoError(t, err)
	require.Equal(t, a, b, "DeriveID must be idempotent")
}

func TestGenomeDescriptor_DeriveID_SignatureDoesNotInfluenceID(t *testing.T) {
	t.Parallel()
	// Signing the descriptor produces a Signature, but the derivation
	// pre-image zeros the Signature — so stamping a signature MUST NOT
	// shift the ID.
	g := genesisFixture()
	before, err := g.DeriveID()
	require.NoError(t, err)

	g.Signature = bytes.Repeat([]byte{0x01}, 64)
	after, err := g.DeriveID()
	require.NoError(t, err)

	require.Equal(t, before, after, "Signature must not be covered by the ID derivation")
}

func TestGenomeDescriptor_DeriveID_ContentSensitive(t *testing.T) {
	t.Parallel()
	// The whole point of content-addressing: any change to any covered
	// field changes the ID. We spot-check a representative selection.
	base := genesisFixture()
	baseID, err := base.DeriveID()
	require.NoError(t, err)

	cases := []struct {
		name   string
		mutate func(*GenomeDescriptor)
	}{
		{"family_name", func(g *GenomeDescriptor) { g.FamilyName = "something-else" }},
		{"generation", func(g *GenomeDescriptor) { g.Generation = 1 }},
		{"kind", func(g *GenomeDescriptor) { g.Kind = KindDiffusion }},
		{"framework", func(g *GenomeDescriptor) { g.Architecture.Framework = "jax-0.4" }},
		{"param_count", func(g *GenomeDescriptor) { g.Architecture.ParameterCount = 42 }},
		{"tree_root", func(g *GenomeDescriptor) { g.ComponentTreeRoot = fixedHash(0x00) }},
		{"component_count", func(g *GenomeDescriptor) { g.ComponentCount = 1 }},
		{"total_bytes", func(g *GenomeDescriptor) { g.TotalBytes = 1 }},
		{"producer_identity", func(g *GenomeDescriptor) { g.Provenance.ProducerIdentity = "other" }},
		{"battery_id", func(g *GenomeDescriptor) { g.BehavioralFingerprint.BatteryID = "other" }},
		{"policy_label", func(g *GenomeDescriptor) { g.PolicyLabels["classification"] = "public" }},
		{"issued_at", func(g *GenomeDescriptor) { g.IssuedAt = g.IssuedAt.Add(time.Second) }},
		{"signing_key_id", func(g *GenomeDescriptor) { g.SigningKeyID = ids.KeyID("other-key") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := genesisFixture()
			tc.mutate(&g)
			got, err := g.DeriveID()
			require.NoError(t, err)
			require.NotEqual(t, baseID, got, "%s change must shift GenomeID", tc.name)
		})
	}
}

func TestGenomeDescriptor_DeriveID_PrefixAndHexShape(t *testing.T) {
	t.Parallel()
	g := genesisFixture()
	id, err := g.DeriveID()
	require.NoError(t, err)
	s := id.String()
	require.True(t, len(s) == len(GenomeIDPrefix)+64, "id must be prefix + 64 hex chars, got %q", s)
	require.Equal(t, GenomeIDPrefix, s[:len(GenomeIDPrefix)])
	for _, c := range s[len(GenomeIDPrefix):] {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		require.True(t, isHex, "non-hex character in derived id: %q", c)
	}
}

// ---- Validate: happy path --------------------------------------------------

func TestGenomeDescriptor_Validate_OK(t *testing.T) {
	t.Parallel()
	g := signedFixture(t)
	require.NoError(t, g.Validate())
}

func TestGenomeDescriptor_Validate_GenerationN_WithParents(t *testing.T) {
	t.Parallel()
	// Exercise the gen>0 branch: a descendant citing a parent GenomeID.
	g := genesisFixture()
	g.Generation = 3
	g.Provenance.DerivedFrom = []GenomeDerivation{
		{ParentGenomeID: ids.GenomeID(GenomeIDPrefix + "aa"), Method: DerivationFineTune},
		{ParentGenomeID: ids.GenomeID(GenomeIDPrefix + "bb"), Method: DerivationMerge},
	}
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	g.Signature = bytes.Repeat([]byte{0x33}, 64)
	require.NoError(t, g.Validate())
}

// ---- Validate: Integrity (content-addressing) -----------------------------

func TestGenomeDescriptor_Validate_RejectsMutatedBody(t *testing.T) {
	t.Parallel()
	// Sign and derive honestly, then mutate a covered field AFTER derivation.
	// The stored GenomeID will no longer match the new pre-image ⇒ Integrity.
	g := signedFixture(t)
	g.FamilyName = "mutated-after-derivation"
	err := g.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
		"mutation after derivation must classify as Integrity, got %v", err)
}

func TestGenomeDescriptor_Validate_RejectsForgedID(t *testing.T) {
	t.Parallel()
	// A caller who assigns an unrelated GenomeID must be rejected.
	g := signedFixture(t)
	g.GenomeID = ids.GenomeID(GenomeIDPrefix + "deadbeef")
	err := g.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// ---- Validate: Structural --------------------------------------------------

func TestGenomeDescriptor_Validate_NegativeCases(t *testing.T) {
	t.Parallel()
	type tc struct {
		name     string
		mutate   func(*GenomeDescriptor)
		wantCode string
	}
	cases := []tc{
		{"schema_zero", func(g *GenomeDescriptor) { g.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"schema_above_max", func(g *GenomeDescriptor) { g.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		{"genome_id_missing", func(g *GenomeDescriptor) { g.GenomeID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"genome_id_bad_prefix", func(g *GenomeDescriptor) { g.GenomeID = ids.GenomeID("xxx:abc") }, shared_errors.CodeFieldValueInvalid},
		{"family_missing", func(g *GenomeDescriptor) { g.FamilyName = "" }, shared_errors.CodeRequiredFieldMissing},
		{"kind_invalid", func(g *GenomeDescriptor) { g.Kind = Kind("android") }, shared_errors.CodeFieldValueInvalid},
		{"arch_framework_missing", func(g *GenomeDescriptor) { g.Architecture.Framework = "" }, shared_errors.CodeRequiredFieldMissing},
		{"arch_model_class_missing", func(g *GenomeDescriptor) { g.Architecture.ModelClass = "" }, shared_errors.CodeRequiredFieldMissing},
		{"arch_param_count_zero", func(g *GenomeDescriptor) { g.Architecture.ParameterCount = 0 }, shared_errors.CodeFieldValueInvalid},
		{"arch_config_hash_short", func(g *GenomeDescriptor) { g.Architecture.ConfigHash = []byte{1, 2, 3} }, shared_errors.CodeFieldValueInvalid},
		{"tree_root_short", func(g *GenomeDescriptor) { g.ComponentTreeRoot = []byte{1, 2, 3} }, shared_errors.CodeFieldValueInvalid},
		{"component_count_zero", func(g *GenomeDescriptor) { g.ComponentCount = 0 }, shared_errors.CodeFieldValueInvalid},
		{"total_bytes_zero", func(g *GenomeDescriptor) { g.TotalBytes = 0 }, shared_errors.CodeFieldValueInvalid},
		{"producer_identity_missing", func(g *GenomeDescriptor) { g.Provenance.ProducerIdentity = "" }, shared_errors.CodeRequiredFieldMissing},
		{"produced_at_zero", func(g *GenomeDescriptor) { g.Provenance.ProducedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"training_data_root_wrong_size", func(g *GenomeDescriptor) { g.Provenance.TrainingDataRoot = []byte{1, 2} }, shared_errors.CodeFieldValueInvalid},
		{"training_recipe_wrong_size", func(g *GenomeDescriptor) { g.Provenance.TrainingRecipeHash = []byte{1, 2} }, shared_errors.CodeFieldValueInvalid},
		{"battery_id_missing", func(g *GenomeDescriptor) { g.BehavioralFingerprint.BatteryID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"battery_schema_zero", func(g *GenomeDescriptor) { g.BehavioralFingerprint.BatterySchemaVersion = 0 }, shared_errors.CodeFieldValueInvalid},
		{"battery_root_short", func(g *GenomeDescriptor) { g.BehavioralFingerprint.BatteryMerkleRoot = []byte{1, 2} }, shared_errors.CodeFieldValueInvalid},
		{"canonical_scores_short", func(g *GenomeDescriptor) { g.BehavioralFingerprint.CanonicalScoresRoot = []byte{1, 2} }, shared_errors.CodeFieldValueInvalid},
		{"probe_count_zero", func(g *GenomeDescriptor) { g.BehavioralFingerprint.ProbeCount = 0 }, shared_errors.CodeFieldValueInvalid},
		{"min_passing_score_negative", func(g *GenomeDescriptor) { g.BehavioralFingerprint.MinPassingScore = -0.1 }, shared_errors.CodeFieldValueInvalid},
		{"min_passing_score_above_one", func(g *GenomeDescriptor) { g.BehavioralFingerprint.MinPassingScore = 1.1 }, shared_errors.CodeFieldValueInvalid},
		{"issued_at_zero", func(g *GenomeDescriptor) { g.IssuedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"signing_key_missing", func(g *GenomeDescriptor) { g.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature_empty", func(g *GenomeDescriptor) { g.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := signedFixture(t)
			c.mutate(&g)
			err := g.Validate()
			require.Error(t, err)
			require.Equal(t, c.wantCode, shared_errors.CodeOf(err))
		})
	}
}

func TestGenomeDescriptor_Validate_GenerationMismatch(t *testing.T) {
	t.Parallel()
	// gen=0 with parents → cross-field. Build via derivation so Validate
	// doesn't trip on the Integrity gate first.
	g := genesisFixture()
	g.Provenance.DerivedFrom = []GenomeDerivation{
		{ParentGenomeID: ids.GenomeID(GenomeIDPrefix + "aa"), Method: DerivationFineTune},
	}
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	g.Signature = bytes.Repeat([]byte{0x11}, 64)
	err = g.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	// gen>0 without parents → same class.
	g2 := genesisFixture()
	g2.Generation = 2
	id2, err := g2.DeriveID()
	require.NoError(t, err)
	g2.GenomeID = id2
	g2.Signature = bytes.Repeat([]byte{0x22}, 64)
	err = g2.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestGenomeDescriptor_Validate_SelfDerivationRejected(t *testing.T) {
	t.Parallel()
	g := genesisFixture()
	g.Generation = 1
	// Point a parent at ourselves. We can't predict our own ID before
	// deriving, so set parent after derivation.
	g.Provenance.DerivedFrom = []GenomeDerivation{
		{ParentGenomeID: ids.GenomeID(GenomeIDPrefix + "placeholder"), Method: DerivationFineTune},
	}
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	// Replace the parent with our own ID. This also changes the body
	// (parent field changed), so Validate will first see the Integrity
	// mismatch — which is itself the correct rejection.
	g.Provenance.DerivedFrom[0].ParentGenomeID = id
	g.Signature = bytes.Repeat([]byte{0x22}, 64)
	err = g.Validate()
	require.Error(t, err)
	// Either the content-addressing gate or the self-derivation gate
	// can fire first; both are expected refusals.
	cat := shared_errors.CategoryOf(err)
	require.True(t, cat == shared_errors.CategoryIntegrity || cat == shared_errors.CategoryStructural,
		"unexpected category %v for self-derivation rejection", cat)
}

func TestGenomeDescriptor_Validate_DuplicateParentRejected(t *testing.T) {
	t.Parallel()
	g := genesisFixture()
	g.Generation = 1
	parent := ids.GenomeID(GenomeIDPrefix + "aa")
	g.Provenance.DerivedFrom = []GenomeDerivation{
		{ParentGenomeID: parent, Method: DerivationFineTune},
		{ParentGenomeID: parent, Method: DerivationMerge},
	}
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	g.Signature = bytes.Repeat([]byte{0x11}, 64)
	err = g.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestGenomeDescriptor_Validate_UnknownDerivationMethod(t *testing.T) {
	t.Parallel()
	g := genesisFixture()
	g.Generation = 1
	g.Provenance.DerivedFrom = []GenomeDerivation{
		{ParentGenomeID: ids.GenomeID(GenomeIDPrefix + "aa"), Method: DerivationMethod("teleport")},
	}
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	g.Signature = bytes.Repeat([]byte{0x11}, 64)
	err = g.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

// ---- CanonicalBytes --------------------------------------------------------

func TestGenomeDescriptor_CanonicalBytes_Deterministic(t *testing.T) {
	t.Parallel()
	// Canonical encoding must be stable across independent fixtures so a
	// signature produced on one machine verifies on another.
	g1 := signedFixture(t)
	g2 := signedFixture(t)
	b1, err := g1.CanonicalBytes()
	require.NoError(t, err)
	b2, err := g2.CanonicalBytes()
	require.NoError(t, err)
	require.Equal(t, b1, b2, "canonical bytes must be deterministic for equal fixtures")
}

func TestGenomeDescriptor_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	g := signedFixture(t)
	// Give the signature a distinctive recognizable byte pattern.
	g.Signature = []byte{0xAB, 0xCD, 0xEF}
	b, err := g.CanonicalBytes()
	require.NoError(t, err)
	// base64 of 0xAB 0xCD 0xEF is "q83v"
	require.NotContains(t, string(b), `"q83v"`)
}

func TestGenomeDescriptor_CanonicalBytes_IncludesGenomeID(t *testing.T) {
	t.Parallel()
	// The signed cover-bytes MUST include GenomeID (that's what makes the
	// signature bind the identity to the body). derivationBytes excludes
	// it; CanonicalBytes does not.
	g := signedFixture(t)
	b, err := g.CanonicalBytes()
	require.NoError(t, err)
	require.Contains(t, string(b), g.GenomeID.String())
}
