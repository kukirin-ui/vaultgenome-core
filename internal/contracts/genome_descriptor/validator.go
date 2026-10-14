// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package genome_descriptor

import (
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// validKinds is the closed set of recognized architectural families.
// Doctrine addition requires a schema-version bump.
var validKinds = map[Kind]struct{}{
	KindTransformer:      {},
	KindDiffusion:        {},
	KindRLPolicy:         {},
	KindMLP:              {},
	KindStateSpace:       {},
	KindMixtureOfExperts: {},
	KindOther:            {},
}

// validDerivationMethods is the closed set of parent→descendant
// transformations. Unknown values are rejected; adding one is a
// doctrinal act, not a runtime extension point.
var validDerivationMethods = map[DerivationMethod]struct{}{
	DerivationFineTune:    {},
	DerivationDistill:     {},
	DerivationMerge:       {},
	DerivationQuantize:    {},
	DerivationReconstruct: {},
}

// Validate runs static consistency checks AND verifies the content-
// addressing invariant (R-14): the stored GenomeID must equal the ID
// derived from the descriptor's own canonical form. Signature verification
// is NOT performed here — see VerifySignature for that.
//
// Classification of failures:
//   - Missing/malformed fields, schema violations, cross-field issues   →
//     Structural.
//   - Stored GenomeID disagrees with derivation                         →
//     Integrity (this is the anti-silent-mutation gate).
func (g GenomeDescriptor) Validate() error {
	if g.SchemaVersion < SchemaVersionMin || g.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"genome_descriptor: schema_version out of supported range",
			nil,
		)
	}
	if g.GenomeID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: genome_id required",
			nil,
		)
	}
	if !strings.HasPrefix(g.GenomeID.String(), GenomeIDPrefix) {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: genome_id missing canonical prefix",
			nil,
		)
	}
	if g.FamilyName == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: family_name required",
			nil,
		)
	}
	if _, ok := validKinds[g.Kind]; !ok {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: unknown kind",
			nil,
		)
	}
	if err := g.validateArchitecture(); err != nil {
		return err
	}
	if len(g.ComponentTreeRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: component_tree_root must be 32 bytes",
			nil,
		)
	}
	if g.ComponentCount == 0 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: component_count must be > 0",
			nil,
		)
	}
	if g.TotalBytes == 0 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: total_bytes must be > 0",
			nil,
		)
	}
	if err := g.validateProvenance(); err != nil {
		return err
	}
	if err := g.validateBehavioralFingerprint(); err != nil {
		return err
	}
	if g.IssuedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: issued_at required",
			nil,
		)
	}
	if g.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: signing_key_id required",
			nil,
		)
	}
	if len(g.Signature) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: signature required",
			nil,
		)
	}
	// ---- Content-addressing invariant (R-14) -----------------------------
	//
	// Recompute the ID from the descriptor's own bytes and compare. A
	// mismatch means someone is presenting a descriptor whose name does
	// not belong to its body — Integrity, not Structural.
	derived, err := g.DeriveID()
	if err != nil {
		return err
	}
	if derived != g.GenomeID {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"genome_descriptor: stored genome_id disagrees with content-addressed derivation",
			nil,
		)
	}
	return nil
}

// validateArchitecture enforces structural invariants on the embedded
// ArchitectureDescriptor. The config itself lives in the component tree;
// here we only check the descriptor-level fields.
func (g *GenomeDescriptor) validateArchitecture() error {
	a := g.Architecture
	if a.Framework == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: architecture.framework required",
			nil,
		)
	}
	if a.ModelClass == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: architecture.model_class required",
			nil,
		)
	}
	if a.ParameterCount == 0 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: architecture.parameter_count must be > 0",
			nil,
		)
	}
	// PrecisionBits == 0 means "mixed" and is allowed.
	if len(a.ConfigHash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: architecture.config_hash must be 32 bytes",
			nil,
		)
	}
	return nil
}

// validateProvenance enforces structural invariants on the provenance
// record and the derivation chain.
func (g *GenomeDescriptor) validateProvenance() error {
	p := g.Provenance
	if p.ProducerIdentity == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: provenance.producer_identity required",
			nil,
		)
	}
	if p.ProducedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: provenance.produced_at required",
			nil,
		)
	}
	// Optional hashes: if present, they must be the right shape.
	if len(p.TrainingDataRoot) != 0 && len(p.TrainingDataRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: provenance.training_data_root must be 32 bytes when present",
			nil,
		)
	}
	if len(p.TrainingRecipeHash) != 0 && len(p.TrainingRecipeHash) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: provenance.training_recipe_hash must be 32 bytes when present",
			nil,
		)
	}
	// Generation 0 ⇔ DerivedFrom empty. Asymmetry is a cross-field error.
	if g.Generation == 0 && len(p.DerivedFrom) != 0 {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"genome_descriptor: generation=0 must have no parents",
			nil,
		)
	}
	if g.Generation > 0 && len(p.DerivedFrom) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"genome_descriptor: generation>0 requires at least one parent in derived_from",
			nil,
		)
	}
	seen := make(map[string]struct{}, len(p.DerivedFrom))
	for i, d := range p.DerivedFrom {
		if d.ParentGenomeID.IsZero() {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"genome_descriptor: provenance.derived_from contains zero parent_genome_id",
				nil,
			)
		}
		if !strings.HasPrefix(d.ParentGenomeID.String(), GenomeIDPrefix) {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"genome_descriptor: provenance.derived_from parent missing canonical prefix",
				nil,
			)
		}
		if d.ParentGenomeID == g.GenomeID {
			return shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"genome_descriptor: genome cannot derive from itself",
				nil,
			)
		}
		if _, dup := seen[d.ParentGenomeID.String()]; dup {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"genome_descriptor: provenance.derived_from contains duplicate parent",
				nil,
			)
		}
		seen[d.ParentGenomeID.String()] = struct{}{}
		if _, ok := validDerivationMethods[d.Method]; !ok {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"genome_descriptor: provenance.derived_from["+toDec(i)+"] unknown method",
				nil,
			)
		}
	}
	return nil
}

// validateBehavioralFingerprint enforces structural invariants on the
// probe-battery commitment.
func (g *GenomeDescriptor) validateBehavioralFingerprint() error {
	b := g.BehavioralFingerprint
	if b.BatteryID == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: behavioral_fingerprint.battery_id required",
			nil,
		)
	}
	if b.BatterySchemaVersion == 0 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: behavioral_fingerprint.battery_schema_version must be > 0",
			nil,
		)
	}
	if len(b.BatteryMerkleRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: behavioral_fingerprint.battery_merkle_root must be 32 bytes",
			nil,
		)
	}
	if len(b.CanonicalScoresRoot) != crypto.HashSize {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: behavioral_fingerprint.canonical_scores_root must be 32 bytes",
			nil,
		)
	}
	if b.ProbeCount == 0 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: behavioral_fingerprint.probe_count must be > 0",
			nil,
		)
	}
	if b.MinPassingScore < 0 || b.MinPassingScore > 1 {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: behavioral_fingerprint.min_passing_score must be in [0,1]",
			nil,
		)
	}
	return nil
}

// toDec is a dependency-free small-integer→decimal helper used only for
// error-message construction. Keeping it here avoids importing strconv
// for a single call site.
func toDec(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
