// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package genome_descriptor

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1

	// GenomeIDPrefix is the human-readable tag that every derived GenomeID
	// carries. It is part of the content-addressing rule; changing it
	// invalidates all existing AGDs.
	GenomeIDPrefix = "gen:"
)

// Kind enumerates the classes of AI systems the platform preserves. The
// list is closed; additions are doctrinal bumps.
type Kind string

const (
	KindTransformer      Kind = "transformer"
	KindDiffusion        Kind = "diffusion"
	KindRLPolicy         Kind = "rl-policy"
	KindMLP              Kind = "mlp"
	KindStateSpace       Kind = "state-space"
	KindMixtureOfExperts Kind = "moe"
	KindOther            Kind = "other"
)

// DerivationMethod enumerates how a descendant genome was produced from a
// parent. Intentionally small; each method carries a specific doctrinal
// meaning for continuity.
type DerivationMethod string

const (
	// DerivationFineTune — continued training on new data. Behavioral
	// fingerprint may drift; identity is preserved.
	DerivationFineTune DerivationMethod = "fine-tune"

	// DerivationDistill — a smaller genome trained to match the parent's
	// behavior on a distribution. Behavior preserved, weights fresh.
	DerivationDistill DerivationMethod = "distill"

	// DerivationMerge — weights interpolated from multiple parents. All
	// parents appear in DerivedFrom.
	DerivationMerge DerivationMethod = "merge"

	// DerivationQuantize — numerical precision reduction (e.g., fp32→int8).
	// Behavioral fingerprint allowed to drift within declared tolerance.
	DerivationQuantize DerivationMethod = "quantize"

	// DerivationReconstruct — this genome is the output of an ACP
	// reconstruction flow from its parent. The canonical path for
	// cross-generation continuity.
	DerivationReconstruct DerivationMethod = "reconstruct"
)

// ArchitectureDescriptor names the shape of the genome sufficient for a
// compatible worker to allocate state and reload weights. It does NOT
// contain weights or probes.
type ArchitectureDescriptor struct {
	// Framework is the target runtime. Stable string; e.g. "pytorch-2.1",
	// "jax-0.4", "onnx-1.15". Required.
	Framework string `json:"framework"`

	// ModelClass is the architecture family within the framework; e.g.
	// "transformer-decoder", "unet-2d". Required.
	ModelClass string `json:"model_class"`

	// ParameterCount is the total number of trainable parameters. Used for
	// sanity checks against the component tree's claimed byte-totals.
	ParameterCount uint64 `json:"parameter_count"`

	// PrecisionBits is the numerical precision encoding of most weights,
	// e.g. 16 for fp16/bf16, 32 for fp32, 8 for int8. Zero means mixed.
	PrecisionBits uint8 `json:"precision_bits"`

	// ConfigHash is the SHA-256 of the framework-specific config (e.g.
	// HuggingFace config.json). The config itself lives as a component
	// in the tree; this field cross-checks the tree's config-kind leaves.
	ConfigHash []byte `json:"config_hash"`
}

// GenomeDerivation records one parent-to-descendant relationship.
type GenomeDerivation struct {
	// ParentGenomeID identifies the parent. The parent AGD is resolvable
	// independently; this field is only the name.
	ParentGenomeID ids.GenomeID `json:"parent_genome_id"`

	// Method names the transformation applied to the parent.
	Method DerivationMethod `json:"method"`
}

// ProvenanceRecord records how this genome came to be — training producer,
// training data root (Merkle root over the corpus, no data materialized),
// training recipe hash, and the derivation chain from parent genomes.
type ProvenanceRecord struct {
	// ProducerIdentity is the stable string form of the trainer's identity
	// (fingerprint or subject). Required.
	ProducerIdentity string `json:"producer_identity"`

	// ProducedAt is wall-clock of production. Required.
	ProducedAt time.Time `json:"produced_at"`

	// TrainingDataRoot is the Merkle root over the training corpus. May be
	// zero-length if data provenance is declared out-of-scope; the policy
	// layer decides whether that is acceptable.
	TrainingDataRoot []byte `json:"training_data_root,omitempty"`

	// TrainingRecipeHash is SHA-256 of the canonical form of the training
	// recipe (code + hyperparameters + environment descriptor). Optional
	// for the same reason as TrainingDataRoot.
	TrainingRecipeHash []byte `json:"training_recipe_hash,omitempty"`

	// DerivedFrom is the list of parents this genome was produced from.
	// Empty ⇒ this is a generation-0 (root) genome.
	DerivedFrom []GenomeDerivation `json:"derived_from,omitempty"`
}

// ProbeBatteryRoot names the behavioral-probe commitment embedded in this
// genome. The battery itself (inputs + expected scores from the ORIGINAL
// genome) lives alongside the AGD; these roots bind the AGD to a specific
// battery version.
type ProbeBatteryRoot struct {
	// BatteryID is a human-readable name for the battery (e.g.
	// "llm-reasoning-v3"). Required.
	BatteryID string `json:"battery_id"`

	// BatterySchemaVersion is the battery format version. Required.
	BatterySchemaVersion uint16 `json:"battery_schema_version"`

	// BatteryMerkleRoot commits to the PROBE DEFINITIONS (inputs and
	// expected-output schemas). A genome and its descendants share the
	// same BatteryMerkleRoot if they are being compared on the same
	// probes. Required (32 bytes).
	BatteryMerkleRoot []byte `json:"battery_merkle_root"`

	// CanonicalScoresRoot commits to the ORIGINAL genome's scores on the
	// battery. Descendant genomes carry their own CanonicalScoresRoot,
	// computed on themselves; behavioral equivalence is a tolerance
	// check across these roots. Required (32 bytes).
	CanonicalScoresRoot []byte `json:"canonical_scores_root"`

	// ProbeCount is the number of probes in the battery. Informational.
	ProbeCount uint32 `json:"probe_count"`

	// MinPassingScore is the default threshold (in [0,1]) below which the
	// behavioral dimension fails. Policy may tighten, never loosen.
	MinPassingScore float64 `json:"min_passing_score"`
}

// GenomeDescriptor is the signed, content-addressed root of an AI Genome.
type GenomeDescriptor struct {
	// SchemaVersion gates the wire format. Readers MUST validate first.
	SchemaVersion uint16 `json:"schema_version"`

	// GenomeID is DERIVED (see Derive()), not assigned. It equals
	//   "gen:" + hex(SHA-256(canonical-JSON(this descriptor with GenomeID=""
	//                                       and Signature=nil))).
	// Validate() recomputes and rejects on mismatch.
	GenomeID ids.GenomeID `json:"genome_id"`

	// FamilyName is a human-readable family identifier (e.g. "continuity-llm").
	// Not unique on its own — the GenomeID is what identifies a genome.
	FamilyName string `json:"family_name"`

	// Generation is 0 for root genomes; N for the Nth descendant in a
	// succession chain. Monotonic across any single chain.
	Generation uint64 `json:"generation"`

	// Kind is the architectural family.
	Kind Kind `json:"kind"`

	// Architecture describes the runtime shape sufficient to allocate state.
	Architecture ArchitectureDescriptor `json:"architecture"`

	// ComponentTreeRoot is the RFC 6962-style SHA-256 Merkle root over the
	// genome's components. Exactly 32 bytes.
	ComponentTreeRoot []byte `json:"component_tree_root"`

	// ComponentCount is the number of leaves in the tree. Must equal the
	// tree's Size(); cross-checked by validators outside this contract.
	ComponentCount uint32 `json:"component_count"`

	// TotalBytes is the sum of Component.ByteSize across all components.
	// Informational; cross-checked by higher layers.
	TotalBytes uint64 `json:"total_bytes"`

	// Provenance is the training-and-derivation record.
	Provenance ProvenanceRecord `json:"provenance"`

	// BehavioralFingerprint is the probe-battery commitment.
	BehavioralFingerprint ProbeBatteryRoot `json:"behavioral_fingerprint"`

	// PolicyLabels are free-form key/value tags the policy engine may
	// evaluate against. Keys are sorted for canonical encoding via the
	// JCS profile. Optional.
	PolicyLabels map[string]string `json:"policy_labels,omitempty"`

	// IssuedAt is wall-clock of AGD issuance. Required.
	IssuedAt time.Time `json:"issued_at"`

	// SigningKeyID identifies the authority that signed this descriptor.
	// Signatures use PurposeSigningAuthority.
	SigningKeyID ids.KeyID `json:"signing_key_id"`

	// Signature is the Ed25519 signature over CanonicalBytes (which
	// excludes Signature itself).
	Signature []byte `json:"signature"`
}
