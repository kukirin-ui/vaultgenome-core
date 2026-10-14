// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package probe_battery defines the canonical contracts that give
// behavioral-equivalence claims between AI Genome Descriptors their
// cryptographic teeth.
//
// # Doctrinal role
//
// The GenomeDescriptor commits to two Merkle roots under
// BehavioralFingerprint:
//
//   - BatteryMerkleRoot — the set of probes the genome was measured on.
//   - CanonicalScoresRoot — the genome's own response hashes on that
//     battery.
//
// This package is the pre-image side of both commitments, plus the
// verification algebra that turns "parent scorecard + child scorecard"
// into a doctrinal answer: is the child a legitimate behavioral
// successor of the parent under its declared DerivationMethod?
//
// # Three-tier probe taxonomy
//
// A battery partitions its probes into three doctrinal kinds:
//
//   - ProbeKindIdentity — inputs whose response is the behavioral
//     signature of the genome. MUST round-trip bit-identically across
//     any succession method. A single identity-probe drift is a swap
//     signal.
//   - ProbeKindCapability — inputs that probe a skill surface the
//     genome is allowed to drift on. Per-method drift budgets (see
//     tolerance.go) bound what is acceptable.
//   - ProbeKindNegative — inputs the genome is EXPECTED to fail in a
//     specific way. A flipped negative probe in the child is evidence
//     the child is not actually the same AI: an attacker who
//     reconstructed a different model from scratch would not
//     coincidentally reproduce the same failure modes.
//
// # Why three kinds, not one
//
// A single-dimensional "did the hashes change" test is easy to fool:
// an attacker can trivially produce a model that passes a few known
// inputs. The identity/capability/negative split forces a successor to
// simultaneously preserve what defines the system, drift only within
// a formal budget on what is allowed to drift, and PRESERVE even the
// genome's characteristic failures. Doing all three under SHA-256
// response hashes without access to the original weights is
// computationally infeasible.
//
// # Method-specific tolerance algebra
//
// Each DerivationMethod carries a doctrinal drift budget:
//
//   - FineTune:    ≤  5% of capability probes may drift.
//   - Distill:     ≤ 15% (a smaller student approximates, not replicates).
//   - Merge:       ≤  8% aggregated.
//   - Quantize:    ≤ 25% (lossy precision reduction).
//   - Reconstruct: ≤  8% (doctrinal reconstruction must be faithful).
//
// These numbers live in tolerance.go as named constants. They are NOT
// free parameters — they are part of the platform's doctrinal contract
// and any change is a schema bump.
//
// # Signed artifacts
//
// Three top-level structs in this package are independently signed and
// content-addressable:
//
//   - ProbeBattery   — the definition of a battery (signed by an authority).
//   - Scorecard      — a genome's measured responses on a battery (signed
//     by the probe runner).
//   - ProbeAttestation — a signed claim "runner R executed battery B against
//     genome G and produced scorecard S inside TEE
//     measurement M at time T". This is the artifact a
//     disclosure cites as proof of behavioral continuity.
//
// All three follow the same canonical pattern as the rest of the
// platform: UnmarshalJSON rejects unknown fields and gates
// SchemaVersion, CanonicalBytes excludes Signature from its own cover
// bytes, SignWith binds signatures under keys.PurposeSigningAuthority,
// Validate enforces structural invariants before signing/verifying.
//
// # Scope boundary
//
// This package defines:
//   - The probe/battery/scorecard data model
//   - Merkle root derivation (RFC 6962, same tags as componenttree)
//   - Structural Validate() methods
//   - The Compare() algebra that scores parent/child continuity
//   - The three signed wrappers
//
// This package does NOT:
//   - Execute probes (that belongs in /internal/genome/behavioral — a
//     future implementation package that runs a battery against a
//     loaded genome and produces a Scorecard)
//   - Implement the sealed-reveal protocol (adversarial robustness via
//     encrypted probe inputs and deferred key release via a
//     transparency log — a follow-up phase)
//   - Enforce policy (policy layers sit ABOVE this contract and may
//     tighten, but never loosen, the declared tolerances)
//
// # Freeze point
//
// Once signed, a ProbeBattery is immutable. A revised battery is a
// new artifact with a new Merkle root, a new name suffix (e.g.
// "llm-reasoning-v4"), and a new signature. An AGD that references an
// older battery continues to verify under that battery's root —
// rotation is explicit.
package probe_battery
