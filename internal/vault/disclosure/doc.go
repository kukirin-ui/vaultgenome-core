// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package disclosure implements the vault's release-side contracts:
// Staged Disclosure for sealed component emissions AND the Continuity
// Issuer that composes signed ContinuityProof bundles.
//
// # Doctrinal role
//
// Two distinct release flows live here. They share the package because
// both are authority-owned, audit-citable, and governed by the same
// "never materialize plaintext genome, always cite content commitments"
// invariant.
//
//  1. Staged Disclosure (forthcoming). The full AI Genome is never
//     reassembled in one place. This sub-system enforces:
//
//     • monotonic sequence-index ordering within a session,
//
//     • sealed payloads only (AES-256-GCM; plaintext never leaves here),
//
//     • one DisclosureMessage per component emission, audit-bound,
//
//     • refusal to authorize if the active policy has drifted from the
//     session's pinned PolicyVersion.
//
//     This is where the "no raw export" invariant is enforced. The
//     doctrine test suite at /test/doctrine asserts that no call path
//     from this package writes plaintext genome bytes to any sink other
//     than the internal GCM sealing function.
//
//  2. Continuity Issuer (issuer.go). Binds a signed AGD succession chain
//     + signed ProbeScorecard + signed ProbeAttestation into a single
//     ContinuityProof bundle. The issuer is the ONLY object in the
//     platform that reads the AGD content-addressed store to extract a
//     full ancestor DAG and commits a cross-binding entry to the
//     witness transparency log. Receiver-side verification is
//     implemented by /internal/contracts/continuity_proof and does not
//     depend on this package.
//
// Corresponds to P3 §[0018] (staged disclosure) and P3 §[0034]
// (continuity attestation).
package disclosure
