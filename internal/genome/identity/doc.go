// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package identity is the public face of the AI Genome content-addressing
// rule. It exposes a single function, Derive, that returns the GenomeID of
// a GenomeDescriptor.
//
// # Why a separate package
//
// The derivation logic itself lives in the canonical contract package
// (/internal/contracts/genome_descriptor) as a method on
// GenomeDescriptor. That placement is correct: the pre-image is defined by
// the contract's own canonical form, and keeping the method next to the
// struct prevents accidental drift. What this package adds is a
// *discovery surface* for the rest of the codebase and for tools:
//
//   - CLI binaries such as acpctl can import this package and call
//     identity.Derive(g) without dragging in the full contract's import
//     graph at the call site.
//   - Readers searching the tree for "how is a GenomeID computed?" land
//     on a package whose whole doc.go answers exactly that question.
//   - The round-trip invariant tests (Derive(g) equals Derive of a JSON
//     round-trip of g) live here so a single regression shows up in a
//     single place instead of being scattered across signers.
//
// Doctrinal pointer (R-14)
//
//	GenomeID = "gen:" + hex(SHA-256(canonical-JSON(descriptor
//	                                 with GenomeID="" and Signature=nil)))
//
// Any change to any covered field shifts the ID. Signing does NOT shift
// the ID (Signature is zeroed in the pre-image). Re-signing a descriptor
// with the same body under a new key does NOT shift the ID either
// (SigningKeyID is covered, but Signature is not — so the ID is stable
// across signatures but not across key-id changes).
//
// # Scope boundary
//
// This package derives. It does NOT sign, validate, or persist. Signing
// is /internal/contracts/genome_descriptor.SignWith. Validation is
// /internal/contracts/genome_descriptor.Validate. Persistence is a future
// concern of the content-addressed store (Stage D Phase A task #35).
package identity
