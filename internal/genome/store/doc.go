// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package store implements the content-addressed object store for AI
// Genome Descriptors (AGDs). It is the infrastructure half of priority
// A (AI Genome format + content-addressed store); the format half lives
// in /internal/contracts/genome_descriptor.
//
// # Doctrinal role
//
// The store is the canonical home of AGDs after they are produced. Every
// downstream consumer — session issuer, disclosure builder, reconstruction
// worker, succession-chain walker — looks up AGDs here by GenomeID. An
// AGD that is not in the store has no continuity-layer presence; an AGD
// that is in the store is attested, signed, and self-consistent.
//
// Integrity invariants (enforced at Put)
//
//  1. Structural validation — every field of the descriptor satisfies
//     its contract (/internal/contracts/genome_descriptor.Validate).
//  2. Content-addressing — the stored GenomeID equals the SHA-256
//     content-addressed derivation of the body (R-14). This is the
//     anti-silent-mutation gate.
//  3. Signature verification — the Ed25519 signature verifies under the
//     Authority key named in SigningKeyID, resolved with purpose
//     keys.PurposeSigningAuthority.
//  4. Collision-resistance — if a GenomeID is already in the store, the
//     incoming bytes MUST byte-match the stored bytes. Same ID with
//     different bodies is an Incident signal (somebody is attempting to
//     rewrite a content-addressed object, which should be cryptographically
//     impossible without a SHA-256 pre-image break).
//
// Put is IDEMPOTENT on exact re-puts — a producer that retries the same
// descriptor byte-for-byte gets a no-op success, not a collision error.
//
// # Storage representation
//
// The store serializes each descriptor to encoding/json bytes at Put and
// deserializes fresh on Get. Canonical-JSON is used only for the pre-image
// of the ID and the signature; storage uses plain JSON so the full object
// (including Signature) round-trips. On Get, the store re-derives the ID
// from the loaded descriptor and verifies it against the lookup key,
// giving callers a cheap backing-store-corruption detector without a
// full signature re-check.
//
// # Scope boundary
//
// This package stores. It does NOT produce descriptors (that's the caller)
// and it does NOT resolve keys (that's /internal/vault/keys). It takes a
// keys.Resolver at construction time and uses it only to verify signatures
// at Put. The store never holds private key material.
package store
