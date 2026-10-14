// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package crypto centralizes the cryptographic primitives used across the
// platform: Ed25519 signing/verification, AES-256-GCM seal/unseal,
// SHA-256 hashing, and canonical-form serialization hooks used to compute
// signature cover-bytes and audit-chain hashes.
//
// # Doctrinal role
//
// There is one cryptographic doctrine in this project: choices are
// narrow and explicit (docs/doctrine/open-decisions-resolved.md R-10). No
// negotiation at runtime, no algorithm-agility field in contracts, no
// silent fallback. If a future algorithm upgrade is needed, it goes
// through a schema-version bump and an explicit migration.
//
// All primitives here wrap the crypto/* and golang.org/x/crypto
// standard libraries. No hand-rolled cryptography.
//
// Stage B: empty package, doctrinal purpose only.
package crypto
