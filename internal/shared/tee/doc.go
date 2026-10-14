// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package tee provides the TEE abstraction consumed by trust, keys, and
// disclosure. MVP: software emulation of a Trusted Execution Environment.
// Production: a backend that calls real TPM / Intel TDX / AMD SEV.
//
// # Doctrinal role
//
// The TEE abstraction defines:
//
//   - a Sealer / Unsealer that binds ciphertext to the TEE identity,
//   - an AttestationQuoter that produces an attestation quote usable in
//     AttestationResult,
//   - a KeyManager that holds the root signing key and never exposes it.
//
// MVP NOTE: the software emulation in Stage D is explicitly labeled in
// its implementation as "NOT a real TEE." It uses real cryptography
// (Ed25519 + AES-256-GCM per docs/doctrine/open-decisions-resolved.md R-10) but the
// root of trust is a local on-disk blob protected by file permissions.
// It is suitable for doctrine demonstration and for CI; it is NOT
// suitable for production deployment. The interface is what persists.
//
// Stage B: empty package, doctrinal purpose only.
package tee
