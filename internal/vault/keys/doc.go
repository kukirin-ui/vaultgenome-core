// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package keys manages the vault's cryptographic key material: the
// Ed25519 signing keys that cover every authority artifact and the
// AES-256-GCM symmetric keys that seal genome components and disclosure
// payloads.
//
// # Doctrinal role
//
// Keys never leave the vault process unsealed. Key rotation is audit-
// bound. On a detected tamper event the keys subsystem performs
// Zeroization per patent P1 §[0020] and docs/doctrine/terminology.md §2.
//
// MVP: keys are generated at first boot and persisted sealed under a
// software root key held in emulated TEE storage. Production: sealed
// under the real TEE sealing key (TPM SRK / TDX key manager / SEV key).
//
// Stage B: empty package, doctrinal purpose only.
package keys
