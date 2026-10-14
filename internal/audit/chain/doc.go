// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package chain maintains the hash-chain integrity of the audit log.
// Every AuditEvent carries PrevHash = SHA-256(canonical-form of prior
// event). The genesis entry has PrevHash = 32 zero bytes.
//
// # Doctrinal role
//
// Hash-chain verification is an offline operation any auditor can run
// without access to vault keys. A broken chain is a tamper event of
// severity critical; it triggers incident termination through
// /internal/vault/incident.
//
// This package also implements periodic chain-tip attestation — the
// vault signs the current chain tip on a cadence so that distributed
// observers can witness continuity without accessing the events
// themselves.
//
// Stage B: empty package, doctrinal purpose only.
package chain
