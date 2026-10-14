// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package store persists AuditEvent records. It is an append-only store;
// deletion is not a supported operation. Retention policy is governed by
// /internal/vault/policy, not by this package.
//
// # Doctrinal role
//
// The audit store is the evidence substrate. If the store is
// unreachable, validation fails — no decision without evidence. The
// store is tamper-evident via the hash chain in /internal/audit/chain,
// not via deletion controls.
//
// MVP: bbolt-backed, aligned with the storage engine decision in
// docs/doctrine/open-decisions-resolved.md R-5. Production: can be replicated
// across nodes or exported to external compliance storage, but the
// chain tip remains vault-authoritative.
//
// Stage B: empty package, doctrinal purpose only.
package store
