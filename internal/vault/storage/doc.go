// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package storage is the persistent store of vault-owned state: sessions,
// manifests, policy versions, and genome-component pointers. Genome
// components themselves are stored sealed under keys managed by
// /internal/vault/keys.
//
// # Doctrinal role
//
// Storage is an interface, not a fixed engine. MVP uses bbolt per
// docs/doctrine/open-decisions-resolved.md R-5. Production may swap in BadgerDB or
// a replicated store. The Storage interface defined here is narrow and
// engine-agnostic; callers depend only on it.
//
// Storage must persist the hash-chain tip so that /internal/audit/chain
// can detect gaps across restarts.
//
// Stage B: empty package, doctrinal purpose only.
package storage
