// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package time provides vault-internal monotonic-clock helpers and the
// wall-clock projection used when persisting timestamps in contracts.
//
// # Doctrinal role
//
// The vault's authoritative time source is its own monotonic clock. Wall-
// clock values are advisory — they are used for human-readable displays
// and for coarse TTL windows, but the order of events inside a workflow
// is determined by monotonic readings. This matters because an adversary
// controlling NTP cannot replay or reorder events against the vault.
//
// All Contract.*.CreatedAt / IssuedAt / OccurredAt / DecidedAt /
// ValidatedAt fields are wall-clock projections of monotonic readings
// taken at the moment the artifact was constructed.
//
// Stage B: empty package, doctrinal purpose only.
package time
