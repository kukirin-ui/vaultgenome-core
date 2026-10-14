// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package witness implements the operator-side transparency log whose
// externally-auditable commitments are defined by
// /internal/contracts/witness.
//
// # Doctrinal role
//
// The contracts package defines the WIRE OBJECTS — LogEntry,
// SignedTreeHead, InclusionProof, ConsistencyProof, WitnessReceipt,
// ForkEvidence — and the rules they must satisfy for an external
// verifier to accept them. This package defines the OPERATOR: the
// thing that actually appends entries, threads the hash chain, signs
// STHs under a witness-purpose key, and answers proof queries.
//
// The cut matters. Receivers of receipts only need the contracts
// package; they MUST be able to verify a bundle without any
// operator-side state. This package is an implementation of the log
// operator role — other implementations (e.g. disk-backed, sealed,
// replicated) can exist and coexist.
//
// # Threat model
//
// The log is the last line of defense against silent history
// rewrites. Concretely, the operator promises:
//
//  1. Append-only — entries are committed in strictly increasing Index
//     order, and an entry, once committed, is never mutated.
//  2. Chain continuity — entry K's PrevLeafHash is the LeafHash of
//     entry K-1 (all-zero at K=0). Because PrevLeafHash is part of the
//     canonical leaf payload, tampering with any earlier entry drifts
//     every later LeafHash.
//  3. Merkle continuity — every STH covers exactly the committed
//     prefix. A ConsistencyProof between two STHs of the same operator
//     MUST verify.
//  4. Time monotonicity — Timestamps are non-decreasing across Index
//     order. A rollback is Incident-class.
//  5. Operator signature — every STH carries a signature under a
//     PurposeSigningWitness key. Authority keys cannot forge STHs.
//
// Any observable violation is a FORK, and forks are routed as Incidents
// by /internal/contracts/witness/fork_detection.
//
// # API surface
//
// Log is a narrow interface that covers the operational contract:
// Append, Head, Size, Entry, InclusionProof, ConsistencyProof, and the
// convenience Receipt for bundle issuance. InMemoryLog is the MVP
// implementation, safe for concurrent use.
//
// # Scope boundary
//
// This package OPERATES a log. It does NOT
//
//   - verify a bundle (that is the receiver's job, using
//     WitnessReceipt.Verify from the contracts package);
//   - persist anything to disk (production operators will wrap
//     InMemoryLog with a sealing layer);
//   - resolve external verifier identities (the log signs; it does not
//     audit receivers).
//
// Keep these boundaries sharp. A log that also verified its own
// disclosures would be its own auditor — exactly the circular trust
// the witness role is meant to break.
package witness
