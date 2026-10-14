// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package succession walks the ancestry of an AI Genome Descriptor
// through the content-addressed store, validating every edge.
//
// # Doctrinal role
//
// An AGD is not a free-standing object: its Provenance.DerivedFrom
// records zero or more parent GenomeIDs, each tagged with a
// DerivationMethod (fine-tune, distill, merge, quantize, reconstruct).
// The doctrinal claim is that this forms a directed acyclic graph
// rooted at one or more generation-0 genomes, and that claim must be
// verifiable at query time — otherwise "cross-generation continuity"
// is a promise without a proof.
//
// The walker is that verifier. Given a GenomeID, it traverses
// DerivedFrom edges via the CAS (/internal/genome/store), checking at
// every node:
//
//  1. The genome is resolvable in the CAS (missing ancestor ⇒ Operational
//     continuity failure; not an Integrity or Incident by itself — a
//     partial view of the store can cause it in practice).
//  2. The CAS's Get already enforced R-14 self-consistency. The walker
//     trusts that gate and does NOT re-verify signatures on every
//     ancestor by default — re-verification is cheap but O(depth) and
//     the CAS guarantees bytes-on-disk match their content-addressed
//     name. Callers that want end-to-end re-verification can call
//     VerifyWithSignatures.
//  3. Generation monotonicity: for every parent P of child C,
//     P.Generation < C.Generation. Violation ⇒ Incident (a forged
//     generation number is a structural attack on the chain).
//  4. No cycles. A SHA-256 cycle in a content-addressed DAG is
//     cryptographically impossible without a pre-image break, so a
//     detected cycle ⇒ Incident.
//  5. Method validity: each edge's DerivationMethod is one of the
//     doctrinal values. (Redundant with per-node Validate but cheap
//     to re-check; defense in depth.)
//
// # Traversal order
//
// The walker performs depth-first traversal from the requested root
// toward ancestors. Visit callbacks fire in pre-order: a node is
// visited before any of its parents. Cycle detection uses a
// "currently-on-stack" set, not a "seen-ever" set — two children
// legitimately sharing a common ancestor (a "diamond" in the DAG,
// common under DerivationMerge) must be visited through both paths
// during verification, but is counted only once for depth/size totals.
//
// # Scope boundary
//
// This package walks. It does NOT repair gaps, re-sign ancestors, or
// mutate the store. All reads go through the Store interface; any
// store-backed implementation (in-memory, disk, sealed) works unchanged.
package succession
