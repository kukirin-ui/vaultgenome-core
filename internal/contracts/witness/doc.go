// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package witness defines the canonical artifacts of the ACP
// transparency log — the public ledger of continuity claims.
//
// # Doctrinal role
//
// Everything the platform has built so far (content-addressed genome
// descriptors, signed succession chains, probe-attested behavioral
// equivalence) rests on ONE remaining trust assumption: the vault
// honestly retains the signatures it has issued. A well-resourced
// adversary who compromises the vault's signing key AND its storage
// could silently rewrite the past — reissue a different AGD under
// the same GenomeID, re-sign a different attestation for the same
// genome — and no external observer could tell.
//
// The transparency log closes that gap. Every doctrinal issuance
// (probe attestation, succession-chain edge) is appended to an
// append-only, hash-chained, Merkle-tree-committed log. The log's
// operator signs a SignedTreeHead (STH) after every append. External
// observers record STHs over time. Any attempt to retroactively
// change history becomes a publicly-detectable FORK: the same log
// operator now has two STHs claiming different tree contents for the
// same tree size.
//
// Doctrinal stance: a fork is an Incident, not a bug. Fork detection
// surfaces as CategoryIncident with CodeTamperSignal. Policy layers
// that consume a disclosure MUST reject any claim whose witness
// receipt references an STH that is inconsistent with any later STH
// they have recorded.
//
// Dual commitment: belt and suspenders
//
// Every LogEntry commits in TWO ways:
//
//   - As a LEAF of an RFC 6962 Merkle tree — efficient inclusion
//     proofs (O(log n)) and efficient consistency proofs between
//     any two tree sizes.
//   - As a LINK in a hash chain — every entry carries PrevLeafHash,
//     chaining entries one to the next from index 0 (all-zero
//     previous) forward.
//
// A tamper anywhere in the log must BOTH disturb the Merkle tree
// AND break the hash chain. An attacker who wants to silently
// rewrite entry K must produce a new entry with the same LeafHash
// AND maintain the chain through entry K+1, K+2, … — both of
// which are cryptographically infeasible without a pre-image break.
//
// # Monotonic time gate
//
// Every entry's Timestamp is required to be >= its predecessor's.
// Non-monotonic timestamps are rejected at append time and at
// verify time. This creates a clock-ordering property operators
// can inspect without running any Merkle math, complementing the
// cryptographic guarantees with human-readable evidence.
//
// # Scope
//
// This contract package defines the signed and content-addressed
// data model:
//
//   - LogEntry — content-addressed record of one witnessed event.
//   - SignedTreeHead — the operator's periodic commitment to the
//     log's Merkle root and chain head.
//   - InclusionProof — RFC 6962-style proof that a specific entry
//     is at a specific index of a tree of a specific size.
//   - ConsistencyProof — RFC 6962-style proof that a tree of size
//     N legitimately grew into a tree of size M (M >= N).
//   - WitnessReceipt — self-contained bundle (Entry, InclusionProof,
//     STH) that a disclosure embeds to prove an attestation was
//     publicly witnessed.
//
// # Stateless verification
//
// Every verifier in this package is pure: no log access, no clock,
// no network. An external auditor with only {oldSTH, newSTH,
// ConsistencyProof} can detect a fork. An external consumer with
// {WitnessReceipt} can confirm "this attestation exists at this
// position of this operator's log as of this STH". Nothing in this
// package requires trust in the log operator beyond their signing
// key.
//
// # Scope boundary
//
// This package does NOT:
//   - Maintain the log (that lives in /internal/genome/witness).
//   - Run a network of co-witnesses or threshold-sign STHs (future
//     phase — the single-signer STH carries an unambiguous
//     SigningKeyID that can be generalized to a multisig).
//   - Publish STHs to external observers (out of scope; Append
//     returns the latest STH to the caller, who is expected to
//     fan it out).
package witness
