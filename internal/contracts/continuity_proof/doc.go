// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package continuity_proof defines the ContinuityProof contract — the
// keystone, stateless-verifiable bundle that binds an AGD's ancestry,
// behavioral probe scorecard, and transparency-log inclusion into ONE
// object an external receiver can check without access to any of the
// issuer's stores.
//
// # Doctrinal role
//
// Three independent primitives already guarantee continuity in the
// system, each in its own slice of the trust plane:
//
//  1. /internal/contracts/genome_descriptor — content-addressed AGDs
//     whose stored GenomeID must equal the SHA-256 derivation of the
//     descriptor's own canonical bytes (R-14). A tamper anywhere in an
//     AGD drifts its content-address and fails this gate.
//
//  2. /internal/contracts/probe_battery — a signed Scorecard whose
//     MerkleRoot is content-addressable and whose BatteryMerkleRoot
//     must match the AGD's BehavioralFingerprint.BatteryMerkleRoot.
//     The scorecard is what pins the subject's behavior at a specific
//     battery version.
//
//  3. /internal/contracts/witness — an RFC 6962 transparency log whose
//     SignedTreeHead is signed under a purpose-separated witness key,
//     and whose LogEntry binds {AttestationRoot, BatteryMerkleRoot,
//     ScorecardRoot, GenomeID} together in one leaf. A WitnessReceipt
//     is stateless-verifiable against any STH from the operator.
//
// Each primitive is strong on its own but insufficient for the full
// continuity story:
//
//   - An AGD is verifiable in isolation but tells you nothing about
//     whether the subject actually behaved like its ancestors claim it
//     should.
//   - A scorecard attests current behavior but does not prove the
//     subject descends from any specific root genome.
//   - A witness receipt proves a commitment was publicly witnessed at
//     a specific log position but does not, by itself, carry the
//     ancestors the commitment is claimed to close over.
//
// ContinuityProof is the ONE contract that binds all three, plus the
// descent chain from Subject to genesis, plus an authority signature
// over the whole package. A receiver holding ONLY:
//
//   - the ContinuityProof bytes,
//   - the authority public key (one VK),
//   - the witness public key (one VK),
//   - and the probe-runner authority public key (one VK),
//
// can verify the full continuity claim with zero network traffic and
// zero access to the issuer's CAS or log. This is the minimum package
// that survives a clean-room rebuild: if the issuer's data centers go
// dark, a disclosure holder can still prove who the subject is, what
// it descends from, how it behaved, and that the witnessing operator
// committed to exactly those three facts.
//
// # Stateless verification — the gate, in order
//
// ContinuityProof.Verify runs these checks, stopping at the first
// failure. The ordering is deliberate: cheapest and most structural
// first, cryptographic reconstruction last.
//
//  1. Validate() — structural gates: field shapes, schema version,
//     chain linkage (every AncestorChain parent reference resolves
//     within the chain), generation monotonicity, at least one root,
//     cross-field bindings between {Subject, scorecard, witness entry}.
//
//  2. For each AGD in AncestorChain: VerifySignature under authority
//     key. Each AGD's Validate re-runs the R-14 content-address gate,
//     so a tamper anywhere in the ancestry chain is caught here.
//
//  3. ProbeScorecard.VerifySignature under the probe-runner authority
//     key. Re-derives the scorecard's MerkleRoot and rejects drift.
//
//  4. WitnessReceipt.Verify under the witness key. Reconstructs the
//     RFC 6962 inclusion proof against the STH's TreeHash and verifies
//     the STH signature under a witness-purpose key.
//
//  5. This contract's own Signature — authority-signed cover bytes.
//     Binds everything above to a single issuing authority.
//
// Failure classification mirrors the underlying primitive:
//   - Structural for shape/schema/cross-field.
//   - Integrity for crypto mismatches (content-address drift, signature
//     failure, Merkle reconstruction failure).
//   - Authority for unknown/purpose-mismatched KeyIDs.
//   - Incident for tamper-signal patterns surfaced by the witness log
//     or the probe battery.
//
// # DAG-aware ancestry
//
// AncestorChain is a FLAT list of unique GenomeDescriptors in
// pre-order DFS from Subject toward roots. Subject is at index 0; at
// least one genesis (Generation=0, DerivedFrom empty) must be present.
// Every AGD's Provenance.DerivedFrom parent MUST appear elsewhere in
// the chain. A merge-parented DAG (two parents sharing a common
// grandparent) is expressed by listing the shared grandparent exactly
// ONCE, with both merge children citing it by GenomeID.
//
// Linear fine-tune chains are a degenerate case: each AGD has exactly
// one parent and the chain visits the spine in order.
//
// # Scope boundary
//
// ContinuityProof is a receiver-side artifact. It does NOT mutate
// stores, does NOT issue new disclosures, does NOT resolve recipient
// identities. It is a sealed claim: "THIS subject descends from THESE
// ancestors, behaves according to THIS scorecard, and was committed to
// THIS position of THIS operator's witness log, all as of the issuing
// authority's signature time."
//
// Composing a ContinuityProof from the issuer side lives in
// /internal/vault/disclosure (Phase D.2). This package only defines
// the wire object and its self-contained verifier.
package continuity_proof
