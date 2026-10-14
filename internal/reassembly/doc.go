// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reassembly is the RECEIVE-SIDE engine that opens sealed
// DisclosureMessages, verifies per-component plaintext against the
// AGD's committed hash and byte-size, rebuilds the RFC 6962 Merkle
// tree, and asserts content-addressing round-trip equality against
// the parent AGD's signed GenomeID.
//
// # Doctrinal role
//
// Staged Disclosure is the rule: the full AI Genome is NEVER
// reassembled in one place on the RELEASE side. The /vault/disclosure/
// issuer emits a sequence of sealed envelopes, each one component, and
// walks away. Reassembly is the MIRROR operation, but on the RECEIVE
// side inside a TEE-bounded reconstruction worker. The moment we open
// a sealed payload here, we are inside the trust boundary the bootstrap
// agreement established; the only remaining job is to verify that the
// bytes we unsealed are the bytes the release side committed to.
//
// The package solves exactly three problems, in order:
//
//  1. AES-256-GCM open. Reconstruct the five-field AAD
//     (disclosure_message.BuildRecipientAADForMessage), call the
//     injected Sealer.Open. A failure here is an Integrity event — the
//     envelope or its seal has been tampered with.
//
//  2. Per-component content check. Recompute SHA-256(plaintext) and
//     compare the byte-count and hash against the AGD's committed
//     componenttree.Component entry for that ComponentID. A mismatch
//     here is an Integrity event — the release side sealed different
//     bytes than the ones it committed to, OR the AGD has been
//     substituted.
//
//  3. Finalization. Once every admitted component covers every
//     committed Component in the AGD, rebuild the Merkle tree from the
//     AGD's committed (path, kind, byte_size, hash) leaves and verify:
//
//     (a) componenttree.BuildTree(agd.Components).RootSlice() ==
//     agd.ComponentTreeRoot   → Integrity on mismatch.
//     (b) agd.DeriveID() == agd.GenomeID   → Integrity on mismatch
//     (this is the R-14 content-addressing invariant, mirrored
//     against the AGD the caller handed us).
//
// Doctrinal boundary — what reassembly DOES NOT do
//
//   - It does not verify the AGD's Ed25519 signature. That belongs to
//     the caller (the bootstrap agreement enforcer in /internal/bootstrap/
//     Stage F.2) BEFORE the Reassembler is constructed. A caller that
//     feeds an AGD here without first VerifySignature-ing it is
//     violating the AGD-authority contract.
//
//   - It does not verify each DisclosureMessage envelope's Ed25519
//     signature. Same rationale — the bootstrap orchestrator's
//     acceptance loop is where that check lives (Stage F.2 §7.4).
//
//   - It does not materialize any genome component to disk. The
//     admitted plaintext slices are returned in the ReassemblyResult;
//     downstream storage is a higher layer's decision.
//
//   - It does not implement de-duplication or gap detection across
//     SequenceIndex. The orchestrator's acceptance loop (F.2) is
//     responsible for that; here we only enforce COVERAGE of committed
//     components, not SEQUENCING of the envelopes that delivered them.
//
// Single-shot pattern (mirrors Orchestrator, F.2 §7.3)
//
// One Reassembler instance = one GenomeID reconstruction. After
// Finalize is called (whether successful or not), the instance is
// closed; further Admit calls refuse with Operational. This keeps the
// state machine small and eliminates the "is this Reassembler reusable"
// question that tends to cause subtle bugs in crypto-heavy code paths.
//
// Doctrine invariants enforced here
//
//   - Invariant #1 (vault is authority): this package is NOT under
//     /vault/. It may import /contracts/, /shared/, and /genome/; it
//     MUST NOT import /vault/disclosure/, /vault/session/, or any
//     other release-side authority package. The shared AAD helper in
//     the /contracts/disclosure_message/ package is the legitimate
//     bridge.
//
//   - Invariant #7 (no raw export): plaintext bytes exit this package
//     exactly once, via ReassemblyResult.Components. Nothing is logged;
//     no byte slice is printed in error messages; the package's test
//     suite asserts no plaintext substring appears in any error
//     message.
package reassembly
