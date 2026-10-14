// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bootstrap is the receive-side orchestrator for AI Genome
// reconstitution.
//
// # Doctrinal role
//
// Stages B–E built the release side of the platform: the Vault
// authorises Staged Disclosure under a trusted session, signs each
// component as a DisclosureMessage, and closes the flow with a
// ReleaseDecision evidenced in the audit chain. Stage F mirrors that
// discipline on the receiving end.
//
// This package owns:
//
//   - The receive-side state machine (state.go) — a seven-state mirror
//     of /internal/vault/orchestration: ingress → unseal → reassemble
//     → validate → ready, with a single rejected terminal. The state
//     model is deliberately narrower than the release-side flow because
//     the receive side has no trust-attestation, session-issuance, or
//     incident-detection responsibilities — those are the Vault's.
//
//   - Cross-manifest agreement (agreement.go) — the only place in the
//     codebase that legitimately holds both a release-side
//     ReconstructionJobManifest and a receive-side BootstrapManifest at
//     once. The agreement enforcer asserts that the two manifests agree
//     on SessionID, PolicyVersion, and the ordered DisclosureID set.
//     Silent drift between the two is a doctrine violation that must
//     surface before any disclosure is admitted.
//
//   - The acceptance loop (orchestrator.go) — drives the state machine
//     from a stream of DisclosureMessage arrivals to a signed
//     ReconstitutionDecision. For each accepted DisclosureMessage the
//     orchestrator (1) verifies the wire-hash matches the expected
//     release-side canonical hash, (2) appends a DISCLOSURE_RECEIVED
//     audit event, (3) signs and emits a ReceivedDisclosure record, in
//     that order. The audit-event-before-record-surface discipline is
//     the receive-side mirror of release-side invariant #8.
//
// Out of scope (Stage F.3+):
//
//   - The reassembly engine itself — the orchestrator consumes a
//     Reassembler interface and does not assemble bytes here.
//   - The receive-side validation pipeline — also injected.
//   - The end-to-end acceptance test (release-side → wire → receive-side
//     → SHA-256 equality) is Stage F.4; the demo update is Stage F.5.
//
// # Concurrency
//
// The Orchestrator holds a single mutex covering Start, Accept,
// MarkReassembled, and Decide. Like StagedSequencer on the release
// side, it is single-shot: one Orchestrator drives one BootstrapManifest
// to a single terminal ReconstitutionDecision.
//
// Corresponds to P1 §[0051]–[0052] (self-bootstrapping receive-side
// orchestration) and P3 §[0042]. See also
// /AI Continuity Platform/docs/doctrine/bootstrap-contracts.md.
package bootstrap
