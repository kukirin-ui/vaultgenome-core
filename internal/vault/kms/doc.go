// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package kms (Key Management System) implements the release-side
// orchestrator for Phase 4 cross-cloud KMS-mediated restore.
//
// # Doctrinal role
//
// The Coordinator runs the cross-cloud attestation handshake, applies
// a KeyReleasePolicy to authorise key release, encapsulates each DEK
// with the X25519 KEM to the key the destination TEE attested for this
// handshake (ADR 0009), and dispatches the resulting KeyReleaseToken to
// the destination's CrossCloudReceiver. Every
// authority decision the Coordinator makes is recorded in the audit
// chain BEFORE the decision becomes visible to its caller —
// audit-first-class invariant (Doctrinal Invariant #8) extended into
// cross-cloud authority decisions.
//
// The Coordinator emits four audit kinds, in strict order:
//
//  1. KindCrossCloudHandshakeInitiated — before the handshake request
//     is dispatched to the destination.
//  2. KindCrossCloudAttestationVerified — after local verification of
//     the destination's Evidence and BEFORE policy is consulted.
//  3. KindKeyReleaseAuthorized — after policy approval and BEFORE the
//     KeyReleaseToken is dispatched.
//  4. KindCrossCloudRestoreCompleted — recorded by ConfirmRestore, later,
//     once the destination's receipt for the restore verifies: Evidence
//     from the TEE the key was released to, over a receipt that names
//     the same release (ADR 0011). A refusal (KindKeyReleaseDenied)
//     ends a flow at step 2 or 3 instead.
//
// # Frozen boundaries respected
//
// The R-10 TEE interfaces (Producer / Verifier / Sealer in
// /internal/shared/tee/tee.go) are NOT modified. The Coordinator uses
// the new tee.Registry layer (Phase 4 Step 2) to resolve a verifier
// for the destination's declared TEE family.
//
// The R-14 frozen wire contracts are NOT modified. The Coordinator
// produces and consumes the two new Phase 4 contracts
// (cross_cloud_handshake_request and key_release_token) introduced
// fresh at SchemaVersion 1.
//
// The R-11 Reconstructor interface is NOT modified. Cross-cloud restore
// does not change reconstruction; it changes only how DEKs reach the
// destination's keystore prior to the existing reassembly flow.
//
// # Extension points
//
// The Coordinator depends on four replaceable abstractions, each
// behind an interface:
//
//   - Transport — wire delivery of handshake + token (mTLS HTTP/2 in
//     production; mock in tests).
//   - KeyReleasePolicy — gate function: given destination measurement
//     and key set, return Authorized true/false (allow-list policy in
//     MVP; attribute-based policy in future).
//   - AuditEmitter — append a Kind+payload to the release-side audit
//     chain, returning the new AuditEventID. The Coordinator never
//     touches the chain's hash-link directly — that is the chain
//     package's concern.
//   - Clock + NonceSource — small replaceable utilities for
//     deterministic tests.
//
// Key wrapping is deliberately not an extension point: the X25519 KEM
// is the only delivery mode, so no configuration can reintroduce the
// measurement-derived symmetric wrap that ADR 0009 removed.
//
// # See also
//
//   - ADR 0006 — Cross-Cloud KMS-Mediated Restore (overall design)
//   - docs/doctrine/bootstrap-contracts.md §5 — contract freezing
//   - docs/doctrine/validation-thresholds.md §9 — audit-first-class
package kms
