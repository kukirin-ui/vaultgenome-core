// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package crosscloud implements the destination-side handler for
// Phase 4 cross-cloud KMS-mediated restore. The Receiver type is
// wired into the acp-bootstrap daemon to handle two new HTTP endpoints
// (POST /v1/crosscloud/handshake and POST /v1/crosscloud/token), and
// in tests it is exercised directly via its HandleHandshakeRequest
// and HandleKeyReleaseToken methods.
//
// # Doctrinal role
//
// Per ADR 0006 §"Detailed Design — Receive-Side":
//
//  1. The Receiver verifies the source authority's Ed25519 signature
//     on every CrossCloudHandshakeRequest and KeyReleaseToken, using
//     a pre-loaded source-authority public key (exchanged
//     out-of-band — the operator's responsibility).
//
//  2. On handshake, the Receiver generates an X25519 key pair for that
//     handshake alone, quotes over kms.RecipientChallenge(public key,
//     handshakeNonce) with its tee.Producer, and returns the Evidence,
//     the public key and the local Measurement hint (ADR 0009). The
//     private key stays in memory, keyed by the request ID, until its
//     token arrives or it expires.
//
//  3. On token receipt, the Receiver:
//     a. Validates the token's structural fields (delegates to
//     krt.KeyReleaseToken.Validate).
//     b. Verifies the token's signature against the source-
//     authority pubkey.
//     c. Verifies that the token's DestinationMeasurement matches
//     the local TEE Producer's Measurement byte-for-byte (the
//     source released to this workload and no other).
//     d. Takes the handshake's private key out of the table (single
//     use) and, for each WrappedKey, opens it with the X25519 KEM
//     under the WrappedKey's AAD; on success, registers the
//     material in the destination's KeyRegistrar (typically
//     keys.InMemoryStore.RegisterSealing). Holding the token and
//     the measurement is worthless without that private key.
//
// # No new audit kinds
//
// Per ADR 0006 explicitly: the cross-cloud handshake adds NO new
// receive-side audit kinds. The destination's keystore registration
// is a privileged-interface operation; the receive-side audit chain
// captures the subsequent disclosure-message flow that uses those
// keys (KindDisclosureReceived, KindRecvValidationStarted, etc.).
// Forensic auditors who need to trace a cross-cloud event correlate
// the source-side chain (which has all four cross-cloud kinds) with
// the destination-side chain (which has the disclosure-flow kinds)
// via the shared DecisionID, ManifestID, and SessionID correlators.
//
// # Frozen boundaries respected
//
// The Receiver consumes the new Phase 4 wire contracts
// (cross_cloud_handshake_request and key_release_token) and uses
// the existing R-10 tee.Producer. It does NOT modify any frozen
// interface or contract.
//
// # See also
//
//   - ADR 0006 — Cross-Cloud KMS-Mediated Restore
//   - ADR 0009 — X25519 KEM for cross-cloud DEK delivery
//   - internal/vault/kms — release-side Coordinator (the symmetric peer)
package crosscloud
