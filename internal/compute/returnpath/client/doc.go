// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package client is the worker-side (acp-compute) half of the Return
// Path. It wraps the transport-layer handshake + MAC-authenticated
// session in a single-session object that speaks the client side of
// the 11-frame wire protocol: dial the vault-facing daemon, run
// DoHandshake as RoleClient, await a JobRequest, unseal the referenced
// sealed material into ComponentMaterial, call the injected
// worker.Reconstructor, sign the resulting CandidateOutputFrame with the
// worker's attested signing key, and ship it back.
//
// # Doctrinal role
//
// This package sits on the worker side of the Return Path boundary. It
// may import:
//
//   - /internal/compute/returnpath            (CandidateOutput shape)
//   - /internal/compute/returnpath/transport  (wire protocol)
//   - /internal/compute/worker                (Reconstructor interface
//   - ComponentMaterial)
//   - /internal/contracts/reconstruction_job_manifest
//     (the shape the worker's
//     Reconstructor expects)
//   - /internal/shared/*                       (crypto, errors, ids, tee,
//     time)
//   - /internal/vault/keys                    (Signer for producing
//     CandidateOutputFrame
//     signatures — the worker
//     has its OWN keystore; it
//     does NOT see any vault-
//     side authority keys)
//
// This package MUST NOT import /internal/compute/returnpath/server or
// any /internal/vault/{orchestration,authority,audit,validation}
// package. The worker is explicitly non-authority (see
// /cmd/acp-compute/doc.go); its only outputs are CandidateOutput
// (through the transport) and error envelopes.
//
// # Sealed material and Opener
//
// JobRequest.SealedMaterial carries opaque SealedMaterialRef entries —
// AES-256-GCM nonce / ciphertext / AAD plus a RecipientKeyID. The worker
// opens each one using an Opener supplied by the caller. In Phase 1
// the Opener is backed by a pre-shared /internal/vault/keys.InMemoryStore
// that has the recipient sealing key registered on both vault and
// worker side; in Phase 3 it becomes the TEE's hardware sealing key.
// The Opener boundary is deliberate: the client package does not know
// WHERE the sealing key lives, only that a named key can be used to
// open a given (nonce, ciphertext, AAD) triple.
//
// ComponentID / SequenceIndex synthesis
//
// SealedMaterialRef does not carry a ComponentID on the wire — the
// wire schema v1.0 is frozen at a minimum shape. The client synthesizes
// a ComponentID from the manifest ID and the slice index using a
// stable, reproducible rule (see materialComponentID); SequenceIndex
// is the slice position. This is a Phase-1 affordance: when the wire
// schema gains an explicit ComponentID field in a future minor version,
// synthesis becomes a fall-back for wire-old peers.
//
// # Freeze status
//
// The Session API (Dial, ServeOneJob, WriteShutdown, Close, State) is
// frozen for the Phase-1 investor demo. Same rules as server/doc.go.
package client
