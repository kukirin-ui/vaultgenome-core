// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package server is the vault-side (sagvd) half of the Return Path. It
// wraps the transport-layer handshake + MAC-authenticated session in a
// single-session object that speaks the server side of the 11-frame
// wire protocol: accept the inbound TCP connection, run DoHandshake as
// RoleServer, hand one JobRequest to the peer, receive JobAccept/Reject,
// receive CandidateOutputFrame, verify the worker's Ed25519 signature,
// and translate into the in-process returnpath.CandidateOutput shape
// that the vault-side validator consumes.
//
// # Doctrinal role
//
// This package sits on the authority side of the Return Path boundary.
// It may import:
//
//   - /internal/compute/returnpath            (CandidateOutput shape)
//   - /internal/compute/returnpath/transport  (wire protocol)
//   - /internal/contracts/reconstruction_job_manifest (JobRequest projection)
//   - /internal/shared/*                       (crypto, errors, ids, tee, time)
//   - /internal/vault/keys                    (Resolver for worker pubkey;
//     the worker signs its
//     CandidateOutputFrame, the
//     vault verifies it)
//
// This package MUST NOT import /internal/compute/returnpath/client.
// The transport package is the shared boundary; the two sibling halves
// never see each other's internals. That isolation is what lets the
// Phase-2 generative backend swap in on the worker side without any
// vault-side change, and vice-versa.
//
// # Freeze status
//
// The Session API (Accept, ServeOneJob, WriteShutdown, Close, State)
// is frozen for the Phase-1 investor demo. The shape of its
// SessionConfig may grow new optional fields as long as the defaults
// preserve the current behaviour. Removing or renaming a method is a
// wire-adjacent break and requires bumping the transport MAGIC in
// lockstep.
//
// # Integration with audit
//
// The server never imports /internal/vault/audit directly — that would
// break the isolation rule. Instead, SessionConfig exposes optional
// callback hooks (OnIntegrityFailure, OnWorkerSignatureFailure,
// OnSessionOpened, OnSessionClosed). Callers in cmd/sagvd wire these
// hooks to their AuditEmitter so transport-level failures land as
// IncidentEvents in the audit chain. A nil hook is legal — the error is
// still surfaced to the caller as a classified return value.
package server
