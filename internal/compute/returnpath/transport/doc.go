// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package transport implements the Return Path wire protocol — the only
// network boundary where vault-internal authority material (sealed
// component plaintext) crosses into non-authority code (the external
// compute worker).
//
// # Doctrinal role
//
// The package is intentionally self-contained: it imports /internal/shared
// primitives (ids, errors, crypto, time) but nothing from /internal/compute
// or /internal/vault. The vault-side (server) and worker-side (client)
// halves live in sibling packages that import this one; neither half
// ever imports the other. This isolation is the doctrinal reason the
// same wire-format binary can be exercised by a conformance test
// without pulling in either the `sagvd` or `acp-compute` internals.
//
// # Wire format
//
// Every frame on the wire has three fixed-layout fields:
//
//	 0       4       8                ...                end
//	+-------+-------+--------------------------------+
//	| MAGIC | LEN   | PAYLOAD (LEN bytes, JCS-JSON) |
//	+-------+-------+--------------------------------+
//
// MAGIC is four fixed bytes (see `WireMagic`) that embed the wire
// version (major 1, minor 0); a mismatch closes the connection
// immediately. LEN is uint32 big-endian with a hard cap of
// `MaxFrameSize` (16 MiB) — anything over is an Integrity failure.
// PAYLOAD is a canonical-JSON object (RFC 8785 / JCS subset, emitted by
// `/internal/shared/crypto.CanonicalJSON`) carrying a frame body with a
// mandatory `type` discriminator that selects one of the eleven
// body structs defined in bodies.go.
//
// Canonical JSON — not generic JSON, not CBOR — is the wire encoding.
// The same encoder signs every contract and hashes every audit event
// in this codebase, so a wire-format bug cannot silently disagree with
// a signature-verification path. Binary payloads (CandidateOutput
// bytes, nonces, signatures, sealed-material refs) travel as
// base64-std `[]byte` fields, the same representation the sealed
// disclosure, session-object signature, and audit-event hash paths
// already use. See docs/internal/phase1-v2-plan.md §3.2 (v1.1 amendment) for the
// reasoning behind this choice.
//
// # Session lifecycle
//
// Every connection begins with a four-frame handshake (§3.3):
//
//  1. HELLO_CLIENT    (client → server): wire-version assertion,
//     client nonce (≥ NonceMinBytes), challenge the client wants the
//     server's TEE evidence to cover.
//  2. HELLO_SERVER    (server → client): echo of client nonce,
//     server's own TEE evidence, server nonce, session-key derivation
//     context.
//  3. ATTEST_CLIENT   (client → server): client's TEE evidence
//     covering the server's challenge.
//  4. SESSION_READY   (server → client): both TEE evidences verified;
//     from this frame onward every frame is authenticated with the
//     handshake-derived HMAC-SHA-256 MAC key (see session.go).
//
// In Phase 1 the TEE evidence comes from a simulated backend — a
// real-hardware swap is Phase 3 and requires zero protocol changes.
// The MAC key is derived from both nonces plus the session-derivation
// context via HKDF-SHA-256; both sides compute the same key
// independently, so the key itself never appears on the wire.
//
// # Failure modes and audit obligations
//
//   - Wire-version mismatch, malformed MAGIC, LEN overflow, canonical-
//     JSON decode failure, unknown `type`, missing mandatory body field:
//     CategoryStructural, CodeProtocolViolation. Peer receives an
//     ErrorEnvelope, connection closes.
//   - Nonce-too-short at handshake: CategoryStructural,
//     CodeNonceTooShort. Peer receives an ErrorEnvelope, connection
//     closes.
//   - MAC verification failure after SESSION_READY: CategoryIntegrity,
//     CodeIntegrityFailure. Connection closes immediately, server-side
//     emits an IncidentEvent (kind=HandshakeOrFrameMACFailed) into the
//     audit chain. The peer is NOT told why — an MAC failure on the
//     hot path is either an adversarial tamper attempt or a
//     session-state corruption, neither of which benefits from
//     diagnostic information on the wire.
//   - Deadline exceeded on the underlying net.Conn: CategoryOperational,
//     CodeDeadlineExceeded. Both sides close.
//
// # Freeze status
//
// The wire-format shape (MAGIC, LEN layout, canonical-JSON payload,
// the eleven body discriminators, the handshake sequence) is frozen
// for wire-version v1.0. Any incompatible change — a new mandatory
// field in a body, a new frame type the receiver can't ignore, a
// change in the MAC construction — requires a wire-version bump in
// MAGIC and an amendment to docs/internal/phase1-v2-plan.md §3.
//
// Compatibility-preserving changes (new optional fields, new codes
// inside ErrorEnvelope, new non-mandatory body fields that default
// to zero) do NOT require a version bump but DO require adding the
// new field to both bodies.go and the canonical-JSON roundtrip test.
package transport
