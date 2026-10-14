// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Transport-specific stable codes. They live in this package rather
// than /internal/shared/errors because the wire protocol is the one
// place they apply; pollution of the shared codes file would hurt
// more than it helps. Every other package in the codebase follows
// the same rule (see audit/store, vault/incident, compute/worker).
const (
	// CodeProtocolViolation is emitted when the peer sends bytes that
	// are well-framed but do not parse as a valid frame body, or when
	// the frame body fails a structural check (missing `type`, unknown
	// `type`, schema-version mismatch, field-type mismatch). This is
	// CategoryStructural: the peer is buggy or adversarial, and no
	// retry at the same wire version will help.
	CodeProtocolViolation = "protocol_violation"

	// CodeTruncatedFrame is emitted when the underlying io.Reader
	// closes or yields EOF partway through a frame header or payload.
	// Category is Structural — truncation mid-frame cannot be
	// distinguished from an adversarial interruption at this layer.
	CodeTruncatedFrame = "truncated_frame"

	// CodeFrameOverSize is emitted when the LEN header exceeds
	// MaxFrameSize. Category is Integrity (not Structural) because a
	// peer that announces a 1-GiB frame is actively hostile, not
	// merely buggy; the audit side treats this as tamper-adjacent
	// evidence and emits an IncidentEvent on receipt.
	CodeFrameOverSize = "frame_over_size"

	// CodeIntegrityFailure is emitted when the post-SESSION_READY MAC
	// does not verify, or when the handshake-derivation context
	// disagrees between the two peers (key mismatch detected on first
	// authenticated frame). Category is Integrity.
	CodeIntegrityFailure = "integrity_failure"

	// CodeNonceTooShort is emitted when a handshake peer sends a nonce
	// shorter than NonceMinBytes. Category is Structural.
	CodeNonceTooShort = "nonce_too_short"

	// CodeHandshakeFailure is emitted when the handshake state machine
	// receives a frame of the wrong type for the current phase (e.g.
	// a JobRequest before SESSION_READY) or when the server's TEE
	// evidence cannot be verified. Category is Authority — the remote
	// end failed an admission check.
	CodeHandshakeFailure = "handshake_failure"

	// CodeDeadlineExceeded is emitted when a net.Conn deadline fires
	// mid-read or mid-write. Category is Operational.
	CodeDeadlineExceeded = "deadline_exceeded"

	// CodeUnsupportedWireVersion is emitted when a peer's HELLO
	// declares a wire-major/minor pair this binary cannot speak.
	// Category is Structural: no amount of retry will help, the peer
	// must upgrade or downgrade.
	CodeUnsupportedWireVersion = "unsupported_wire_version"
)

// ErrorEnvelope is the on-wire representation of a classified error.
// It mirrors the /internal/shared/errors taxonomy one-for-one so that
// the receiver can reconstruct a shared_errors.Error at its layer
// without losing Category or Code information.
//
// The envelope is sent as the body of an `error` frame (see bodies.go)
// and is also used as the body of a final frame before a graceful
// close when one side wants to tell the other why the connection is
// about to go away.
//
// Fields
//
//   - Category: one of "structural", "authority", "operational",
//     "integrity", "incident" (the five non-Unknown Category values
//     in shared/errors).
//   - Code: the stable canonical code (e.g. "protocol_violation",
//     "integrity_failure", or any of the shared/errors Code* values).
//   - HumanMessage: a short, non-sensitive diagnostic. MUST NOT
//     contain plaintext model material, secrets, or other sensitive
//     data — wire error envelopes are the one place a misbehaving
//     receiver could log verbatim to an insecure log sink.
//   - ManifestID: optional correlator for audit purposes; zero-value
//     means "not known at the point the error was raised".
type ErrorEnvelope struct {
	Category     string `json:"category"`
	Code         string `json:"code"`
	HumanMessage string `json:"human_message"`
	ManifestID   string `json:"manifest_id,omitempty"`
}

// categoryString maps a shared_errors.Category to its on-wire string.
// CategoryUnknown maps to "structural" — we do NOT emit "unknown" on
// the wire because that would let a miscategorized error escape the
// classification discipline; anything uncategorized is treated as a
// structural peer-buggy condition until properly classified.
func categoryString(c shared_errors.Category) string {
	switch c {
	case shared_errors.CategoryAuthority:
		return "authority"
	case shared_errors.CategoryOperational:
		return "operational"
	case shared_errors.CategoryIntegrity:
		return "integrity"
	case shared_errors.CategoryIncident:
		return "incident"
	case shared_errors.CategoryStructural:
		fallthrough
	case shared_errors.CategoryUnknown:
		fallthrough
	default:
		return "structural"
	}
}

// parseCategory reverses categoryString. An unknown string is treated
// as structural (same discipline: never let an unclassified thing
// through as Unknown).
func parseCategory(s string) shared_errors.Category {
	switch s {
	case "authority":
		return shared_errors.CategoryAuthority
	case "operational":
		return shared_errors.CategoryOperational
	case "integrity":
		return shared_errors.CategoryIntegrity
	case "incident":
		return shared_errors.CategoryIncident
	case "structural":
		fallthrough
	default:
		return shared_errors.CategoryStructural
	}
}

// NewErrorEnvelope builds an ErrorEnvelope from a classified error.
// If err is not a shared_errors.Error, the envelope is filled with
// Category="structural", Code="protocol_violation", and
// HumanMessage=err.Error() — the same discipline as categoryString.
//
// manifestID is an optional correlator; pass the empty string when
// unknown.
//
// HumanMessage is truncated to 1024 bytes; messages longer than that
// are either stack traces that leaked from a bug or adversarial
// amplification and are not useful on the wire.
func NewErrorEnvelope(err error, manifestID string) ErrorEnvelope {
	if err == nil {
		return ErrorEnvelope{
			Category:     "structural",
			Code:         CodeProtocolViolation,
			HumanMessage: "returnpath/transport: nil error passed to NewErrorEnvelope",
			ManifestID:   manifestID,
		}
	}
	cat := shared_errors.CategoryOf(err)
	code := shared_errors.CodeOf(err)
	if code == "" {
		code = CodeProtocolViolation
	}
	msg := err.Error()
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	return ErrorEnvelope{
		Category:     categoryString(cat),
		Code:         code,
		HumanMessage: msg,
		ManifestID:   manifestID,
	}
}

// AsClassifiedError reconstructs a shared_errors.Error from an
// envelope. The resulting error has the envelope's Category and Code
// and an Error() string of "returnpath/transport[<code>]: <message>".
// Callers that need the manifest ID can read it from envelope.ManifestID
// directly.
func (e ErrorEnvelope) AsClassifiedError() error {
	cat := parseCategory(e.Category)
	code := e.Code
	if code == "" {
		code = CodeProtocolViolation
	}
	msg := "returnpath/transport: " + e.HumanMessage
	if e.HumanMessage == "" {
		msg = "returnpath/transport: <empty error envelope>"
	}
	switch cat {
	case shared_errors.CategoryAuthority:
		return shared_errors.Authority(code, msg, nil)
	case shared_errors.CategoryOperational:
		return shared_errors.Operational(code, msg, nil)
	case shared_errors.CategoryIntegrity:
		return shared_errors.Integrity(code, msg, nil)
	case shared_errors.CategoryIncident:
		return shared_errors.Incident(code, msg, nil)
	case shared_errors.CategoryStructural:
		fallthrough
	default:
		return shared_errors.Structural(code, msg, nil)
	}
}
