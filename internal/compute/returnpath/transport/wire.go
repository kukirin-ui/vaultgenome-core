// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"encoding/binary"
	"errors"
	"io"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Wire-format constants. These values are frozen for wire-version v1.0
// per docs/internal/phase1-v2-plan.md §3.2 and the package doc.go "Freeze status"
// section. Changing any of them requires a MAGIC bump.
const (
	// MagicSize is the length of the MAGIC prefix in bytes.
	MagicSize = 4

	// LengthSize is the length of the LEN field in bytes (uint32 BE).
	LengthSize = 4

	// HeaderSize is the combined prefix: MAGIC + LEN.
	HeaderSize = MagicSize + LengthSize

	// WireMajor and WireMinor are the wire-format version, embedded in
	// the two low bytes of MAGIC. v1.0 is frozen.
	WireMajor uint8 = 1
	WireMinor uint8 = 0

	// MaxFrameSize is the hard cap on a single frame's PAYLOAD length.
	// A peer announcing LEN > MaxFrameSize is treated as an Integrity
	// failure: the connection closes and an audit entry is emitted, and
	// an attacker that forges an oversized LEN header cannot even provoke
	// an allocation. A job is one frame — the genome travels base64 inside
	// the JobRequest — so the cap bounds the genome: 16 MiB until
	// 2026-09-17, when a 32B model's LoRA genome (33.6 MB, a 44.8 MB
	// JobRequest) met it on an H100 (ADR 0013, amended); 128 MiB since,
	// room for a 70B adapter at the same rank. Both ends of a Return Path
	// must run a build with the same cap; sagvd refuses at dispatch a
	// genome its own cap does not carry.
	MaxFrameSize uint32 = 128 * 1024 * 1024 // 128 MiB

	// NonceMinBytes is the minimum length a handshake nonce must have.
	// Enforced at both endpoints. Derived from §15.2 of
	// docs/doctrine/bootstrap-contracts.md (nonce minimum across every
	// protocol layer in this codebase).
	NonceMinBytes = 16

	// MACSize is the HMAC-SHA-256 tag length. Post-SESSION_READY
	// frames carry this many additional bytes appended to the PAYLOAD
	// (LEN accounts for the MAC). See session.go.
	MACSize = 32
)

// WireMagic is the canonical four-byte MAGIC prefix every frame starts
// with: ASCII "RP" followed by the major/minor wire-version bytes.
//
// The value is returned by the accessor so callers cannot accidentally
// mutate a shared slice; compile-time constant-ness would be preferable
// but Go does not permit fixed-size byte arrays as package-level
// constants.
func WireMagic() [MagicSize]byte {
	return [MagicSize]byte{'R', 'P', WireMajor, WireMinor}
}

// Frame is the decoded form of one wire frame. Payload is the raw
// canonical-JSON bytes BEFORE any MAC is applied or stripped; session
// layers (see session.go) handle MAC wrapping/unwrapping above this
// layer.
//
// A Frame instance carries no state about which FrameType its payload
// encodes — that's the job of bodies.go. The wire framing layer is
// deliberately type-agnostic so the same ReadFrame/WriteFrame pair
// handles every body kind.
type Frame struct {
	// Payload is the canonical-JSON body (plus MAC suffix after
	// SESSION_READY). Length is bounded by MaxFrameSize.
	Payload []byte
}

// ErrWireClosed is returned by ReadFrame when the underlying
// io.Reader reports io.EOF at a frame boundary (i.e. before any MAGIC
// byte has been consumed). It is NOT classified as an error — a clean
// close at a frame boundary is normal operation.
//
// Callers that want classified-error semantics should check errors.Is
// against this sentinel and translate as appropriate for their layer.
var ErrWireClosed = errors.New("returnpath/transport: wire closed at frame boundary")

// WriteFrame writes one frame to w. It serializes MAGIC, LEN (big-
// endian uint32), then the payload bytes. It does NOT flush — the
// caller is responsible for ensuring the underlying writer flushes
// at whatever boundary it cares about (most callers will pass a
// net.Conn, which is already flush-on-write at the syscall level).
//
// Contract:
//
//   - len(payload) must be > 0 and ≤ MaxFrameSize. Zero-length frames
//     are a protocol violation (every body type has at least a `type`
//     field, which encodes to non-empty JSON).
//   - Any short write from w.Write is surfaced unchanged so the caller
//     can distinguish "peer closed mid-frame" from structured errors.
//
// Returns the total number of bytes written (MAGIC + LEN + payload).
func WriteFrame(w io.Writer, payload []byte) (int, error) {
	n := len(payload)
	if n == 0 {
		return 0, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: refusing to write zero-length frame",
			nil,
		)
	}
	if uint64(n) > uint64(MaxFrameSize) {
		return 0, shared_errors.Integrity(
			CodeIntegrityFailure,
			"returnpath/transport: frame payload exceeds MaxFrameSize",
			nil,
		)
	}

	var header [HeaderSize]byte
	m := WireMagic()
	copy(header[:MagicSize], m[:])
	binary.BigEndian.PutUint32(header[MagicSize:], uint32(n))

	written := 0
	k, err := w.Write(header[:])
	written += k
	if err != nil {
		return written, err
	}
	if k != HeaderSize {
		return written, io.ErrShortWrite
	}

	k, err = w.Write(payload)
	written += k
	if err != nil {
		return written, err
	}
	if k != n {
		return written, io.ErrShortWrite
	}
	return written, nil
}

// ReadFrame reads exactly one frame from r. Returns the raw payload
// (the bytes between header and next-frame boundary); the caller is
// responsible for passing the payload to the canonical-JSON decoder
// and, if the session is post-SESSION_READY, for stripping + verifying
// the MAC suffix.
//
// Contract:
//
//   - Reads HeaderSize bytes first. EOF before any header byte is
//     a clean close; surfaces ErrWireClosed (NOT wrapped as a
//     classified error, so callers doing io.EOF translation can
//     check errors.Is(err, ErrWireClosed)).
//   - EOF partway through the header is a structural protocol
//     violation (truncated frame): returns Structural /
//     CodeTruncatedFrame.
//   - Header MAGIC bytes MUST match WireMagic exactly. Any mismatch is
//     Structural / CodeProtocolViolation.
//   - Header LEN > MaxFrameSize is Integrity / CodeFrameOverSize (and
//     the connection MUST be closed by the caller — we do not read the
//     oversized payload to avoid the DoS).
//   - A short read on the payload is Structural / CodeTruncatedFrame.
//
// A successful ReadFrame leaves the reader positioned exactly at the
// next frame's MAGIC byte.
func ReadFrame(r io.Reader) (Frame, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			// Clean close at a frame boundary — not a protocol
			// violation. Distinguish from truncation (see below).
			return Frame{}, ErrWireClosed
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Frame{}, shared_errors.Structural(
				CodeTruncatedFrame,
				"returnpath/transport: truncated frame at header",
				err,
			)
		}
		return Frame{}, err
	}

	expected := WireMagic()
	for i := 0; i < MagicSize; i++ {
		if header[i] != expected[i] {
			return Frame{}, shared_errors.Structural(
				CodeProtocolViolation,
				"returnpath/transport: frame MAGIC mismatch",
				nil,
			)
		}
	}

	length := binary.BigEndian.Uint32(header[MagicSize:])
	if length == 0 {
		return Frame{}, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: zero-length frame",
			nil,
		)
	}
	if length > MaxFrameSize {
		return Frame{}, shared_errors.Integrity(
			CodeFrameOverSize,
			"returnpath/transport: frame payload exceeds MaxFrameSize",
			nil,
		)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return Frame{}, shared_errors.Structural(
				CodeTruncatedFrame,
				"returnpath/transport: truncated frame at payload",
				err,
			)
		}
		return Frame{}, err
	}
	return Frame{Payload: payload}, nil
}
