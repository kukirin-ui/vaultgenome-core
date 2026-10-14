// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"io"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// IntegrityHook is the callback a Conn invokes on MAC verification
// failure. Callers in the server/client sibling packages wire this to
// their audit emitter so the failure lands as an IncidentEvent of kind
// HandshakeOrFrameMACFailed (see docs/internal/phase1-v2-plan.md §3.5).
//
// The transport package intentionally does NOT import any audit or
// incident package — that would break the isolation rule stated in
// doc.go. The hook keeps the dependency flowing the right way:
// transport defines the interface, the caller supplies the sink.
//
// A nil hook is legal; it simply means "no auditing at the transport
// layer." The MAC failure is still surfaced to the caller as a
// classified error in that case.
type IntegrityHook func(err error)

// Conn is a MAC-authenticated frame duplex built on top of a raw
// io.ReadWriter (typically a *net.TCPConn) and a SessionState returned
// by DoHandshake. Every outbound frame's payload is appended with a
// 32-byte HMAC-SHA-256 tag under the directional TxKey; every inbound
// frame's tag is verified under the directional RxKey before the body
// is surfaced.
//
// A Conn is safe for one concurrent reader and one concurrent writer
// (same pattern as net.Conn). Two goroutines writing at once would
// produce interleaved frames; the write mutex serializes them.
type Conn struct {
	rw    io.ReadWriter
	state *SessionState

	writeMu sync.Mutex
	readMu  sync.Mutex

	// integrityHook is called once per MAC failure observed on the
	// read path. Called synchronously from Read(); callers that need
	// non-blocking audit emission should spawn a goroutine inside the
	// hook.
	integrityHook IntegrityHook

	// closed records whether Close has been called. A Conn may be
	// closed more than once but only the first call delegates to the
	// underlying io.Closer.
	closed bool
}

// ConnOption configures a Conn at construction time.
type ConnOption func(*Conn)

// WithIntegrityHook installs a hook that fires once per MAC
// verification failure observed by this Conn's Read path.
func WithIntegrityHook(h IntegrityHook) ConnOption {
	return func(c *Conn) { c.integrityHook = h }
}

// WrapConn returns a Conn that MAC-wraps every frame using the keys
// derived during the handshake. rw is usually a *net.TCPConn; state
// is the return value of DoHandshake.
//
// WrapConn does not take ownership of rw in the sense of closing it
// on error — the caller remains responsible for rw's lifecycle. Conn.
// Close IS wired to rw.Close() if rw is an io.Closer, so in the
// common case the caller simply defers conn.Close() after the
// handshake.
func WrapConn(rw io.ReadWriter, state *SessionState, opts ...ConnOption) (*Conn, error) {
	if rw == nil {
		return nil, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: WrapConn called with nil io.ReadWriter",
			nil,
		)
	}
	if state == nil {
		return nil, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: WrapConn called with nil SessionState",
			nil,
		)
	}
	if len(state.TxKey) != MACSize || len(state.RxKey) != MACSize {
		return nil, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: SessionState has malformed MAC keys",
			nil,
		)
	}
	c := &Conn{rw: rw, state: state}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// State returns a pointer to the underlying SessionState. Callers MUST
// treat the returned pointer as read-only — mutating TxKey or RxKey at
// runtime breaks MAC continuity and is a programmer error.
func (c *Conn) State() *SessionState { return c.state }

// Write encodes v as a canonical-JSON body, appends the HMAC-SHA-256
// tag computed with TxKey, and writes one frame to the wire.
//
// v MUST be a frame body type with a `type` discriminator (one of the
// eleven body structs in bodies.go). Writing a non-body shape is a
// programmer error and yields a Structural / CodeProtocolViolation on
// the encode step.
//
// Write is safe for concurrent callers (serialized by an internal
// mutex); this matches the net.Conn Write contract and lets one
// goroutine pump heartbeats while another sends job results.
func (c *Conn) Write(v any) error {
	payload, err := EncodeBody(v)
	if err != nil {
		return err
	}
	tag := crypto.HMACSHA256(c.state.TxKey, payload)

	// Concatenate body + tag so a single frame carries both. The LEN
	// header on the wire covers body+tag together, matching the §3.2
	// invariant "PAYLOAD is LEN bytes."
	framed := make([]byte, 0, len(payload)+MACSize)
	framed = append(framed, payload...)
	framed = append(framed, tag...)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := WriteFrame(c.rw, framed); err != nil {
		return err
	}
	return nil
}

// Read reads one frame, verifies its MAC, and returns the frame type
// discriminator alongside the body bytes (without the trailing tag).
// Callers then DecodeBody the returned bytes into the concrete struct
// they expected for that type.
//
// On MAC verification failure, the integrity hook (if installed) is
// invoked before Read returns an Integrity / CodeIntegrityFailure
// error. The connection is NOT closed by Read — the caller decides
// whether a MAC failure is recoverable (it is not, per §3.5, but
// deferring the close to the caller keeps the transport layer
// side-effect-free apart from the hook).
//
// Read is safe for one concurrent caller at a time; a second Read
// while a first is in flight blocks on the read mutex.
func (c *Conn) Read() (FrameType, []byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	f, err := ReadFrame(c.rw)
	if err != nil {
		return "", nil, err
	}
	if len(f.Payload) < MACSize {
		// A post-SESSION_READY frame MUST carry at least MACSize bytes
		// of tag. Anything shorter is a protocol violation (and may be
		// an adversary trying to strip the MAC).
		return "", nil, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: frame too short to carry MAC tag",
			nil,
		)
	}
	body := f.Payload[:len(f.Payload)-MACSize]
	tag := f.Payload[len(f.Payload)-MACSize:]

	if err := crypto.HMACSHA256Verify(c.state.RxKey, body, tag); err != nil {
		// Wrap as Integrity / CodeIntegrityFailure so callers can
		// pattern-match on the transport code even if the underlying
		// shared_errors.CodeSignatureInvalid was used by the crypto
		// primitive.
		classified := shared_errors.Integrity(
			CodeIntegrityFailure,
			"returnpath/transport: frame MAC verification failed",
			err,
		)
		if c.integrityHook != nil {
			c.integrityHook(classified)
		}
		return "", nil, classified
	}

	t, err := PeekType(body)
	if err != nil {
		return "", nil, err
	}
	if !IsValidFrameType(FrameType(t)) {
		return "", nil, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: unknown frame type after SESSION_READY",
			nil,
		)
	}
	return FrameType(t), body, nil
}

// WriteError is a convenience helper that wraps an error as an
// ErrorFrame and writes it. Used by server/client sibling packages on
// the "graceful close with a classified reason" path. manifestID may
// be empty.
func (c *Conn) WriteError(err error, manifestID string) error {
	env := NewErrorEnvelope(err, manifestID)
	return c.Write(NewErrorFrame(env))
}

// WriteShutdown sends a Shutdown frame with the given reason and
// human-readable message, stamped with the current wall-clock instant.
// Callers then typically call Close() to release the underlying
// net.Conn.
//
// The transport layer deliberately uses time.Now() here rather than
// shared_time.Clock: the Shutdown timestamp is advisory and appears
// only on the wire; the authoritative "when did this session end"
// belongs to the audit chain on the server side and is stamped by
// the caller of WriteShutdown, not by this frame.
func (c *Conn) WriteShutdown(reason, humanMessage string) error {
	return c.Write(NewShutdown(time.Now().UTC(), reason, humanMessage))
}

// Close delegates to the underlying io.Closer if rw implements it.
// Safe to call multiple times; subsequent calls are no-ops.
func (c *Conn) Close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if closer, ok := c.rw.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
