// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// Role identifies which half of the handshake a caller is running.
// Declared as a typed int rather than a string so a forgotten assignment
// produces a zero value that fails the explicit check in DoHandshake,
// rather than defaulting silently to "client" or "server".
type Role int

const (
	// RoleUnspecified is the zero value; DoHandshake rejects it.
	RoleUnspecified Role = 0
	// RoleClient is the initiating side (acp-compute worker).
	RoleClient Role = 1
	// RoleServer is the responding side (sagvd vault-facing daemon).
	RoleServer Role = 2
)

// Transcript captures the four wire-visible byte fields that both
// peers see during the handshake. The same four bytes feed into the
// session-key HKDF and into the TEE challenge construction, so both
// sides must agree byte-for-byte on every field.
//
// All four fields are the *decoded* byte values (not the canonical-JSON
// encoded form). The canonical-JSON round-trip is a pure pass-through
// for []byte (base64 in, raw out) and is therefore deterministic.
type Transcript struct {
	ClientNonce       []byte
	ServerNonce       []byte
	ProposedChallenge []byte
	DerivationContext []byte
}

// HandshakeConfig controls a single handshake attempt. A zero Config is
// rejected — every field below is either mandatory or has an explicit
// fallback documented alongside.
type HandshakeConfig struct {
	// Role is RoleClient or RoleServer. Required.
	Role Role

	// Conn is the underlying io.ReadWriter (usually a *net.TCPConn). The
	// handshake issues four ReadFrame/WriteFrame calls against this
	// ReadWriter in the order specified by §3.3. Deadlines are set by
	// the caller on the underlying net.Conn; the handshake does not
	// adjust them.
	Conn io.ReadWriter

	// Producer is the local TEE quote generator. Used by both roles to
	// produce attestation evidence over the transcript-derived
	// challenge.
	Producer tee.Producer

	// Verifier is the local TEE quote verifier. Used to check the
	// *peer's* attestation evidence. MUST be configured with the
	// expected peer Measurement — a missing Measurement check is a
	// handshake-authority hole.
	Verifier tee.Verifier

	// NonceReader is the entropy source for this side's nonce. Default
	// is crypto/rand.Reader; tests may substitute a deterministic
	// reader for reproducibility.
	NonceReader io.Reader

	// Clock provides the timestamp baked into SessionReady.ReadyAt. If
	// nil, a SystemClock is used.
	Clock shared_time.Clock

	// ProposedChallenge is the challenge the *client* wants the server's
	// TEE evidence to cover. Ignored by the server. If empty on the
	// client side, an empty challenge is sent — the transcript still
	// binds both nonces, so empty is safe; it simply means the client
	// does not need any extra bytes covered beyond the transcript.
	ProposedChallenge []byte

	// DerivationContext is emitted by the *server* in HelloServer and
	// feeds into the HKDF session-key derivation on both sides. Ignored
	// on the client. If empty on the server side, a random 16-byte
	// context is generated — this is the safe default and is what the
	// Phase-1 daemons will use.
	DerivationContext []byte
}

// SessionState is what DoHandshake returns on success. All four fields
// are populated; the MAC keys are private to the session layer and do
// not appear in any audit output.
type SessionState struct {
	Role            Role
	Transcript      Transcript
	TxKey           []byte // 32 bytes; used to MAC frames we write
	RxKey           []byte // 32 bytes; used to verify frames we read
	PeerMeasurement tee.Measurement
	// PeerDetail is what the verifier said beyond the measurement (the
	// platform, the GPUs), for the audit record; nil for a verifier
	// with nothing more to say.
	PeerDetail *tee.AttestationDetail
	ReadyAt    time.Time
}

// handshake-level domain-separation labels. These are concatenated into
// the SHA-256 pre-image that forms each side's TEE challenge. A change
// in any of them requires a wire-version bump (MAGIC change) per §3.1.
var (
	labelServerAtt = []byte("rp-wire-v1.0 SERVER-ATT")
	labelClientAtt = []byte("rp-wire-v1.0 CLIENT-ATT")
	labelHKDFSalt  = []byte("rp-wire-v1.0 hkdf-salt")
	labelHKDFInfo  = []byte("rp-wire-v1.0 session-mac")
)

// lenPrefixed writes len(b) as a big-endian uint32 followed by b. Used
// in transcript-hash construction to avoid any field-boundary ambiguity:
// two different (ClientNonce, ProposedChallenge) splits will never
// produce the same transcript hash.
func lenPrefixed(dst, b []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, b...)
	return dst
}

// transcriptServerChallenge returns the 32-byte SHA-256 commitment the
// server's TEE evidence must cover. Both peers compute it independently
// from the bytes they observed on the wire, so no separate "which
// challenge to use" negotiation is necessary.
func transcriptServerChallenge(clientNonce, proposedChallenge []byte) []byte {
	var buf []byte
	buf = append(buf, labelServerAtt...)
	buf = lenPrefixed(buf, clientNonce)
	buf = lenPrefixed(buf, proposedChallenge)
	h := crypto.SHA256(buf)
	return h[:]
}

// transcriptClientChallenge returns the 32-byte SHA-256 commitment the
// client's TEE evidence must cover. By construction it binds both
// nonces and the derivation context, so a replay of the client's quote
// across sessions is rejected by the server's verifier.
func transcriptClientChallenge(clientNonce, serverNonce, derivationContext []byte) []byte {
	var buf []byte
	buf = append(buf, labelClientAtt...)
	buf = lenPrefixed(buf, clientNonce)
	buf = lenPrefixed(buf, serverNonce)
	buf = lenPrefixed(buf, derivationContext)
	h := crypto.SHA256(buf)
	return h[:]
}

// deriveSessionKeys runs HKDF-SHA-256 over the transcript and returns
// the two directional MAC keys (c2s = client-to-server, s2c =
// server-to-client), each 32 bytes. IKM is ClientNonce || ServerNonce;
// salt is a fixed per-version domain label; info is labelHKDFInfo
// concatenated with the per-handshake DerivationContext.
//
// Same inputs ⇒ same outputs: both peers call this function with the
// same transcript and derive identical keys.
func deriveSessionKeys(t Transcript) (c2s, s2c []byte, err error) {
	ikm := make([]byte, 0, len(t.ClientNonce)+len(t.ServerNonce))
	ikm = append(ikm, t.ClientNonce...)
	ikm = append(ikm, t.ServerNonce...)

	info := make([]byte, 0, len(labelHKDFInfo)+len(t.DerivationContext))
	info = append(info, labelHKDFInfo...)
	info = append(info, t.DerivationContext...)

	out, err := crypto.HKDFSHA256(labelHKDFSalt, ikm, info, 2*MACSize)
	if err != nil {
		return nil, nil, err
	}
	return out[:MACSize], out[MACSize : 2*MACSize], nil
}

// writeBody encodes v via EncodeBody (canonical JSON) and pushes the
// bytes out via WriteFrame. Pre-SESSION_READY only — this is the raw,
// un-MAC'd path used exclusively during the handshake.
func writeBody(w io.Writer, v any) error {
	payload, err := EncodeBody(v)
	if err != nil {
		return err
	}
	if _, err := WriteFrame(w, payload); err != nil {
		return err
	}
	return nil
}

// readBodyAs reads one frame, PeekType-checks that its type
// discriminator matches expected, and decodes the body into dst.
// Returns the raw payload on success for callers that need it (e.g.
// for transcript accounting), plus the decoded body (via dst).
//
// On type mismatch, the caller may also receive an ErrorFrame (this
// function surfaces it through the error return so the caller can
// unwrap and forward the envelope). A wire-level decode error is a
// Structural / CodeProtocolViolation per the frame doctrine.
func readBodyAs(r io.Reader, expected FrameType, dst any) ([]byte, error) {
	f, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	t, err := PeekType(f.Payload)
	if err != nil {
		return nil, err
	}
	if FrameType(t) == FrameTypeError {
		// The peer chose to tell us *why* they're refusing the handshake.
		// Decode the envelope and surface it as a classified error.
		var ef ErrorFrame
		if derr := DecodeBody(f.Payload, &ef); derr != nil {
			return nil, derr
		}
		return f.Payload, ef.Envelope.AsClassifiedError()
	}
	if FrameType(t) != expected {
		return nil, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: handshake frame type does not match expected phase",
			nil,
		)
	}
	if err := DecodeBody(f.Payload, dst); err != nil {
		return nil, err
	}
	return f.Payload, nil
}

// sendErrorAndReturn writes an ErrorFrame containing a classified error
// and returns the same error to the local caller. Best-effort: a write
// failure on the error frame itself is swallowed, because at that point
// the connection is already going down and we prefer to surface the
// originating error to our caller rather than the secondary one.
func sendErrorAndReturn(w io.Writer, err error) error {
	env := NewErrorEnvelope(err, "")
	ef := NewErrorFrame(env)
	_ = writeBody(w, ef) // best-effort
	return err
}

// DoHandshake runs the appropriate handshake state machine for
// cfg.Role and returns the derived SessionState. On any protocol-level
// failure, a classified error is returned and, where feasible, an
// ErrorFrame is also written to the peer so they can close cleanly.
//
// The function does NOT close cfg.Conn on error — that is the caller's
// job (for example, wire_integration_test.go tears down the listener;
// the sagvd server closes the net.Conn; the acp-compute client
// reconnects).
func DoHandshake(cfg HandshakeConfig) (*SessionState, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	switch cfg.Role {
	case RoleClient:
		return doClientHandshake(cfg)
	case RoleServer:
		return doServerHandshake(cfg)
	default:
		// Already rejected by validateConfig, but belt-and-suspenders.
		return nil, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: unspecified Role in HandshakeConfig",
			nil,
		)
	}
}

func validateConfig(cfg HandshakeConfig) error {
	if cfg.Role != RoleClient && cfg.Role != RoleServer {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: HandshakeConfig.Role must be RoleClient or RoleServer",
			nil,
		)
	}
	if cfg.Conn == nil {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: HandshakeConfig.Conn is required",
			nil,
		)
	}
	if cfg.Producer == nil {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: HandshakeConfig.Producer is required",
			nil,
		)
	}
	if cfg.Verifier == nil {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: HandshakeConfig.Verifier is required",
			nil,
		)
	}
	return nil
}

func nonceReader(cfg HandshakeConfig) io.Reader {
	if cfg.NonceReader != nil {
		return cfg.NonceReader
	}
	return rand.Reader
}

func clockOf(cfg HandshakeConfig) shared_time.Clock {
	if cfg.Clock != nil {
		return cfg.Clock
	}
	return shared_time.NewSystemClock()
}

func freshNonce(r io.Reader, n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, shared_errors.Operational(
			CodeHandshakeFailure,
			"returnpath/transport: nonce generation failed",
			err,
		)
	}
	return out, nil
}

// ---- client half ----------------------------------------------------------

func doClientHandshake(cfg HandshakeConfig) (*SessionState, error) {
	// Step 1: HELLO_CLIENT.
	clientNonce, err := freshNonce(nonceReader(cfg), NonceMinBytes)
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}
	hc, err := NewHelloClient(clientNonce, cfg.ProposedChallenge)
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}
	if err := writeBody(cfg.Conn, hc); err != nil {
		return nil, err
	}

	// Step 2: HELLO_SERVER.
	var hs HelloServer
	if _, err := readBodyAs(cfg.Conn, FrameTypeHelloServer, &hs); err != nil {
		return nil, err
	}
	if err := hs.Validate(); err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}
	// Echo check: the server's echo of our nonce MUST be byte-identical.
	if !constantTimeEqual(hs.ClientNonceEcho, clientNonce) {
		return nil, sendErrorAndReturn(cfg.Conn, shared_errors.Authority(
			CodeHandshakeFailure,
			"returnpath/transport: HelloServer.ClientNonceEcho does not match ClientNonce",
			nil,
		))
	}

	// Verify the server's TEE evidence over the transcript-derived
	// challenge. The verifier extracts the peer's measurement; the
	// caller's Verifier construction (SimulatedVerifier in Phase 1)
	// pre-binds the expected measurement so an attacker cannot
	// substitute a valid quote from a different enclave.
	serverChallenge := transcriptServerChallenge(clientNonce, cfg.ProposedChallenge)
	peerM, peerDetail, err := tee.VerifyDetailed(cfg.Verifier, tee.Evidence(hs.ServerEvidence), tee.Nonce(serverChallenge))
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, shared_errors.Authority(
			CodeHandshakeFailure,
			"returnpath/transport: server TEE evidence verification failed",
			err,
		))
	}

	// Step 3: ATTEST_CLIENT. Produce our evidence over the full
	// transcript; the server will recompute the same challenge bytes
	// and Verify() against them.
	clientChallenge := transcriptClientChallenge(
		clientNonce, hs.ServerNonce, hs.DerivationContext,
	)
	clientEv, err := cfg.Producer.Quote(tee.Nonce(clientChallenge))
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, shared_errors.Authority(
			CodeHandshakeFailure,
			"returnpath/transport: client TEE quote generation failed",
			err,
		))
	}
	ac, err := NewAttestClient([]byte(clientEv))
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}
	if err := writeBody(cfg.Conn, ac); err != nil {
		return nil, err
	}

	// Step 4: SESSION_READY.
	var sr SessionReady
	if _, err := readBodyAs(cfg.Conn, FrameTypeSessionReady, &sr); err != nil {
		return nil, err
	}
	if err := sr.Validate(); err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}

	// Derive session keys. Client: TxKey = c2s, RxKey = s2c.
	tr := Transcript{
		ClientNonce:       clientNonce,
		ServerNonce:       hs.ServerNonce,
		ProposedChallenge: cfg.ProposedChallenge,
		DerivationContext: hs.DerivationContext,
	}
	c2s, s2c, err := deriveSessionKeys(tr)
	if err != nil {
		return nil, err
	}
	return &SessionState{
		Role:            RoleClient,
		Transcript:      tr,
		TxKey:           c2s,
		RxKey:           s2c,
		PeerMeasurement: peerM,
		PeerDetail:      peerDetail,
		ReadyAt:         sr.ReadyAt,
	}, nil
}

// ---- server half ----------------------------------------------------------

func doServerHandshake(cfg HandshakeConfig) (*SessionState, error) {
	// Step 1: read HELLO_CLIENT.
	var hc HelloClient
	if _, err := readBodyAs(cfg.Conn, FrameTypeHelloClient, &hc); err != nil {
		return nil, err
	}
	if err := hc.Validate(); err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}

	// Step 2: assemble HELLO_SERVER.
	serverNonce, err := freshNonce(nonceReader(cfg), NonceMinBytes)
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}
	derivationContext := cfg.DerivationContext
	if len(derivationContext) == 0 {
		// Safe default: 16 random bytes. Provides per-session HKDF
		// domain separation even when the caller did not supply one.
		derivationContext, err = freshNonce(nonceReader(cfg), 16)
		if err != nil {
			return nil, sendErrorAndReturn(cfg.Conn, err)
		}
	}
	serverChallenge := transcriptServerChallenge(hc.ClientNonce, hc.ProposedChallenge)
	serverEv, err := cfg.Producer.Quote(tee.Nonce(serverChallenge))
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, shared_errors.Authority(
			CodeHandshakeFailure,
			"returnpath/transport: server TEE quote generation failed",
			err,
		))
	}
	hs, err := NewHelloServer(hc.ClientNonce, serverNonce, []byte(serverEv), derivationContext)
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}
	if err := writeBody(cfg.Conn, hs); err != nil {
		return nil, err
	}

	// Step 3: read ATTEST_CLIENT and verify.
	var ac AttestClient
	if _, err := readBodyAs(cfg.Conn, FrameTypeAttestClient, &ac); err != nil {
		return nil, err
	}
	if err := ac.Validate(); err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, err)
	}
	clientChallenge := transcriptClientChallenge(
		hc.ClientNonce, serverNonce, derivationContext,
	)
	peerM, peerDetail, err := tee.VerifyDetailed(cfg.Verifier, tee.Evidence(ac.ClientEvidence), tee.Nonce(clientChallenge))
	if err != nil {
		return nil, sendErrorAndReturn(cfg.Conn, shared_errors.Authority(
			CodeHandshakeFailure,
			"returnpath/transport: client TEE evidence verification failed",
			err,
		))
	}

	// Step 4: send SESSION_READY.
	ready := NewSessionReady(clockOf(cfg).Now())
	if err := writeBody(cfg.Conn, ready); err != nil {
		return nil, err
	}

	// Derive session keys. Server: TxKey = s2c, RxKey = c2s.
	tr := Transcript{
		ClientNonce:       hc.ClientNonce,
		ServerNonce:       serverNonce,
		ProposedChallenge: hc.ProposedChallenge,
		DerivationContext: derivationContext,
	}
	c2s, s2c, err := deriveSessionKeys(tr)
	if err != nil {
		return nil, err
	}
	return &SessionState{
		Role:            RoleServer,
		Transcript:      tr,
		TxKey:           s2c,
		RxKey:           c2s,
		PeerMeasurement: peerM,
		PeerDetail:      peerDetail,
		ReadyAt:         ready.ReadyAt,
	}, nil
}

// constantTimeEqual compares two byte slices in constant time relative
// to the length of a, returning true iff the slices are equal. Used
// for the ClientNonceEcho check so that an attacker who guessed the
// first bytes of a client nonce cannot time-side-channel the remainder.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
