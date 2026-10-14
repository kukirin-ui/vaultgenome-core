// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// Conformance suite — six subtests corresponding to docs/internal/phase1-v2-plan.md
// §3.6. Each subtest runs against an in-process loopback listener so
// the same transport binary exercised by production is what the test
// exercises. No fakes, no in-memory pipe shortcuts — the wire is real
// TCP and the framing is the real binary serializer.

const testHandshakeTimeout = 3 * time.Second

// ---- test scaffolding -----------------------------------------------------

type peerTEEs struct {
	clientProducer *tee.Simulated
	serverProducer *tee.Simulated
	clientVerifier *tee.SimulatedVerifier // verifies server evidence
	serverVerifier *tee.SimulatedVerifier // verifies client evidence
}

// newPeerTEEs builds mutually-trusting simulated TEEs: the client's
// verifier is pre-registered with the server's measurement + public
// key, and vice versa. This models the Phase-1 "both sides know each
// other's expected enclave" baseline; real-hardware Phase-3 swaps this
// for SGX / TDX quote validation against an attestation appraisal
// policy.
func newPeerTEEs(t *testing.T) peerTEEs {
	t.Helper()
	clientSeed := bytes.Repeat([]byte{0x11}, crypto.Ed25519SeedSize)
	serverSeed := bytes.Repeat([]byte{0x22}, crypto.Ed25519SeedSize)
	client, err := tee.NewSimulated([]byte("acp-compute-worker-v1"), clientSeed)
	require.NoError(t, err)
	server, err := tee.NewSimulated([]byte("sagvd-returnpath-v1"), serverSeed)
	require.NoError(t, err)
	return peerTEEs{
		clientProducer: client,
		serverProducer: server,
		clientVerifier: tee.NewSimulatedVerifier(server.PublicKey(), server.Measurement()),
		serverVerifier: tee.NewSimulatedVerifier(client.PublicKey(), client.Measurement()),
	}
}

// listenLoopback opens a loopback listener on a random high port and
// returns it. Tests use the listener as both the accept point and the
// cleanup target.
func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	return lis
}

type handshakeResult struct {
	state *SessionState
	err   error
}

// runLoopbackHandshake spawns the server-side handshake goroutine,
// dials from the test goroutine, and returns both (client, server)
// handshake outcomes. The caller is responsible for closing any
// successfully-handshaked connections.
//
// The TxKey/RxKey asymmetry between the two roles is the whole reason
// this helper exists: unit-testing either side alone would not catch
// a direction-key mixup. The conformance happy path test MUST round-
// trip a MAC-wrapped frame in both directions for this reason.
func runLoopbackHandshake(t *testing.T, peers peerTEEs, opts ...func(*HandshakeConfig)) (clientConn, serverConn net.Conn, clientState, serverState *SessionState) {
	t.Helper()
	lis := listenLoopback(t)

	serverCh := make(chan handshakeResult, 1)
	var serverAccepted net.Conn

	go func() {
		c, err := lis.Accept()
		if err != nil {
			serverCh <- handshakeResult{nil, err}
			return
		}
		serverAccepted = c
		_ = c.SetDeadline(time.Now().Add(testHandshakeTimeout))
		cfg := HandshakeConfig{
			Role:     RoleServer,
			Conn:     c,
			Producer: peers.serverProducer,
			Verifier: peers.serverVerifier,
			Clock:    shared_time.NewSystemClock(),
		}
		for _, o := range opts {
			o(&cfg)
		}
		s, herr := DoHandshake(cfg)
		serverCh <- handshakeResult{s, herr}
	}()

	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	_ = dialed.SetDeadline(time.Now().Add(testHandshakeTimeout))

	cfg := HandshakeConfig{
		Role:              RoleClient,
		Conn:              dialed,
		Producer:          peers.clientProducer,
		Verifier:          peers.clientVerifier,
		Clock:             shared_time.NewSystemClock(),
		ProposedChallenge: []byte("test-proposed-challenge"),
	}
	for _, o := range opts {
		o(&cfg)
	}
	cs, cerr := DoHandshake(cfg)
	sr := <-serverCh

	require.NoError(t, cerr, "client handshake failed")
	require.NoError(t, sr.err, "server handshake failed")
	require.NotNil(t, cs)
	require.NotNil(t, sr.state)

	t.Cleanup(func() {
		_ = dialed.Close()
		if serverAccepted != nil {
			_ = serverAccepted.Close()
		}
	})
	return dialed, serverAccepted, cs, sr.state
}

// writeRawFrame is the test-only counterpart to WriteFrame that allows
// injecting a crafted LEN field for the over-size-frame conformance
// subtest. It bypasses the MaxFrameSize guard that WriteFrame itself
// applies on the sender side.
func writeRawFrame(w io.Writer, length uint32, payload []byte) error {
	var hdr [HeaderSize]byte
	m := WireMagic()
	copy(hdr[:MagicSize], m[:])
	binary.BigEndian.PutUint32(hdr[MagicSize:], length)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ---- Subtest 1: Happy path ------------------------------------------------

func TestConformance_01_HappyPath(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	clientRW, serverRW, clientState, serverState := runLoopbackHandshake(t, peers)

	// Session keys MUST be mirror-reflected across the roles: client's
	// TxKey (c2s) equals server's RxKey, and vice versa.
	require.Equal(t, clientState.TxKey, serverState.RxKey,
		"c2s key mismatch across peers")
	require.Equal(t, clientState.RxKey, serverState.TxKey,
		"s2c key mismatch across peers")
	// Peer measurements MUST be the sibling's simulated measurement.
	require.Equal(t, peers.serverProducer.Measurement(), clientState.PeerMeasurement)
	require.Equal(t, peers.clientProducer.Measurement(), serverState.PeerMeasurement)
	// ReadyAt is within a wide window around test start.
	require.WithinDuration(t, time.Now(), clientState.ReadyAt, 10*time.Second)

	// Wrap both sides as MAC-authenticated Conns and round-trip a body.
	var clientHook, serverHook atomic.Int32
	clientConn, err := WrapConn(clientRW, clientState,
		WithIntegrityHook(func(error) { clientHook.Add(1) }))
	require.NoError(t, err)
	serverConn, err := WrapConn(serverRW, serverState,
		WithIntegrityHook(func(error) { serverHook.Add(1) }))
	require.NoError(t, err)

	// Client → server: Heartbeat.
	require.NoError(t, clientConn.Write(NewHeartbeat(time.Now())))
	typ, body, err := serverConn.Read()
	require.NoError(t, err)
	require.Equal(t, FrameTypeHeartbeat, typ)
	var hb Heartbeat
	require.NoError(t, DecodeBody(body, &hb))
	require.NoError(t, hb.Validate())

	// Server → client: Heartbeat.
	require.NoError(t, serverConn.Write(NewHeartbeat(time.Now())))
	typ, body, err = clientConn.Read()
	require.NoError(t, err)
	require.Equal(t, FrameTypeHeartbeat, typ)
	require.NoError(t, DecodeBody(body, &hb))

	// Graceful close: server sends Shutdown, client reads it.
	require.NoError(t, serverConn.WriteShutdown(CodeShutdownNormal, "test done"))
	typ, body, err = clientConn.Read()
	require.NoError(t, err)
	require.Equal(t, FrameTypeShutdown, typ)
	var sd Shutdown
	require.NoError(t, DecodeBody(body, &sd))
	require.Equal(t, CodeShutdownNormal, sd.Reason)

	require.Zero(t, clientHook.Load(), "integrity hook must not fire on happy path")
	require.Zero(t, serverHook.Load(), "integrity hook must not fire on happy path")

	_ = clientConn.Close()
	_ = serverConn.Close()
}

// ---- Subtest 2: Nonce too short -------------------------------------------

func TestConformance_02_NonceTooShort(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	lis := listenLoopback(t)

	serverCh := make(chan handshakeResult, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			serverCh <- handshakeResult{nil, err}
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(testHandshakeTimeout))
		s, herr := DoHandshake(HandshakeConfig{
			Role:     RoleServer,
			Conn:     c,
			Producer: peers.serverProducer,
			Verifier: peers.serverVerifier,
		})
		serverCh <- handshakeResult{s, herr}
	}()

	conn, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testHandshakeTimeout))

	// Hand-craft a HelloClient with an under-length nonce bypassing the
	// constructor. Canonical-JSON-encode it directly so the server sees
	// the violation only on its Validate() step.
	bad := HelloClient{
		Type:        FrameTypeHelloClient,
		WireMajor:   WireMajor,
		WireMinor:   WireMinor,
		ClientNonce: bytes.Repeat([]byte{0xAA}, NonceMinBytes-1),
	}
	payload, err := EncodeBody(bad)
	require.NoError(t, err)
	_, err = WriteFrame(conn, payload)
	require.NoError(t, err)

	// The server writes an ErrorFrame back before closing. Read it and
	// assert the code is nonce_too_short.
	f, err := ReadFrame(conn)
	require.NoError(t, err)
	typStr, err := PeekType(f.Payload)
	require.NoError(t, err)
	require.Equal(t, string(FrameTypeError), typStr)
	var ef ErrorFrame
	require.NoError(t, DecodeBody(f.Payload, &ef))
	require.Equal(t, CodeNonceTooShort, ef.Envelope.Code)
	require.Equal(t, "structural", ef.Envelope.Category)

	sr := <-serverCh
	require.Error(t, sr.err)
	require.Equal(t, CodeNonceTooShort, shared_errors.CodeOf(sr.err))
}

// ---- Subtest 3: MAC tamper ------------------------------------------------

func TestConformance_03_MACTamper(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	clientRW, serverRW, clientState, serverState := runLoopbackHandshake(t, peers)

	var hookFired atomic.Int32
	var lastHookErr atomic.Value

	serverConn, err := WrapConn(serverRW, serverState,
		WithIntegrityHook(func(err error) {
			hookFired.Add(1)
			lastHookErr.Store(err)
		}))
	require.NoError(t, err)

	// Assemble a valid MAC-wrapped heartbeat on the client side, then
	// flip a bit in the tag before shipping it. We use the primitives
	// directly rather than Conn.Write so we can tamper.
	hbBody, err := EncodeBody(NewHeartbeat(time.Now()))
	require.NoError(t, err)
	tag := crypto.HMACSHA256(clientState.TxKey, hbBody)
	// Flip one bit of the tag.
	tag[0] ^= 0x01
	framed := append(append([]byte{}, hbBody...), tag...)
	_ = clientRW.SetDeadline(time.Now().Add(testHandshakeTimeout))
	_, err = WriteFrame(clientRW, framed)
	require.NoError(t, err)

	_, _, err = serverConn.Read()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, CodeIntegrityFailure, shared_errors.CodeOf(err))
	require.Equal(t, int32(1), hookFired.Load(),
		"integrity hook MUST fire exactly once on MAC tamper")
	hooked, _ := lastHookErr.Load().(error)
	require.NotNil(t, hooked)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(hooked))
}

// ---- Subtest 4: Over-size frame ------------------------------------------

func TestConformance_04_OverSizeFrame(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	clientRW, serverRW, _, serverState := runLoopbackHandshake(t, peers)

	var integritySeen atomic.Int32
	serverConn, err := WrapConn(serverRW, serverState,
		WithIntegrityHook(func(error) { integritySeen.Add(1) }))
	require.NoError(t, err)

	_ = clientRW.SetDeadline(time.Now().Add(testHandshakeTimeout))

	// Announce a LEN header well above MaxFrameSize. The server must
	// refuse before allocating a buffer for the oversized payload.
	require.NoError(t, writeRawFrame(clientRW, MaxFrameSize+1, nil))

	_, _, err = serverConn.Read()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, CodeFrameOverSize, shared_errors.CodeOf(err))
	// ReadFrame rejected the LEN before any MAC check, so the MAC hook
	// must NOT have fired: oversized frames are a wire-layer integrity
	// failure, not a MAC integrity failure.
	require.Zero(t, integritySeen.Load())
}

// ---- Subtest 5: Unknown frame type ----------------------------------------

func TestConformance_05_UnknownFrameType(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	clientRW, serverRW, clientState, serverState := runLoopbackHandshake(t, peers)

	serverConn, err := WrapConn(serverRW, serverState)
	require.NoError(t, err)

	// Craft a body shape with a valid `type` field string that is NOT
	// one of the eleven defined FrameTypes. Using a plain map we still
	// get canonical-JSON encoding via EncodeBody (the shared canonical
	// encoder handles maps with string keys).
	bogus := map[string]any{
		"type":    "totally_bogus_frame",
		"payload": "unused",
	}
	body, err := EncodeBody(bogus)
	require.NoError(t, err)
	tag := crypto.HMACSHA256(clientState.TxKey, body)
	framed := append(append([]byte{}, body...), tag...)
	_ = clientRW.SetDeadline(time.Now().Add(testHandshakeTimeout))
	_, err = WriteFrame(clientRW, framed)
	require.NoError(t, err)

	_, _, err = serverConn.Read()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
}

// ---- Subtest 6: Heartbeat liveness ----------------------------------------

func TestConformance_06_HeartbeatLiveness(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	clientRW, serverRW, clientState, serverState := runLoopbackHandshake(t, peers)

	clientConn, err := WrapConn(clientRW, clientState)
	require.NoError(t, err)
	serverConn, err := WrapConn(serverRW, serverState)
	require.NoError(t, err)

	// Exchange N heartbeats in each direction under a short per-call
	// deadline. The test proves the MAC path is bidirectional, nonce-
	// free (heartbeats don't carry nonces), and does not leak state
	// across calls.
	const rounds = 5
	for i := 0; i < rounds; i++ {
		_ = clientRW.SetDeadline(time.Now().Add(testHandshakeTimeout))
		_ = serverRW.SetDeadline(time.Now().Add(testHandshakeTimeout))

		now := time.Now()
		require.NoError(t, clientConn.Write(NewHeartbeat(now)))
		typ, body, err := serverConn.Read()
		require.NoError(t, err)
		require.Equal(t, FrameTypeHeartbeat, typ)
		var hb Heartbeat
		require.NoError(t, DecodeBody(body, &hb))
		require.NoError(t, hb.Validate())

		require.NoError(t, serverConn.Write(NewHeartbeat(now)))
		typ, body, err = clientConn.Read()
		require.NoError(t, err)
		require.Equal(t, FrameTypeHeartbeat, typ)
		require.NoError(t, DecodeBody(body, &hb))
		require.NoError(t, hb.Validate())
	}
}
