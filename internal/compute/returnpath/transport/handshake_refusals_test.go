// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// The handshake refuses what it must at each phase, on each side, and
// tells the peer why with an error frame. Each test scripts one side of
// a TCP loopback and runs the real handshake on the other.

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy source closed") }

type failingProducer struct{ m tee.Measurement }

func (p failingProducer) Quote(tee.Nonce) (tee.Evidence, error) {
	return nil, errors.New("the device is gone")
}
func (p failingProducer) Measurement() tee.Measurement { return p.m }

func TestDoHandshake_RefusesABadConfig(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	c, s := net.Pipe()
	defer func() { _ = c.Close(); _ = s.Close() }()
	good := HandshakeConfig{Role: RoleClient, Conn: c, Producer: peers.clientProducer, Verifier: peers.clientVerifier}
	for name, mut := range map[string]func(*HandshakeConfig){
		"role":     func(cfg *HandshakeConfig) { cfg.Role = RoleUnspecified },
		"conn":     func(cfg *HandshakeConfig) { cfg.Conn = nil },
		"producer": func(cfg *HandshakeConfig) { cfg.Producer = nil },
		"verifier": func(cfg *HandshakeConfig) { cfg.Verifier = nil },
	} {
		cfg := good
		mut(&cfg)
		_, err := DoHandshake(cfg)
		require.Error(t, err, name)
		require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err), name)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), name)
	}
}

func TestReadBodyAs_SurfacesThePeersErrorFrame(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	refusal := shared_errors.Authority(CodeHandshakeFailure, "the server did not like the evidence", nil)
	require.NoError(t, writeBody(&buf, NewErrorFrame(NewErrorEnvelope(refusal, ""))))
	var hs HelloServer
	payload, err := readBodyAs(&buf, FrameTypeHelloServer, &hs)
	require.Error(t, err)
	require.NotEmpty(t, payload, "the raw frame comes back with the classified error")
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

func TestReadBodyAs_RefusesTheWrongPhase(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, writeBody(&buf, NewHeartbeat(time.Now())))
	var hs HelloServer
	_, err := readBodyAs(&buf, FrameTypeHelloServer, &hs)
	require.Error(t, err)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
}

func TestReadBodyAs_RefusesABodyThatDoesNotDecode(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	_, err := WriteFrame(&buf, []byte(`{"type":"hello_server","client_nonce_echo":123}`))
	require.NoError(t, err)
	var hs HelloServer
	_, err = readBodyAs(&buf, FrameTypeHelloServer, &hs)
	require.Error(t, err)
}

// scriptedServer accepts one connection and hands it to the script; the
// client under test dials it. Deadlines keep a wrong script from hanging.
func scriptedServer(t *testing.T, script func(conn net.Conn)) net.Conn {
	t.Helper()
	lis := listenLoopback(t)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		_ = c.SetDeadline(time.Now().Add(testHandshakeTimeout))
		script(c)
		_ = c.Close()
	}()
	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	_ = dialed.SetDeadline(time.Now().Add(testHandshakeTimeout))
	t.Cleanup(func() { _ = dialed.Close() })
	return dialed
}

func readErrorFrame(t *testing.T, conn net.Conn) ErrorFrame {
	t.Helper()
	f, err := ReadFrame(conn)
	require.NoError(t, err)
	var ef ErrorFrame
	require.NoError(t, DecodeBody(f.Payload, &ef))
	require.Equal(t, FrameTypeError, ef.Type)
	return ef
}

func TestClientHandshake_NonceSourceFailure(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	got := make(chan ErrorFrame, 1)
	conn := scriptedServer(t, func(c net.Conn) { got <- readErrorFrame(t, c) })
	_, err := DoHandshake(HandshakeConfig{Role: RoleClient, Conn: conn, Producer: peers.clientProducer,
		Verifier: peers.clientVerifier, NonceReader: failingReader{}})
	require.Error(t, err)
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	ef := <-got
	require.Equal(t, CodeHandshakeFailure, ef.Envelope.Code, "the peer is told")
}

func TestClientHandshake_EchoMismatch(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	got := make(chan ErrorFrame, 1)
	conn := scriptedServer(t, func(c net.Conn) {
		var hc HelloClient
		_, err := readBodyAs(c, FrameTypeHelloClient, &hc)
		require.NoError(t, err)
		wrongEcho := bytes.Repeat([]byte{0xEE}, NonceMinBytes)
		hs, err := NewHelloServer(wrongEcho, nonceOf(0x33), []byte("evidence"), []byte("ctx"))
		require.NoError(t, err)
		require.NoError(t, writeBody(c, hs))
		got <- readErrorFrame(t, c)
	})
	_, err := DoHandshake(HandshakeConfig{Role: RoleClient, Conn: conn, Producer: peers.clientProducer, Verifier: peers.clientVerifier})
	require.Error(t, err)
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Contains(t, err.Error(), "ClientNonceEcho")
	require.Equal(t, CodeHandshakeFailure, (<-got).Envelope.Code)
}

func TestClientHandshake_WrongPhaseFrame(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	conn := scriptedServer(t, func(c net.Conn) {
		var hc HelloClient
		_, err := readBodyAs(c, FrameTypeHelloClient, &hc)
		require.NoError(t, err)
		require.NoError(t, writeBody(c, NewHeartbeat(time.Now())))
	})
	_, err := DoHandshake(HandshakeConfig{Role: RoleClient, Conn: conn, Producer: peers.clientProducer, Verifier: peers.clientVerifier})
	require.Error(t, err)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
}

func TestClientHandshake_ServerEvidenceRejected(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	// A verifier pinned to a different attestor: the server's genuine
	// evidence does not verify, and the client refuses with the peer told.
	otherSeed := bytes.Repeat([]byte{0x44}, crypto.Ed25519SeedSize)
	other, err := tee.NewSimulated([]byte("someone-else"), otherSeed)
	require.NoError(t, err)
	lis := listenLoopback(t)
	serverErr := make(chan error, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(testHandshakeTimeout))
		_, herr := DoHandshake(HandshakeConfig{Role: RoleServer, Conn: c, Producer: peers.serverProducer, Verifier: peers.serverVerifier})
		serverErr <- herr
	}()
	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	defer func() { _ = dialed.Close() }()
	_ = dialed.SetDeadline(time.Now().Add(testHandshakeTimeout))
	_, cerr := DoHandshake(HandshakeConfig{Role: RoleClient, Conn: dialed, Producer: peers.clientProducer,
		Verifier: tee.NewSimulatedVerifier(other.PublicKey(), other.Measurement())})
	require.Error(t, cerr)
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(cerr))
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(cerr))
	require.Contains(t, cerr.Error(), "server TEE evidence verification failed")
	serr := <-serverErr
	require.Error(t, serr, "the server, waiting for AttestClient, reads the client's error frame instead")
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(serr))
}

func TestClientHandshake_OwnQuoteFails(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	lis := listenLoopback(t)
	serverErr := make(chan error, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(testHandshakeTimeout))
		_, herr := DoHandshake(HandshakeConfig{Role: RoleServer, Conn: c, Producer: peers.serverProducer, Verifier: peers.serverVerifier})
		serverErr <- herr
	}()
	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	defer func() { _ = dialed.Close() }()
	_ = dialed.SetDeadline(time.Now().Add(testHandshakeTimeout))
	_, cerr := DoHandshake(HandshakeConfig{Role: RoleClient, Conn: dialed,
		Producer: failingProducer{m: peers.clientProducer.Measurement()}, Verifier: peers.clientVerifier})
	require.Error(t, cerr)
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(cerr))
	require.Contains(t, cerr.Error(), "client TEE quote generation failed")
	require.Error(t, <-serverErr)
}

func TestServerHandshake_OwnQuoteFails(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	clientSide, serverSide := net.Pipe()
	defer func() { _ = clientSide.Close(); _ = serverSide.Close() }()
	serverErr := make(chan error, 1)
	go func() {
		_, herr := DoHandshake(HandshakeConfig{Role: RoleServer, Conn: serverSide,
			Producer: failingProducer{m: peers.serverProducer.Measurement()}, Verifier: peers.serverVerifier})
		serverErr <- herr
	}()
	hc := mustHelloClient(t, time.Now())
	require.NoError(t, writeBody(clientSide, hc))
	ef := readErrorFrame(t, clientSide)
	require.Equal(t, CodeHandshakeFailure, ef.Envelope.Code)
	serr := <-serverErr
	require.Error(t, serr)
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(serr))
	require.Contains(t, serr.Error(), "server TEE quote generation failed")
}

func TestServerHandshake_NonceSourceFailure(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	clientSide, serverSide := net.Pipe()
	defer func() { _ = clientSide.Close(); _ = serverSide.Close() }()
	serverErr := make(chan error, 1)
	go func() {
		_, herr := DoHandshake(HandshakeConfig{Role: RoleServer, Conn: serverSide, Producer: peers.serverProducer,
			Verifier: peers.serverVerifier, NonceReader: failingReader{}})
		serverErr <- herr
	}()
	require.NoError(t, writeBody(clientSide, mustHelloClient(t, time.Now())))
	ef := readErrorFrame(t, clientSide)
	require.Equal(t, CodeHandshakeFailure, ef.Envelope.Code)
	serr := <-serverErr
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(serr))
}

func TestServerHandshake_ClientEvidenceRejected(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	otherSeed := bytes.Repeat([]byte{0x55}, crypto.Ed25519SeedSize)
	other, err := tee.NewSimulated([]byte("someone-else"), otherSeed)
	require.NoError(t, err)
	lis := listenLoopback(t)
	serverErr := make(chan error, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(testHandshakeTimeout))
		// The server expects someone else's measurement: the client's
		// genuine evidence is refused at the AttestClient phase.
		_, herr := DoHandshake(HandshakeConfig{Role: RoleServer, Conn: c, Producer: peers.serverProducer,
			Verifier: tee.NewSimulatedVerifier(other.PublicKey(), other.Measurement())})
		serverErr <- herr
	}()
	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	defer func() { _ = dialed.Close() }()
	_ = dialed.SetDeadline(time.Now().Add(testHandshakeTimeout))
	_, cerr := DoHandshake(HandshakeConfig{Role: RoleClient, Conn: dialed, Producer: peers.clientProducer, Verifier: peers.clientVerifier})
	require.Error(t, cerr, "the client, waiting for SessionReady, reads the refusal")
	require.Equal(t, CodeHandshakeFailure, shared_errors.CodeOf(cerr))
	serr := <-serverErr
	require.Error(t, serr)
	require.Contains(t, serr.Error(), "client TEE evidence verification failed")
}

func TestServerHandshake_WrongPhaseFrameFromClient(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	clientSide, serverSide := net.Pipe()
	defer func() { _ = clientSide.Close(); _ = serverSide.Close() }()
	serverErr := make(chan error, 1)
	go func() {
		_, herr := DoHandshake(HandshakeConfig{Role: RoleServer, Conn: serverSide, Producer: peers.serverProducer, Verifier: peers.serverVerifier})
		serverErr <- herr
	}()
	require.NoError(t, writeBody(clientSide, NewHeartbeat(time.Now())))
	serr := <-serverErr
	require.Error(t, serr)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(serr))
}

func TestServerHandshake_UsesTheGivenDerivationContext(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	ctx := []byte("operator-named-context")
	c, s, cs, ss := runLoopbackHandshake(t, peers, func(cfg *HandshakeConfig) {
		if cfg.Role == RoleServer {
			cfg.DerivationContext = ctx
		}
	})
	defer func() { _ = c.Close(); _ = s.Close() }()
	require.Equal(t, ctx, ss.Transcript.DerivationContext)
	require.Equal(t, ctx, cs.Transcript.DerivationContext, "the client learns it from HelloServer")
	require.Equal(t, cs.TxKey, ss.RxKey)
	require.Equal(t, cs.RxKey, ss.TxKey)
}

var _ io.Reader = failingReader{}
