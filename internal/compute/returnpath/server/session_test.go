// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

const testTimeout = 5 * time.Second

// peers holds the vault side's TEE and the worker side's TEE and
// signing key, mutually trusting, so a test can play the worker from a
// raw transport connection.
type peers struct {
	clientProducer *tee.Simulated
	serverProducer *tee.Simulated
	clientVerifier *tee.SimulatedVerifier
	serverVerifier *tee.SimulatedVerifier

	workerStore *keys.InMemoryStore
	workerKID   ids.KeyID
	workerVK    keys.VerifyingKey
	resolver    *PublicKeyResolver

	clock *shared_time.FakeClock
}

func newPeers(t *testing.T) *peers {
	t.Helper()
	cp, err := tee.NewSimulated([]byte("acp-compute-worker-v1-server-test"), bytes.Repeat([]byte{0x11}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	sp, err := tee.NewSimulated([]byte("sagvd-returnpath-v1-server-test"), bytes.Repeat([]byte{0x22}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	clock := shared_time.NewFakeClock(time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC))
	workerStore := keys.NewInMemoryStore(clock)
	kid := ids.KeyID("worker-output-signer")
	vk, err := workerStore.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	resolver := NewPublicKeyResolver(nil)
	require.NoError(t, resolver.Register(kid, vk))
	return &peers{
		clientProducer: cp,
		serverProducer: sp,
		clientVerifier: tee.NewSimulatedVerifier(sp.PublicKey(), sp.Measurement()),
		serverVerifier: tee.NewSimulatedVerifier(cp.PublicKey(), cp.Measurement()),
		workerStore:    workerStore,
		workerKID:      kid,
		workerVK:       vk,
		resolver:       resolver,
		clock:          clock,
	}
}

// loopbackPair is a connected TCP pair on loopback.
func loopbackPair(t *testing.T) (clientConn, serverConn net.Conn) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	clientConn, err = net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	serverConn = <-accepted
	require.NotNil(t, serverConn)
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	return clientConn, serverConn
}

// rawWorker completes the worker side of the handshake on conn and
// returns the MAC-authenticated connection. It runs on a goroutine, so
// it reports rather than fails.
func rawWorker(p *peers, conn net.Conn) (*transport.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		return nil, err
	}
	state, err := transport.DoHandshake(transport.HandshakeConfig{
		Role: transport.RoleClient, Conn: conn, Producer: p.clientProducer, Verifier: p.clientVerifier,
		Clock: p.clock, ProposedChallenge: []byte("server-test-challenge"),
	})
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		return nil, err
	}
	return transport.WrapConn(conn, state)
}

func serverConfig(p *peers, conn net.Conn) SessionConfig {
	return SessionConfig{
		Conn: conn, Producer: p.serverProducer, Verifier: p.serverVerifier, Clock: p.clock,
		WorkerKeyResolver: p.resolver, HandshakeTimeout: testTimeout,
	}
}

// jobRequest is a wire-valid job. The server never opens the sealed
// material, so its contents only need to pass validation.
func jobRequest(p *peers) transport.JobRequest {
	issued := p.clock.Now().UTC()
	return transport.JobRequest{
		Type: transport.FrameTypeJobRequest, SchemaVersion: 1,
		ManifestID: "manifest-server-test-1", SessionID: "session-server-test-1",
		ExpectedOutputKind: string(rjm.OutputKindBytesFixedLength), ExpectedOutputMaxBytes: 64,
		Deadline: issued.Add(30 * time.Second), IssuedAt: issued,
		SealedMaterial: []transport.SealedMaterialRef{{RecipientKeyID: "recipient-1", Nonce: []byte("nonce-bytes!"), Ciphertext: []byte("ciphertext")}},
	}
}

func acceptFor(p *peers, req transport.JobRequest) transport.JobAccept {
	return transport.JobAccept{Type: transport.FrameTypeJobAccept, ManifestID: req.ManifestID, AcceptedAt: p.clock.Now().UTC(), EstimatedDuration: time.Second}
}

// signedOutput is a candidate output for req, signed under the worker's
// key, which the server's resolver holds.
func signedOutput(t *testing.T, p *peers, req transport.JobRequest, out []byte) transport.CandidateOutputFrame {
	t.Helper()
	f := transport.CandidateOutputFrame{
		Type: transport.FrameTypeCandidateOutput, ManifestID: req.ManifestID, SessionID: req.SessionID,
		OutputKind: req.ExpectedOutputKind, Bytes: out, ProducedAt: p.clock.Now().UTC(),
		WorkerSigningKeyID: string(p.workerKID),
	}
	cover, err := f.CoverBytes()
	require.NoError(t, err)
	sig, err := p.workerStore.Sign(p.workerKID, keys.PurposeSigningAuthority, cover)
	require.NoError(t, err)
	f.WorkerSignature = sig
	return f
}

// worker runs script as the worker on clientConn after the handshake and
// reports its outcome on the returned channel. readJob, when set, reads
// the JobRequest the server opens with before the script runs.
func worker(p *peers, clientConn net.Conn, readJob bool, script func(c *transport.Conn) error) <-chan error {
	done := make(chan error, 1)
	go func() {
		c, err := rawWorker(p, clientConn)
		if err != nil {
			done <- err
			return
		}
		if readJob {
			typ, _, err := c.Read()
			if err != nil {
				done <- err
				return
			}
			if typ != transport.FrameTypeJobRequest {
				done <- errors.New("the vault opened with " + string(typ))
				return
			}
		}
		done <- script(c)
	}()
	return done
}

func requireClassified(t *testing.T, err error, cat shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, cat, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// --- configuration ---------------------------------------------------------

// TestSessionConfig_Defaults proves the optional fields get their
// documented defaults and that values the caller set are kept.
func TestSessionConfig_Defaults(t *testing.T) {
	t.Parallel()
	var c SessionConfig
	c.defaults()
	require.NotNil(t, c.Clock)
	require.Equal(t, 10*time.Second, c.HandshakeTimeout)
	require.Equal(t, keys.PurposeSigningAuthority, c.WorkerKeyPurpose)

	clock := shared_time.NewFakeClock(time.Unix(0, 0))
	set := SessionConfig{Clock: clock, HandshakeTimeout: time.Minute, WorkerKeyPurpose: keys.PurposeSigningWitness}
	set.defaults()
	require.Same(t, clock, set.Clock)
	require.Equal(t, time.Minute, set.HandshakeTimeout)
	require.Equal(t, keys.PurposeSigningWitness, set.WorkerKeyPurpose)
}

// TestAccept_RefusesIncompleteConfig proves every mandatory field is
// checked before a byte is read, naming the field.
func TestAccept_RefusesIncompleteConfig(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	_, serverConn := loopbackPair(t)
	cases := map[string]func(*SessionConfig){
		"Conn":              func(c *SessionConfig) { c.Conn = nil },
		"Producer":          func(c *SessionConfig) { c.Producer = nil },
		"Verifier":          func(c *SessionConfig) { c.Verifier = nil },
		"WorkerKeyResolver": func(c *SessionConfig) { c.WorkerKeyResolver = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := serverConfig(p, serverConn)
			mutate(&cfg)
			sess, err := Accept(cfg)
			require.Nil(t, sess)
			requireClassified(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
			require.ErrorContains(t, err, name)
		})
	}
}

// noDeadlineConn is a connection that cannot bound the handshake.
type noDeadlineConn struct{ net.Conn }

var errNoDeadline = errors.New("deadlines unsupported")

func (noDeadlineConn) SetDeadline(time.Time) error { return errNoDeadline }

// TestAccept_RefusesAConnectionWithoutDeadlines proves a handshake that
// cannot be bounded in time is not attempted.
func TestAccept_RefusesAConnectionWithoutDeadlines(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	sess, err := Accept(serverConfig(p, noDeadlineConn{Conn: b}))
	require.Nil(t, sess)
	requireClassified(t, err, shared_errors.CategoryOperational, transport.CodeDeadlineExceeded)
	require.ErrorIs(t, err, errNoDeadline)
}

// TestAccept_HandshakeRefusals proves a handshake the worker cannot
// complete is refused with the transport's classification and that the
// connection is handed back open for the caller to close.
func TestAccept_HandshakeRefusals(t *testing.T) {
	t.Parallel()
	t.Run("unsupported wire version", func(t *testing.T) {
		t.Parallel()
		p := newPeers(t)
		clientConn, serverConn := loopbackPair(t)
		sent := make(chan error, 1)
		go func() {
			hello, err := transport.NewHelloClient(bytes.Repeat([]byte{7}, transport.NonceMinBytes), nil)
			if err != nil {
				sent <- err
				return
			}
			hello.WireMajor++
			body, err := transport.EncodeBody(hello)
			if err != nil {
				sent <- err
				return
			}
			_, err = transport.WriteFrame(clientConn, body)
			sent <- err
		}()
		sess, err := Accept(serverConfig(p, serverConn))
		require.Nil(t, sess)
		requireClassified(t, err, shared_errors.CategoryStructural, transport.CodeUnsupportedWireVersion)
		require.NoError(t, <-sent)
		require.NoError(t, serverConn.SetDeadline(time.Time{}), "the connection is left open for the caller")
	})
	t.Run("worker hangs up", func(t *testing.T) {
		t.Parallel()
		p := newPeers(t)
		clientConn, serverConn := loopbackPair(t)
		require.NoError(t, clientConn.Close())
		sess, err := Accept(serverConfig(p, serverConn))
		require.Nil(t, sess)
		require.ErrorIs(t, err, transport.ErrWireClosed)
	})
}

// --- the job cycle ---------------------------------------------------------

// TestServeOneJob_HappyPath proves one full cycle from the vault's side:
// the job goes out, heartbeats on the way are skipped, the accept and
// the signed output come back, the output is verified under the
// worker's key, and the hooks see the session open and close with the
// shutdown reason.
func TestServeOneJob_HappyPath(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	req := jobRequest(p)
	out := signedOutput(t, p, req, []byte("reconstructed-bytes"))
	clientConn, serverConn := loopbackPair(t)
	done := worker(p, clientConn, true, func(c *transport.Conn) error {
		for _, f := range []any{transport.NewHeartbeat(time.Now()), acceptFor(p, req), transport.NewHeartbeat(time.Now()), out} {
			if err := c.Write(f); err != nil {
				return err
			}
		}
		typ, _, err := c.Read()
		if err != nil {
			return err
		}
		if typ != transport.FrameTypeShutdown {
			return errors.New("expected a shutdown, got " + string(typ))
		}
		return nil
	})

	var opened *transport.SessionState
	var closedWith []string
	cfg := serverConfig(p, serverConn)
	cfg.OnSessionOpened = func(s *transport.SessionState) { opened = s }
	cfg.OnSessionClosed = func(reason string) { closedWith = append(closedWith, reason) }
	sess, err := Accept(cfg)
	require.NoError(t, err)
	require.NotNil(t, opened)
	require.Same(t, opened, sess.State())

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	v, err := sess.ServeOneJobVerified(ctx, req)
	require.NoError(t, err)
	require.Equal(t, p.workerKID, v.WorkerSigningKeyID)
	require.Equal(t, ids.ManifestID(req.ManifestID), v.Output.ManifestID)
	require.Equal(t, ids.SessionID(req.SessionID), v.Output.SessionID)
	require.Equal(t, rjm.OutputKindBytesFixedLength, v.Output.OutputKind)
	require.Equal(t, out.Bytes, v.Output.Bytes)
	require.True(t, out.ProducedAt.Equal(v.Output.ProducedAt), "ProducedAt survives the wire")

	require.NoError(t, sess.WriteShutdown(transport.CodeShutdownNormal, "done"))
	require.NoError(t, <-done)
	require.NoError(t, sess.Close())
	require.NoError(t, sess.Close(), "a second Close is a no-op")
	require.Equal(t, []string{transport.CodeShutdownNormal}, closedWith)
	require.NoError(t, sess.WriteShutdown("late", "ignored"), "a shutdown after Close writes nothing")
	require.Equal(t, []string{transport.CodeShutdownNormal}, closedWith)
}

// TestServeOneJob_CloseWithoutShutdownReportsNoReason proves the close
// hook sees an empty reason when no Shutdown frame preceded Close, and
// that a closed session refuses further jobs.
func TestServeOneJob_CloseWithoutShutdownReportsNoReason(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	clientConn, serverConn := loopbackPair(t)
	done := worker(p, clientConn, false, func(*transport.Conn) error { return nil })
	var reasons []string
	cfg := serverConfig(p, serverConn)
	cfg.OnSessionClosed = func(reason string) { reasons = append(reasons, reason) }
	sess, err := Accept(cfg)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.NoError(t, sess.Close())
	require.Equal(t, []string{""}, reasons)

	_, err = sess.ServeOneJob(context.Background(), jobRequest(p))
	requireClassified(t, err, shared_errors.CategoryStructural, transport.CodeProtocolViolation)
	require.ErrorContains(t, err, "closed Session")
}

// TestServeOneJob_RefusedBeforeAnyIO proves the checks that run before
// the job is written: a finished context, an invalid request, and a
// connection that is already dead.
func TestServeOneJob_RefusedBeforeAnyIO(t *testing.T) {
	t.Parallel()
	t.Run("context already done", func(t *testing.T) {
		t.Parallel()
		p := newPeers(t)
		clientConn, serverConn := loopbackPair(t)
		done := worker(p, clientConn, false, func(*transport.Conn) error { return nil })
		sess, err := Accept(serverConfig(p, serverConn))
		require.NoError(t, err)
		require.NoError(t, <-done)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = sess.ServeOneJob(ctx, jobRequest(p))
		requireClassified(t, err, shared_errors.CategoryOperational, CodeContextCancelled)
		require.ErrorIs(t, err, context.Canceled)
	})
	t.Run("invalid request", func(t *testing.T) {
		t.Parallel()
		p := newPeers(t)
		clientConn, serverConn := loopbackPair(t)
		done := worker(p, clientConn, false, func(*transport.Conn) error { return nil })
		sess, err := Accept(serverConfig(p, serverConn))
		require.NoError(t, err)
		require.NoError(t, <-done)
		req := jobRequest(p)
		req.SchemaVersion = 2
		_, err = sess.ServeOneJob(context.Background(), req)
		requireClassified(t, err, shared_errors.CategoryStructural, transport.CodeProtocolViolation)
		require.ErrorContains(t, err, "schema_version")
	})
	t.Run("connection already closed", func(t *testing.T) {
		t.Parallel()
		p := newPeers(t)
		clientConn, serverConn := loopbackPair(t)
		done := worker(p, clientConn, false, func(*transport.Conn) error { return nil })
		sess, err := Accept(serverConfig(p, serverConn))
		require.NoError(t, err)
		require.NoError(t, <-done)
		require.NoError(t, serverConn.Close())
		_, err = sess.ServeOneJob(context.Background(), jobRequest(p))
		require.ErrorIs(t, err, net.ErrClosed)
	})
}

// TestServeOneJob_ContextCancelledWhileWaiting proves cancellation is
// noticed between frames in both waiting phases. The worker cancels the
// context between two heartbeats, so by the time the second heartbeat
// has been read the cancellation is certainly visible.
func TestServeOneJob_ContextCancelledWhileWaiting(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		accept bool
		msg    string
	}{
		"before the accept": {accept: false, msg: "awaiting JobAccept/JobReject"},
		"before the output": {accept: true, msg: "awaiting CandidateOutputFrame"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newPeers(t)
			req := jobRequest(p)
			clientConn, serverConn := loopbackPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := worker(p, clientConn, true, func(c *transport.Conn) error {
				if tc.accept {
					if err := c.Write(acceptFor(p, req)); err != nil {
						return err
					}
				}
				if err := c.Write(transport.NewHeartbeat(time.Now())); err != nil {
					return err
				}
				cancel()
				return c.Write(transport.NewHeartbeat(time.Now()))
			})
			sess, err := Accept(serverConfig(p, serverConn))
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			_, err = sess.ServeOneJob(ctx, req)
			requireClassified(t, err, shared_errors.CategoryOperational, CodeContextCancelled)
			require.ErrorContains(t, err, tc.msg)
			require.NoError(t, <-done)
		})
	}
}

// TestServeOneJob_WorkerHangsUp proves a worker that closes the
// connection, before or after accepting, is reported as a closed wire
// rather than as a protocol error.
func TestServeOneJob_WorkerHangsUp(t *testing.T) {
	t.Parallel()
	for name, accept := range map[string]bool{"before the accept": false, "after the accept": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newPeers(t)
			req := jobRequest(p)
			clientConn, serverConn := loopbackPair(t)
			done := worker(p, clientConn, true, func(c *transport.Conn) error {
				if accept {
					if err := c.Write(acceptFor(p, req)); err != nil {
						return err
					}
				}
				return c.Close()
			})
			sess, err := Accept(serverConfig(p, serverConn))
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			_, err = sess.ServeOneJob(ctx, req)
			require.ErrorIs(t, err, transport.ErrWireClosed)
			require.NoError(t, <-done)
		})
	}
}

// TestServeOneJob_RefusesWhatTheWorkerMayNotSend pins the category and
// code for every frame the vault refuses while waiting for the accept
// and while waiting for the output: rejects, mismatched accepts,
// malformed or invalid bodies, error envelopes, shutdowns and frames
// of the wrong type.
func TestServeOneJob_RefusesWhatTheWorkerMayNotSend(t *testing.T) {
	t.Parallel()
	type typed struct {
		Type       transport.FrameType `json:"type"`
		ManifestID int                 `json:"manifest_id"`
	}
	type typedEnvelope struct {
		Type     transport.FrameType `json:"type"`
		Envelope string              `json:"envelope"`
	}
	type typedBytes struct {
		Type  transport.FrameType `json:"type"`
		Bytes int                 `json:"bytes"`
	}
	cases := map[string]struct {
		accept bool
		frame  func(t *testing.T, p *peers, req transport.JobRequest) any
		cat    shared_errors.Category
		code   string
		msg    string
	}{
		"a reject": {
			frame: func(_ *testing.T, p *peers, req transport.JobRequest) any {
				return transport.JobReject{Type: transport.FrameTypeJobReject, ManifestID: req.ManifestID, RejectedAt: p.clock.Now().UTC(), Reason: "no_capacity", HumanMessage: "busy"}
			},
			cat: shared_errors.CategoryAuthority, code: CodeWorkerRejected, msg: "no_capacity",
		},
		"an accept for another manifest": {
			frame: func(_ *testing.T, p *peers, req transport.JobRequest) any {
				a := acceptFor(p, req)
				a.ManifestID = "another-manifest"
				return a
			},
			cat: shared_errors.CategoryAuthority, code: CodeManifestMismatch,
		},
		"an accept that does not decode": {
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return typed{Type: transport.FrameTypeJobAccept, ManifestID: 7}
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "decode",
		},
		"an accept without an estimate": {
			frame: func(_ *testing.T, p *peers, req transport.JobRequest) any {
				a := acceptFor(p, req)
				a.EstimatedDuration = 0
				return a
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "estimated_duration",
		},
		"a reject that does not decode": {
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return typed{Type: transport.FrameTypeJobReject, ManifestID: 7}
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "decode",
		},
		"a reject without a reason": {
			frame: func(_ *testing.T, p *peers, req transport.JobRequest) any {
				return transport.JobReject{Type: transport.FrameTypeJobReject, ManifestID: req.ManifestID, RejectedAt: p.clock.Now().UTC()}
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "reason required",
		},
		"an error envelope": {
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return transport.NewErrorFrame(transport.NewErrorEnvelope(shared_errors.Integrity("frame_mac", "bad MAC", nil), ""))
			},
			cat: shared_errors.CategoryIntegrity, code: "frame_mac",
		},
		"an error envelope that does not decode": {
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return typedEnvelope{Type: transport.FrameTypeError, Envelope: "x"}
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "decode",
		},
		"a shutdown instead of an answer": {
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return transport.NewShutdown(time.Now(), transport.CodeShutdownNormal, "bye")
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "unexpected frame type while awaiting JobAccept",
		},
		"an output before the accept": {
			frame: func(t *testing.T, p *peers, req transport.JobRequest) any {
				return signedOutput(t, p, req, []byte("early"))
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "unexpected frame type while awaiting JobAccept",
		},
		"after the accept, a shutdown": {
			accept: true,
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return transport.NewShutdown(time.Now(), transport.CodeShutdownNormal, "gave up")
			},
			cat: shared_errors.CategoryAuthority, code: transport.CodeHandshakeFailure, msg: "Shutdown before CandidateOutputFrame",
		},
		"after the accept, an error envelope": {
			accept: true,
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return transport.NewErrorFrame(transport.NewErrorEnvelope(shared_errors.Operational("worker_busy", "later", nil), ""))
			},
			cat: shared_errors.CategoryOperational, code: "worker_busy",
		},
		"after the accept, an error envelope that does not decode": {
			accept: true,
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return typedEnvelope{Type: transport.FrameTypeError, Envelope: "x"}
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "decode",
		},
		"after the accept, a second accept": {
			accept: true,
			frame:  func(_ *testing.T, p *peers, req transport.JobRequest) any { return acceptFor(p, req) },
			cat:    shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "unexpected frame type while awaiting CandidateOutputFrame",
		},
		"after the accept, an output that does not decode": {
			accept: true,
			frame: func(*testing.T, *peers, transport.JobRequest) any {
				return typedBytes{Type: transport.FrameTypeCandidateOutput, Bytes: 1}
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "decode",
		},
		"after the accept, an empty output": {
			accept: true,
			frame: func(t *testing.T, p *peers, req transport.JobRequest) any {
				f := signedOutput(t, p, req, []byte("x"))
				f.Bytes = nil
				return f
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation, msg: "bytes required",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newPeers(t)
			req := jobRequest(p)
			frame := tc.frame(t, p, req)
			clientConn, serverConn := loopbackPair(t)
			done := worker(p, clientConn, true, func(c *transport.Conn) error {
				if tc.accept {
					if err := c.Write(acceptFor(p, req)); err != nil {
						return err
					}
				}
				if err := c.Write(transport.NewHeartbeat(time.Now())); err != nil {
					return err
				}
				return c.Write(frame)
			})
			sess, err := Accept(serverConfig(p, serverConn))
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			_, err = sess.ServeOneJob(ctx, req)
			requireClassified(t, err, tc.cat, tc.code)
			if tc.msg != "" {
				require.ErrorContains(t, err, tc.msg)
			}
			require.NoError(t, <-done)
		})
	}
}

// TestServeOneJob_RefusesAnOutputItCannotTrust proves the checks on a
// well-formed output: it must be bound to the job, fit the manifest's
// size budget, and carry a signature that verifies under a key the
// resolver holds for the declared purpose. A signature failure also
// reaches the hook with the offending frame.
func TestServeOneJob_RefusesAnOutputItCannotTrust(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		frame    func(t *testing.T, p *peers, req transport.JobRequest) transport.CandidateOutputFrame
		resolver func(p *peers) keys.Resolver
		cat      shared_errors.Category
		code     string
		msg      string
		hook     bool
	}{
		"bound to another output kind": {
			frame: func(t *testing.T, p *peers, req transport.JobRequest) transport.CandidateOutputFrame {
				f := signedOutput(t, p, req, []byte("x"))
				f.OutputKind = "something_else"
				return f
			},
			cat: shared_errors.CategoryAuthority, code: CodeManifestMismatch, msg: "bindings",
		},
		"over the size budget": {
			frame: func(t *testing.T, p *peers, req transport.JobRequest) transport.CandidateOutputFrame {
				return signedOutput(t, p, req, bytes.Repeat([]byte{1}, int(req.ExpectedOutputMaxBytes)+1))
			},
			cat: shared_errors.CategoryAuthority, code: CodeManifestMismatch, msg: "ExpectedOutputMaxBytes",
		},
		"forged signature": {
			frame: func(t *testing.T, p *peers, req transport.JobRequest) transport.CandidateOutputFrame {
				f := signedOutput(t, p, req, []byte("x"))
				f.WorkerSignature[0] ^= 0xFF
				return f
			},
			cat: shared_errors.CategoryIntegrity, code: CodeWorkerSignatureInvalid, msg: "verification failed", hook: true,
		},
		"signing key the vault does not hold": {
			frame: func(t *testing.T, p *peers, req transport.JobRequest) transport.CandidateOutputFrame {
				f := signedOutput(t, p, req, []byte("x"))
				f.WorkerSigningKeyID = "worker-unknown"
				return f
			},
			cat: shared_errors.CategoryIntegrity, code: CodeWorkerSignatureInvalid, msg: "resolver", hook: true,
		},
		"signing key held for another purpose": {
			frame: func(t *testing.T, p *peers, req transport.JobRequest) transport.CandidateOutputFrame {
				return signedOutput(t, p, req, []byte("x"))
			},
			resolver: func(p *peers) keys.Resolver {
				vk := p.workerVK
				vk.Purpose = keys.PurposeSigningAudit
				return NewPublicKeyResolver(map[ids.KeyID]keys.VerifyingKey{p.workerKID: vk})
			},
			cat: shared_errors.CategoryIntegrity, code: CodeWorkerSignatureInvalid, msg: "resolver", hook: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newPeers(t)
			req := jobRequest(p)
			frame := tc.frame(t, p, req)
			clientConn, serverConn := loopbackPair(t)
			done := worker(p, clientConn, true, func(c *transport.Conn) error {
				if err := c.Write(acceptFor(p, req)); err != nil {
					return err
				}
				return c.Write(frame)
			})
			cfg := serverConfig(p, serverConn)
			if tc.resolver != nil {
				cfg.WorkerKeyResolver = tc.resolver(p)
			}
			var hooked []transport.CandidateOutputFrame
			var hookedErr error
			cfg.OnWorkerSignatureFailure = func(f transport.CandidateOutputFrame, err error) {
				hooked = append(hooked, f)
				hookedErr = err
			}
			sess, err := Accept(cfg)
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			v, err := sess.ServeOneJobVerified(ctx, req)
			requireClassified(t, err, tc.cat, tc.code)
			require.ErrorContains(t, err, tc.msg)
			require.Empty(t, v.WorkerSigningKeyID)
			require.Nil(t, v.Output.Bytes)
			if tc.hook {
				require.Len(t, hooked, 1)
				require.Equal(t, frame.WorkerSignature, hooked[0].WorkerSignature)
				require.Equal(t, err, hookedErr)
			} else {
				require.Empty(t, hooked)
			}
			require.NoError(t, <-done)
		})
	}
}

// TestVerifyWorkerSignature_EmptyKeyID proves the verifier's own guard
// against a frame with no signing key, which the frame validator keeps
// from the wire but the verifier still refuses on its own.
func TestVerifyWorkerSignature_EmptyKeyID(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	s := &Session{cfg: SessionConfig{WorkerKeyResolver: p.resolver, WorkerKeyPurpose: keys.PurposeSigningAuthority}}
	f := signedOutput(t, p, jobRequest(p), []byte("x"))
	f.WorkerSigningKeyID = ""
	err := s.verifyWorkerSignature(f)
	requireClassified(t, err, shared_errors.CategoryIntegrity, CodeWorkerSignatureInvalid)
	require.ErrorContains(t, err, "WorkerSigningKeyID empty")
}

// TestServeOneJob_BadMACReachesTheIntegrityHook proves a frame whose
// MAC does not verify is refused as an integrity failure and reported
// to the integrity hook before the refusal is returned.
func TestServeOneJob_BadMACReachesTheIntegrityHook(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	req := jobRequest(p)
	clientConn, serverConn := loopbackPair(t)
	done := worker(p, clientConn, true, func(*transport.Conn) error {
		body, err := transport.EncodeBody(acceptFor(p, req))
		if err != nil {
			return err
		}
		_, err = transport.WriteFrame(clientConn, append(body, make([]byte, transport.MACSize)...))
		return err
	})
	var hooked []error
	cfg := serverConfig(p, serverConn)
	cfg.OnIntegrityFailure = func(err error) { hooked = append(hooked, err) }
	sess, err := Accept(cfg)
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	_, err = sess.ServeOneJob(ctx, req)
	requireClassified(t, err, shared_errors.CategoryIntegrity, transport.CodeIntegrityFailure)
	require.Len(t, hooked, 1)
	require.Equal(t, err, hooked[0])
	require.NoError(t, <-done)
}
