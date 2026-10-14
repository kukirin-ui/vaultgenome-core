// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

const testTimeout = 5 * time.Second

// peers holds the worker side's TEE, signing key and sealing key and
// the vault side's TEE, mutually trusting, so a test can play the vault
// from a raw transport connection.
type peers struct {
	clientProducer *tee.Simulated
	serverProducer *tee.Simulated
	clientVerifier *tee.SimulatedVerifier
	serverVerifier *tee.SimulatedVerifier

	workerStore  *keys.InMemoryStore
	workerKID    ids.KeyID
	workerVK     keys.VerifyingKey
	sealingStore *keys.InMemoryStore
	recipientKID ids.KeyID

	clock *shared_time.FakeClock
}

func newPeers(t *testing.T) *peers {
	t.Helper()
	cp, err := tee.NewSimulated([]byte("acp-compute-worker-v1-client-test"), bytes.Repeat([]byte{0x11}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	sp, err := tee.NewSimulated([]byte("sagvd-returnpath-v1-client-test"), bytes.Repeat([]byte{0x22}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	clock := shared_time.NewFakeClock(time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC))
	workerStore := keys.NewInMemoryStore(clock)
	kid := ids.KeyID("worker-output-signer")
	vk, err := workerStore.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	sealingStore := keys.NewInMemoryStore(clock)
	recipient := ids.KeyID("session-recipient-sealing")
	require.NoError(t, sealingStore.GenerateSealing(recipient))
	return &peers{
		clientProducer: cp,
		serverProducer: sp,
		clientVerifier: tee.NewSimulatedVerifier(sp.PublicKey(), sp.Measurement()),
		serverVerifier: tee.NewSimulatedVerifier(cp.PublicKey(), cp.Measurement()),
		workerStore:    workerStore,
		workerKID:      kid,
		workerVK:       vk,
		sealingStore:   sealingStore,
		recipientKID:   recipient,
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

// rawVault completes the vault side of the handshake on conn and returns
// the MAC-authenticated connection. It runs on a goroutine, so it
// reports rather than fails.
func rawVault(p *peers, conn net.Conn) (*transport.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		return nil, err
	}
	state, err := transport.DoHandshake(transport.HandshakeConfig{
		Role: transport.RoleServer, Conn: conn, Producer: p.serverProducer, Verifier: p.serverVerifier, Clock: p.clock,
	})
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		return nil, err
	}
	return transport.WrapConn(conn, state)
}

// vault runs script as the vault on serverConn after the handshake and
// reports its outcome on the returned channel.
func vault(p *peers, serverConn net.Conn, script func(c *transport.Conn) error) <-chan error {
	done := make(chan error, 1)
	go func() {
		c, err := rawVault(p, serverConn)
		if err != nil {
			done <- err
			return
		}
		done <- script(c)
	}()
	return done
}

func clientConfig(t *testing.T, p *peers, conn net.Conn) SessionConfig {
	t.Helper()
	recon, err := worker.NewDeterministicReconstructor(p.clock)
	require.NoError(t, err)
	return SessionConfig{
		Conn: conn, Producer: p.clientProducer, Verifier: p.clientVerifier, Clock: p.clock,
		Reconstructor: recon, Signer: p.workerStore, SigningKeyID: p.workerKID,
		Opener: KeyStoreOpener{Sealer: p.sealingStore}, ProposedChallenge: []byte("client-test-challenge"),
		HandshakeTimeout: testTimeout,
	}
}

// jobRequest seals each plaintext to the worker's recipient key, bound
// to the job and its slot, and wraps them in a wire-valid JobRequest.
func jobRequest(t *testing.T, p *peers, plaintexts ...[]byte) transport.JobRequest {
	t.Helper()
	const manifestID = "manifest-client-test-1"
	sealed := make([]transport.SealedMaterialRef, 0, len(plaintexts))
	for i, pt := range plaintexts {
		aad := append([]byte("rp-client-test-aad|"+manifestID+"|"), byte(i))
		nonce, ct, err := p.sealingStore.Seal(p.recipientKID, pt, aad)
		require.NoError(t, err)
		sealed = append(sealed, transport.SealedMaterialRef{RecipientKeyID: string(p.recipientKID), Nonce: nonce, Ciphertext: ct, AAD: aad})
	}
	issued := p.clock.Now().UTC()
	req := transport.JobRequest{
		Type: transport.FrameTypeJobRequest, SchemaVersion: 1, ManifestID: manifestID, SessionID: "session-client-test-1",
		ExpectedOutputKind: string(rjm.OutputKindBytesFixedLength), ExpectedOutputMaxBytes: 1024,
		Deadline: issued.Add(30 * time.Second), IssuedAt: issued, SealedMaterial: sealed,
	}
	require.NoError(t, req.Validate())
	return req
}

// referenceOutput is what the worker must produce for req: the same
// reconstructor over the same components, identified the way the
// session identifies them.
func referenceOutput(t *testing.T, p *peers, req transport.JobRequest, plaintexts ...[]byte) returnpath.CandidateOutput {
	t.Helper()
	recon, err := worker.NewDeterministicReconstructor(p.clock)
	require.NoError(t, err)
	comps := make([]worker.ComponentMaterial, 0, len(plaintexts))
	for i, pt := range plaintexts {
		comps = append(comps, worker.ComponentMaterial{ComponentID: materialComponentID(req.ManifestID, i), SequenceIndex: uint32(i), Plaintext: pt})
	}
	out, err := recon.Reconstruct(context.Background(), manifestFromJobRequest(req), comps)
	require.NoError(t, err)
	return out
}

func requireClassified(t *testing.T, err error, cat shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, cat, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// readAs reads one frame of the expected type into dst.
func readAs(c *transport.Conn, want transport.FrameType, dst any) error {
	typ, body, err := c.Read()
	if err != nil {
		return err
	}
	if typ != want {
		return errors.New("expected " + string(want) + ", got " + string(typ))
	}
	return transport.DecodeBody(body, dst)
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
	require.Equal(t, keys.PurposeSigningAuthority, c.SigningPurpose)

	clock := shared_time.NewFakeClock(time.Unix(0, 0))
	set := SessionConfig{Clock: clock, HandshakeTimeout: time.Minute, SigningPurpose: keys.PurposeSigningWitness}
	set.defaults()
	require.Same(t, clock, set.Clock)
	require.Equal(t, time.Minute, set.HandshakeTimeout)
	require.Equal(t, keys.PurposeSigningWitness, set.SigningPurpose)
}

// TestDial_RefusesIncompleteConfig proves every mandatory field is
// checked before a byte is sent, naming the field.
func TestDial_RefusesIncompleteConfig(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	clientConn, _ := loopbackPair(t)
	cases := map[string]func(*SessionConfig){
		"Conn":          func(c *SessionConfig) { c.Conn = nil },
		"Producer":      func(c *SessionConfig) { c.Producer = nil },
		"Verifier":      func(c *SessionConfig) { c.Verifier = nil },
		"Reconstructor": func(c *SessionConfig) { c.Reconstructor = nil },
		"Signer":        func(c *SessionConfig) { c.Signer = nil },
		"SigningKeyID":  func(c *SessionConfig) { c.SigningKeyID = "" },
		"Opener":        func(c *SessionConfig) { c.Opener = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := clientConfig(t, p, clientConn)
			mutate(&cfg)
			sess, err := Dial(cfg)
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

// TestDial_RefusesAConnectionWithoutDeadlines proves a handshake that
// cannot be bounded in time is not attempted.
func TestDial_RefusesAConnectionWithoutDeadlines(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	sess, err := Dial(clientConfig(t, p, noDeadlineConn{Conn: a}))
	require.Nil(t, sess)
	requireClassified(t, err, shared_errors.CategoryOperational, transport.CodeDeadlineExceeded)
	require.ErrorIs(t, err, errNoDeadline)
}

// TestDial_HandshakeRefused proves a vault that answers the hello with
// an error envelope has its refusal returned classified, and that the
// connection is handed back open for the caller to close.
func TestDial_HandshakeRefused(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	clientConn, serverConn := loopbackPair(t)
	answered := make(chan error, 1)
	go func() {
		if _, err := transport.ReadFrame(serverConn); err != nil {
			answered <- err
			return
		}
		refusal := shared_errors.Authority("policy_denied", "this worker is not admitted", nil)
		body, err := transport.EncodeBody(transport.NewErrorFrame(transport.NewErrorEnvelope(refusal, "")))
		if err != nil {
			answered <- err
			return
		}
		_, err = transport.WriteFrame(serverConn, body)
		answered <- err
	}()
	sess, err := Dial(clientConfig(t, p, clientConn))
	require.Nil(t, sess)
	requireClassified(t, err, shared_errors.CategoryAuthority, "policy_denied")
	require.NoError(t, <-answered)
	require.NoError(t, clientConn.SetDeadline(time.Time{}), "the connection is left open for the caller")
}

// --- the job cycle ---------------------------------------------------------

// TestServeOneJob_HappyPath proves one full cycle from the worker's
// side: heartbeats before the job are skipped, the accept carries the
// manifest and half the remaining budget, the hooks fire, and the
// output is the reference reconstruction signed under the worker's key.
func TestServeOneJob_HappyPath(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	plaintexts := [][]byte{[]byte("component-a"), []byte("component-b"), []byte("component-c")}
	req := jobRequest(t, p, plaintexts...)
	reference := referenceOutput(t, p, req, plaintexts...)
	clientConn, serverConn := loopbackPair(t)

	var gotAccept transport.JobAccept
	var gotOutput transport.CandidateOutputFrame
	done := vault(p, serverConn, func(c *transport.Conn) error {
		if err := c.Write(transport.NewHeartbeat(time.Now())); err != nil {
			return err
		}
		if err := c.Write(req); err != nil {
			return err
		}
		if err := readAs(c, transport.FrameTypeJobAccept, &gotAccept); err != nil {
			return err
		}
		return readAs(c, transport.FrameTypeCandidateOutput, &gotOutput)
	})

	var opened *transport.SessionState
	var hookedAccept []transport.JobAccept
	cfg := clientConfig(t, p, clientConn)
	cfg.OnSessionOpened = func(s *transport.SessionState) { opened = s }
	cfg.OnJobAccepted = func(a transport.JobAccept) { hookedAccept = append(hookedAccept, a) }
	sess, err := Dial(cfg)
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()
	require.NotNil(t, opened)
	require.Same(t, opened, sess.State())

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	require.NoError(t, sess.ServeOneJob(ctx))
	require.NoError(t, <-done)

	require.NoError(t, gotAccept.Validate())
	require.Equal(t, req.ManifestID, gotAccept.ManifestID)
	require.True(t, gotAccept.AcceptedAt.Equal(p.clock.Now()), "accepted at the worker clock's now")
	require.Equal(t, req.Deadline.Sub(p.clock.Now())/2, gotAccept.EstimatedDuration)
	require.Len(t, hookedAccept, 1)
	require.Equal(t, gotAccept.ManifestID, hookedAccept[0].ManifestID)
	require.Equal(t, gotAccept.EstimatedDuration, hookedAccept[0].EstimatedDuration)
	require.True(t, gotAccept.AcceptedAt.Equal(hookedAccept[0].AcceptedAt))

	require.NoError(t, gotOutput.Validate())
	require.Equal(t, req.ManifestID, gotOutput.ManifestID)
	require.Equal(t, req.SessionID, gotOutput.SessionID)
	require.Equal(t, req.ExpectedOutputKind, gotOutput.OutputKind)
	require.Equal(t, reference.Bytes, gotOutput.Bytes)
	require.True(t, reference.ProducedAt.Equal(gotOutput.ProducedAt), "ProducedAt comes from the worker clock")
	require.Equal(t, string(p.workerKID), gotOutput.WorkerSigningKeyID)
	cover, err := gotOutput.CoverBytes()
	require.NoError(t, err)
	require.NoError(t, crypto.Verify(p.workerVK.PublicKey, cover, gotOutput.WorkerSignature))
}

// TestServeOneJob_RefusedBeforeAnyIO proves a closed session and a
// finished context are refused before the session reads anything.
func TestServeOneJob_RefusedBeforeAnyIO(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	clientConn, serverConn := loopbackPair(t)
	done := vault(p, serverConn, func(*transport.Conn) error { return nil })
	var reasons []string
	cfg := clientConfig(t, p, clientConn)
	cfg.OnSessionClosed = func(reason string) { reasons = append(reasons, reason) }
	sess, err := Dial(cfg)
	require.NoError(t, err)
	require.NoError(t, <-done)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = sess.ServeOneJob(ctx)
	requireClassified(t, err, shared_errors.CategoryOperational, CodeContextCancelled)
	require.ErrorIs(t, err, context.Canceled)

	require.NoError(t, sess.WriteShutdown("worker_draining", "going away"))
	require.NoError(t, sess.Close())
	require.NoError(t, sess.Close(), "a second Close is a no-op")
	require.NoError(t, sess.WriteShutdown("late", "ignored"), "a shutdown after Close writes nothing")
	require.Equal(t, []string{"worker_draining"}, reasons)

	err = sess.ServeOneJob(context.Background())
	requireClassified(t, err, shared_errors.CategoryStructural, transport.CodeProtocolViolation)
	require.ErrorContains(t, err, "closed Session")
}

// failingReconstructor refuses every job with the configured error.
type failingReconstructor struct{ err error }

func (f failingReconstructor) Reconstruct(context.Context, rjm.ReconstructionJobManifest, []worker.ComponentMaterial) (returnpath.CandidateOutput, error) {
	return returnpath.CandidateOutput{}, f.err
}

// TestServeOneJob_RejectsTheJobItCannotDo proves each refusal is
// returned classified and told to the vault as a JobReject carrying
// the same code: an expired deadline and unopenable material before
// any accept, a failed reconstruction after it (keeping the
// reconstructor's own code when it has one).
func TestServeOneJob_RejectsTheJobItCannotDo(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		tune     func(p *peers, cfg *SessionConfig)
		accepted bool
		cat      shared_errors.Category
		code     string
		msg      string
	}{
		"the deadline has passed on arrival": {
			tune: func(p *peers, _ *SessionConfig) { p.clock.Step(time.Hour) },
			cat:  shared_errors.CategoryOperational, code: transport.CodeDeadlineExceeded, msg: "already passed",
		},
		"material sealed to a key it does not hold": {
			tune: func(p *peers, cfg *SessionConfig) {
				cfg.Opener = KeyStoreOpener{Sealer: keys.NewInMemoryStore(p.clock)}
			},
			cat: shared_errors.CategoryIntegrity, code: CodeUnsealFailure,
		},
		"a reconstructor that fails without a code": {
			tune: func(_ *peers, cfg *SessionConfig) {
				cfg.Reconstructor = failingReconstructor{errors.New("the door did not open")}
			},
			accepted: true,
			cat:      shared_errors.CategoryOperational, code: CodeReconstructFailure, msg: "the door did not open",
		},
		"a reconstructor that fails with its own code": {
			tune: func(_ *peers, cfg *SessionConfig) {
				cfg.Reconstructor = failingReconstructor{shared_errors.Authority("backend_denied", "policy says no", nil)}
			},
			accepted: true,
			cat:      shared_errors.CategoryOperational, code: "backend_denied", msg: "policy says no",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newPeers(t)
			req := jobRequest(t, p, []byte("alpha"), []byte("beta"))
			clientConn, serverConn := loopbackPair(t)
			var accepts []transport.JobAccept
			var reject transport.JobReject
			done := vault(p, serverConn, func(c *transport.Conn) error {
				if err := c.Write(req); err != nil {
					return err
				}
				for {
					typ, body, err := c.Read()
					if err != nil {
						return err
					}
					switch typ {
					case transport.FrameTypeJobAccept:
						var a transport.JobAccept
						if err := transport.DecodeBody(body, &a); err != nil {
							return err
						}
						accepts = append(accepts, a)
					case transport.FrameTypeJobReject:
						return transport.DecodeBody(body, &reject)
					default:
						return errors.New("unexpected frame " + string(typ))
					}
				}
			})
			cfg := clientConfig(t, p, clientConn)
			sess, err := Dial(cfg)
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			tc.tune(p, &sess.cfg)

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			err = sess.ServeOneJob(ctx)
			requireClassified(t, err, tc.cat, tc.code)
			if tc.msg != "" {
				require.ErrorContains(t, err, tc.msg)
			}
			require.NoError(t, <-done)
			require.Equal(t, tc.accepted, len(accepts) == 1, "an accept precedes the reject only once the material opened")
			require.NoError(t, reject.Validate())
			require.Equal(t, req.ManifestID, reject.ManifestID)
			require.Equal(t, tc.code, reject.Reason)
			require.Equal(t, err.Error(), reject.HumanMessage)
			require.True(t, reject.RejectedAt.Equal(p.clock.Now()), "rejected at the worker clock's now")
		})
	}
}

// TestServeOneJob_SignFailureAfterAccept proves a worker whose keystore
// cannot sign the output returns an integrity refusal and sends neither
// an output nor a reject after its accept.
func TestServeOneJob_SignFailureAfterAccept(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	req := jobRequest(t, p, []byte("alpha"))
	clientConn, serverConn := loopbackPair(t)
	var after error
	done := vault(p, serverConn, func(c *transport.Conn) error {
		if err := c.Write(req); err != nil {
			return err
		}
		var a transport.JobAccept
		if err := readAs(c, transport.FrameTypeJobAccept, &a); err != nil {
			return err
		}
		_, _, after = c.Read()
		return nil
	})
	cfg := clientConfig(t, p, clientConn)
	cfg.SigningKeyID = "worker-key-the-store-lacks"
	sess, err := Dial(cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	err = sess.ServeOneJob(ctx)
	requireClassified(t, err, shared_errors.CategoryIntegrity, CodeSignFailure)
	require.NoError(t, sess.Close())
	require.NoError(t, <-done)
	require.ErrorIs(t, after, transport.ErrWireClosed, "nothing follows the accept but the close")
}

// pipePair is a synchronous in-memory connection pair: a write fails at
// once when the other end is closed, which makes write failures
// deterministic.
func pipePair(t *testing.T) (clientConn, serverConn net.Conn) {
	t.Helper()
	clientConn, serverConn = net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	return clientConn, serverConn
}

// TestServeOneJob_WriteFailures proves a vault that goes away after
// sending the job, or after taking the accept, fails the corresponding
// write with the pipe's error rather than hanging.
func TestServeOneJob_WriteFailures(t *testing.T) {
	t.Parallel()
	for name, afterAccept := range map[string]bool{"the accept cannot be written": false, "the output cannot be written": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newPeers(t)
			req := jobRequest(t, p, []byte("alpha"))
			clientConn, serverConn := pipePair(t)
			done := vault(p, serverConn, func(c *transport.Conn) error {
				if err := c.Write(req); err != nil {
					return err
				}
				if afterAccept {
					var a transport.JobAccept
					if err := readAs(c, transport.FrameTypeJobAccept, &a); err != nil {
						return err
					}
				}
				return c.Close()
			})
			sess, err := Dial(clientConfig(t, p, clientConn))
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			err = sess.ServeOneJob(ctx)
			require.ErrorIs(t, err, io.ErrClosedPipe)
			require.NoError(t, <-done)
		})
	}
}

// TestServeOneJob_AwaitingAJob_TranslatesWhatTheVaultSends pins what the
// worker does with each thing the vault may send instead of a usable
// job: a closed wire, a job that does not decode or validate, an error
// envelope (well-formed or not), a shutdown and a frame of the wrong
// type.
func TestServeOneJob_AwaitingAJob_TranslatesWhatTheVaultSends(t *testing.T) {
	t.Parallel()
	type typedSchema struct {
		Type          transport.FrameType `json:"type"`
		SchemaVersion string              `json:"schema_version"`
	}
	type typedEnvelope struct {
		Type     transport.FrameType `json:"type"`
		Envelope string              `json:"envelope"`
	}
	cases := map[string]struct {
		send func(c *transport.Conn, req transport.JobRequest) error
		err  func(t *testing.T, err error)
	}{
		"the vault hangs up": {
			send: func(c *transport.Conn, _ transport.JobRequest) error { return c.Close() },
			err:  func(t *testing.T, err error) { require.ErrorIs(t, err, transport.ErrWireClosed) },
		},
		"a job that does not decode": {
			send: func(c *transport.Conn, _ transport.JobRequest) error {
				return c.Write(typedSchema{Type: transport.FrameTypeJobRequest, SchemaVersion: "one"})
			},
			err: func(t *testing.T, err error) {
				requireClassified(t, err, shared_errors.CategoryStructural, transport.CodeProtocolViolation)
				require.ErrorContains(t, err, "decode")
			},
		},
		"a job of another schema version": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				req.SchemaVersion = 2
				return c.Write(req)
			},
			err: func(t *testing.T, err error) {
				requireClassified(t, err, shared_errors.CategoryStructural, transport.CodeProtocolViolation)
				require.ErrorContains(t, err, "schema_version")
			},
		},
		"an error envelope": {
			send: func(c *transport.Conn, _ transport.JobRequest) error {
				return c.WriteError(shared_errors.Authority("policy_denied", "the vault says no", nil), "m-1")
			},
			err: func(t *testing.T, err error) {
				requireClassified(t, err, shared_errors.CategoryAuthority, "policy_denied")
			},
		},
		"an error envelope that does not decode": {
			send: func(c *transport.Conn, _ transport.JobRequest) error {
				return c.Write(typedEnvelope{Type: transport.FrameTypeError, Envelope: "x"})
			},
			err: func(t *testing.T, err error) {
				requireClassified(t, err, shared_errors.CategoryStructural, transport.CodeProtocolViolation)
				require.ErrorContains(t, err, "decode")
			},
		},
		"a shutdown before any job": {
			send: func(c *transport.Conn, _ transport.JobRequest) error {
				return c.WriteShutdown(transport.CodeShutdownNormal, "nothing today")
			},
			err: func(t *testing.T, err error) {
				requireClassified(t, err, shared_errors.CategoryOperational, transport.CodeHandshakeFailure)
				require.ErrorContains(t, err, "Shutdown before any JobRequest")
			},
		},
		"a frame of the wrong type": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				return c.Write(transport.JobAccept{Type: transport.FrameTypeJobAccept, ManifestID: req.ManifestID, AcceptedAt: time.Now().UTC(), EstimatedDuration: time.Second})
			},
			err: func(t *testing.T, err error) {
				requireClassified(t, err, shared_errors.CategoryStructural, transport.CodeProtocolViolation)
				require.ErrorContains(t, err, "unexpected frame type while awaiting JobRequest")
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newPeers(t)
			req := jobRequest(t, p, []byte("alpha"))
			clientConn, serverConn := loopbackPair(t)
			done := vault(p, serverConn, func(c *transport.Conn) error { return tc.send(c, req) })
			sess, err := Dial(clientConfig(t, p, clientConn))
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			tc.err(t, sess.ServeOneJob(ctx))
			require.NoError(t, <-done)
		})
	}
}

// cancelOnReadConn cancels a context from inside the first Read made
// after it is armed, so a test can place a cancellation exactly between
// two frames of a session that is already waiting.
type cancelOnReadConn struct {
	net.Conn
	armed  atomic.Bool
	cancel context.CancelFunc
}

func (c *cancelOnReadConn) Read(b []byte) (int, error) {
	if c.armed.CompareAndSwap(true, false) {
		c.cancel()
	}
	return c.Conn.Read(b)
}

// TestServeOneJob_ContextCancelledWhileWaiting proves a cancellation
// that lands while the worker waits between frames is noticed as soon
// as the next frame has been read, and reported as such.
func TestServeOneJob_ContextCancelledWhileWaiting(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	clientConn, serverConn := loopbackPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrapped := &cancelOnReadConn{Conn: clientConn, cancel: cancel}
	done := vault(p, serverConn, func(c *transport.Conn) error {
		return c.Write(transport.NewHeartbeat(time.Now()))
	})
	sess, err := Dial(clientConfig(t, p, wrapped))
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()
	require.NoError(t, <-done)

	wrapped.armed.Store(true)
	err = sess.ServeOneJob(ctx)
	requireClassified(t, err, shared_errors.CategoryOperational, CodeContextCancelled)
	require.ErrorContains(t, err, "while awaiting JobRequest")
	require.ErrorIs(t, err, context.Canceled)
}

// TestServeOneJob_BadMACReachesTheIntegrityHook proves a frame whose
// MAC does not verify is refused as an integrity failure and reported
// to the integrity hook before the refusal is returned.
func TestServeOneJob_BadMACReachesTheIntegrityHook(t *testing.T) {
	t.Parallel()
	p := newPeers(t)
	clientConn, serverConn := loopbackPair(t)
	done := vault(p, serverConn, func(*transport.Conn) error {
		body, err := transport.EncodeBody(transport.NewHeartbeat(time.Now()))
		if err != nil {
			return err
		}
		_, err = transport.WriteFrame(serverConn, append(body, make([]byte, transport.MACSize)...))
		return err
	})
	var hooked []error
	cfg := clientConfig(t, p, clientConn)
	cfg.OnIntegrityFailure = func(err error) { hooked = append(hooked, err) }
	sess, err := Dial(cfg)
	require.NoError(t, err)
	defer func() { _ = sess.Close() }()
	require.NoError(t, <-done)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	err = sess.ServeOneJob(ctx)
	requireClassified(t, err, shared_errors.CategoryIntegrity, transport.CodeIntegrityFailure)
	require.Len(t, hooked, 1)
	require.Equal(t, err, hooked[0])
}
