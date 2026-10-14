// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package returnpath_test

// The refusals of the two session packages, driven from a raw peer: a
// connection that completed the transport handshake and speaks frames the
// session packages never send on their own — heartbeats out of turn, error
// envelopes, shutdowns before the job, frames of the wrong type, a reject,
// an accept for another manifest. Each answer's category and code is the
// contract the daemons rely on.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/client"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/server"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

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

// rawPeer completes the transport handshake on conn in the given role and
// returns the MAC-authenticated connection. It runs in a goroutine, so it
// reports rather than fails.
func rawPeer(peers *integrationPeers, role transport.Role, conn net.Conn) (*transport.Conn, error) {
	cfg := transport.HandshakeConfig{Role: role, Conn: conn, Clock: peers.clock}
	if role == transport.RoleClient {
		cfg.Producer, cfg.Verifier, cfg.ProposedChallenge = peers.clientProducer, peers.clientVerifier, []byte("raw-peer-challenge")
	} else {
		cfg.Producer, cfg.Verifier = peers.serverProducer, peers.serverVerifier
	}
	if err := conn.SetDeadline(time.Now().Add(integrationTimeout)); err != nil {
		return nil, err
	}
	state, err := transport.DoHandshake(cfg)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(integrationTimeout)); err != nil {
		return nil, err
	}
	return transport.WrapConn(conn, state)
}

func clientConfig(peers *integrationPeers, conn net.Conn, recon worker.Reconstructor, opener client.Opener) client.SessionConfig {
	return client.SessionConfig{
		Conn: conn, Producer: peers.clientProducer, Verifier: peers.clientVerifier, Clock: peers.clock,
		Reconstructor: recon, Signer: peers.workerStore, SigningKeyID: peers.workerSigningKeyID,
		SigningPurpose: keys.PurposeSigningAuthority, Opener: opener,
		ProposedChallenge: []byte("negatives-challenge"), HandshakeTimeout: integrationTimeout,
	}
}

func serverConfig(peers *integrationPeers, conn net.Conn) server.SessionConfig {
	return server.SessionConfig{
		Conn: conn, Producer: peers.serverProducer, Verifier: peers.serverVerifier, Clock: peers.clock,
		WorkerKeyResolver: peers.resolver, HandshakeTimeout: integrationTimeout,
	}
}

func requireClassified(t *testing.T, err error, cat shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, cat, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// A session config missing any required field is refused before a byte is
// sent, as a structural error naming the field.
func TestSessions_RefuseAnIncompleteConfig(t *testing.T) {
	t.Parallel()
	peers := newIntegrationPeers(t)
	recon, err := worker.NewDeterministicReconstructor(peers.clock)
	require.NoError(t, err)
	clientConn, serverConn := loopbackPair(t)
	opener := client.KeyStoreOpener{Sealer: peers.sealingStore}

	for name, mutate := range map[string]func(*client.SessionConfig){
		"Conn":          func(c *client.SessionConfig) { c.Conn = nil },
		"Producer":      func(c *client.SessionConfig) { c.Producer = nil },
		"Verifier":      func(c *client.SessionConfig) { c.Verifier = nil },
		"Reconstructor": func(c *client.SessionConfig) { c.Reconstructor = nil },
		"Signer":        func(c *client.SessionConfig) { c.Signer = nil },
		"SigningKeyID":  func(c *client.SessionConfig) { c.SigningKeyID = "" },
		"Opener":        func(c *client.SessionConfig) { c.Opener = nil },
	} {
		cfg := clientConfig(peers, clientConn, recon, opener)
		mutate(&cfg)
		_, err := client.Dial(cfg)
		requireClassified(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
		require.ErrorContains(t, err, name)
	}
	for name, mutate := range map[string]func(*server.SessionConfig){
		"Conn":              func(c *server.SessionConfig) { c.Conn = nil },
		"Producer":          func(c *server.SessionConfig) { c.Producer = nil },
		"Verifier":          func(c *server.SessionConfig) { c.Verifier = nil },
		"WorkerKeyResolver": func(c *server.SessionConfig) { c.WorkerKeyResolver = nil },
	} {
		cfg := serverConfig(peers, serverConn)
		mutate(&cfg)
		_, err := server.Accept(cfg)
		requireClassified(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
		require.ErrorContains(t, err, name)
	}
}

// The worker, waiting for its job, skips heartbeats and turns what else
// the vault may send into the error the daemon acts on.
func TestClient_AwaitingAJob_TranslatesWhatTheVaultSends(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		send func(c *transport.Conn) error
		cat  shared_errors.Category
		code string
	}{
		"an error envelope": {
			send: func(c *transport.Conn) error {
				return c.WriteError(shared_errors.Authority("policy_denied", "the vault says no", nil), "m-1")
			},
			cat: shared_errors.CategoryAuthority, code: "policy_denied",
		},
		"a shutdown before any job": {
			send: func(c *transport.Conn) error { return c.WriteShutdown(transport.CodeShutdownNormal, "nothing today") },
			cat:  shared_errors.CategoryOperational, code: transport.CodeHandshakeFailure,
		},
		"a frame of the wrong type": {
			send: func(c *transport.Conn) error {
				return c.Write(transport.JobAccept{Type: transport.FrameTypeJobAccept, ManifestID: "m-1", AcceptedAt: time.Now().UTC(), EstimatedDuration: time.Second})
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			peers := newIntegrationPeers(t)
			recon, err := worker.NewDeterministicReconstructor(peers.clock)
			require.NoError(t, err)
			clientConn, serverConn := loopbackPair(t)
			vault := make(chan error, 1)
			go func() {
				c, err := rawPeer(peers, transport.RoleServer, serverConn)
				if err != nil {
					vault <- err
					return
				}
				if err := c.Write(transport.NewHeartbeat(time.Now().UTC())); err != nil {
					vault <- err
					return
				}
				vault <- tc.send(c)
			}()
			sess, err := client.Dial(clientConfig(peers, clientConn, recon, client.KeyStoreOpener{Sealer: peers.sealingStore}))
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			require.NotNil(t, sess.State())
			require.NoError(t, <-vault)
			ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
			defer cancel()
			requireClassified(t, sess.ServeOneJob(ctx), tc.cat, tc.code)
		})
	}
}

type failingReconstructor struct{ err error }

func (f failingReconstructor) Reconstruct(context.Context, rjm.ReconstructionJobManifest, []worker.ComponentMaterial) (returnpath.CandidateOutput, error) {
	return returnpath.CandidateOutput{}, f.err
}

// A job the worker cannot carry out is rejected on the wire with the
// error's code, before or after the accept, and the error comes back to
// the daemon classified.
func TestClient_RejectsTheJobItCannotDo(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		opener   func(*integrationPeers) client.Opener
		recon    func(*integrationPeers) worker.Reconstructor
		accepted bool
		cat      shared_errors.Category
		code     string
	}{
		"material sealed to a key it does not hold": {
			opener: func(p *integrationPeers) client.Opener {
				return client.KeyStoreOpener{Sealer: keys.NewInMemoryStore(p.clock)}
			},
			recon: func(p *integrationPeers) worker.Reconstructor {
				r, _ := worker.NewDeterministicReconstructor(p.clock)
				return r
			},
			cat: shared_errors.CategoryIntegrity, code: client.CodeUnsealFailure,
		},
		"a reconstructor that fails": {
			opener: func(p *integrationPeers) client.Opener { return client.KeyStoreOpener{Sealer: p.sealingStore} },
			recon: func(*integrationPeers) worker.Reconstructor {
				return failingReconstructor{errors.New("the door did not open")}
			},
			accepted: true,
			cat:      shared_errors.CategoryOperational, code: client.CodeReconstructFailure,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			peers := newIntegrationPeers(t)
			req, _ := buildJobRequest(t, peers, [][]byte{[]byte("alpha"), []byte("beta")})
			clientConn, serverConn := loopbackPair(t)
			type seen struct {
				accept *transport.JobAccept
				reject transport.JobReject
				err    error
			}
			vault := make(chan seen, 1)
			go func() {
				c, err := rawPeer(peers, transport.RoleServer, serverConn)
				if err != nil {
					vault <- seen{err: err}
					return
				}
				if err := c.Write(req); err != nil {
					vault <- seen{err: err}
					return
				}
				var s seen
				for {
					typ, body, err := c.Read()
					if err != nil {
						s.err = err
						break
					}
					if typ == transport.FrameTypeJobAccept {
						var a transport.JobAccept
						s.err = transport.DecodeBody(body, &a)
						s.accept = &a
						continue
					}
					if typ == transport.FrameTypeJobReject {
						s.err = transport.DecodeBody(body, &s.reject)
					} else {
						s.err = errors.New("unexpected frame " + string(typ))
					}
					break
				}
				vault <- s
			}()
			sess, err := client.Dial(clientConfig(peers, clientConn, tc.recon(peers), tc.opener(peers)))
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
			defer cancel()
			requireClassified(t, sess.ServeOneJob(ctx), tc.cat, tc.code)

			s := <-vault
			require.NoError(t, s.err)
			require.Equal(t, tc.accepted, s.accept != nil, "an accept precedes the reject only once the material opened")
			require.Equal(t, transport.FrameTypeJobReject, s.reject.Type)
			require.Equal(t, req.ManifestID, s.reject.ManifestID)
			require.Equal(t, tc.code, s.reject.Reason)
			require.NotEmpty(t, s.reject.HumanMessage)
			require.LessOrEqual(t, len(s.reject.HumanMessage), 256)
			require.False(t, s.reject.RejectedAt.IsZero())
		})
	}
}

// The vault, having sent a job, takes only an accept or a reject for it
// and then only the candidate output — everything else the worker could
// send is refused with the category the authority records.
func TestServer_ServingAJob_RefusesWhatTheWorkerMayNotSend(t *testing.T) {
	t.Parallel()
	now := func() time.Time { return time.Now().UTC() }
	accept := func(req transport.JobRequest) transport.JobAccept {
		return transport.JobAccept{Type: transport.FrameTypeJobAccept, ManifestID: req.ManifestID, AcceptedAt: now(), EstimatedDuration: time.Second}
	}
	for name, tc := range map[string]struct {
		send func(c *transport.Conn, req transport.JobRequest) error
		cat  shared_errors.Category
		code string
		msg  string
	}{
		"a reject": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				if err := c.Write(transport.NewHeartbeat(now())); err != nil {
					return err
				}
				return c.Write(transport.JobReject{Type: transport.FrameTypeJobReject, ManifestID: req.ManifestID, RejectedAt: now(), Reason: "no_capacity", HumanMessage: "busy"})
			},
			cat: shared_errors.CategoryAuthority, code: server.CodeWorkerRejected, msg: "no_capacity",
		},
		"an accept for another manifest": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				a := accept(req)
				a.ManifestID = "another-manifest"
				return c.Write(a)
			},
			cat: shared_errors.CategoryAuthority, code: server.CodeManifestMismatch,
		},
		"an error envelope instead of an answer": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				return c.WriteError(shared_errors.Integrity("frame_mac", "the worker saw a bad MAC", nil), req.ManifestID)
			},
			cat: shared_errors.CategoryIntegrity, code: "frame_mac",
		},
		"a shutdown instead of an answer": {
			send: func(c *transport.Conn, _ transport.JobRequest) error {
				return c.WriteShutdown(transport.CodeShutdownNormal, "bye")
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation,
		},
		"a shutdown after the accept": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				if err := c.Write(accept(req)); err != nil {
					return err
				}
				if err := c.Write(transport.NewHeartbeat(now())); err != nil {
					return err
				}
				return c.WriteShutdown(transport.CodeShutdownNormal, "gave up")
			},
			cat: shared_errors.CategoryAuthority, code: transport.CodeHandshakeFailure,
		},
		"an error envelope after the accept": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				if err := c.Write(accept(req)); err != nil {
					return err
				}
				return c.WriteError(shared_errors.Operational("worker_busy", "later", nil), req.ManifestID)
			},
			cat: shared_errors.CategoryOperational, code: "worker_busy",
		},
		"a second accept after the accept": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				if err := c.Write(accept(req)); err != nil {
					return err
				}
				return c.Write(accept(req))
			},
			cat: shared_errors.CategoryStructural, code: transport.CodeProtocolViolation,
		},
		"an output bound to another session": {
			send: func(c *transport.Conn, req transport.JobRequest) error {
				if err := c.Write(accept(req)); err != nil {
					return err
				}
				return c.Write(transport.CandidateOutputFrame{
					Type: transport.FrameTypeCandidateOutput, ManifestID: req.ManifestID, SessionID: "another-session",
					OutputKind: req.ExpectedOutputKind, Bytes: []byte("x"), ProducedAt: now(),
					WorkerSigningKeyID: "worker-output-signer", WorkerSignature: make([]byte, 64),
				})
			},
			cat: shared_errors.CategoryAuthority, code: server.CodeManifestMismatch,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			peers := newIntegrationPeers(t)
			req, _ := buildJobRequest(t, peers, [][]byte{[]byte("alpha")})
			clientConn, serverConn := loopbackPair(t)
			workerDone := make(chan error, 1)
			go func() {
				c, err := rawPeer(peers, transport.RoleClient, clientConn)
				if err != nil {
					workerDone <- err
					return
				}
				typ, _, err := c.Read()
				if err != nil {
					workerDone <- err
					return
				}
				if typ != transport.FrameTypeJobRequest {
					workerDone <- errors.New("the vault opened with " + string(typ))
					return
				}
				workerDone <- tc.send(c, req)
			}()
			sess, err := server.Accept(serverConfig(peers, serverConn))
			require.NoError(t, err)
			defer func() { _ = sess.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
			defer cancel()
			_, err = sess.ServeOneJob(ctx, req)
			requireClassified(t, err, tc.cat, tc.code)
			if tc.msg != "" {
				require.ErrorContains(t, err, tc.msg)
			}
			require.NoError(t, <-workerDone)
		})
	}
}
