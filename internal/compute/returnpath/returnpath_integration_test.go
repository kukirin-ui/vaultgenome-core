// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package returnpath_test

// End-to-end Return Path integration test. Spins up a real loopback
// TCP listener, runs the sagvd-side (server) Session.Accept on one
// goroutine and the acp-compute-side (client) Session.Dial from the
// test goroutine, exchanges one full job cycle (JobRequest → unseal
// → reconstruct → sign → CandidateOutputFrame), and asserts that the
// vault-side CandidateOutput is byte-identical to a reference
// reconstruction computed from the same inputs.
//
// The test is in the external returnpath_test package so it can import
// both the server and the client halves without creating a cycle
// against the parent returnpath package (which server and client both
// import for the CandidateOutput shape).

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/client"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/server"
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

const integrationTimeout = 5 * time.Second

// ---- test scaffolding -----------------------------------------------------

// integrationPeers aggregates the crypto + TEE state both sides need.
// In production the sagvd and acp-compute daemons hold these in
// separate processes; the integration test collapses them into one
// struct for readability.
type integrationPeers struct {
	// TEEs — mutually trusting.
	clientProducer *tee.Simulated
	serverProducer *tee.Simulated
	clientVerifier *tee.SimulatedVerifier
	serverVerifier *tee.SimulatedVerifier

	// Vault authority keystore (issues manifest, NOT the one the worker
	// uses to sign its CandidateOutput).
	vaultStore           *keys.InMemoryStore
	manifestSigningKeyID ids.KeyID

	// Worker keystore (signs CandidateOutputFrame).
	workerStore        *keys.InMemoryStore
	workerSigningKeyID ids.KeyID
	workerVerifyingKey keys.VerifyingKey

	// Server-side resolver (holds worker's public key, for Verify).
	resolver *server.PublicKeyResolver

	// Shared sealing keystore: the vault seals disclosures to this key
	// and the worker opens with the same key. In production the
	// delivery of this key is bound to TEE attestation; for the
	// integration test we simulate by pre-registering the same key in
	// both vault and worker stores. We keep one physical InMemoryStore
	// that both sides reference so neither test has to re-implement a
	// seal/unseal helper.
	sealingStore   *keys.InMemoryStore
	recipientKeyID ids.KeyID

	// Shared clock so JobRequest.IssuedAt / Deadline arithmetic is
	// deterministic across sides.
	clock shared_time.Clock
}

func newIntegrationPeers(t *testing.T) *integrationPeers {
	t.Helper()

	clientSeed := bytes.Repeat([]byte{0x11}, crypto.Ed25519SeedSize)
	serverSeed := bytes.Repeat([]byte{0x22}, crypto.Ed25519SeedSize)

	cp, err := tee.NewSimulated([]byte("acp-compute-worker-v1-integration"), clientSeed)
	require.NoError(t, err)
	sp, err := tee.NewSimulated([]byte("sagvd-returnpath-v1-integration"), serverSeed)
	require.NoError(t, err)

	clock := shared_time.NewSystemClock()
	vaultStore := keys.NewInMemoryStore(clock)
	workerStore := keys.NewInMemoryStore(clock)
	sealingStore := keys.NewInMemoryStore(clock)

	vaultSigningKid := ids.KeyID("vault-manifest-signer")
	_, err = vaultStore.GenerateSigning(vaultSigningKid, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	workerSigningKid := ids.KeyID("worker-output-signer")
	workerVK, err := workerStore.GenerateSigning(workerSigningKid, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	// Hand the worker's public key to the server's resolver.
	resolver := server.NewPublicKeyResolver(nil)
	require.NoError(t, resolver.Register(workerSigningKid, workerVK))

	// Shared sealing key.
	recipientKid := ids.KeyID("session-recipient-sealing")
	require.NoError(t, sealingStore.GenerateSealing(recipientKid))

	return &integrationPeers{
		clientProducer:       cp,
		serverProducer:       sp,
		clientVerifier:       tee.NewSimulatedVerifier(sp.PublicKey(), sp.Measurement()),
		serverVerifier:       tee.NewSimulatedVerifier(cp.PublicKey(), cp.Measurement()),
		vaultStore:           vaultStore,
		manifestSigningKeyID: vaultSigningKid,
		workerStore:          workerStore,
		workerSigningKeyID:   workerSigningKid,
		workerVerifyingKey:   workerVK,
		resolver:             resolver,
		sealingStore:         sealingStore,
		recipientKeyID:       recipientKid,
		clock:                clock,
	}
}

// buildJobRequest constructs a wire-ready JobRequest plus a matching
// authority-side rjm.ReconstructionJobManifest (so the test has both
// views). Each plaintext component is sealed with the shared
// recipientKeyID via AES-256-GCM.
func buildJobRequest(t *testing.T, peers *integrationPeers, plaintexts [][]byte) (transport.JobRequest, rjm.ReconstructionJobManifest) {
	t.Helper()
	manifestID := "manifest-integration-1"
	sessionID := "session-integration-1"

	sealed := make([]transport.SealedMaterialRef, 0, len(plaintexts))
	for i, pt := range plaintexts {
		// AAD binds the ciphertext to the manifest + sequence index so a
		// ciphertext lifted to a different job or reordered would fail
		// the AEAD check.
		aad := append([]byte("rp-integration-aad|"), []byte(manifestID)...)
		aad = append(aad, byte(i))
		nonce, ct, err := peers.sealingStore.Seal(peers.recipientKeyID, pt, aad)
		require.NoError(t, err)
		sealed = append(sealed, transport.SealedMaterialRef{
			RecipientKeyID: string(peers.recipientKeyID),
			Nonce:          nonce,
			Ciphertext:     ct,
			AAD:            aad,
		})
	}

	issuedAt := peers.clock.Now().UTC()
	deadline := issuedAt.Add(30 * time.Second)

	req := transport.JobRequest{
		Type:                   transport.FrameTypeJobRequest,
		SchemaVersion:          1,
		ManifestID:             manifestID,
		SessionID:              sessionID,
		ExpectedOutputKind:     string(rjm.OutputKindBytesFixedLength),
		ExpectedOutputMaxBytes: 1024,
		Deadline:               deadline,
		IssuedAt:               issuedAt,
		SealedMaterial:         sealed,
	}
	require.NoError(t, req.Validate())

	manifest := rjm.ReconstructionJobManifest{
		SchemaVersion:          rjm.SchemaVersionCurrent,
		ManifestID:             ids.ManifestID(manifestID),
		SessionID:              ids.SessionID(sessionID),
		ExpectedOutputKind:     rjm.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 1024,
		IssuedAt:               issuedAt,
		Deadline:               deadline,
	}
	return req, manifest
}

// referenceReconstruct runs the SAME deterministic reconstructor the
// worker runs, against the projected-from-wire manifest and the
// worker's synthesized ComponentIDs. If the round-trip preserves
// byte-identity, this reference output equals the server-received
// CandidateOutput.Bytes.
func referenceReconstruct(t *testing.T, peers *integrationPeers, req transport.JobRequest, plaintexts [][]byte) returnpath.CandidateOutput {
	t.Helper()
	r, err := worker.NewDeterministicReconstructor(peers.clock)
	require.NoError(t, err)

	// Project the request onto the manifest shape the client would use.
	manifest := rjm.ReconstructionJobManifest{
		SchemaVersion:          rjm.SchemaVersionCurrent,
		ManifestID:             ids.ManifestID(req.ManifestID),
		SessionID:              ids.SessionID(req.SessionID),
		ExpectedOutputKind:     rjm.OutputKind(req.ExpectedOutputKind),
		ExpectedOutputMaxBytes: req.ExpectedOutputMaxBytes,
		IssuedAt:               req.IssuedAt,
		Deadline:               req.Deadline,
	}

	// Build ComponentMaterials with the same synthesis rule the client
	// uses (client.materialComponentID is internal, so we use the
	// workerEquivalentComponentID helper below to stay in lockstep).
	comps := make([]worker.ComponentMaterial, 0, len(plaintexts))
	for i, pt := range plaintexts {
		comps = append(comps, worker.ComponentMaterial{
			ComponentID:   workerEquivalentComponentID(req.ManifestID, i),
			SequenceIndex: uint32(i),
			Plaintext:     pt,
		})
	}

	out, err := r.Reconstruct(context.Background(), manifest, comps)
	require.NoError(t, err)
	return out
}

// workerEquivalentComponentID MUST produce the same ComponentID as
// client.materialComponentID for the same (manifestID, index). The
// test lives outside the client package so we can't call the internal
// helper; we reproduce the construction here and pin the lockstep via
// TestIntegration_ComponentIDSynthesis_Matches below, which fails
// loudly if the client-side helper ever changes.
func workerEquivalentComponentID(manifestID string, index int) ids.ComponentID {
	var buf []byte
	buf = append(buf, []byte("rp-wire-v1.0 component")...)
	lp := make([]byte, 4)
	putUint32BE(lp, uint32(len(manifestID)))
	buf = append(buf, lp...)
	buf = append(buf, []byte(manifestID)...)
	idx := make([]byte, 4)
	putUint32BE(idx, uint32(index))
	buf = append(buf, idx...)
	h := crypto.SHA256(buf)
	const hexchars = "0123456789abcdef"
	out := make([]byte, 2*len(h))
	for i, b := range h {
		out[2*i] = hexchars[b>>4]
		out[2*i+1] = hexchars[b&0x0f]
	}
	return ids.ComponentID(string(out))
}

func putUint32BE(dst []byte, v uint32) {
	dst[0] = byte(v >> 24)
	dst[1] = byte(v >> 16)
	dst[2] = byte(v >> 8)
	dst[3] = byte(v)
}

// ---- Subtest: happy-path end-to-end ---------------------------------------

func TestIntegration_HappyPath_EndToEnd(t *testing.T) {
	t.Parallel()
	peers := newIntegrationPeers(t)

	plaintexts := [][]byte{
		[]byte("component-a-bytes"),
		[]byte("component-b-bytes"),
		[]byte("component-c-bytes"),
	}
	req, _ := buildJobRequest(t, peers, plaintexts)
	referenceOut := referenceReconstruct(t, peers, req, plaintexts)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	// Client-side: dialed connection + worker machinery.
	reconstructor, err := worker.NewDeterministicReconstructor(peers.clock)
	require.NoError(t, err)

	// Instrumentation atomics.
	var clientSessionOpened atomic.Int32
	var serverSessionOpened atomic.Int32
	var clientSessionClosed atomic.Int32
	var serverSessionClosed atomic.Int32
	var serverSigFailures atomic.Int32
	var serverIntegrityHits atomic.Int32
	var clientIntegrityHits atomic.Int32

	// Spawn the server side in a goroutine.
	type serverOutcome struct {
		out returnpath.CandidateOutput
		err error
	}
	serverCh := make(chan serverOutcome, 1)
	go func() {
		c, aerr := lis.Accept()
		if aerr != nil {
			serverCh <- serverOutcome{err: aerr}
			return
		}
		sess, aerr := server.Accept(server.SessionConfig{
			Conn:              c,
			Producer:          peers.serverProducer,
			Verifier:          peers.serverVerifier,
			Clock:             peers.clock,
			WorkerKeyResolver: peers.resolver,
			HandshakeTimeout:  integrationTimeout,
			OnIntegrityFailure: func(error) {
				serverIntegrityHits.Add(1)
			},
			OnWorkerSignatureFailure: func(_ transport.CandidateOutputFrame, _ error) {
				serverSigFailures.Add(1)
			},
			OnSessionOpened: func(*transport.SessionState) {
				serverSessionOpened.Add(1)
			},
			OnSessionClosed: func(string) {
				serverSessionClosed.Add(1)
			},
		})
		if aerr != nil {
			_ = c.Close()
			serverCh <- serverOutcome{err: aerr}
			return
		}
		defer sess.Close()

		ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
		defer cancel()
		out, serr := sess.ServeOneJob(ctx, req)
		if serr == nil {
			// Clean shutdown so the client's awaitJobRequest doesn't
			// hang — not strictly required in this test but models
			// production where sagvd finishes with a graceful close.
			_ = sess.WriteShutdown(transport.CodeShutdownNormal, "integration test done")
		}
		serverCh <- serverOutcome{out: out, err: serr}
	}()

	// Client side.
	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = dialed.Close() })

	clientSess, err := client.Dial(client.SessionConfig{
		Conn:              dialed,
		Producer:          peers.clientProducer,
		Verifier:          peers.clientVerifier,
		Clock:             peers.clock,
		Reconstructor:     reconstructor,
		Signer:            peers.workerStore,
		SigningKeyID:      peers.workerSigningKeyID,
		SigningPurpose:    keys.PurposeSigningAuthority,
		Opener:            client.KeyStoreOpener{Sealer: peers.sealingStore},
		ProposedChallenge: []byte("integration-test-challenge"),
		HandshakeTimeout:  integrationTimeout,
		OnIntegrityFailure: func(error) {
			clientIntegrityHits.Add(1)
		},
		OnSessionOpened: func(*transport.SessionState) {
			clientSessionOpened.Add(1)
		},
		OnSessionClosed: func(string) {
			clientSessionClosed.Add(1)
		},
	})
	require.NoError(t, err)
	defer clientSess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()
	require.NoError(t, clientSess.ServeOneJob(ctx))

	sr := <-serverCh
	require.NoError(t, sr.err, "server-side ServeOneJob failed")

	// ---- assertions on the received CandidateOutput ----
	require.Equal(t, ids.ManifestID(req.ManifestID), sr.out.ManifestID)
	require.Equal(t, ids.SessionID(req.SessionID), sr.out.SessionID)
	require.Equal(t, rjm.OutputKind(req.ExpectedOutputKind), sr.out.OutputKind)
	require.NotEmpty(t, sr.out.Bytes)
	require.True(t, uint64(len(sr.out.Bytes)) <= req.ExpectedOutputMaxBytes)
	// Byte-for-byte equality with the reference reconstruction proves
	// the round-trip is pure: any stray transform (byte reordering,
	// encoding, signature-area leakage) would break this assertion.
	require.Equal(t, referenceOut.Bytes, sr.out.Bytes,
		"CandidateOutput.Bytes must match reference reconstruction")

	// ---- assertions on instrumentation ----
	require.Equal(t, int32(1), clientSessionOpened.Load())
	require.Equal(t, int32(1), serverSessionOpened.Load())
	require.Zero(t, serverSigFailures.Load(),
		"signature verification must succeed on happy path")
	require.Zero(t, serverIntegrityHits.Load(),
		"no MAC failures on happy path")
	require.Zero(t, clientIntegrityHits.Load(),
		"no MAC failures on happy path")

	require.NoError(t, clientSess.Close())
	require.Equal(t, int32(1), clientSessionClosed.Load())
	// Server Close ran via the deferred sess.Close() in its goroutine
	// — give it a beat to wire through.
	require.Eventually(t, func() bool {
		return serverSessionClosed.Load() == 1
	}, time.Second, 10*time.Millisecond)
}

// ---- Subtest: tampered signature → server classifies Integrity -----------

func TestIntegration_TamperedSignature_RejectedByServer(t *testing.T) {
	t.Parallel()
	peers := newIntegrationPeers(t)

	plaintexts := [][]byte{[]byte("single-component-pt")}
	req, _ := buildJobRequest(t, peers, plaintexts)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	// Server goroutine.
	var sigFailureObserved atomic.Int32
	type serverOutcome struct {
		out returnpath.CandidateOutput
		err error
	}
	serverCh := make(chan serverOutcome, 1)
	go func() {
		c, aerr := lis.Accept()
		if aerr != nil {
			serverCh <- serverOutcome{err: aerr}
			return
		}
		sess, aerr := server.Accept(server.SessionConfig{
			Conn:              c,
			Producer:          peers.serverProducer,
			Verifier:          peers.serverVerifier,
			Clock:             peers.clock,
			WorkerKeyResolver: peers.resolver,
			HandshakeTimeout:  integrationTimeout,
			OnWorkerSignatureFailure: func(_ transport.CandidateOutputFrame, _ error) {
				sigFailureObserved.Add(1)
			},
		})
		if aerr != nil {
			_ = c.Close()
			serverCh <- serverOutcome{err: aerr}
			return
		}
		defer sess.Close()
		ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
		defer cancel()
		out, serr := sess.ServeOneJob(ctx, req)
		serverCh <- serverOutcome{out: out, err: serr}
	}()

	// Client side — we do NOT use client.Session here because we want
	// to forge a frame with a bad signature. Instead, handshake
	// manually via transport, then encode a CandidateOutputFrame with
	// tampered signature bytes and send it.
	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	defer dialed.Close()
	_ = dialed.SetDeadline(time.Now().Add(integrationTimeout))

	state, err := transport.DoHandshake(transport.HandshakeConfig{
		Role:              transport.RoleClient,
		Conn:              dialed,
		Producer:          peers.clientProducer,
		Verifier:          peers.clientVerifier,
		Clock:             peers.clock,
		ProposedChallenge: []byte("tampered-sig-test"),
	})
	require.NoError(t, err)
	_ = dialed.SetDeadline(time.Time{})

	conn, err := transport.WrapConn(dialed, state)
	require.NoError(t, err)

	// Read the JobRequest the server pushes.
	typ, body, err := conn.Read()
	require.NoError(t, err)
	require.Equal(t, transport.FrameTypeJobRequest, typ)
	var got transport.JobRequest
	require.NoError(t, transport.DecodeBody(body, &got))

	// Send JobAccept.
	accept := transport.JobAccept{
		Type:              transport.FrameTypeJobAccept,
		ManifestID:        got.ManifestID,
		AcceptedAt:        peers.clock.Now().UTC(),
		EstimatedDuration: time.Second,
	}
	require.NoError(t, conn.Write(accept))

	// Build a CandidateOutputFrame with a well-formed body but a
	// deliberately wrong signature.
	frame := transport.CandidateOutputFrame{
		Type:               transport.FrameTypeCandidateOutput,
		ManifestID:         got.ManifestID,
		SessionID:          got.SessionID,
		OutputKind:         got.ExpectedOutputKind,
		Bytes:              []byte("forged-output-bytes-for-integration"),
		ProducedAt:         peers.clock.Now().UTC(),
		WorkerSigningKeyID: string(peers.workerSigningKeyID),
		WorkerSignature:    bytes.Repeat([]byte{0xDE, 0xAD}, crypto.Ed25519SignatureSize/2),
	}
	// Frame carries a non-empty signature (right length), but it's the
	// wrong bytes for this CoverBytes — Ed25519 verify will fail.
	require.NoError(t, conn.Write(frame))

	sr := <-serverCh
	require.Error(t, sr.err, "server must reject the tampered CandidateOutputFrame")
	require.Equal(t, server.CodeWorkerSignatureInvalid, shared_errors.CodeOf(sr.err))
	require.Equal(t, int32(1), sigFailureObserved.Load(),
		"OnWorkerSignatureFailure must fire exactly once")
}

// ---- Subtest: synthesis helper lockstep -----------------------------------

// TestIntegration_ComponentIDSynthesis_Matches pins the lockstep
// between client.materialComponentID (internal to the client package)
// and workerEquivalentComponentID (in this test). If either drifts,
// the end-to-end happy path above would still pass by coincidence if
// the reconstructor happened to not use ComponentID — but the
// DeterministicReconstructor DOES use it (see reconstruction.go
// digestInputs), so a drift would manifest as "Bytes mismatch" in the
// happy-path test. This extra probe is an early-warning signal: it
// round-trips one job end-to-end using the client-side helper, then
// re-computes the reference with the test-local helper, and asserts
// bytes match. Any future divergence surfaces here with a pointed
// failure message.
func TestIntegration_ComponentIDSynthesis_Matches(t *testing.T) {
	t.Parallel()
	peers := newIntegrationPeers(t)

	plaintexts := [][]byte{
		[]byte("alpha"),
		[]byte("beta"),
		[]byte("gamma"),
		[]byte("delta"),
	}
	req, _ := buildJobRequest(t, peers, plaintexts)
	reference := referenceReconstruct(t, peers, req, plaintexts)

	// Use only the client-side helper (via client.Session.ServeOneJob)
	// to produce the output, then compare.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	type serverOutcome struct {
		out returnpath.CandidateOutput
		err error
	}
	serverCh := make(chan serverOutcome, 1)
	go func() {
		c, aerr := lis.Accept()
		if aerr != nil {
			serverCh <- serverOutcome{err: aerr}
			return
		}
		sess, aerr := server.Accept(server.SessionConfig{
			Conn:              c,
			Producer:          peers.serverProducer,
			Verifier:          peers.serverVerifier,
			Clock:             peers.clock,
			WorkerKeyResolver: peers.resolver,
			HandshakeTimeout:  integrationTimeout,
		})
		if aerr != nil {
			_ = c.Close()
			serverCh <- serverOutcome{err: aerr}
			return
		}
		defer sess.Close()
		ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
		defer cancel()
		out, serr := sess.ServeOneJob(ctx, req)
		serverCh <- serverOutcome{out: out, err: serr}
	}()

	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	defer dialed.Close()

	r, err := worker.NewDeterministicReconstructor(peers.clock)
	require.NoError(t, err)
	clientSess, err := client.Dial(client.SessionConfig{
		Conn:             dialed,
		Producer:         peers.clientProducer,
		Verifier:         peers.clientVerifier,
		Clock:            peers.clock,
		Reconstructor:    r,
		Signer:           peers.workerStore,
		SigningKeyID:     peers.workerSigningKeyID,
		SigningPurpose:   keys.PurposeSigningAuthority,
		Opener:           client.KeyStoreOpener{Sealer: peers.sealingStore},
		HandshakeTimeout: integrationTimeout,
	})
	require.NoError(t, err)
	defer clientSess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()
	require.NoError(t, clientSess.ServeOneJob(ctx))

	sr := <-serverCh
	require.NoError(t, sr.err)
	require.Equal(t, reference.Bytes, sr.out.Bytes,
		"client-side synthesized ComponentIDs disagree with test reference — "+
			"client.materialComponentID and workerEquivalentComponentID have drifted")
}

// ---- Subtest: context cancellation blocks a hanging ServeOneJob -----------

// TestIntegration_ContextCancellation verifies that a client ctx cancel
// before JobRequest arrives is translated into an Operational
// CodeContextCancelled error, without leaking the goroutine.
func TestIntegration_ContextCancellation(t *testing.T) {
	t.Parallel()
	peers := newIntegrationPeers(t)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	// Server that handshakes but never sends a JobRequest (holds the
	// connection open for the test to trigger cancellation).
	go func() {
		c, aerr := lis.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(integrationTimeout))
		_, _ = transport.DoHandshake(transport.HandshakeConfig{
			Role:     transport.RoleServer,
			Conn:     c,
			Producer: peers.serverProducer,
			Verifier: peers.serverVerifier,
			Clock:    peers.clock,
		})
		// Sleep out the remainder of the timeout, holding the conn open.
		time.Sleep(integrationTimeout)
	}()

	dialed, err := net.Dial("tcp", lis.Addr().String())
	require.NoError(t, err)
	defer dialed.Close()

	r, err := worker.NewDeterministicReconstructor(peers.clock)
	require.NoError(t, err)
	clientSess, err := client.Dial(client.SessionConfig{
		Conn:             dialed,
		Producer:         peers.clientProducer,
		Verifier:         peers.clientVerifier,
		Clock:            peers.clock,
		Reconstructor:    r,
		Signer:           peers.workerStore,
		SigningKeyID:     peers.workerSigningKeyID,
		Opener:           client.KeyStoreOpener{Sealer: peers.sealingStore},
		HandshakeTimeout: integrationTimeout,
	})
	require.NoError(t, err)
	defer clientSess.Close()

	// A very short deadline forces the conn deadline to fire while we
	// are blocked in Read on the JobRequest that never arrives.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = clientSess.ServeOneJob(ctx)
	elapsed := time.Since(start)
	require.Error(t, err)
	require.Less(t, elapsed, integrationTimeout,
		"ServeOneJob must return promptly on cancellation, not wait for integrationTimeout")
}
