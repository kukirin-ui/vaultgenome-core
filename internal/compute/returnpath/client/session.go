// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

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

// ---- public codes ---------------------------------------------------------

// CodeUnsealFailure is emitted when an Opener.Open call on a
// SealedMaterialRef fails (wrong key, tampered ciphertext, AAD mismatch).
// Category is Integrity — an unseal failure is indistinguishable from
// adversarial material substitution at this layer.
const CodeUnsealFailure = "unseal_failure"

// CodeReconstructFailure is emitted when the Reconstructor returns an
// error. The error's own Category is preserved; CodeReconstructFailure
// is the additional transport-layer code so callers can pattern-match
// both ways.
const CodeReconstructFailure = "reconstruct_failure"

// CodeSignFailure is emitted when signing the CandidateOutputFrame
// fails (unknown kid, purpose mismatch). Category is Integrity — the
// worker's keystore failed a capability check, which means the worker
// is incorrectly configured and cannot produce a non-repudiable output.
const CodeSignFailure = "sign_failure"

// CodeContextCancelled is emitted when ctx.Done() fires during a
// ServeOneJob phase. Category is Operational.
const CodeContextCancelled = "context_cancelled"

// ---- Opener ---------------------------------------------------------------

// Opener is the sealing-key capability the client uses to unwrap
// SealedMaterialRef entries. The worker supplies an Opener backed by
// its own keystore (typically /internal/vault/keys.InMemoryStore with
// the recipient sealing key pre-registered for the worker; in Phase 3
// this becomes a TEE hardware sealing key).
//
// The client package defines its own Opener interface rather than
// taking a keys.Sealer directly so that callers can plug in alternate
// sealing backends (TEE-bound, HSM-bound) without the vault/keys
// dependency leaking into every worker build.
//
// Open takes the string form of the recipient key ID (which is the
// form carried on the wire in SealedMaterialRef.RecipientKeyID) and
// returns the plaintext. Any failure is wrapped by the caller as
// Integrity / CodeUnsealFailure before surfacing.
type Opener interface {
	Open(recipientKeyID string, nonce, ciphertext, aad []byte) ([]byte, error)
}

// KeyStoreOpener adapts a keys.Sealer to Opener. The adapter exists so
// a caller can write `Opener: client.KeyStoreOpener{Sealer: store}`
// without a one-off closure.
type KeyStoreOpener struct {
	Sealer keys.Sealer
}

// Open implements Opener.
func (a KeyStoreOpener) Open(recipientKeyID string, nonce, ciphertext, aad []byte) ([]byte, error) {
	if a.Sealer == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/client: KeyStoreOpener.Sealer not set", nil)
	}
	return a.Sealer.Open(ids.KeyID(recipientKeyID), nonce, ciphertext, aad)
}

// ---- config ---------------------------------------------------------------

// SessionConfig controls one client-side Session.
type SessionConfig struct {
	// Conn is the dialed net.Conn. Required. Session takes ownership.
	Conn net.Conn

	// Producer is the worker-side TEE. Required.
	Producer tee.Producer

	// Verifier verifies the server's TEE evidence. Required.
	Verifier tee.Verifier

	// NonceReader supplies entropy for the client nonce. Optional;
	// defaults to crypto/rand.Reader inside the handshake.
	NonceReader io.Reader

	// Clock provides the timestamps baked into emitted
	// CandidateOutputFrame.ProducedAt (via the Reconstructor) and any
	// Shutdown frames. Optional; defaults to SystemClock.
	Clock shared_time.Clock

	// Reconstructor is the R-11-frozen worker backend: given a manifest
	// and the unsealed components, produces a CandidateOutput. Required.
	Reconstructor worker.Reconstructor

	// Signer is the worker's signing keystore. Required. The Signer MUST
	// hold the private half of SigningKeyID; the vault side resolves
	// the corresponding VerifyingKey via its Resolver.
	Signer keys.Signer

	// SigningKeyID is the KeyID the worker's CandidateOutputFrame.
	// WorkerSigningKeyID will carry on the wire. Required.
	SigningKeyID ids.KeyID

	// SigningPurpose is the Purpose passed to Signer.Sign. Defaults to
	// PurposeSigningAuthority (matches server.SessionConfig.WorkerKeyPurpose).
	SigningPurpose keys.Purpose

	// Opener unseals SealedMaterialRef entries. Required.
	Opener Opener

	// ProposedChallenge is forwarded to transport.HandshakeConfig.
	// Optional.
	ProposedChallenge []byte

	// HandshakeTimeout bounds the 4-frame handshake. Defaults to 10
	// seconds.
	HandshakeTimeout time.Duration

	// --- optional callbacks; nil = no-op ---

	// OnIntegrityFailure — wired into transport.WithIntegrityHook.
	OnIntegrityFailure func(err error)

	// OnJobAccepted fires after the client sends JobAccept and before
	// the Reconstructor is invoked.
	OnJobAccepted func(accept transport.JobAccept)

	// OnSessionOpened fires after a successful handshake.
	OnSessionOpened func(state *transport.SessionState)

	// OnSessionClosed fires on Close.
	OnSessionClosed func(reason string)
}

func (c *SessionConfig) defaults() {
	if c.Clock == nil {
		c.Clock = shared_time.NewSystemClock()
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	if c.SigningPurpose == keys.PurposeUnknown {
		c.SigningPurpose = keys.PurposeSigningAuthority
	}
}

func (c *SessionConfig) validate() error {
	if c.Conn == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/client: SessionConfig.Conn required", nil)
	}
	if c.Producer == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/client: SessionConfig.Producer required", nil)
	}
	if c.Verifier == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/client: SessionConfig.Verifier required", nil)
	}
	if c.Reconstructor == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/client: SessionConfig.Reconstructor required", nil)
	}
	if c.Signer == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/client: SessionConfig.Signer required", nil)
	}
	if c.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/client: SessionConfig.SigningKeyID required", nil)
	}
	if c.Opener == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/client: SessionConfig.Opener required", nil)
	}
	return nil
}

// ---- Session --------------------------------------------------------------

// Session is a single worker-side Return Path session. One handshake,
// one job cycle, then close. Not safe for concurrent use.
type Session struct {
	cfg        SessionConfig
	conn       *transport.Conn
	state      *transport.SessionState
	raw        net.Conn
	closed     bool
	shutReason string
}

// Dial runs the client-side handshake on cfg.Conn and returns a Session
// ready to receive one JobRequest and produce one CandidateOutputFrame.
// On any handshake failure cfg.Conn is left open for the caller to
// close.
func Dial(cfg SessionConfig) (*Session, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if err := cfg.Conn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout)); err != nil {
		return nil, shared_errors.Operational(
			transport.CodeDeadlineExceeded,
			"returnpath/client: SetDeadline for handshake failed", err)
	}

	state, err := transport.DoHandshake(transport.HandshakeConfig{
		Role:              transport.RoleClient,
		Conn:              cfg.Conn,
		Producer:          cfg.Producer,
		Verifier:          cfg.Verifier,
		NonceReader:       cfg.NonceReader,
		Clock:             cfg.Clock,
		ProposedChallenge: cfg.ProposedChallenge,
	})
	if err != nil {
		return nil, err
	}

	_ = cfg.Conn.SetDeadline(time.Time{})

	opts := []transport.ConnOption{}
	if cfg.OnIntegrityFailure != nil {
		opts = append(opts, transport.WithIntegrityHook(cfg.OnIntegrityFailure))
	}
	conn, err := transport.WrapConn(cfg.Conn, state, opts...)
	if err != nil {
		return nil, err
	}

	s := &Session{
		cfg:   cfg,
		conn:  conn,
		state: state,
		raw:   cfg.Conn,
	}
	if cfg.OnSessionOpened != nil {
		cfg.OnSessionOpened(state)
	}
	return s, nil
}

// State returns the underlying transport.SessionState. Read-only.
func (s *Session) State() *transport.SessionState { return s.state }

// ServeOneJob drives the client-side job cycle end-to-end:
//
//  1. Await a JobRequest (Heartbeats are skipped).
//  2. Unseal each SealedMaterialRef into a ComponentMaterial.
//  3. Construct a rjm.ReconstructionJobManifest from the wire-visible
//     fields (GenomeID / PolicyVersion / DisclosureIDs / RecipientKeyID
//     are NOT on the wire in v1.0 and are left zero).
//  4. Send a JobAccept with an EstimatedDuration derived from the
//     manifest deadline.
//  5. Call the Reconstructor.
//  6. Sign the resulting bytes under SigningKeyID and send a
//     CandidateOutputFrame.
//
// On any step failure before Reconstruct completes, the client sends a
// JobReject with the classified error's code, then returns the error.
// After a successful Reconstruct, signature/send failures still return
// an error but the JobReject is NOT sent (the server has already been
// told to expect a CandidateOutput via JobAccept; Shutdown is the
// correct close path at that point).
func (s *Session) ServeOneJob(ctx context.Context) error {
	if s.closed {
		return shared_errors.Structural(
			transport.CodeProtocolViolation,
			"returnpath/client: ServeOneJob called on closed Session", nil)
	}
	if err := ctx.Err(); err != nil {
		return shared_errors.Operational(
			CodeContextCancelled,
			"returnpath/client: context already done at ServeOneJob entry", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.raw.SetDeadline(deadline)
	}

	// Step 1: read JobRequest.
	req, err := s.awaitJobRequest(ctx)
	if err != nil {
		return err
	}

	// Step 2: unseal materials. Unseal failures are pre-Accept, so we
	// send a JobReject rather than a Shutdown.
	components, err := s.unsealComponents(req)
	if err != nil {
		_ = s.sendReject(req.ManifestID, err)
		return err
	}

	// Step 3: JobAccept. EstimatedDuration is bounded by the remaining
	// budget between now and the manifest Deadline.
	now := s.cfg.Clock.Now()
	remaining := req.Deadline.Sub(now)
	if remaining <= 0 {
		// Manifest already expired on arrival; reject operationally.
		expired := shared_errors.Operational(
			transport.CodeDeadlineExceeded,
			"returnpath/client: JobRequest.Deadline already passed on arrival", nil)
		_ = s.sendReject(req.ManifestID, expired)
		return expired
	}
	accept := transport.JobAccept{
		Type:              transport.FrameTypeJobAccept,
		ManifestID:        req.ManifestID,
		AcceptedAt:        now.UTC(),
		EstimatedDuration: remaining / 2, // conservative mid-budget estimate
	}
	if err := s.conn.Write(accept); err != nil {
		return err
	}
	if s.cfg.OnJobAccepted != nil {
		s.cfg.OnJobAccepted(accept)
	}

	// Step 4: reconstruct.
	manifest := manifestFromJobRequest(req)
	cand, err := s.cfg.Reconstructor.Reconstruct(ctx, manifest, components)
	if err != nil {
		// Classify as reconstruct failure but preserve underlying code.
		// Reject path: the server has sent the job and is awaiting
		// either a CandidateOutput or a Reject; Reject is correct here.
		rc := shared_errors.CodeOf(err)
		if rc == "" {
			rc = CodeReconstructFailure
		}
		wrapped := shared_errors.Operational(
			rc,
			"returnpath/client: Reconstructor failed: "+err.Error(),
			err)
		_ = s.sendReject(req.ManifestID, wrapped)
		return wrapped
	}

	// Step 5: build the CandidateOutputFrame and sign.
	frame := transport.CandidateOutputFrame{
		Type:               transport.FrameTypeCandidateOutput,
		ManifestID:         string(cand.ManifestID),
		SessionID:          string(cand.SessionID),
		OutputKind:         string(cand.OutputKind),
		Bytes:              append([]byte(nil), cand.Bytes...),
		ProducedAt:         cand.ProducedAt.UTC(),
		WorkerSigningKeyID: string(s.cfg.SigningKeyID),
		// WorkerSignature filled in below once CoverBytes is built.
	}
	cover, err := frame.CoverBytes()
	if err != nil {
		return err
	}
	sig, err := s.cfg.Signer.Sign(s.cfg.SigningKeyID, s.cfg.SigningPurpose, cover)
	if err != nil {
		return shared_errors.Integrity(
			CodeSignFailure,
			"returnpath/client: Signer.Sign failed", err)
	}
	frame.WorkerSignature = sig

	// Step 6: send the CandidateOutputFrame.
	if err := s.conn.Write(frame); err != nil {
		return err
	}
	return nil
}

// awaitJobRequest reads frames, skipping Heartbeats, until it sees a
// JobRequest. An ErrorFrame is classified-error-translated; a Shutdown
// before any job arrives is Operational (server closed early).
func (s *Session) awaitJobRequest(ctx context.Context) (transport.JobRequest, error) {
	for {
		if err := ctx.Err(); err != nil {
			return transport.JobRequest{}, shared_errors.Operational(
				CodeContextCancelled,
				"returnpath/client: context done while awaiting JobRequest", err)
		}
		typ, body, err := s.conn.Read()
		if err != nil {
			return transport.JobRequest{}, err
		}
		switch typ {
		case transport.FrameTypeJobRequest:
			var req transport.JobRequest
			if err := transport.DecodeBody(body, &req); err != nil {
				return transport.JobRequest{}, err
			}
			if err := req.Validate(); err != nil {
				return transport.JobRequest{}, err
			}
			return req, nil
		case transport.FrameTypeHeartbeat:
			continue
		case transport.FrameTypeError:
			var ef transport.ErrorFrame
			if err := transport.DecodeBody(body, &ef); err != nil {
				return transport.JobRequest{}, err
			}
			return transport.JobRequest{}, ef.Envelope.AsClassifiedError()
		case transport.FrameTypeShutdown:
			return transport.JobRequest{}, shared_errors.Operational(
				transport.CodeHandshakeFailure,
				"returnpath/client: peer sent Shutdown before any JobRequest", nil)
		default:
			return transport.JobRequest{}, shared_errors.Structural(
				transport.CodeProtocolViolation,
				"returnpath/client: unexpected frame type while awaiting JobRequest", nil)
		}
	}
}

// unsealComponents opens each SealedMaterialRef and assembles a
// []worker.ComponentMaterial. ComponentID is synthesized from the
// manifest ID and the slice index (deterministic, unique within the
// job). SequenceIndex is the slice position.
func (s *Session) unsealComponents(req transport.JobRequest) ([]worker.ComponentMaterial, error) {
	out := make([]worker.ComponentMaterial, 0, len(req.SealedMaterial))
	for i, m := range req.SealedMaterial {
		pt, err := s.cfg.Opener.Open(m.RecipientKeyID, m.Nonce, m.Ciphertext, m.AAD)
		if err != nil {
			return nil, shared_errors.Integrity(
				CodeUnsealFailure,
				"returnpath/client: unsealing SealedMaterial failed", err)
		}
		out = append(out, worker.ComponentMaterial{
			ComponentID:   materialComponentID(req.ManifestID, i),
			SequenceIndex: uint32(i),
			Plaintext:     pt,
		})
	}
	return out, nil
}

// sendReject is a best-effort JobReject emission on the error path
// before any CandidateOutputFrame has been built. A write failure is
// swallowed: the caller already has the primary error to surface.
func (s *Session) sendReject(manifestID string, cause error) error {
	r := transport.JobReject{
		Type:         transport.FrameTypeJobReject,
		ManifestID:   manifestID,
		RejectedAt:   s.cfg.Clock.Now().UTC(),
		Reason:       safeCode(cause),
		HumanMessage: shortMessage(cause),
	}
	return s.conn.Write(r)
}

// WriteShutdown sends a Shutdown frame. Best-effort.
func (s *Session) WriteShutdown(reason, humanMessage string) error {
	if s.closed {
		return nil
	}
	s.shutReason = reason
	return s.conn.WriteShutdown(reason, humanMessage)
}

// Close releases the underlying net.Conn. Safe to call multiple times.
func (s *Session) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.conn.Close()
	if s.cfg.OnSessionClosed != nil {
		s.cfg.OnSessionClosed(s.shutReason)
	}
	return err
}

// ---- helpers --------------------------------------------------------------

// manifestFromJobRequest projects the wire-visible subset of a
// JobRequest onto an rjm.ReconstructionJobManifest. Fields not carried
// on the wire (GenomeID, PolicyVersion, DisclosureIDs, RecipientKeyID,
// SigningKeyID, Signature) are left zero. This is the documented
// Phase-1 behaviour; when a future wire schema carries these fields,
// this function becomes the single-point migration target.
func manifestFromJobRequest(req transport.JobRequest) rjm.ReconstructionJobManifest {
	return rjm.ReconstructionJobManifest{
		SchemaVersion:          rjm.SchemaVersionCurrent,
		ManifestID:             ids.ManifestID(req.ManifestID),
		SessionID:              ids.SessionID(req.SessionID),
		ExpectedOutputKind:     rjm.OutputKind(req.ExpectedOutputKind),
		ExpectedOutputMaxBytes: req.ExpectedOutputMaxBytes,
		Deadline:               req.Deadline,
		IssuedAt:               req.IssuedAt,
	}
}

// materialComponentID synthesizes a ComponentID for a given job+index.
// The synthesis is deterministic: SHA-256("rp-wire-v1.0 component" ||
// lp(manifestID) || uint32be(index)) → 32 bytes → hex. Any change to
// this construction is a wire-adjacent break.
//
// Rationale. The DeterministicReconstructor hashes components'
// ComponentIDs into its output digest; for the worker and server to
// agree on that digest (which becomes the CandidateOutput.Bytes), both
// sides must synthesize identical IDs. This function is the single
// point of truth; the server side re-derives the same IDs when it
// reconstructs a reference CandidateOutput for integration tests.
func materialComponentID(manifestID string, index int) ids.ComponentID {
	var buf []byte
	buf = append(buf, []byte("rp-wire-v1.0 component")...)
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(manifestID)))
	buf = append(buf, lp[:]...)
	buf = append(buf, []byte(manifestID)...)
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], uint32(index))
	buf = append(buf, idx[:]...)
	h := crypto.SHA256(buf)
	// Hex-encode the 32-byte digest for a compact, ASCII-stable ID.
	const hexchars = "0123456789abcdef"
	out := make([]byte, 2*len(h))
	for i, b := range h {
		out[2*i] = hexchars[b>>4]
		out[2*i+1] = hexchars[b&0x0f]
	}
	return ids.ComponentID(string(out))
}

// safeCode returns the classified code of err, defaulting to
// CodeReconstructFailure if no code is attached. Used only in the
// JobReject error path.
func safeCode(err error) string {
	if err == nil {
		return CodeReconstructFailure
	}
	if code := shared_errors.CodeOf(err); code != "" {
		return code
	}
	return CodeReconstructFailure
}

// shortMessage truncates an error message to 256 bytes for safe
// inclusion in JobReject.HumanMessage. A longer message is either a
// stack trace that leaked from a bug or adversarial amplification and
// is not useful on the wire.
func shortMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 256 {
		msg = msg[:256]
	}
	return msg
}
