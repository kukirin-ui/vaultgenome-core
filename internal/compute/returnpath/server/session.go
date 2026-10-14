// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"net"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- public codes ---------------------------------------------------------

// CodeWorkerRejected is emitted by ServeOneJob when the peer returns a
// JobReject instead of a JobAccept. Category is Authority — the worker
// refused an admission check, the server treats it as the remote end
// declining the job.
const CodeWorkerRejected = "worker_rejected_job"

// CodeWorkerSignatureInvalid is emitted when the CandidateOutputFrame's
// WorkerSignature fails Ed25519 verification under the key resolved via
// WorkerKeyResolver. Category is Integrity; callers on cmd/sagvd wire
// this into IncidentEvent emission.
const CodeWorkerSignatureInvalid = "worker_signature_invalid"

// CodeManifestMismatch is emitted when the CandidateOutputFrame's
// ManifestID/SessionID/OutputKind do not match the JobRequest this
// Session just issued. Category is Authority — the worker responded to
// the wrong job, which is a binding violation.
const CodeManifestMismatch = "manifest_mismatch"

// CodeContextCancelled is emitted when ctx.Done() fires during a
// ServeOneJob phase. Category is Operational.
const CodeContextCancelled = "context_cancelled"

// ---- config ---------------------------------------------------------------

// SessionConfig controls one server-side Session. A zero Config is
// rejected by Accept — every mandatory field is called out below.
type SessionConfig struct {
	// Conn is the accepted net.Conn returned from the listener. Required.
	// Session takes ownership: Close() will close Conn.
	Conn net.Conn

	// Producer is the vault-side TEE. Produces server evidence during
	// the handshake. Required.
	Producer tee.Producer

	// Verifier verifies the worker's TEE evidence. MUST be configured
	// with the worker's expected Measurement — a missing expected
	// measurement is a handshake-authority hole. Required.
	Verifier tee.Verifier

	// Clock provides the timestamps baked into SessionReady and any
	// Shutdown frames the Session emits. Optional; defaults to
	// SystemClock.
	Clock shared_time.Clock

	// WorkerKeyResolver is consulted to verify the Ed25519 signature on
	// every received CandidateOutputFrame. The KeyID used is the
	// frame's WorkerSigningKeyID. Required — without it the server
	// cannot prove non-repudiation on the worker emission.
	WorkerKeyResolver keys.Resolver

	// WorkerKeyPurpose is the Purpose the resolver will be asked to
	// produce for each WorkerSigningKeyID. Defaults to
	// PurposeSigningAuthority (the vault treats the worker's signing
	// key as an authority-binding capability for the scope of this
	// session only).
	WorkerKeyPurpose keys.Purpose

	// DerivationContext is passed through to DoHandshake. If empty, the
	// handshake generates a 16-byte random context (safe default).
	DerivationContext []byte

	// HandshakeTimeout bounds the time Accept will wait for the full
	// 4-frame handshake. Defaults to 10 seconds; tests may set it
	// shorter.
	HandshakeTimeout time.Duration

	// --- optional callbacks; nil = no-op ---

	// OnIntegrityFailure is wired into transport.WithIntegrityHook.
	// Fires once per MAC verification failure on the read path. The
	// error is already classified (CategoryIntegrity). Do NOT block in
	// the callback — it runs synchronously inside Conn.Read.
	OnIntegrityFailure func(err error)

	// OnWorkerSignatureFailure fires when a CandidateOutputFrame's
	// Ed25519 signature fails verification. The frame is passed so the
	// caller can record it into an IncidentEvent; the error is already
	// classified (CategoryIntegrity).
	OnWorkerSignatureFailure func(frame transport.CandidateOutputFrame, err error)

	// OnSessionOpened fires after a successful handshake but before any
	// application frame is written or read.
	OnSessionOpened func(state *transport.SessionState)

	// OnSessionClosed fires from Close(). reason is the shutdown reason
	// code if Close was preceded by a WriteShutdown, otherwise "".
	OnSessionClosed func(reason string)
}

// defaults installs sensible defaults for optional fields and leaves
// mandatory fields alone so Accept can produce a pointed error.
func (c *SessionConfig) defaults() {
	if c.Clock == nil {
		c.Clock = shared_time.NewSystemClock()
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	if c.WorkerKeyPurpose == keys.PurposeUnknown {
		c.WorkerKeyPurpose = keys.PurposeSigningAuthority
	}
}

func (c *SessionConfig) validate() error {
	if c.Conn == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/server: SessionConfig.Conn required", nil)
	}
	if c.Producer == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/server: SessionConfig.Producer required", nil)
	}
	if c.Verifier == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/server: SessionConfig.Verifier required", nil)
	}
	if c.WorkerKeyResolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"returnpath/server: SessionConfig.WorkerKeyResolver required", nil)
	}
	return nil
}

// ---- Session --------------------------------------------------------------

// Session is a single vault-side Return Path session: one handshaked,
// MAC-authenticated duplex connection over which the server issues one
// JobRequest and receives one CandidateOutputFrame (plus any Heartbeats
// interleaved on the way).
//
// Session is NOT safe for concurrent use. Exactly one goroutine should
// own a Session at a time, matching the single-reader / single-writer
// contract of transport.Conn.
//
// Ownership: Session takes ownership of cfg.Conn on success. Close
// releases the underlying net.Conn.
type Session struct {
	cfg        SessionConfig
	conn       *transport.Conn
	state      *transport.SessionState
	raw        net.Conn
	closed     bool
	shutReason string // last WriteShutdown reason, empty if none
}

// Accept performs the server-side handshake on cfg.Conn and returns a
// Session ready to serve one JobRequest. On any handshake failure the
// underlying net.Conn is left open — the caller is responsible for
// closing it. (This matches transport.DoHandshake's contract and gives
// the caller one place to emit IncidentEvents before closing.)
//
// The handshake is bounded by cfg.HandshakeTimeout; on timeout the
// returned error is classified Operational with Code=deadline_exceeded.
func Accept(cfg SessionConfig) (*Session, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if err := cfg.Conn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout)); err != nil {
		return nil, shared_errors.Operational(
			transport.CodeDeadlineExceeded,
			"returnpath/server: SetDeadline for handshake failed", err)
	}

	state, err := transport.DoHandshake(transport.HandshakeConfig{
		Role:              transport.RoleServer,
		Conn:              cfg.Conn,
		Producer:          cfg.Producer,
		Verifier:          cfg.Verifier,
		Clock:             cfg.Clock,
		DerivationContext: cfg.DerivationContext,
	})
	if err != nil {
		return nil, err
	}

	// Clear deadline so the Session can manage it per-call.
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

// State returns the underlying transport.SessionState. Callers treat
// it as read-only; see transport.Conn.State for the contract.
func (s *Session) State() *transport.SessionState { return s.state }

// VerifiedCandidate is a CandidateOutput together with the worker
// signing key ID under which its CandidateOutputFrame signature was
// verified. The key ID is authenticated, not merely reported: it is
// returned only after the frame's Ed25519 signature has checked out
// against the key the WorkerKeyResolver holds for that ID, so callers
// may record it as the provenance of the result (job view, audit chain).
type VerifiedCandidate struct {
	Output             returnpath.CandidateOutput
	WorkerSigningKeyID ids.KeyID
}

// ServeOneJob runs ServeOneJobVerified and returns only the candidate
// output, for callers that do not need the signing-key provenance.
func (s *Session) ServeOneJob(ctx context.Context, req transport.JobRequest) (returnpath.CandidateOutput, error) {
	v, err := s.ServeOneJobVerified(ctx, req)
	return v.Output, err
}

// ServeOneJobVerified drives the server-side job cycle end-to-end:
//
//  1. Canonical-encode and send req as a JobRequest frame.
//  2. Read frames until we see a JobAccept or JobReject (Heartbeats are
//     skipped).
//  3. If JobReject, return Authority / CodeWorkerRejected wrapping the
//     worker's reason.
//  4. If JobAccept, read frames until we see a CandidateOutputFrame
//     (Heartbeats are skipped).
//  5. Verify the CandidateOutputFrame against the JobRequest: match
//     ManifestID, SessionID, OutputKind; re-compute CoverBytes and
//     Ed25519-verify the WorkerSignature via WorkerKeyResolver.
//  6. Translate to a returnpath.CandidateOutput and return it with the
//     verified worker signing key ID.
//
// On any transport error, the Session is left partially-usable: callers
// typically call WriteShutdown then Close. On signature failure, the
// error is Integrity / CodeWorkerSignatureInvalid and
// OnWorkerSignatureFailure (if set) fires before the error returns.
//
// ctx is honored via SetDeadline: if ctx carries a deadline, it is
// propagated to the net.Conn. A cancelled ctx without a deadline is
// surfaced before the first I/O with CodeContextCancelled. Callers
// wanting strict cancellation should also close the net.Conn when ctx
// is done (Session.Close does this).
func (s *Session) ServeOneJobVerified(ctx context.Context, req transport.JobRequest) (VerifiedCandidate, error) {
	var zero VerifiedCandidate
	if s.closed {
		return zero, shared_errors.Structural(
			transport.CodeProtocolViolation,
			"returnpath/server: ServeOneJob called on closed Session", nil)
	}
	if err := ctx.Err(); err != nil {
		return zero, shared_errors.Operational(
			CodeContextCancelled,
			"returnpath/server: context already done at ServeOneJob entry", err)
	}
	if err := req.Validate(); err != nil {
		return zero, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.raw.SetDeadline(deadline)
	}

	// Step 1: send JobRequest.
	if err := s.conn.Write(req); err != nil {
		return zero, err
	}

	// Step 2: await JobAccept or JobReject.
	reply, err := s.awaitJobReply(ctx)
	if err != nil {
		return zero, err
	}
	if reply.rejected {
		return zero, shared_errors.Authority(
			CodeWorkerRejected,
			"returnpath/server: worker returned JobReject ("+reply.reject.Reason+"): "+reply.reject.HumanMessage,
			nil)
	}
	if reply.accept.ManifestID != req.ManifestID {
		return zero, shared_errors.Authority(
			CodeManifestMismatch,
			"returnpath/server: JobAccept.ManifestID does not match JobRequest.ManifestID", nil)
	}

	// Step 3: await CandidateOutputFrame.
	frame, err := s.awaitCandidateOutput(ctx)
	if err != nil {
		return zero, err
	}

	// Step 4: cross-field check against the JobRequest we just sent.
	if frame.ManifestID != req.ManifestID ||
		frame.SessionID != req.SessionID ||
		frame.OutputKind != req.ExpectedOutputKind {
		return zero, shared_errors.Authority(
			CodeManifestMismatch,
			"returnpath/server: CandidateOutputFrame bindings do not match JobRequest", nil)
	}

	// Step 5: size budget. A worker MUST NOT exceed the manifest's
	// ExpectedOutputMaxBytes — that bound is the only thing standing
	// between a misbehaving worker and unbounded memory consumption in
	// the validation pipeline.
	if uint64(len(frame.Bytes)) > req.ExpectedOutputMaxBytes {
		return zero, shared_errors.Authority(
			CodeManifestMismatch,
			"returnpath/server: CandidateOutputFrame.Bytes exceeds JobRequest.ExpectedOutputMaxBytes", nil)
	}

	// Step 6: Ed25519-verify the worker signature.
	if err := s.verifyWorkerSignature(frame); err != nil {
		if s.cfg.OnWorkerSignatureFailure != nil {
			s.cfg.OnWorkerSignatureFailure(frame, err)
		}
		return zero, err
	}

	// Step 7: translate to in-process CandidateOutput.
	out := returnpath.CandidateOutput{
		ManifestID: ids.ManifestID(frame.ManifestID),
		SessionID:  ids.SessionID(frame.SessionID),
		OutputKind: rjm.OutputKind(frame.OutputKind),
		Bytes:      append([]byte(nil), frame.Bytes...),
		ProducedAt: frame.ProducedAt,
	}
	return VerifiedCandidate{Output: out, WorkerSigningKeyID: ids.KeyID(frame.WorkerSigningKeyID)}, nil
}

// jobReply captures the two possible responses to a JobRequest. Exactly
// one of accept / reject is populated; rejected reports which.
type jobReply struct {
	rejected bool
	accept   transport.JobAccept
	reject   transport.JobReject
}

// awaitJobReply reads frames from conn, skipping Heartbeats, until it
// observes a JobAccept or JobReject or an ErrorFrame from the peer. An
// ErrorFrame is translated to a classified error. Any other frame type
// is a protocol violation.
func (s *Session) awaitJobReply(ctx context.Context) (jobReply, error) {
	for {
		if err := ctx.Err(); err != nil {
			return jobReply{}, shared_errors.Operational(
				CodeContextCancelled,
				"returnpath/server: context done while awaiting JobAccept/JobReject", err)
		}
		typ, body, err := s.conn.Read()
		if err != nil {
			return jobReply{}, err
		}
		switch typ {
		case transport.FrameTypeJobAccept:
			var a transport.JobAccept
			if err := transport.DecodeBody(body, &a); err != nil {
				return jobReply{}, err
			}
			if err := a.Validate(); err != nil {
				return jobReply{}, err
			}
			return jobReply{accept: a}, nil
		case transport.FrameTypeJobReject:
			var r transport.JobReject
			if err := transport.DecodeBody(body, &r); err != nil {
				return jobReply{}, err
			}
			if err := r.Validate(); err != nil {
				return jobReply{}, err
			}
			return jobReply{rejected: true, reject: r}, nil
		case transport.FrameTypeHeartbeat:
			// skip
			continue
		case transport.FrameTypeError:
			var ef transport.ErrorFrame
			if err := transport.DecodeBody(body, &ef); err != nil {
				return jobReply{}, err
			}
			return jobReply{}, ef.Envelope.AsClassifiedError()
		default:
			return jobReply{}, shared_errors.Structural(
				transport.CodeProtocolViolation,
				"returnpath/server: unexpected frame type while awaiting JobAccept/JobReject",
				nil)
		}
	}
}

// awaitCandidateOutput reads frames, skipping Heartbeats, until it sees
// a CandidateOutputFrame (or a peer-initiated ErrorFrame / Shutdown).
// Shutdown before a candidate output arrives is Authority-classified:
// the worker closed early without delivering.
func (s *Session) awaitCandidateOutput(ctx context.Context) (transport.CandidateOutputFrame, error) {
	for {
		if err := ctx.Err(); err != nil {
			return transport.CandidateOutputFrame{}, shared_errors.Operational(
				CodeContextCancelled,
				"returnpath/server: context done while awaiting CandidateOutputFrame", err)
		}
		typ, body, err := s.conn.Read()
		if err != nil {
			return transport.CandidateOutputFrame{}, err
		}
		switch typ {
		case transport.FrameTypeCandidateOutput:
			var f transport.CandidateOutputFrame
			if err := transport.DecodeBody(body, &f); err != nil {
				return transport.CandidateOutputFrame{}, err
			}
			if err := f.Validate(); err != nil {
				return transport.CandidateOutputFrame{}, err
			}
			return f, nil
		case transport.FrameTypeHeartbeat:
			continue
		case transport.FrameTypeError:
			var ef transport.ErrorFrame
			if err := transport.DecodeBody(body, &ef); err != nil {
				return transport.CandidateOutputFrame{}, err
			}
			return transport.CandidateOutputFrame{}, ef.Envelope.AsClassifiedError()
		case transport.FrameTypeShutdown:
			return transport.CandidateOutputFrame{}, shared_errors.Authority(
				transport.CodeHandshakeFailure,
				"returnpath/server: peer sent Shutdown before CandidateOutputFrame", nil)
		default:
			return transport.CandidateOutputFrame{}, shared_errors.Structural(
				transport.CodeProtocolViolation,
				"returnpath/server: unexpected frame type while awaiting CandidateOutputFrame",
				nil)
		}
	}
}

// verifyWorkerSignature re-encodes the frame with a zeroed signature
// (matching transport.CandidateOutputFrame.CoverBytes) and runs
// crypto.Verify under the resolver-bound public key.
//
// Returns Integrity / CodeWorkerSignatureInvalid on any failure path:
// unknown key ID, purpose mismatch, or signature forgery. The outer
// hook (OnWorkerSignatureFailure) is invoked by the caller, not here,
// so tests can observe the error in isolation.
func (s *Session) verifyWorkerSignature(f transport.CandidateOutputFrame) error {
	if f.WorkerSigningKeyID == "" {
		return shared_errors.Integrity(
			CodeWorkerSignatureInvalid,
			"returnpath/server: CandidateOutputFrame.WorkerSigningKeyID empty", nil)
	}
	vk, err := s.cfg.WorkerKeyResolver.Resolve(
		ids.KeyID(f.WorkerSigningKeyID), s.cfg.WorkerKeyPurpose)
	if err != nil {
		return shared_errors.Integrity(
			CodeWorkerSignatureInvalid,
			"returnpath/server: resolver could not produce worker verifying key", err)
	}
	cover, err := f.CoverBytes()
	if err != nil {
		return shared_errors.Integrity(
			CodeWorkerSignatureInvalid,
			"returnpath/server: cannot re-encode CandidateOutputFrame for verification", err)
	}
	if err := crypto.Verify(vk.PublicKey, cover, f.WorkerSignature); err != nil {
		return shared_errors.Integrity(
			CodeWorkerSignatureInvalid,
			"returnpath/server: CandidateOutputFrame.WorkerSignature verification failed", err)
	}
	return nil
}

// WriteShutdown sends a Shutdown frame with the given reason and
// human-readable message. Best-effort: the Session still expects a
// subsequent Close() to release the net.Conn.
func (s *Session) WriteShutdown(reason, humanMessage string) error {
	if s.closed {
		return nil
	}
	s.shutReason = reason
	return s.conn.WriteShutdown(reason, humanMessage)
}

// Close closes the underlying net.Conn. Safe to call multiple times.
// Fires OnSessionClosed exactly once (on the first call).
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
