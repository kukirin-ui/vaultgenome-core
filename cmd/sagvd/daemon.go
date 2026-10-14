// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/server"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/observability/health"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	valservice "github.com/vault-genome/vaultgenome-core/internal/validation/service"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
	"github.com/vault-genome/vaultgenome-core/internal/vault/trust"
)

// Daemon is the sagvd runtime: a long-lived process that binds a
// Return Path listener, accepts acp-compute connections, and drives one
// queued job per accepted session through the nine stages of the flow
// (ADR 0015):
//
//	handshake  the worker's TEE Evidence verified against the pin
//	Next       a queued job (its request was admitted at intake, stage 1)
//	Admit      stage 2 — trust decided for this request and this peer
//	IssueSession, Disclose, IssueManifest — stages 3, 4, 5
//	JobRequest on the wire; CandidateOutput back — stage 6
//	judge      the gate: top-1 agreement and the determinism ladder
//	Validate, Decide, Seal — stages 7, 8, 9
//
// Every stage is on the audit log before it takes effect; a stage that
// cannot be taken aborts the flow on the record and fails the job.
//
// Lifecycle mirrors cmd/acp-compute's Daemon:
//
//	d, err := NewDaemon(cfg, materials, queue, genomes, audit, clock, logger, registry)
//	...
//	go d.Run(ctx)   // blocks until ctx is cancelled
//	<-ctx.Done()
//	d.Shutdown()    // flips health flags, closes listener
//	d.Zeroize()     // wipes the in-memory keystore (terminal)
//
// Concurrency model: single-worker at the dispatcher. The accept
// goroutine hands each accepted net.Conn into the dispatcher, which
// runs one session to completion before accepting the next. Multiple
// workers may *connect* concurrently — only one gets the current job;
// the others wait.
type Daemon struct {
	cfg       Config
	mat       *materials
	queue     *JobQueue
	genomes   *genomeJobs      // nil when gate jobs are not configured
	audit     *returnPathAudit // nil when no audit.log_path is configured
	clock     shared_time.Clock
	log       *slog.Logger
	tlsConfig *tls.Config

	health  *health.State
	metrics *daemonMetrics

	// listener is the TCP (or TLS-wrapped TCP) listener the
	// dispatcher accepts on. nil until Run has bound it; guarded by
	// listenerMu because Addr may be read while Run binds.
	listenerMu sync.Mutex
	listener   net.Listener
}

// daemonMetrics bundles the sagvd_* counters / gauges owned by the
// dispatcher side. The HTTP API owns jobs_submitted_total separately
// (via httpMetrics) because it is bumped on the POST path, never by
// the dispatcher. Both bundles share the same metrics.Registry and
// are exposed together on /metrics.
type daemonMetrics struct {
	jobsCompleted    *metrics.Counter // labels: outcome={success|reject|fail}
	gateVerdicts     *metrics.Counter // labels: level={EXACT|EQUIVALENT|FAIL|ERROR}
	releases         *metrics.Counter // labels: decision={release|refuse|trust_denied}
	sessionsOpened   *metrics.Counter // unlabeled
	handshakeFailure *metrics.Counter // labels: phase
	queueDepth       *metrics.Gauge   // set on every dispatcher tick
	lastSuccessUnix  *metrics.Gauge
	startUnix        *metrics.Gauge
}

// Error and shutdown codes of the dispatcher.
const (
	// CodeTrustDenied (Authority): Trust Admission denied the request;
	// the release decision on record refuses it (reason trust_denied).
	CodeTrustDenied = "trust_denied"

	// CodeReleaseRefused (Operational): validation did not pass and the
	// release decision on record refuses the answer.
	CodeReleaseRefused = "release_refused"

	// CodeReAttest is the shutdown code a worker receives when its
	// Evidence is too old to hand it a job: dial again, attest again.
	CodeReAttest = "re_attest"

	// attestationGrace is how much longer than the job's deadline the
	// attestation and the session stay valid, so an answer at the
	// deadline is validated under a live session.
	attestationGrace = 30 * time.Second
)

// NewDaemon wires every piece the daemon needs. cfg is expected to
// have already been validated; mat was produced by LoadMaterials;
// queue is shared with the HTTP API so submissions flow in and
// results flow out atomically; genomes opens the genomes jobs name
// (nil only when gate jobs are not configured); audit is the Return
// Path log (nil only when audit.log_path is not configured, which
// Validate refuses once gate jobs are enabled).
func NewDaemon(
	cfg Config,
	mat *materials,
	queue *JobQueue,
	genomes *genomeJobs,
	audit *returnPathAudit,
	clock shared_time.Clock,
	logger *slog.Logger,
	registry *metrics.Registry,
) (*Daemon, error) {
	if cfg.Vault.ListenAddress == "" {
		return nil, errors.New("sagvd: Daemon requires vault.listen_address")
	}
	if mat == nil {
		return nil, errors.New("sagvd: Daemon requires non-nil materials")
	}
	if queue == nil {
		return nil, errors.New("sagvd: Daemon requires non-nil JobQueue")
	}
	if clock == nil {
		return nil, errors.New("sagvd: Daemon requires non-nil clock")
	}
	if registry == nil {
		return nil, errors.New("sagvd: Daemon requires non-nil metrics.Registry")
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}

	var tlsConfig *tls.Config
	if cfg.Vault.TLS.Enabled {
		tc, err := loadServerTLS(cfg.TEE, cfg.Vault.TLS)
		if err != nil {
			return nil, err
		}
		tlsConfig = tc
	}

	return &Daemon{
		cfg:       cfg,
		mat:       mat,
		queue:     queue,
		genomes:   genomes,
		audit:     audit,
		clock:     clock,
		log:       logger,
		tlsConfig: tlsConfig,
		health:    health.NewState(),
		metrics:   registerDaemonMetrics(registry, clock),
	}, nil
}

// Health returns the underlying health.State so the caller can pass
// it to health.NewServer.
func (d *Daemon) Health() *health.State { return d.health }

// Metrics exposes the daemon's metric bundle so the HTTP API can
// bump jobs_submitted_total without importing metric names twice.
// The returned pointer is aliased; callers must not construct new
// metrics through it.
func (d *Daemon) Metrics() *daemonMetrics { return d.metrics }

// Addr returns the bound listener address (useful in tests where
// cfg.Vault.ListenAddress ends in :0). Returns the configured
// address verbatim before Run binds it.
func (d *Daemon) Addr() string {
	d.listenerMu.Lock()
	defer d.listenerMu.Unlock()
	if d.listener == nil {
		return d.cfg.Vault.ListenAddress
	}
	return d.listener.Addr().String()
}

// Run binds the Return Path listener and enters the accept /
// dispatch loop. Blocks until ctx is cancelled; on cancellation the
// listener is closed (unblocking Accept) and Run returns nil.
//
// On a bind failure Run returns the error without flipping health
// flags — the caller can report it and exit.
func (d *Daemon) Run(ctx context.Context) error {
	ln, err := d.listen()
	if err != nil {
		return err
	}
	d.listenerMu.Lock()
	d.listener = ln
	d.listenerMu.Unlock()
	d.log.Info("sagvd return-path listener bound", "address", ln.Addr().String(),
		"tls_enabled", d.cfg.Vault.TLS.Enabled)
	d.health.MarkReady()

	// Close the listener when ctx fires so a blocked Accept returns.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Non-terminal accept errors (temporary: true) are
			// briefly backed off so a burst of bad peers can't
			// spin the CPU.
			d.log.Warn("sagvd accept error", "err", err)
			if !sleepContext(ctx, 250*time.Millisecond) {
				return nil
			}
			continue
		}
		d.serveOne(ctx, conn)
	}
}

// Shutdown flips health flags so orchestrator probes start failing
// before the listener is torn down. Closing the listener itself is
// handled by Run's ctx.Done hook.
func (d *Daemon) Shutdown() {
	d.health.MarkDown()
}

// Zeroize wipes the in-memory keystore. Call only after Run has
// returned; afterwards the daemon is unusable.
func (d *Daemon) Zeroize() {
	if d.mat != nil && d.mat.Store != nil {
		d.mat.Store.Zeroize()
	}
}

// ---- session dispatch ----------------------------------------------------

// serveOne runs exactly one Return Path session end-to-end:
//  1. TLS-wrap the raw conn (if TLS is enabled)
//  2. server.Accept the 4-frame handshake
//  3. queue.Next — block until a job is available or ctx is done
//  4. the flow's stages 2–9 around sess.ServeOneJobVerified
//  5. queue.CompleteGated / CompleteFailure
//  6. sess.WriteShutdown + sess.Close
//
// Any error is logged with its classification; the connection is
// always closed before return so fd-leak is impossible.
func (d *Daemon) serveOne(parent context.Context, raw net.Conn) {
	// Close the connection when the daemon shuts down. net.Conn I/O does
	// not observe context cancellation, and Run serves connections
	// inline, so a session blocked on its worker would otherwise hold
	// shutdown until the job deadline.
	stopOnShutdown := context.AfterFunc(parent, func() { _ = raw.Close() })
	defer stopOnShutdown()

	// Wrap TLS first if configured; a failed TLS handshake is
	// Operational (peer never authenticated).
	var conn net.Conn = raw
	if d.tlsConfig != nil {
		tlsConn := tls.Server(raw, d.tlsConfig)
		handshakeCtx, cancel := context.WithTimeout(parent,
			d.cfg.Runtime.HandshakeTimeout())
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			cancel()
			_ = raw.Close()
			if parent.Err() != nil {
				// The daemon is stopping: a handshake it cut short is
				// not a decision about the peer, and is not recorded as one.
				d.log.Debug("sagvd TLS handshake cut short by shutdown", "remote_addr", raw.RemoteAddr().String())
				return
			}
			d.metrics.handshakeFailure.Inc(
				metrics.Label{Name: "phase", Value: "tls"},
			)
			d.log.Warn("sagvd TLS handshake failed",
				"remote_addr", raw.RemoteAddr().String(),
				"err", err)
			d.recordRefusal("tls", raw.RemoteAddr().String(), shared_errors.Authority("tls_handshake_failed", "TLS handshake failed", err))
			return
		}
		cancel()
		conn = tlsConn
	}
	remote := conn.RemoteAddr().String()

	// tamper is set when the wire signals tamper during the session; it
	// is what op.tamper_absent checks at validation.
	var tamper atomic.Bool

	// 4-frame Return Path handshake. On failure the net.Conn is
	// left open by server.Accept (matches the transport contract);
	// we close it explicitly on every error path below.
	sess, err := server.Accept(server.SessionConfig{
		Conn:              conn,
		Producer:          d.mat.Producer,
		Verifier:          d.mat.Verifier,
		Clock:             d.clock,
		WorkerKeyResolver: d.mat.WorkerResolver,
		HandshakeTimeout:  d.cfg.Runtime.HandshakeTimeout(),
		OnSessionOpened: func(state *transport.SessionState) {
			d.metrics.sessionsOpened.Inc()
			d.log.Info("sagvd session opened", append([]any{
				"remote_addr", remote,
				"peer_measurement", hex.EncodeToString(state.PeerMeasurement[:]),
				"ready_at", state.ReadyAt.Format(time.RFC3339Nano),
			}, peerDetailLogFields(state.PeerDetail)...)...)
		},
		OnIntegrityFailure: func(ihErr error) {
			tamper.Store(true)
			d.log.Error("sagvd integrity failure on wire",
				"code", shared_errors.CodeOf(ihErr),
				"err", ihErr)
		},
		OnWorkerSignatureFailure: func(frame transport.CandidateOutputFrame, sigErr error) {
			tamper.Store(true)
			d.log.Error("sagvd worker signature verification failed",
				"manifest_id", frame.ManifestID,
				"session_id", frame.SessionID,
				"worker_kid", frame.WorkerSigningKeyID,
				"err", sigErr)
		},
		OnSessionClosed: func(reason string) {
			d.log.Debug("sagvd session closed", "reason", reason)
		},
	})
	if err != nil {
		_ = conn.Close()
		if parent.Err() != nil {
			d.log.Debug("sagvd return-path handshake cut short by shutdown", "remote_addr", remote)
			return
		}
		d.metrics.handshakeFailure.Inc(
			metrics.Label{Name: "phase", Value: "handshake"},
		)
		d.log.Warn("sagvd return-path handshake failed",
			"remote_addr", remote,
			"code", shared_errors.CodeOf(err),
			"err", err)
		d.recordRefusal("handshake", remote, err)
		return
	}
	defer func() { _ = sess.Close() }()
	var peerMeasurement tee.Measurement
	var peerDetail *tee.AttestationDetail
	var evidenceAt time.Time
	if state := sess.State(); state != nil {
		peerMeasurement = state.PeerMeasurement
		peerDetail = state.PeerDetail
		evidenceAt = state.ReadyAt
	}

	// Bound the whole job cycle (Next + the flow) by JobTimeout.
	sessCtx, cancel := context.WithTimeout(parent, d.cfg.Runtime.JobTimeout())
	defer cancel()

	// Wait for the next queued job. If the context is cancelled
	// while we wait, close the session cleanly.
	job, err := d.queue.Next(sessCtx)
	if err != nil {
		_ = sess.WriteShutdown(transport.CodeShutdownNormal, "sagvd: no work pending")
		return
	}
	d.metrics.queueDepth.Set(float64(d.queue.Depth()))

	// A worker that attested long ago attests again before it is handed
	// a job: the session is closed, the job keeps its place.
	if age, maxAge := d.clock.Now().Sub(evidenceAt), d.cfg.Runtime.EvidenceMaxAge(); age > maxAge {
		d.queue.Requeue(job.ID)
		if auditErr := d.audit.TrustStale(remote, d.mat.PeerProvider, peerMeasurement, evidenceAt, age, maxAge); auditErr != nil {
			d.log.Error("sagvd audit log refused a record", "phase", "session", "err", auditErr)
		}
		_ = sess.WriteShutdown(CodeReAttest, "sagvd: the session's Evidence is older than runtime.evidence_max_age; attest again")
		d.log.Info("sagvd session too old for a job; worker told to attest again",
			"remote_addr", remote, "job_id", job.ID, "evidence_age", age.Round(time.Second), "evidence_max_age", maxAge)
		return
	}

	flow := job.Flow
	ttl := job.DeadlineFor + attestationGrace
	log := d.log.With("job_id", job.ID, "request_id", flow.Request().RequestID.String(), "genome_id", job.Info.GenomeID)

	// Stage 2 — Trust Admission for this request and this peer.
	dec, err := flow.Admit(trust.Peer{
		Provider: d.mat.PeerProvider, Measurement: peerMeasurement, RemoteAddr: remote, EvidenceAt: evidenceAt, Detail: peerDetail,
	}, ttl)
	if err != nil {
		d.abortJob(job, "trust", err, sess, log)
		return
	}
	if !dec.Allowed {
		d.refuseAtTrust(job, dec, sess, log)
		return
	}

	// Stage 3 — the session.
	sessObj, err := flow.IssueSession(ttl)
	if err != nil {
		d.abortJob(job, "session", err, sess, log)
		return
	}

	// Stage 4 — staged disclosure of the model side to this session.
	components, err := d.genomes.components(job.Info)
	if err != nil {
		d.abortJob(job, "disclose", err, sess, log)
		return
	}
	msgs, err := flow.Disclose(components)
	if err != nil {
		d.abortJob(job, "disclose", err, sess, log)
		return
	}

	// Stage 5 — the manifest, and the JobRequest it becomes on the wire.
	now := d.clock.Now().UTC()
	deadline := now.Add(job.DeadlineFor)
	detail, _ := json.Marshal(job.Info.View)
	man, err := flow.IssueManifest(orchestration.ManifestParams{
		OutputKind: rjm.OutputKindBytesFixedLength, MaxBytes: job.Info.Budget, Deadline: deadline, Detail: detail,
	})
	if err != nil {
		d.abortJob(job, "manifest", err, sess, log)
		return
	}
	req, err := jobRequestFrom(man, msgs)
	if err != nil {
		d.abortJob(job, "dispatch", err, sess, log)
		return
	}
	d.queue.MarkDispatched(job.ID, deadline)
	log.Info("sagvd dispatching job",
		"manifest_id", man.ManifestID,
		"session_id", sessObj.SessionID,
		"disclosures", len(msgs),
		"peer_measurement", hex.EncodeToString(peerMeasurement),
		"deadline", deadline.Format(time.RFC3339),
	)

	verified, err := sess.ServeOneJobVerified(sessCtx, req)
	if err != nil {
		d.abortJob(job, "serve", err, sess, log)
		return
	}
	out := verified.Output
	workerKID := string(verified.WorkerSigningKeyID)

	// Stage 6 — the candidate on record before it is judged.
	sum := sha256.Sum256(out.Bytes)
	if err := flow.CandidateReceived(orchestration.CandidateRecord{
		OutputKind: string(out.OutputKind), Bytes: len(out.Bytes), SHA256: hex.EncodeToString(sum[:]),
		ProducedAt: out.ProducedAt, WorkerSigningKeyID: workerKID,
	}); err != nil {
		d.abortJob(job, "candidate", err, sess, log)
		return
	}

	// The gate: the answer held to the sealed references on both
	// dimensions. An output that is not an answer aborts the flow.
	j, err := judge(job.Info.Gate, out)
	if err != nil {
		d.abortJob(job, "judge", err, sess, log)
		return
	}
	if j.GateErr == nil {
		if err := signVerdict(&j.Gate, d.mat.Store, d.mat.AuthoritySigningKeyID, d.mat.AuthoritySigningPublicKey); err != nil {
			d.abortJob(job, "judge", shared_errors.Authority("verdict_sign_failed", "sign the gate verdict", err), sess, log)
			return
		}
	}
	d.metrics.gateVerdicts.Inc(metrics.Label{Name: "level", Value: j.Gate.Level})

	// Stage 7 — validation: six operational sub-checks over the flow's own
	// artifacts, and the gate's two verdicts, on the record.
	vr, err := flow.Validate(orchestration.ValidateParams{
		Evaluated: map[validation_result.Dimension]valservice.EvaluatedDimension{
			validation_result.DimensionSemantic:   j.Semantic,
			validation_result.DimensionBehavioral: j.Behavioral,
		},
		TamperSignalled: tamper.Load(),
	})
	if err != nil {
		d.abortJob(job, "validate", err, sess, log)
		return
	}

	// Stages 8 and 9 — the decision, signed after its record; the seal.
	decision, err := flow.Decide()
	if err != nil {
		d.abortJob(job, "decide", err, sess, log)
		return
	}
	if _, err := flow.Seal(); err != nil {
		d.abortJob(job, "seal", err, sess, log)
		return
	}

	if decision.Release {
		d.queue.CompleteGated(job.ID, out, workerKID, j.Gate, &j.Top1, nil)
		d.metrics.releases.Inc(metrics.Label{Name: "decision", Value: "release"})
		d.metrics.jobsCompleted.Inc(metrics.Label{Name: "outcome", Value: "success"})
		d.metrics.lastSuccessUnix.Set(float64(d.clock.Now().Unix()))
		_ = sess.WriteShutdown(transport.CodeShutdownNormal, "sagvd: job complete")
		log.Info("sagvd release authorized",
			"manifest_id", man.ManifestID,
			"session_id", sessObj.SessionID,
			"decision_id", decision.DecisionID,
			"validation_result_id", vr.ValidationResultID,
			"level", j.Gate.Level,
			"door", j.Gate.Door,
			"rung", j.Gate.Rung,
			"fixtures", j.Gate.Fixtures,
			"top1_agreed", j.Top1.Agreed,
			"max_abs_err", j.Gate.SignedVerdict.Verdict.MaxAbsErr,
			"max_rel_err", j.Gate.SignedVerdict.Verdict.MaxRelErr,
			"output_bytes", len(out.Bytes),
			"worker_signing_kid", workerKID,
			"audit_tip", flow.Snapshot().AuditTip,
		)
		return
	}

	// Refused: the ladder's own error when no door opened, otherwise the
	// validation that refused.
	refusal := j.GateErr
	if refusal == nil {
		refusal = shared_errors.Operational(CodeReleaseRefused,
			fmt.Sprintf("release refused: validation %s (%s)", vr.OverallVerdict, firstFindingText(vr)), nil)
	}
	d.queue.CompleteGated(job.ID, out, workerKID, j.Gate, &j.Top1, refusal)
	d.metrics.releases.Inc(metrics.Label{Name: "decision", Value: "refuse"})
	d.metrics.jobsCompleted.Inc(metrics.Label{Name: "outcome", Value: outcomeFromError(refusal)})
	_ = sess.WriteShutdown(transport.CodeShutdownNormal, "sagvd: job judged")
	log.Warn("sagvd release refused",
		"manifest_id", man.ManifestID,
		"session_id", sessObj.SessionID,
		"decision_id", decision.DecisionID,
		"reason", decision.Reason,
		"validation_result_id", vr.ValidationResultID,
		"overall_verdict", vr.OverallVerdict,
		"level", j.Gate.Level,
		"fixtures", j.Gate.Fixtures,
		"top1_agreed", j.Top1.Agreed,
		"category", shared_errors.CategoryOf(refusal).String(),
		"code", shared_errors.CodeOf(refusal),
		"err", refusal,
		"worker_signing_kid", workerKID,
	)
}

// refuseAtTrust ends a job Trust Admission denied: the release decision
// on record refuses it citing the attestation, the flow is sealed, the
// worker is released for the next job.
func (d *Daemon) refuseAtTrust(job Job, dec trust.Decision, sess *server.Session, log *slog.Logger) {
	err := shared_errors.Authority(CodeTrustDenied, "trust admission denied the request: "+dec.Detail, nil)
	if _, decErr := job.Flow.Decide(); decErr != nil {
		d.abortJob(job, "decide", decErr, sess, log)
		return
	}
	if _, sealErr := job.Flow.Seal(); sealErr != nil {
		d.abortJob(job, "seal", sealErr, sess, log)
		return
	}
	d.queue.CompleteFailure(job.ID, err)
	d.metrics.releases.Inc(metrics.Label{Name: "decision", Value: "trust_denied"})
	d.metrics.jobsCompleted.Inc(metrics.Label{Name: "outcome", Value: "fail"})
	_ = sess.WriteShutdown(transport.CodeShutdownNormal, "sagvd: request denied at trust admission")
	log.Warn("sagvd trust admission denied the request",
		"attestation_id", dec.Result.AttestationID,
		"reason", dec.Reason,
		"detail", dec.Detail,
		"stop_serial", dec.StopSerial,
		"peer_provider", dec.PeerProvider,
		"peer_measurement", dec.PeerMeasurementHex,
	)
}

// abortJob ends a job the flow could not carry to a decision: on record
// first (the flow's abort), then in the queue, then on the wire.
func (d *Daemon) abortJob(job Job, stage string, err error, sess *server.Session, log *slog.Logger) {
	if auditErr := job.Flow.Abort(stage, err); auditErr != nil {
		log.Error("sagvd audit log refused a record", "stage", stage, "err", auditErr)
	}
	d.queue.CompleteFailure(job.ID, err)
	d.metrics.jobsCompleted.Inc(
		metrics.Label{Name: "outcome", Value: outcomeFromError(err)},
	)
	_ = sess.WriteShutdown(shared_errors.CodeOf(err), "sagvd: job failed")
	log.Warn("sagvd job failed",
		"stage", stage,
		"state", job.Flow.State().String(),
		"category", shared_errors.CategoryOf(err).String(),
		"code", shared_errors.CodeOf(err),
		"err", err,
	)
}

// recordRefusal puts a refused peer on record. A log that cannot take
// it is logged loudly; there is no job to fail.
func (d *Daemon) recordRefusal(phase, remote string, err error) {
	if auditErr := d.audit.TrustRefused(phase, remote, d.mat.PeerProvider, err); auditErr != nil {
		d.log.Error("sagvd audit log refused a record", "phase", phase, "err", auditErr)
	}
}

// jobRequestFrom is the JobRequest a signed manifest and its disclosures
// make on the Return Path wire: one SealedMaterialRef per disclosure, in
// sequence order, each under the AAD the disclosure was sealed with.
func jobRequestFrom(man rjm.ReconstructionJobManifest, msgs []disclosure_message.DisclosureMessage) (transport.JobRequest, error) {
	req := transport.JobRequest{
		Type:                   transport.FrameTypeJobRequest,
		SchemaVersion:          1,
		ManifestID:             man.ManifestID.String(),
		SessionID:              man.SessionID.String(),
		ExpectedOutputKind:     string(man.ExpectedOutputKind),
		ExpectedOutputMaxBytes: man.ExpectedOutputMaxBytes,
		Deadline:               man.Deadline,
		IssuedAt:               man.IssuedAt,
	}
	for i := range msgs {
		m := &msgs[i]
		aad, err := disclosure_message.BuildRecipientAADForMessage(m)
		if err != nil {
			return transport.JobRequest{}, err
		}
		req.SealedMaterial = append(req.SealedMaterial, transport.SealedMaterialRef{
			RecipientKeyID: m.RecipientKeyID.String(), Nonce: m.Nonce, Ciphertext: m.SealedPayload, AAD: aad,
		})
	}
	if err := req.Validate(); err != nil {
		return transport.JobRequest{}, err
	}
	frame, err := transport.EncodeBody(req)
	if err != nil {
		return transport.JobRequest{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "encode JobRequest", err)
	}
	if uint64(len(frame)) > uint64(transport.MaxFrameSize) {
		return transport.JobRequest{}, shared_errors.Operational(CodeGenomeTooLarge,
			fmt.Sprintf("the genome makes a %d-byte JobRequest; the Return Path carries frames of at most %d bytes", len(frame), transport.MaxFrameSize), nil)
	}
	return req, nil
}

// firstFindingText names the first finding of a validation result, for
// a refusal's message.
func firstFindingText(vr validation_result.ValidationResult) string {
	for _, dim := range []validation_result.Dimension{validation_result.DimensionOperational, validation_result.DimensionSemantic, validation_result.DimensionBehavioral} {
		if dv, ok := vr.Dimensions[dim]; ok && len(dv.Details) > 0 {
			return string(dim) + ": " + dv.Details[0].Code + ": " + dv.Details[0].Message
		}
	}
	return "no finding"
}

// ---- listener setup -----------------------------------------------------

// listen binds a TCP listener on the configured address. When TLS
// is disabled, returns the plain net.Listener; when enabled, the
// TLS wrap happens per-connection in serveOne so a stalled TLS
// handshake cannot block the accept loop.
func (d *Daemon) listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", d.cfg.Vault.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("sagvd: listen %q: %w", d.cfg.Vault.ListenAddress, err)
	}
	return ln, nil
}

// loadServerTLS assembles a *tls.Config for an mTLS server. Loads
// the server certificate + key and the client-CA bundle; sets
// ClientAuth to RequireAndVerifyClientCert so an unauthenticated
// worker cannot even begin a Return Path handshake.
func loadServerTLS(teeCfg TEEConfig, cfg TLSConfig) (*tls.Config, error) {
	certPEM, err := os.ReadFile(cfg.ServerCert)
	if err != nil {
		return nil, fmt.Errorf("sagvd: load server keypair: %w", err)
	}
	// The key file may be sealed to this host (`sagvd seal-keys`, ADR 0023).
	keyPEM, err := readSecret(teeCfg, cfg.ServerKey, 0, "vault.tls.server_key")
	if err != nil {
		return nil, fmt.Errorf("sagvd: load server keypair: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("sagvd: load server keypair: %w", err)
	}
	caBytes, err := os.ReadFile(cfg.ClientCAs)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read client CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("sagvd: client CA bundle contains no valid PEM certificates")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ---- metrics registration -----------------------------------------------

// registerDaemonMetrics registers the sagvd_* family on registry
// and returns the bundle. The start_unix gauge is set immediately
// so operators can compute uptime from a single /metrics scrape.
func registerDaemonMetrics(r *metrics.Registry, clock shared_time.Clock) *daemonMetrics {
	m := &daemonMetrics{
		jobsCompleted: r.NewCounter(
			"sagvd_jobs_completed_total",
			"Total jobs that reached a terminal state, labelled by outcome.",
		),
		gateVerdicts: r.NewCounter(
			"sagvd_gate_verdicts_total",
			"Gate verdicts on restored models, labelled by level (EXACT, EQUIVALENT, FAIL, ERROR).",
		),
		releases: r.NewCounter(
			"sagvd_release_decisions_total",
			"Release decisions signed by the authority, labelled by decision (release, refuse, trust_denied).",
		),
		sessionsOpened: r.NewCounter(
			"sagvd_sessions_opened_total",
			"Total Return Path sessions that completed the 4-frame handshake.",
		),
		handshakeFailure: r.NewCounter(
			"sagvd_handshake_failures_total",
			"Total Return Path handshake failures, labelled by phase (tls|handshake).",
		),
		queueDepth: r.NewGauge(
			"sagvd_queue_depth",
			"Pending jobs waiting for a worker to pick them up.",
		),
		lastSuccessUnix: r.NewGauge(
			"sagvd_last_success_unix",
			"Unix-seconds of the vault's last successful job (0 if none).",
		),
		startUnix: r.NewGauge(
			"sagvd_start_unix",
			"Unix-seconds of the vault process start time.",
		),
	}
	m.startUnix.Set(float64(clock.Now().Unix()))
	return m
}

// ---- helpers -------------------------------------------------------------

// outcomeFromError maps a classified error to the
// jobs_completed_total{outcome} label. The taxonomy matches
// cmd/acp-compute/jobOutcomeFromError so a Grafana dashboard can
// cross-reference the two sides.
func outcomeFromError(err error) string {
	switch shared_errors.CategoryOf(err) {
	case shared_errors.CategoryOperational, shared_errors.CategoryStructural:
		return "reject"
	case shared_errors.CategoryAuthority, shared_errors.CategoryIntegrity, shared_errors.CategoryIncident:
		return "fail"
	default:
		return "fail"
	}
}

// sleepContext blocks for d unless ctx is cancelled first. Returns
// true if the sleep ran to completion, false if ctx was cancelled.
func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
