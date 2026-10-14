// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/client"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// Dialer abstracts net.Dial-style entry so tests can plug an in-memory
// net.Conn pair instead of a real TCP dial. Matches the shape of
// (&net.Dialer{}).DialContext.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Daemon is the acp-compute runtime: a long-lived process that dials
// sagvd over the Return Path, serves exactly one job per connection,
// and tracks its liveness / readiness on a local HTTP surface.
//
// Lifecycle:
//
//	d, err := NewDaemon(cfg, materials, clock, logger)
//	...
//	go d.Run(ctx)   // blocks until ctx is cancelled
//	<-ctx.Done()
//	d.Shutdown(...) // flips health flags and stops the HTTP server
//
// The daemon is intentionally single-threaded in the dial loop: Phase 1
// is a demo, one job at a time, no concurrency to reason about. Phase 2
// introduces a bounded worker pool when multi-tenant parallelism is on
// the critical path.
type Daemon struct {
	cfg       Config
	mat       *materials
	clock     shared_time.Clock
	log       *slog.Logger
	recon     worker.Reconstructor
	dialer    Dialer
	tlsConfig *tls.Config

	health  *healthState
	metrics *daemonMetrics
}

// daemonMetrics is the internal bundle of counters/gauges the daemon
// drives. Exposed via the /metrics HTTP endpoint.
type daemonMetrics struct {
	jobsTotal       *Counter // labels: outcome={success|reject|fail}
	handshakeFail   *Counter // labels: phase
	dialFail        *Counter // unlabeled
	sessionsOpened  *Counter
	lastSuccessUnix *Gauge // Unix seconds of the last successful job
	connectedGauge  *Gauge // 1 while a session is active, else 0
	uptimeStartUnix *Gauge // fixed at construction — useful for "uptime = now - this"
}

// NewDaemon wires every piece the daemon needs. cfg is the validated
// on-disk Config. mat holds the loaded keys / TEE. A nil dialer
// defaults to net.Dialer{}; tests pass an in-memory stub.
//
// The caller is responsible for building the Reconstructor. Production
// uses worker.NewGenomeReconstructor (the vg_genome door behind the
// frozen R-11 interface); tests that want reproducibility against a
// fixed hash-expansion reference pass worker.NewDeterministicReconstructor.
// Both implement the interface, so this field's type
// (worker.Reconstructor) does not change with the backend.
func NewDaemon(
	cfg Config,
	mat *materials,
	clock shared_time.Clock,
	logger *slog.Logger,
	recon worker.Reconstructor,
	registry *Registry,
) (*Daemon, error) {
	if cfg.Vault.Address == "" {
		return nil, errors.New("acp-compute: Daemon requires cfg.Vault.Address")
	}
	if mat == nil {
		return nil, errors.New("acp-compute: Daemon requires non-nil materials")
	}
	if clock == nil {
		return nil, errors.New("acp-compute: Daemon requires non-nil clock")
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if recon == nil {
		return nil, errors.New("acp-compute: Daemon requires non-nil Reconstructor")
	}
	if registry == nil {
		return nil, errors.New("acp-compute: Daemon requires non-nil Registry")
	}

	var tlsConfig *tls.Config
	if cfg.Vault.TLS.Enabled {
		tc, err := loadClientTLS(cfg.TEE, cfg.Vault.TLS)
		if err != nil {
			return nil, err
		}
		tlsConfig = tc
	}

	return &Daemon{
		cfg:       cfg,
		mat:       mat,
		clock:     clock,
		log:       logger,
		recon:     recon,
		dialer:    &net.Dialer{Timeout: cfg.Runtime.HandshakeTimeout()},
		tlsConfig: tlsConfig,
		health:    newHealthState(),
		metrics:   registerDaemonMetrics(registry, clock),
	}, nil
}

// WithDialer installs a custom Dialer. Used by tests to substitute an
// in-memory pair; callers should not use it in production.
func (d *Daemon) WithDialer(dl Dialer) *Daemon {
	if dl != nil {
		d.dialer = dl
	}
	return d
}

// Health returns the underlying healthState so HealthServer can be
// constructed by main().
func (d *Daemon) Health() *healthState { return d.health }

// Run drives the dial → serve → close loop until ctx is cancelled.
// Every iteration is one complete Return Path session (one handshake,
// one job). On error we log, increment the appropriate metric, and
// back off exponentially up to DialBackoffMax; on success we sleep
// IdleBetweenJobs before the next dial so reconnect churn stays
// bounded.
//
// Run returns nil when ctx is cancelled (graceful shutdown). It
// returns a non-nil error only on an unrecoverable internal fault
// (currently: no such case — every wire-level failure loops).
func (d *Daemon) Run(ctx context.Context) error {
	backoff := d.cfg.Runtime.DialBackoffInitial()
	max := d.cfg.Runtime.DialBackoffMax()

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		err := d.runOnce(ctx)
		if err == nil {
			backoff = d.cfg.Runtime.DialBackoffInitial()
			if pause := d.cfg.Runtime.IdleBetweenJobs(); pause > 0 {
				if !sleepContext(ctx, pause) {
					return nil
				}
			}
			continue
		}

		// A cycle cut short by shutdown is the shutdown itself, not a
		// fault: its error is whatever the closed connection produced.
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		d.log.Warn("return-path cycle failed",
			"err", err,
			"category", shared_errors.CategoryOf(err).String(),
			"code", shared_errors.CodeOf(err),
			"backoff_ms", backoff.Milliseconds(),
		)

		if !sleepContext(ctx, backoff) {
			return nil
		}
		// Exponential backoff with cap.
		backoff *= 2
		if backoff > max {
			backoff = max
		}
	}
}

// Shutdown is the cooperative-close hook. It flips health flags so
// orchestrator probes start failing immediately. Callers should then
// cancel the context passed to Run; Run will return and the caller can
// Zeroize() the keystore.
func (d *Daemon) Shutdown() {
	d.health.MarkDown()
	d.metrics.connectedGauge.Set(0)
}

// Zeroize wipes the in-memory keystore. Call only after Run has
// returned; afterwards the daemon is unusable.
func (d *Daemon) Zeroize() {
	if d.mat != nil && d.mat.Store != nil {
		d.mat.Store.Zeroize()
	}
}

// ---- one-shot cycle ------------------------------------------------------

// runOnce performs one Return Path session. On any failure we return
// the error classified; Run drives the backoff around us.
func (d *Daemon) runOnce(parent context.Context) (retErr error) {
	// Bound the whole session by JobTimeout so a slow peer cannot wedge
	// the daemon forever. A separate bound covers the handshake phase
	// inside client.Dial.
	ctx, cancel := context.WithTimeout(parent, d.cfg.Runtime.JobTimeout())
	defer cancel()

	conn, err := d.dial(ctx)
	if err != nil {
		d.metrics.dialFail.Inc()
		return fmt.Errorf("acp-compute: dial %s: %w", d.cfg.Vault.Address, err)
	}
	// net.Conn I/O does not observe context cancellation. Close the
	// connection as soon as ctx is done — on SIGTERM (parent cancelled)
	// or when the job deadline passes — so a worker idling in a session
	// that is waiting for work never outlives its shutdown signal.
	stopOnDone := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopOnDone()

	sess, err := client.Dial(client.SessionConfig{
		Conn:             conn,
		Producer:         d.mat.Producer,
		Verifier:         d.mat.Verifier,
		Clock:            d.clock,
		Reconstructor:    d.recon,
		Signer:           d.mat.Store,
		SigningKeyID:     d.mat.SigningKeyID,
		Opener:           client.KeyStoreOpener{Sealer: d.mat.Store},
		HandshakeTimeout: d.cfg.Runtime.HandshakeTimeout(),
		OnSessionOpened: func(state *transport.SessionState) {
			d.metrics.sessionsOpened.Inc()
			d.metrics.connectedGauge.Set(1)
			d.log.Debug("return-path session opened",
				"peer_measurement", hex.EncodeToString(state.PeerMeasurement[:]),
				"ready_at", state.ReadyAt.Format(time.RFC3339Nano),
			)
		},
		OnJobAccepted: func(acc transport.JobAccept) {
			d.log.Debug("job accepted",
				"manifest_id", acc.ManifestID,
				"accepted_at", acc.AcceptedAt.Format(time.RFC3339Nano),
			)
		},
		OnSessionClosed: func(reason string) {
			d.metrics.connectedGauge.Set(0)
			d.log.Debug("return-path session closed", "reason", reason)
		},
		OnIntegrityFailure: func(ihErr error) {
			d.log.Error("integrity failure on wire",
				"err", ihErr,
				"code", shared_errors.CodeOf(ihErr),
			)
		},
	})
	if err != nil {
		_ = conn.Close()
		d.metrics.handshakeFail.Inc(Label{Name: "phase", Value: "handshake"})
		return fmt.Errorf("acp-compute: client.Dial: %w", err)
	}
	// Ensure the session is always closed, regardless of success path.
	defer func() {
		_ = sess.Close()
	}()

	if err := sess.ServeOneJob(ctx); err != nil {
		outcome := jobOutcomeFromError(err)
		d.metrics.jobsTotal.Inc(Label{Name: "outcome", Value: outcome})
		// Best-effort Shutdown frame with the classified reason.
		_ = sess.WriteShutdown(shared_errors.CodeOf(err), "acp-compute: job failed")
		return fmt.Errorf("acp-compute: ServeOneJob: %w", err)
	}

	// Clean close.
	_ = sess.WriteShutdown(transport.CodeShutdownNormal, "acp-compute: job complete")
	d.metrics.jobsTotal.Inc(Label{Name: "outcome", Value: "success"})
	d.metrics.lastSuccessUnix.Set(float64(d.clock.Now().Unix()))
	d.health.MarkReady()
	return nil
}

// dial opens a TCP (optionally TLS-wrapped) connection to the vault.
func (d *Daemon) dial(ctx context.Context) (net.Conn, error) {
	raw, err := d.dialer.DialContext(ctx, "tcp", d.cfg.Vault.Address)
	if err != nil {
		return nil, err
	}
	if d.tlsConfig == nil {
		return raw, nil
	}
	// Wrap in TLS and complete the handshake under the context deadline
	// so a peer that accepts the TCP SYN but stalls the TLS doesn't
	// block us indefinitely.
	tlsConn := tls.Client(raw, d.tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// ---- metrics registration ------------------------------------------------

func registerDaemonMetrics(r *Registry, clock shared_time.Clock) *daemonMetrics {
	m := &daemonMetrics{
		jobsTotal: r.NewCounter(
			"acp_compute_jobs_total",
			"Total Return Path jobs processed, labelled by outcome.",
		),
		handshakeFail: r.NewCounter(
			"acp_compute_handshake_failures_total",
			"Total handshake failures, labelled by phase.",
		),
		dialFail: r.NewCounter(
			"acp_compute_dial_failures_total",
			"Total TCP dial failures against the vault address.",
		),
		sessionsOpened: r.NewCounter(
			"acp_compute_sessions_opened_total",
			"Total Return Path sessions that completed handshake.",
		),
		lastSuccessUnix: r.NewGauge(
			"acp_compute_last_success_unix",
			"Unix-seconds of the worker's last successful job (0 if none).",
		),
		connectedGauge: r.NewGauge(
			"acp_compute_session_active",
			"1 while a Return Path session is active, 0 otherwise.",
		),
		uptimeStartUnix: r.NewGauge(
			"acp_compute_start_unix",
			"Unix-seconds of the worker process start time.",
		),
	}
	m.uptimeStartUnix.Set(float64(clock.Now().Unix()))
	return m
}

// ---- helpers -------------------------------------------------------------

// jobOutcomeFromError maps a classified error into a metric label.
// Integrity → "fail" (something broke); Operational → "reject"
// (manifest deadline / client-side rejection); Structural → "reject"
// (malformed wire frame); Authority / Incident → "fail".
func jobOutcomeFromError(err error) string {
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

// newCertPool parses PEM bytes into a *x509.CertPool. Rejects empty or
// unparseable bundles Structurally so an operator can see the cause.
func newCertPool(pem []byte) (*x509.CertPool, error) {
	if len(pem) == 0 {
		return nil, errors.New("acp-compute: CA bundle empty")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("acp-compute: CA bundle contains no valid PEM certificates")
	}
	return pool, nil
}

// loadClientTLS assembles a *tls.Config for an mTLS client. File
// reading uses plain os.ReadFile + tls.X509KeyPair; no custom cert
// parsing. The returned config sets ServerName for hostname
// verification and pins to the CA bundle in cfg.CABundle.
func loadClientTLS(teeCfg TEEConfig, cfg TLSConfig) (*tls.Config, error) {
	certPEM, err := os.ReadFile(cfg.ClientCert)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: load client keypair: %w", err)
	}
	// The key file may be sealed to this host (`acp-compute seal-keys`, ADR 0023).
	keyPEM, err := readSecret(teeCfg, cfg.ClientKey, 0, "vault.tls.client_key")
	if err != nil {
		return nil, fmt.Errorf("acp-compute: load client keypair: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: load client keypair: %w", err)
	}
	caBytes, err := os.ReadFile(cfg.CABundle)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: read CA bundle: %w", err)
	}
	pool, err := newCertPool(caBytes)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
