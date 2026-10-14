// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// The Return Path audit log (ADR 0014, 0015). Every decision the daemon
// takes goes to a durable, signed, hash-linked log BEFORE it becomes
// visible — the same log format, signing key and verifier (`acpctl audit
// verify`) as the cross-cloud releases, in its own file (audit.log_path).
//
// The nine-stage flow writes its own events through the orchestration
// Authority (REQUEST_RECEIVED through RELEASE_DECIDED and the incident
// arcs). This file holds the log itself and the two decisions the daemon
// takes before a flow exists — a peer refused at the TLS or Return Path
// handshake, a peer whose Evidence is too old to be handed a job — as
// TRUST_EVALUATED denials with no request behind them.
//
// A log that cannot be written stops the decision: a job is not queued,
// a candidate is not judged, a verdict is not surfaced (audit first-class,
// doctrine invariant #08).

// AuditConfig is where the daemon keeps its Return Path log.
type AuditConfig struct {
	// LogPath is the append-only bbolt file every Return Path decision
	// is written to, signed under keys.audit_signing and verified end to
	// end when it is opened. Required when gate jobs are enabled
	// (genome.bundle_dir). It must not be the cross-cloud subcommands'
	// crosscloud.audit_log_path: the daemon holds its file open, and one
	// process holds a log at a time.
	LogPath string `json:"log_path,omitempty"`
}

// CodeAuditUnavailable (Operational): the audit log could not record a
// decision, so the decision was not taken.
const CodeAuditUnavailable = "audit_unavailable"

// auditPayloadSchema names the payload shapes below.
const auditPayloadSchema = "vault-genome/returnpath-audit/v1"

// returnPathAudit is the daemon's audit log and refusal surface.
type returnPathAudit struct {
	emitter *chainAuditEmitter
	chain   chain.Chain // counts every append into sagvd_audit_events_total
	keyID   ids.KeyID
	keys    *keys.InMemoryStore
	log     *store.BBoltStore
}

// openReturnPathAudit opens (or creates) the daemon's audit log under
// keys.audit_signing, verifying whatever it already holds.
func openReturnPathAudit(cfg Config, clock shared_time.Clock, registry *metrics.Registry) (*returnPathAudit, error) {
	if cfg.Audit.LogPath == "" {
		return nil, nil
	}
	if cfg.Keys.AuditSigning.KeyID == "" || cfg.Keys.AuditSigning.SeedPath == "" {
		return nil, errors.New("sagvd: audit.log_path needs keys.audit_signing.kid and seed_path")
	}
	seed, err := readSecret(cfg.TEE, cfg.Keys.AuditSigning.SeedPath, crypto.Ed25519SeedSize, "keys.audit_signing.seed_path")
	if err != nil {
		return nil, err
	}
	kid := ids.KeyID(cfg.Keys.AuditSigning.KeyID)
	ks := keys.NewInMemoryStore(clock)
	if _, err := ks.RegisterSigningFromSeed(kid, keys.PurposeSigningAudit, seed); err != nil {
		return nil, fmt.Errorf("sagvd: register audit signing key: %w", err)
	}
	logStore, err := store.Open(cfg.Audit.LogPath)
	if err != nil {
		return nil, fmt.Errorf("sagvd: open audit.log_path: %w", err)
	}
	c, err := chain.OpenPersistentChain(logStore, ks)
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: audit.log_path %q: %w", cfg.Audit.LogPath, err)
	}
	counted := &countingChain{Chain: c}
	if registry != nil {
		counted.events = registry.NewCounter("sagvd_audit_events_total",
			"Return Path audit events appended to audit.log_path, labelled by kind.")
	}
	emitter, err := newChainAuditEmitter(counted, ks, kid, clock, "rp-evt-")
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: build Return Path audit emitter: %w", err)
	}
	emitter.counter = uint64(c.Len())
	return &returnPathAudit{emitter: emitter, chain: counted, keyID: kid, keys: ks, log: logStore}, nil
}

// Close releases the log. Safe on a nil receiver.
func (a *returnPathAudit) Close() error {
	if a == nil || a.log == nil {
		return nil
	}
	a.keys.Zeroize()
	return a.log.Close()
}

// Len is the number of events on record; Tip the hash of the last one.
func (a *returnPathAudit) Len() int {
	if a == nil {
		return 0
	}
	return a.chain.Len()
}

func (a *returnPathAudit) Tip() string {
	if a == nil {
		return ""
	}
	return hex.EncodeToString(a.chain.Tip())
}

// Chain, Signer and KeyID are what the orchestration Authority writes
// its events with. nil-safe: without a log there is no chain.
func (a *returnPathAudit) Chain() chain.Chain {
	if a == nil {
		return nil
	}
	return a.chain
}

func (a *returnPathAudit) Signer() keys.Signer {
	if a == nil {
		return nil
	}
	return a.keys
}

func (a *returnPathAudit) KeyID() ids.KeyID {
	if a == nil {
		return ""
	}
	return a.keyID
}

// emit appends one event with no request behind it; a failure is the
// audit_unavailable error the caller reports.
func (a *returnPathAudit) emit(kind audit_event.Kind, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: encode audit payload", err)
	}
	if _, err := a.emitter.Emit(kind, raw, "", "", ""); err != nil {
		return shared_errors.Operational(CodeAuditUnavailable,
			fmt.Sprintf("sagvd: the audit log did not record %s", kind), err)
	}
	return nil
}

// trustPayload is a TRUST_EVALUATED denial taken before any request: a
// peer refused, or a peer told to attest again.
type trustPayload struct {
	Schema             string     `json:"schema"`
	Outcome            string     `json:"outcome"` // deny
	Phase              string     `json:"phase"`   // tls | handshake | session
	RemoteAddr         string     `json:"remote_addr,omitempty"`
	PeerProvider       string     `json:"peer_provider"`
	PeerMeasurementHex string     `json:"peer_measurement_hex,omitempty"`
	EvidenceAt         *time.Time `json:"evidence_at,omitempty"`
	EvidenceAgeSeconds float64    `json:"evidence_age_seconds,omitempty"`
	MaxAgeSeconds      float64    `json:"evidence_max_age_seconds,omitempty"`
	Category           string     `json:"category,omitempty"`
	Code               string     `json:"code,omitempty"`
	Reason             string     `json:"reason,omitempty"`
}

// TrustRefused records a peer whose TLS or Return Path handshake was
// refused: no session opened, no job was handed out.
func (a *returnPathAudit) TrustRefused(phase, remote string, peer tee.Provider, err error) error {
	if a == nil {
		return nil
	}
	return a.emit(audit_event.KindTrustEvaluated, trustPayload{
		Schema: auditPayloadSchema, Outcome: "deny", Phase: phase, RemoteAddr: remote, PeerProvider: string(peer),
		Category: shared_errors.CategoryOf(err).String(), Code: shared_errors.CodeOf(err), Reason: err.Error(),
	})
}

// CodeEvidenceStale (Authority): the worker's Return Path Evidence is
// older than runtime.evidence_max_age; it must attest again before it is
// handed a job.
const CodeEvidenceStale = "evidence_stale"

// TrustStale records a session whose Evidence was too old to hand a job
// to: the session is closed, the job stays queued.
func (a *returnPathAudit) TrustStale(remote string, peer tee.Provider, measurement tee.Measurement, evidenceAt time.Time, age, maxAge time.Duration) error {
	if a == nil {
		return nil
	}
	at := evidenceAt.UTC()
	return a.emit(audit_event.KindTrustEvaluated, trustPayload{
		Schema: auditPayloadSchema, Outcome: "deny", Phase: "session", RemoteAddr: remote, PeerProvider: string(peer),
		PeerMeasurementHex: hex.EncodeToString(measurement), EvidenceAt: &at,
		EvidenceAgeSeconds: age.Seconds(), MaxAgeSeconds: maxAge.Seconds(),
		Category: shared_errors.CategoryAuthority.String(), Code: CodeEvidenceStale,
		Reason: fmt.Sprintf("the worker's Evidence is %s old, runtime.evidence_max_age is %s; attest again", age.Round(time.Second), maxAge),
	})
}

// countingChain counts every event appended to the log, by kind, into
// sagvd_audit_events_total. Every writer — the daemon's refusals, the
// Authority's flow events, the disclosure sequencer, the validation and
// incident services — goes through it.
type countingChain struct {
	chain.Chain
	events *metrics.Counter
}

func (c *countingChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	sealed, err := c.Chain.Append(evt, signer)
	if err == nil && c.events != nil {
		c.events.Inc(metrics.Label{Name: "kind", Value: string(sealed.Kind)})
	}
	return sealed, err
}
