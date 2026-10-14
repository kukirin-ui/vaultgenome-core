// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// Decisions recorded in FAILOVER_DECIDED.
const (
	DecisionFailover = "failover"
	DecisionDeclined = "declined"
)

// Report statuses.
const (
	StatusRestored = "restored" // the standby restored the genome and the receipt was confirmed
	StatusDeclined = "declined" // the policy did not allow a failover for this trigger
	StatusFailed   = "failed"   // a failover was decided and did not complete
)

// Config wires an executor.
type Config struct {
	Policy Policy
	// Outbox is the primary's outbox, as replicated to the release authority.
	Outbox string
	// Escrow is the release authority's escrow key.
	Escrow *ecdh.PrivateKey
	// Primary verifies the primary TEE's reports on the outbox's records;
	// required when the policy pins the primary (ADR 0017).
	Primary tee.Verifier
	// Coordinator releases keys under a release policy that includes this
	// failover policy's Gate, and confirms receipts (Config.Receipts set).
	Coordinator *kms.Coordinator
	// Audit is the log the coordinator appends to; Events reads it back.
	Audit  kms.AuditEmitter
	Events func() []audit_event.AuditEvent
	IDs    kms.IDGenerator
	Clock  shared_time.Clock
	// Poll is how often the outbox is read; ConfirmWait bounds how long the
	// standby may take to restore and gate once its key is released.
	Poll        time.Duration
	ConfirmWait time.Duration
	Log         *slog.Logger
}

// Executor carries out one failover policy.
type Executor struct {
	cfg Config
	log *slog.Logger
}

// New checks the policy is well formed and not spent. Whether it still
// stands is decided when a trigger fires, and a policy that has expired by
// then is declined on the record.
func New(cfg Config) (*Executor, error) {
	switch {
	case cfg.Outbox == "" || cfg.Escrow == nil || cfg.Coordinator == nil || cfg.Audit == nil || cfg.Events == nil || cfg.IDs == nil || cfg.Clock == nil:
		return nil, errors.New("failover: outbox, escrow key, coordinator, audit log, ID generator and clock required")
	case cfg.Poll <= 0 || cfg.ConfirmWait <= 0:
		return nil, errors.New("failover: poll and confirm wait must be positive")
	}
	if err := cfg.Policy.validate(); err != nil {
		return nil, err
	}
	if cfg.Policy.PinsPrimary() && cfg.Primary == nil {
		return nil, fmt.Errorf("failover: the policy pins the primary's %s TEE, and no verifier for it was given", cfg.Policy.Primary.Kind)
	}
	if err := CheckNotSpent(cfg.Policy, cfg.Events()); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	_, sid := cfg.Policy.Sentinel()
	return &Executor{
		cfg: cfg,
		log: cfg.Log.With(slog.Uint64("policy_serial", cfg.Policy.Serial), slog.String("sentinel", sid)),
	}, nil
}

// Run watches until a trigger fires, then acts on it. It returns when the
// failover completed, was declined or failed — or, with ctx's error, when
// ctx ends first. A release authority that should not hold its audit log
// open while it waits watches with a Watcher and calls Failover itself.
func (e *Executor) Run(ctx context.Context) (Report, error) {
	t, err := NewWatcher(e.cfg.Policy, e.cfg.Outbox, e.cfg.Clock.Now, e.cfg.Primary).Watch(ctx, e.cfg.Poll, e.log)
	if err != nil {
		return Report{}, err
	}
	return e.Failover(ctx, *t)
}

// decidedPayload is the JSON payload of a KindFailoverDecided audit event.
type decidedPayload struct {
	Decision       string      `json:"decision"`
	Reason         string      `json:"reason"`
	PolicySerial   uint64      `json:"policy_serial"`
	PolicySHA256   []byte      `json:"policy_sha256"`
	Sentinel       string      `json:"sentinel"`
	Trigger        TriggerKind `json:"trigger"`
	TriggerAt      time.Time   `json:"trigger_at"`
	EvidenceSHA256 []byte      `json:"evidence_sha256"`
	// PrimaryMeasurementHex is what the trigger's record's TEE report
	// attests, when the policy pins the primary.
	PrimaryMeasurementHex string         `json:"primary_measurement_hex,omitempty"`
	DecisionID            ids.DecisionID `json:"decision_id,omitempty"`
	Generation            *uint64        `json:"generation,omitempty"`
	BundleSHA256          string         `json:"bundle_sha256,omitempty"`
	KeyID                 ids.KeyID      `json:"key_id,omitempty"`
	SealedAt              *time.Time     `json:"sealed_at,omitempty"`
	RPOSeconds            *float64       `json:"rpo_seconds,omitempty"`
	ChainEnd              *uint64        `json:"chain_end,omitempty"`
	ReportedLast          *uint64        `json:"reported_last,omitempty"`
	StandbyKind           tee.Provider   `json:"standby_kind"`
	StandbyEndpoint       string         `json:"standby_endpoint"`
	DecidedAt             time.Time      `json:"decided_at"`
}

// Failover acts on a trigger: choose the genome, record the decision,
// release its escrowed key to the standby, confirm the standby's receipt.
func (e *Executor) Failover(ctx context.Context, t Trigger) (Report, error) {
	p := e.cfg.Policy
	_, sid := p.Sentinel()
	evidence := sha256.Sum256(t.Evidence)
	rep := newReport(p, sid, t, evidence[:], t.Ignored)

	choice, why, err := Choose(e.cfg.Outbox, p, t, escrow.KeyTag(e.cfg.Escrow.PublicKey()), e.cfg.Primary)
	if err != nil {
		return rep.fail(err), err
	}
	rep.SetAside = choice.SetAside
	if why == "" {
		if err := p.ActiveAt(e.cfg.Clock.Now()); err != nil {
			why = err.Error()
		}
	}
	decidedAt := e.cfg.Clock.Now().UTC()
	payload := decidedPayload{
		Decision:        DecisionFailover,
		PolicySerial:    p.Serial,
		PolicySHA256:    p.Digest(),
		Sentinel:        sid,
		Trigger:         t.Kind,
		TriggerAt:       t.At,
		EvidenceSHA256:  evidence[:],
		StandbyKind:     tee.Provider(p.Standby.Kind),
		StandbyEndpoint: p.Standby.Endpoint,
		DecidedAt:       decidedAt,
	}
	if len(t.PrimaryMeasurement) > 0 {
		payload.PrimaryMeasurementHex = hex.EncodeToString(t.PrimaryMeasurement)
	}
	payload.ChainEnd = choice.ChainEnd
	if l := t.reportedLast(); l != nil {
		g := l.Generation
		payload.ReportedLast = &g
	}
	if choice.Record.KeyID != "" {
		g, sealed, rpo := choice.Record.Generation, choice.Record.SealedAt, choice.RPO.Seconds()
		payload.Generation, payload.BundleSHA256, payload.KeyID, payload.SealedAt, payload.RPOSeconds = &g, choice.Record.BundleSHA256, ids.KeyID(choice.Record.KeyID), &sealed, &rpo
		rep.Genome = genomeReport(choice)
	}
	if why != "" {
		payload.Decision, payload.Reason = DecisionDeclined, why
	} else {
		if payload.DecisionID, err = e.cfg.IDs.NewDecisionID(); err != nil {
			return rep.fail(err), err
		}
		payload.Reason = fmt.Sprintf("%s under failover policy serial %d: restore generation %d on the standby", t.Kind, p.Serial, choice.Record.Generation)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return rep.fail(err), err
	}
	auditID, err := e.cfg.Audit.Emit(audit_event.KindFailoverDecided, raw, "", "", "")
	if err != nil {
		return rep.fail(err), err
	}
	rep.Decision = &DecisionReport{Decision: payload.Decision, Reason: payload.Reason, DecisionID: payload.DecisionID, AuditID: auditID, DecidedAt: decidedAt}
	if payload.Decision == DecisionDeclined {
		e.log.Warn("failover declined", slog.String("reason", why))
		rep.Status = StatusDeclined
		return rep, nil
	}
	e.log.Warn("failover decided", slog.String("decision_id", string(payload.DecisionID)), slog.Uint64("generation", choice.Record.Generation), slog.String("key_id", choice.Record.KeyID))

	// The key, from escrow, only now — and only to the standby.
	dek, err := escrow.Open(choice.Envelope, e.cfg.Escrow)
	if err != nil {
		return rep.fail(err), err
	}
	res, err := e.cfg.Coordinator.CoordinateRestore(ctx, kms.CoordinationRequest{
		DecisionID:          payload.DecisionID,
		DestinationKind:     tee.Provider(p.Standby.Kind),
		DestinationEndpoint: p.Standby.Endpoint,
		KeysToRelease:       []kms.KeyMaterial{{KeyID: ids.KeyID(choice.Record.KeyID), Purpose: krt.PurposeSealing, Plaintext: dek}},
	})
	clear(dek)
	if err != nil {
		return rep.fail(err), err
	}
	rep.Release = &ReleaseReport{
		RequestID:              res.HandshakeRequestID,
		TokenID:                res.TokenID,
		DestinationKind:        p.Standby.Kind,
		DestinationMeasurement: hex.EncodeToString(res.DestinationMeasurement),
		PolicyVersion:          res.PolicyVersion,
		AuthorizedAt:           res.DispatchedAt,
		AuditID:                res.KeyReleaseAuditID,
	}
	e.log.Info("genome key released to the standby", slog.String("request_id", string(res.HandshakeRequestID)))

	release, err := kms.FindAuthorizedRelease(e.cfg.Events(), payload.DecisionID)
	if err != nil {
		return rep.fail(err), err
	}
	creq := kms.ConfirmRequest{
		Release:             release,
		DestinationEndpoint: p.Standby.Endpoint,
		KeyID:               ids.KeyID(choice.Record.KeyID),
		Expect:              &choice.Expected,
		RequireGate:         p.RequireGate,
	}
	confirmed, err := e.confirm(ctx, creq)
	if err != nil {
		return rep.fail(err), err
	}
	rep.Restore = restoreReport(confirmed, p.RequireGate)
	rep.Status = StatusRestored
	rep.Timing = timing(t, choice, rep.Release.AuthorizedAt, confirmed)
	e.log.Info("failover complete: the standby restored the genome", slog.Float64("failover_seconds", rep.Timing.FailoverSeconds), slog.Float64("rpo_seconds", rep.Timing.RPOSeconds))
	return rep, nil
}

// confirm asks for the standby's receipt until it confirms, fails for a
// reason other than "not yet", or ConfirmWait runs out.
func (e *Executor) confirm(ctx context.Context, req kms.ConfirmRequest) (kms.ConfirmResult, error) {
	deadline := time.Now().Add(e.cfg.ConfirmWait)
	for {
		res, err := e.cfg.Coordinator.ConfirmRestore(ctx, req)
		if err == nil || !shared_errors.Is(err, shared_errors.CategoryOperational) || !time.Now().Add(e.cfg.Poll).Before(deadline) {
			return res, err
		}
		select {
		case <-ctx.Done():
			return kms.ConfirmResult{}, ctx.Err()
		case <-time.After(e.cfg.Poll):
		}
	}
}

// Report is what a failover run did, for the operator and the record.
type Report struct {
	Status       string              `json:"status"`
	Error        string              `json:"error,omitempty"`
	PolicySerial uint64              `json:"policy_serial"`
	PolicySHA256 string              `json:"policy_sha256"`
	Sentinel     string              `json:"sentinel"`
	Trigger      *TriggerReport      `json:"trigger,omitempty"`
	Decision     *DecisionReport     `json:"decision,omitempty"`
	Genome       *GenomeReport       `json:"genome,omitempty"`
	Release      *ReleaseReport      `json:"release,omitempty"`
	Restore      *RestoreReport      `json:"restore,omitempty"`
	Timing       *Timing             `json:"timing,omitempty"`
	SetAside     []sentinel.Rejected `json:"set_aside,omitempty"`
	Ignored      []string            `json:"ignored,omitempty"`
}

// TriggerReport describes the trigger.
type TriggerReport struct {
	Kind            TriggerKind `json:"kind"`
	At              time.Time   `json:"at"`
	ObservedAt      time.Time   `json:"observed_at"`
	AliveObservedAt *time.Time  `json:"alive_observed_at,omitempty"`
	EvidenceSHA256  string      `json:"evidence_sha256"`
	// PrimaryMeasurementHex is what the record's TEE report attests, when
	// the policy pins the primary.
	PrimaryMeasurementHex string          `json:"primary_measurement_hex,omitempty"`
	Tripped               []sentinel.Trip `json:"tripped,omitempty"`
	ReportedLast          *sentinel.Link  `json:"reported_last,omitempty"`
}

// DecisionReport is the recorded decision.
type DecisionReport struct {
	Decision   string           `json:"decision,omitempty"`
	Reason     string           `json:"reason,omitempty"`
	DecisionID ids.DecisionID   `json:"decision_id,omitempty"`
	AuditID    ids.AuditEventID `json:"audit_id,omitempty"`
	DecidedAt  time.Time        `json:"decided_at"`
}

// GenomeReport is the genome chosen.
type GenomeReport struct {
	Generation    uint64    `json:"generation"`
	Bundle        string    `json:"bundle"`
	BundleSHA256  string    `json:"bundle_sha256"`
	BundleBytes   int64     `json:"bundle_bytes"`
	KeyID         string    `json:"key_id"`
	PayloadSHA256 string    `json:"payload_sha256"`
	TreeSHA256    string    `json:"tree_sha256"`
	SealedAt      time.Time `json:"sealed_at"`
	ChainEnd      *uint64   `json:"chain_end,omitempty"`
}

// ReleaseReport is the key release to the standby.
type ReleaseReport struct {
	RequestID              ids.RequestID    `json:"request_id"`
	TokenID                ids.DecisionID   `json:"token_id"`
	DestinationKind        string           `json:"destination_kind"`
	DestinationMeasurement string           `json:"destination_measurement_hex"`
	PolicyVersion          string           `json:"policy_version"`
	AuthorizedAt           time.Time        `json:"authorized_at"`
	AuditID                ids.AuditEventID `json:"audit_id"`
}

// RestoreReport is the standby's confirmed restore.
type RestoreReport struct {
	KeyReceivedAt  time.Time        `json:"key_received_at"`
	RestoredAt     time.Time        `json:"restored_at"`
	RestoreSeconds float64          `json:"restore_seconds"`
	Files          int              `json:"files"`
	Bytes          int64            `json:"bytes"`
	TreeSHA256     string           `json:"tree_sha256"`
	Gate           *receipt.Gate    `json:"gate,omitempty"`
	RequiredGate   string           `json:"required_gate,omitempty"`
	ReceiptSHA256  string           `json:"receipt_sha256"`
	ConfirmedAt    time.Time        `json:"confirmed_at"`
	AuditID        ids.AuditEventID `json:"audit_id"`
}

// Timing is how long the failover took and how much state it lost.
type Timing struct {
	// RPOSeconds: the trigger less the chosen genome's seal time, both by
	// the primary's clock — the state the restored genome does not hold.
	RPOSeconds float64 `json:"rpo_seconds"`
	// DetectSeconds: for a lost heartbeat, from the last heartbeat seen to
	// the trigger, by the release authority's clock (the timeout, plus up
	// to one poll); for a compromise report, from the sentinel's detection
	// to the executor seeing the report, across both clocks.
	DetectSeconds float64 `json:"detect_seconds"`
	// ReleaseSeconds: trigger observed to key release authorised.
	ReleaseSeconds float64 `json:"release_seconds"`
	// RestoreSeconds and GateSeconds: on the standby, by its clock.
	RestoreSeconds float64 `json:"restore_seconds"`
	GateSeconds    float64 `json:"gate_seconds,omitempty"`
	// FailoverSeconds: trigger observed to restore confirmed, by the
	// release authority's clock.
	FailoverSeconds float64 `json:"failover_seconds"`
	// RTOSeconds: DetectSeconds plus FailoverSeconds — from the failure
	// the trigger records to a confirmed, gated restore on the standby.
	RTOSeconds float64 `json:"rto_seconds"`
}

func newReport(p Policy, sid string, t Trigger, evidence []byte, ignored []string) Report {
	rep := Report{
		PolicySerial: p.Serial,
		PolicySHA256: hex.EncodeToString(p.Digest()),
		Sentinel:     sid,
		Trigger: &TriggerReport{
			Kind:           t.Kind,
			At:             t.At,
			ObservedAt:     t.ObservedAt,
			EvidenceSHA256: hex.EncodeToString(evidence),
			ReportedLast:   t.reportedLast(),
		},
		Ignored: ignored,
	}
	if !t.AliveObservedAt.IsZero() {
		at := t.AliveObservedAt
		rep.Trigger.AliveObservedAt = &at
	}
	if len(t.PrimaryMeasurement) > 0 {
		rep.Trigger.PrimaryMeasurementHex = hex.EncodeToString(t.PrimaryMeasurement)
	}
	if t.Compromise != nil {
		rep.Trigger.Tripped = t.Compromise.Tripped
	}
	return rep
}

func (r Report) fail(err error) Report {
	r.Status, r.Error = StatusFailed, err.Error()
	return r
}

func genomeReport(c Choice) *GenomeReport {
	return &GenomeReport{
		Generation:    c.Record.Generation,
		Bundle:        c.Record.Bundle,
		BundleSHA256:  c.Record.BundleSHA256,
		BundleBytes:   c.Record.BundleBytes,
		KeyID:         c.Record.KeyID,
		PayloadSHA256: c.Record.PayloadSHA256,
		TreeSHA256:    c.Expected.TreeSHA256,
		SealedAt:      c.Record.SealedAt,
		ChainEnd:      c.ChainEnd,
	}
}

func restoreReport(c kms.ConfirmResult, required string) *RestoreReport {
	rc := c.Receipt
	return &RestoreReport{
		KeyReceivedAt:  rc.KeyReceivedAt,
		RestoredAt:     rc.RestoredAt,
		RestoreSeconds: rc.RestoreSeconds,
		Files:          rc.Files,
		Bytes:          rc.Bytes,
		TreeSHA256:     rc.TreeSHA256,
		Gate:           rc.Gate,
		RequiredGate:   required,
		ReceiptSHA256:  hex.EncodeToString(c.ReceiptSHA256),
		ConfirmedAt:    c.ConfirmedAt,
		AuditID:        c.AuditID,
	}
}

func timing(t Trigger, c Choice, authorizedAt time.Time, confirmed kms.ConfirmResult) *Timing {
	tm := &Timing{
		RPOSeconds:      c.RPO.Seconds(),
		ReleaseSeconds:  authorizedAt.Sub(t.ObservedAt).Seconds(),
		RestoreSeconds:  confirmed.Receipt.RestoreSeconds,
		FailoverSeconds: confirmed.ConfirmedAt.Sub(t.ObservedAt).Seconds(),
	}
	if g := confirmed.Receipt.Gate; g != nil {
		tm.GateSeconds = g.BackendSeconds
	}
	switch {
	case t.Kind == TriggerHeartbeatTimeout && !t.AliveObservedAt.IsZero():
		tm.DetectSeconds = t.ObservedAt.Sub(t.AliveObservedAt).Seconds()
	default:
		tm.DetectSeconds = max(0, t.ObservedAt.Sub(t.At).Seconds())
	}
	tm.RTOSeconds = tm.DetectSeconds + tm.FailoverSeconds
	return tm
}
