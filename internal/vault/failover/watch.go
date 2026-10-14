// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// TriggerKind names a sign of failure.
type TriggerKind string

const (
	// TriggerCompromise: the sentinel reported that a tripwire fired.
	TriggerCompromise TriggerKind = "compromise-report"
	// TriggerHeartbeatTimeout: the sentinel's heartbeat stopped rising.
	TriggerHeartbeatTimeout TriggerKind = "heartbeat-timeout"
	// TriggerStoppedOverdue: the sentinel said it was stopped and did not
	// come back within the policy's grace.
	TriggerStoppedOverdue TriggerKind = "stopped-overdue"
)

// Trigger is a sign of failure the policy acts on.
type Trigger struct {
	Kind TriggerKind
	// At is when the primary failed, by the primary's own clock: when the
	// sentinel detected the compromise, or when it wrote its last
	// heartbeat. Genomes are chosen against it.
	At time.Time
	// ObservedAt is when the executor saw the trigger fire, by the release
	// authority's clock.
	ObservedAt time.Time
	// AliveObservedAt is when the executor last saw the heartbeat rise, by
	// the release authority's clock; zero if it never saw one.
	AliveObservedAt time.Time
	// Evidence is the signed record that fired it, as read.
	Evidence   []byte
	Compromise *sentinel.Compromise
	Heartbeat  *sentinel.Heartbeat
	// PrimaryMeasurement is what the record's TEE report attests, when
	// the policy pins the primary.
	PrimaryMeasurement tee.Measurement
	// Ignored lists the outbox records seen before the trigger that did not
	// count: unsigned, signed by another key, or put back out of order.
	Ignored []string
}

// reportedLast is the newest generation the primary said it sealed.
func (t Trigger) reportedLast() *sentinel.Link {
	if t.Compromise != nil {
		return t.Compromise.Last
	}
	if t.Heartbeat != nil {
		return t.Heartbeat.Last
	}
	return nil
}

// Watcher turns what the primary's outbox holds into a trigger. It trusts
// only what verifies under the policy's sentinel key; everything else it
// notes, once, as ignored.
type Watcher struct {
	policy  Policy
	outbox  string
	pub     ed25519.PublicKey
	primary tee.Verifier
	now     func() time.Time

	hb        *sentinel.Heartbeat
	hbRaw     []byte
	hbAt      tee.Measurement
	aliveAt   time.Time
	stoppedAt time.Time // when the executor first saw the sentinel say stopped
	seen      map[string]bool

	// Ignored lists the records that were present but did not count.
	Ignored []string
	// State says what the watcher is waiting for.
	State string
}

// NewWatcher watches outbox under p. primary verifies the records' TEE
// reports when p pins the primary; it is ignored otherwise.
func NewWatcher(p Policy, outbox string, now func() time.Time, primary tee.Verifier) *Watcher {
	pub, _ := p.Sentinel()
	return &Watcher{policy: p, outbox: outbox, pub: pub, primary: primary, now: now, seen: map[string]bool{}}
}

// attestedRecord is a record that can show its TEE report.
type attestedRecord interface {
	Attested(tee.Verifier) (tee.Measurement, error)
}

// attested checks a record's TEE report against the pinned primary and
// returns the measurement it attests; nil when the policy pins none.
func (w *Watcher) attested(rec attestedRecord) (tee.Measurement, error) {
	if !w.policy.PinsPrimary() {
		return nil, nil
	}
	m, err := rec.Attested(w.primary)
	if err != nil {
		return nil, err
	}
	if !w.policy.PrimaryAllows(m) {
		return nil, fmt.Errorf("attested by %s measurement %x, which the policy does not pin as the primary", w.policy.Primary.Kind, m)
	}
	return m, nil
}

func (w *Watcher) ignore(file string, err error) {
	note := fmt.Sprintf("%s: %v", file, err)
	if !w.seen[note] {
		w.seen[note] = true
		w.Ignored = append(w.Ignored, note)
	}
}

// Watch polls the outbox every poll until a trigger fires or ctx ends.
func (w *Watcher) Watch(ctx context.Context, poll time.Duration, log *slog.Logger) (*Trigger, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	state := ""
	for {
		if t := w.Observe(); t != nil {
			log.Warn("failover triggered", slog.String("trigger", string(t.Kind)), slog.Time("at", t.At))
			return t, nil
		}
		if w.State != state {
			state = w.State
			log.Info("failover watch", slog.String("state", state))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Observe reads the outbox once and returns the trigger that fired, if
// any. The heartbeat timeout runs on the release authority's clock, from
// the moment it last saw the heartbeat's sequence number rise, so no clock
// skew between the machines moves it.
func (w *Watcher) Observe() *Trigger {
	t := w.observe()
	if t != nil {
		t.Ignored = append([]string(nil), w.Ignored...)
	}
	return t
}

func (w *Watcher) observe() *Trigger {
	now := w.now().UTC()
	if w.policy.Triggers.CompromiseReport {
		c, raw, err := sentinel.ReadCompromise(w.outbox, w.pub)
		var m tee.Measurement
		if err == nil {
			m, err = w.attested(c)
		}
		switch {
		case err == nil:
			return &Trigger{Kind: TriggerCompromise, At: c.DetectedAt, ObservedAt: now, AliveObservedAt: w.aliveAt, Evidence: raw, Compromise: &c, Heartbeat: w.hb, PrimaryMeasurement: m}
		case !errors.Is(err, sentinel.ErrAbsent):
			w.ignore(sentinel.CompromiseFile, err)
		}
	}
	h, raw, err := sentinel.ReadHeartbeat(w.outbox, w.pub)
	var m tee.Measurement
	if err == nil && (w.hb == nil || h.Seq > w.hb.Seq) {
		m, err = w.attested(h)
	}
	switch {
	case err == nil && (w.hb == nil || h.Seq > w.hb.Seq):
		w.hb, w.hbRaw, w.hbAt, w.aliveAt = &h, raw, m, now
		if h.Status != sentinel.StatusStopped {
			w.stoppedAt = time.Time{}
		} else if w.stoppedAt.IsZero() {
			w.stoppedAt = now
		}
	case err == nil && h.Seq < w.hb.Seq:
		w.ignore(sentinel.HeartbeatFile, fmt.Errorf("sequence %d after %d: an older heartbeat was put back", h.Seq, w.hb.Seq))
	case err != nil && !errors.Is(err, sentinel.ErrAbsent):
		w.ignore(sentinel.HeartbeatFile, err)
	}
	if w.hb == nil {
		w.State = "waiting for the primary's first heartbeat"
		return nil
	}
	trigger := func(kind TriggerKind) *Trigger {
		return &Trigger{Kind: kind, At: w.hb.At, ObservedAt: now, AliveObservedAt: w.aliveAt, Evidence: w.hbRaw, Heartbeat: w.hb, PrimaryMeasurement: w.hbAt}
	}
	switch w.hb.Status {
	case sentinel.StatusCompromised:
		if w.policy.Triggers.CompromiseReport {
			return trigger(TriggerCompromise)
		}
	case sentinel.StatusStopped:
		grace := time.Duration(w.policy.Triggers.StoppedGraceSeconds) * time.Second
		if grace <= 0 {
			w.State = "the primary's sentinel was stopped by its operator: standing down"
			return nil
		}
		if now.Sub(w.stoppedAt) >= grace {
			return trigger(TriggerStoppedOverdue)
		}
		w.State = fmt.Sprintf("the primary's sentinel was stopped by its operator: standing down for %s more", (grace - now.Sub(w.stoppedAt)).Round(time.Second))
		return nil
	}
	if t := w.policy.Triggers.HeartbeatTimeoutSeconds; t > 0 && now.Sub(w.aliveAt) >= time.Duration(t)*time.Second {
		return trigger(TriggerHeartbeatTimeout)
	}
	w.State = "watching"
	return nil
}
