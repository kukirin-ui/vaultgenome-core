// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package sentinel

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Source is the state a sentinel keeps sealed.
type Source interface {
	Kind() string
	Ref() string
	// Fingerprint is cheap and changes whenever the content may have
	// changed; the sentinel reads it every tick.
	Fingerprint() (string, error)
	// Capture streams the payload (see bundle.Capture).
	Capture() bundle.Capture
}

// Config configures a sentinel.
type Config struct {
	Source Source
	// Outbox is the directory everything is written to.
	Outbox string
	// Escrow is the release authority's escrow public key: every genome's
	// key is encapsulated to it and nothing else keeps it.
	Escrow *ecdh.PublicKey
	// Key signs every record.
	Key ed25519.PrivateKey
	// Attestor, when set, is the primary's TEE: every record also carries
	// its report, bound to the record's content, and AttestorKind names
	// it (ADR 0017). A policy that pins the primary's measurement accepts
	// nothing without one.
	Attestor     tee.Producer
	AttestorKind tee.Provider
	// Parent, for an empty outbox, is the genome this state was restored
	// from: the first generation sealed here follows it.
	Parent *bundle.Identity
	Wires  []Wire
	// Interval is the time between ticks; Settle is how long the state must
	// stay unchanged before it is sealed, so a file being written is never
	// sealed half-way.
	Interval time.Duration
	Settle   time.Duration
	Clock    func() time.Time
	Log      *slog.Logger
}

// Outcome is how a sentinel's run ended.
type Outcome string

const (
	OutcomeStopped     Outcome = "stopped"
	OutcomeCompromised Outcome = "compromised"
)

// Result describes a finished run.
type Result struct {
	Outcome     Outcome
	Generations int // sealed during this run
	Last        *Link
	Compromise  *Compromise
}

// Sentinel keeps one state sealed and watches its wires.
type Sentinel struct {
	cfg Config
	id  string
	log *slog.Logger

	started   time.Time
	seq       uint64
	last      *SealRecord
	parent    *bundle.Identity
	sealedFP  string // fingerprint of the state last sealed (or found already sealed)
	seenFP    string // fingerprint seen at the last tick
	seenSince time.Time
	sealed    int
}

// New checks cfg, arms every wire and reads the outbox: a sentinel resumes
// the chain it finds there, and refuses an outbox a compromise report
// closed or whose newest genome does not check out.
func New(cfg Config) (*Sentinel, error) {
	switch {
	case cfg.Source == nil || cfg.Outbox == "" || cfg.Escrow == nil || len(cfg.Key) != ed25519.PrivateKeySize:
		return nil, errors.New("sentinel: source, outbox, escrow key and sentinel key required")
	case cfg.Interval <= 0:
		return nil, errors.New("sentinel: interval must be positive")
	case cfg.Settle < 0:
		return nil, errors.New("sentinel: settle must not be negative")
	case (cfg.Attestor == nil) != (cfg.AttestorKind == ""):
		return nil, errors.New("sentinel: attestor and attestor kind go together")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	pub := cfg.Key.Public().(ed25519.PublicKey)
	s := &Sentinel{cfg: cfg, id: KeyID(pub), log: cfg.Log.With(slog.String("sentinel", KeyID(pub))), started: cfg.Clock().UTC()}

	if err := os.MkdirAll(cfg.Outbox, 0o755); err != nil {
		return nil, err
	}
	if _, _, err := ReadCompromise(cfg.Outbox, pub); !errors.Is(err, ErrAbsent) {
		return nil, fmt.Errorf("sentinel: %s holds a compromise report (%v): this outbox is closed; start a new one once the incident is handled", cfg.Outbox, err)
	}
	chain, rejected, err := ReadChain(cfg.Outbox, pub)
	if err != nil {
		return nil, err
	}
	if len(rejected) > 0 {
		return nil, fmt.Errorf("sentinel: %s holds records that are not this sentinel's chain (%s: %s): refusing to add to it", cfg.Outbox, rejected[0].File, rejected[0].Reason)
	}
	if n := len(chain); n > 0 {
		last := chain[n-1]
		if _, _, err := CheckGenome(cfg.Outbox, last); err != nil {
			return nil, fmt.Errorf("sentinel: the newest genome in %s does not check out: %w", cfg.Outbox, err)
		}
		s.last = &last
		if cfg.Parent != nil {
			return nil, errors.New("sentinel: a parent is only for an empty outbox; this one continues its own chain")
		}
	}
	s.parent = cfg.Parent
	if h, _, err := ReadHeartbeat(cfg.Outbox, pub); err == nil {
		s.seq = h.Seq // heartbeats keep rising across restarts
	}
	for _, w := range cfg.Wires {
		if err := w.Arm(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ID is the sentinel's key ID.
func (s *Sentinel) ID() string { return s.id }

// Run ticks until ctx ends (outcome stopped) or a wire fires (outcome
// compromised). It returns an error only when it cannot write to the
// outbox; a seal that fails is logged and tried again.
func (s *Sentinel) Run(ctx context.Context) (Result, error) {
	s.log.Info("sentinel started", slog.String("outbox", s.cfg.Outbox), slog.Int("wires", len(s.cfg.Wires)))
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		if res, done, err := s.tick(); err != nil || done {
			return res, err
		}
		select {
		case <-ctx.Done():
			err := s.heartbeat(StatusStopped)
			s.log.Info("sentinel stopped", slog.Int("sealed", s.sealed))
			return Result{Outcome: OutcomeStopped, Generations: s.sealed, Last: s.lastLink()}, err
		case <-ticker.C:
		}
	}
}

func (s *Sentinel) now() time.Time { return s.cfg.Clock().UTC() }

// tick checks the wires first — nothing is sealed on a machine whose wires
// fired — then seals the state if it settled into something new, then
// writes a heartbeat.
func (s *Sentinel) tick() (Result, bool, error) {
	var trips []Trip
	for _, w := range s.cfg.Wires {
		if t := w.Check(); t != nil {
			trips = append(trips, *t)
		}
	}
	if len(trips) > 0 {
		c, err := s.compromised(trips)
		return Result{Outcome: OutcomeCompromised, Generations: s.sealed, Last: s.lastLink(), Compromise: &c}, true, err
	}
	s.maybeSeal()
	return Result{}, false, s.heartbeat(StatusWatching)
}

func (s *Sentinel) maybeSeal() {
	now := s.now()
	fp, err := s.cfg.Source.Fingerprint()
	if err != nil {
		s.log.Warn("state unreadable; not sealing", slog.String("err", err.Error()))
		return
	}
	if fp != s.seenFP {
		s.seenFP, s.seenSince = fp, now
	}
	if fp == s.sealedFP || now.Sub(s.seenSince) < s.cfg.Settle {
		return
	}
	if err := s.seal(fp); err != nil {
		// Most often the state changed while it was read: wait for it to
		// settle again.
		s.seenSince = now
		s.log.Warn("seal failed; will try again", slog.String("err", err.Error()))
	}
}

// seal describes the state and, if it is not what was last sealed, seals
// it as the next generation: bundle, then escrow envelope, then — the
// commit point — the signed record.
func (s *Sentinel) seal(fp string) error {
	src := s.cfg.Source
	h, err := bundle.Describe(src.Kind(), src.Ref(), src.Capture())
	if err != nil {
		return err
	}
	if s.last != nil && s.last.PayloadSHA256 == h.PayloadSHA256 {
		s.sealedFP = fp // the same content as the newest genome
		return nil
	}
	switch {
	case s.last != nil:
		h.Generation = s.last.Generation + 1
		h.ParentBundleSHA256 = s.last.BundleSHA256
		h.ParentPayloadSHA256 = strings.TrimPrefix(s.last.PayloadSHA256, "sha256:")
		h.ParentGeneration = s.last.Generation
	case s.parent != nil:
		h.Generation = s.parent.Header.Generation + 1
		h.ParentBundleSHA256 = s.parent.SHA256
		h.ParentPayloadSHA256 = strings.TrimPrefix(s.parent.Header.PayloadSHA256, "sha256:")
		h.ParentGeneration = s.parent.Header.Generation
	}
	gen := h.Generation
	h.SealedAt = s.now()
	staged := filepath.Join(s.cfg.Outbox, "."+BundleName(gen)+".partial")
	out, err := bundle.SealFile(staged, h, src.Capture())
	if err != nil {
		return err
	}
	env, err := escrow.Seal(out.DEK, out.Header.KeyID, s.cfg.Escrow)
	clear(out.DEK)
	var envRaw []byte
	if err == nil {
		envRaw, err = env.Marshal()
	}
	if err == nil {
		err = writeAtomic(s.cfg.Outbox, EscrowName(gen), append(envRaw, '\n'), false)
	}
	if err == nil {
		err = os.Rename(staged, filepath.Join(s.cfg.Outbox, BundleName(gen)))
	}
	if err != nil {
		_ = os.Remove(staged)
		return err
	}
	rec := SealRecord{
		Sentinel:           s.id,
		Generation:         gen,
		Bundle:             BundleName(gen),
		BundleSHA256:       out.SHA256,
		BundleBytes:        out.Size,
		KeyID:              out.Header.KeyID,
		Escrow:             EscrowName(gen),
		EscrowKey:          env.EscrowKey,
		PayloadSHA256:      out.Header.PayloadSHA256,
		ParentBundleSHA256: out.Header.ParentBundleSHA256,
		SealedAt:           out.Header.SealedAt,
	}
	if s.cfg.Attestor != nil {
		// The chip's word over the record, before the key's: a seal the
		// chip will not vouch for is not committed.
		if rec, err = AttestRecord(rec, s.cfg.Attestor, s.cfg.AttestorKind); err != nil {
			_ = os.Remove(filepath.Join(s.cfg.Outbox, BundleName(gen)))
			_ = os.Remove(filepath.Join(s.cfg.Outbox, EscrowName(gen)))
			return err
		}
	}
	rec, err = SignRecord(rec, s.cfg.Key)
	var raw []byte
	if err == nil {
		raw, err = encode(rec)
	}
	if err == nil {
		err = writeAtomic(s.cfg.Outbox, RecordName(gen), raw, true)
	}
	if err != nil {
		return err
	}
	s.last, s.parent, s.sealedFP = &rec, nil, fp
	s.sealed++
	s.log.Info("genome sealed",
		slog.Uint64("generation", gen),
		slog.String("key_id", rec.KeyID),
		slog.String("bundle_sha256", rec.BundleSHA256),
		slog.Int64("bundle_bytes", rec.BundleBytes),
		slog.String("payload_sha256", rec.PayloadSHA256))
	return nil
}

func (s *Sentinel) lastLink() *Link {
	if s.last == nil {
		return nil
	}
	l := s.last.Link()
	return &l
}

// heartbeat writes the next heartbeat. With an attestor, a heartbeat the
// chip will not vouch for is not written: the sequence does not move, the
// authority sees silence, and a primary whose chip stops answering times
// out like a dead one.
func (s *Sentinel) heartbeat(status string) error {
	h := Heartbeat{
		Sentinel:  s.id,
		Seq:       s.seq + 1,
		At:        s.now(),
		StartedAt: s.started,
		Status:    status,
		Last:      s.lastLink(),
		Wires:     len(s.cfg.Wires),
	}
	if s.cfg.Attestor != nil {
		var err error
		if h, err = AttestHeartbeat(h, s.cfg.Attestor, s.cfg.AttestorKind); err != nil {
			s.log.Warn("heartbeat not attested by the TEE; not written", slog.String("err", err.Error()))
			return nil
		}
	}
	h, err := SignHeartbeat(h, s.cfg.Key)
	var raw []byte
	if err == nil {
		raw, err = encode(h)
	}
	if err == nil {
		err = writeAtomic(s.cfg.Outbox, HeartbeatFile, raw, false)
	}
	if err == nil {
		s.seq = h.Seq
	}
	return err
}

// compromised writes the compromise report, then a last heartbeat that
// says so. Sealing has already stopped: tick never reaches maybeSeal once
// a wire fires.
func (s *Sentinel) compromised(trips []Trip) (Compromise, error) {
	c := Compromise{
		Sentinel:   s.id,
		DetectedAt: s.now(),
		Tripped:    trips,
		Last:       s.lastLink(),
	}
	if s.cfg.Attestor != nil {
		// The report is written even if the chip will not vouch for it:
		// a pinning authority ignores it and times out on the silence
		// that follows, which is the same failover, later.
		var err error
		if c, err = AttestCompromise(c, s.cfg.Attestor, s.cfg.AttestorKind); err != nil {
			s.log.Warn("compromise report not attested by the TEE; written unattested", slog.String("err", err.Error()))
			c.Attestation = nil
		}
	}
	c, err := SignCompromise(c, s.cfg.Key)
	var raw []byte
	if err == nil {
		raw, err = encode(c)
	}
	if err == nil {
		err = writeAtomic(s.cfg.Outbox, CompromiseFile, raw, false)
	}
	if err != nil {
		return c, err
	}
	for _, t := range trips {
		s.log.Error("tripwire fired", slog.String("wire", t.Wire), slog.String("target", t.Target), slog.String("got", t.Got))
	}
	// The compromise report is the artifact that matters and it is written.
	// The closing "compromised" heartbeat is a courtesy for a watcher that
	// reads heartbeats rather than the report; if it cannot be written, the
	// compromise still stands — do not turn a detected-and-reported
	// compromise into an error (which would read as "the sentinel failed").
	if err := s.heartbeat(StatusCompromised); err != nil {
		s.log.Warn("closing heartbeat after compromise not written", slog.String("err", err.Error()))
	}
	return c, nil
}
