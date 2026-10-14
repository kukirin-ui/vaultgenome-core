// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// The limits on the primary's word (ADR 0017): its TEE must vouch for
// every record when the policy pins it; `stopped` stands the authority
// down only for the policy's grace; nothing past the sentinel's last
// attested word is restored.

func primaryTEE(t *testing.T) (*tee.Simulated, tee.Verifier) {
	t.Helper()
	p, err := tee.NewSimulated([]byte("primary-v1"), bytes.Repeat([]byte{0x21}, 32))
	must(t, err)
	return p, tee.NewSimulatedVerifier(p.PublicKey(), p.Measurement())
}

// pinned returns d's policy pinning the primary's simulated TEE.
func (d *drill) pinned(primary *tee.Simulated, mutate ...func(*Policy)) Policy {
	p := d.policy()
	p.Primary = &Primary{Kind: string(tee.ProviderSimulated), Measurements: []string{hex.EncodeToString(primary.Measurement())}, AttestorPublicKey: primary.PublicKey()}
	for _, m := range mutate {
		m(&p)
	}
	signed, err := Sign(p, d.operator)
	must(d.t, err)
	return signed
}

// attested runs the primary's sentinel with its TEE attesting every record.
func (d *drill) attested(ctx context.Context, primary *tee.Simulated) <-chan sentinel.Result {
	d.t.Helper()
	s, err := sentinel.New(sentinel.Config{
		Source: dirSource{d.state}, Outbox: d.outbox, Escrow: d.escrow.PublicKey(), Key: d.sentinelKey,
		Attestor: primary, AttestorKind: tee.ProviderSimulated,
		Wires: []sentinel.Wire{&sentinel.PathWire{Path: d.canary}}, Interval: 20 * time.Millisecond, Settle: 40 * time.Millisecond,
	})
	must(d.t, err)
	ctx, cancel := context.WithCancel(ctx)
	out := make(chan sentinel.Result, 1)
	done := make(chan struct{})
	d.t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		res, err := s.Run(ctx)
		if err != nil {
			d.t.Errorf("sentinel: %v", err)
		}
		out <- res
	}()
	return out
}

func TestPolicyPinsThePrimary(t *testing.T) {
	_, op := operatorKey(t)
	sPub, _ := operatorKey(t)
	primary, _ := primaryTEE(t)
	base := func() Policy {
		p := testPolicy(sPub)
		p.Primary = &Primary{Kind: string(tee.ProviderSimulated), Measurements: []string{hex.EncodeToString(primary.Measurement())}, AttestorPublicKey: primary.PublicKey()}
		p.Triggers.StoppedGraceSeconds = 60
		return p
	}
	signed, err := Sign(base(), op)
	must(t, err)
	if !signed.PinsPrimary() || !signed.PrimaryAllows(primary.Measurement()) || signed.PrimaryAllows(bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("the pin does not hold")
	}
	raw, err := json.Marshal(signed)
	must(t, err)
	if !strings.Contains(string(raw), `"stopped_grace_seconds":60`) || !strings.Contains(string(raw), `"primary":{`) {
		t.Fatalf("policy %s", raw)
	}
	for name, mutate := range map[string]func(*Policy){
		"unknown kind":        func(p *Policy) { p.Primary.Kind = "quantum" },
		"no measurement":      func(p *Policy) { p.Primary.Measurements = nil },
		"upper-case hex":      func(p *Policy) { p.Primary.Measurements = []string{strings.ToUpper(p.Primary.Measurements[0])} },
		"simulated, no key":   func(p *Policy) { p.Primary.AttestorPublicKey = nil },
		"hardware with a key": func(p *Policy) { p.Primary.Kind = string(tee.ProviderGCPSEVSNP) },
		"negative grace":      func(p *Policy) { p.Triggers.StoppedGraceSeconds = -1 },
	} {
		p := base()
		mutate(&p)
		if _, err := Sign(p, op); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	hw := base()
	hw.Primary = &Primary{Kind: string(tee.ProviderGCPSEVSNP), Measurements: []string{hex.EncodeToString(bytes.Repeat([]byte{7}, 48))}}
	if _, err := Sign(hw, op); err != nil {
		t.Fatalf("a hardware primary pinned by measurement alone: %v", err)
	}
	unpinned := testPolicy(sPub)
	if unpinned.PinsPrimary() || unpinned.PrimaryAllows(primary.Measurement()) {
		t.Fatal("an unpinned policy pins")
	}
}

// Under a pinning policy the drill runs as before — the records carry the
// chip's word — and the decision names the primary's measurement.
func TestFailoverOnCompromiseWithAPinnedPrimary(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	primary, verifier := primaryTEE(t)
	pol := d.pinned(primary)
	d.coordinator(mustRegistry(t, d), mustAuthority(t))
	if _, err := New(Config{Policy: pol, Outbox: d.outbox, Escrow: d.escrow, Coordinator: d.coord, Audit: d.audit, Events: d.audit.Events,
		IDs: &seqIDs{}, Clock: d.clock(), Poll: 20 * time.Millisecond, ConfirmWait: 20 * time.Second}); err == nil || !strings.Contains(err.Error(), "no verifier") {
		t.Fatalf("a pinning policy without a verifier: %v", err)
	}
	ex, err := New(Config{Policy: pol, Outbox: d.outbox, Escrow: d.escrow, Primary: verifier, Coordinator: d.coord, Audit: d.audit, Events: d.audit.Events,
		IDs: &seqIDs{}, Clock: d.clock(), Poll: 20 * time.Millisecond, ConfirmWait: 20 * time.Second})
	must(t, err)
	reports := make(chan Report, 1)
	go func() {
		rep, err := ex.Run(context.Background())
		if err != nil {
			t.Errorf("executor: %v", err)
		}
		reports <- rep
	}()
	results := d.attested(context.Background(), primary)
	d.waitChain(1)
	writeModel(t, d.state, "weights v2", 1.5, -2)
	chain := d.waitChain(2)
	must(t, os.WriteFile(d.canary, []byte("read by an intruder"), 0o600))
	<-results

	rep := <-reports
	if rep.Status != StatusRestored || rep.Trigger.Kind != TriggerCompromise || rep.Genome == nil || rep.Genome.Generation != 1 {
		t.Fatalf("report %+v", rep)
	}
	want := hex.EncodeToString(primary.Measurement())
	if rep.Trigger.PrimaryMeasurementHex != want {
		t.Fatalf("trigger attested by %q, want %q", rep.Trigger.PrimaryMeasurementHex, want)
	}
	if p := decidedPayloadOf(t, d.audit.Events()); p.PrimaryMeasurementHex != want {
		t.Fatalf("decision names primary %q", p.PrimaryMeasurementHex)
	}
	if got := d.restored(chain[1].KeyID); got != "weights v2" {
		t.Fatalf("restored %q", got)
	}
}

// The sentinel's seed stolen, the chip not: forged heartbeats keep no
// authority quiet, a forged compromise report moves nothing, and the
// silence that is left fails over.
func TestStolenSeedWithoutTheChipIsSilence(t *testing.T) {
	d := newDrill(t)
	primary, verifier := primaryTEE(t)
	pol := d.pinned(primary)
	ctx, cancel := context.WithCancel(context.Background())
	results := d.attested(ctx, primary)
	chain := d.waitChain(1)
	// A genuine heartbeat from the primary while it watched, kept aside.
	pub := d.sentinelKey.Public().(ed25519.PublicKey)
	var last sentinel.Heartbeat
	var lastRaw []byte
	for deadline := time.Now().Add(5 * time.Second); ; {
		h, raw, err := sentinel.ReadHeartbeat(d.outbox, pub)
		if err == nil && h.Status == sentinel.StatusWatching && h.Last != nil {
			last, lastRaw = h, raw
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no watching heartbeat naming a generation: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-results

	// The thief writes heartbeats with the seed, off the chip.
	forge := func(seq uint64) {
		h, err := sentinel.SignHeartbeat(sentinel.Heartbeat{Sentinel: sentinel.KeyID(pub), Seq: seq, At: time.Now().UTC(), StartedAt: last.StartedAt,
			Status: sentinel.StatusWatching, Last: last.Last, Wires: 1}, d.sentinelKey)
		must(t, err)
		raw, err := json.Marshal(h)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(d.outbox, sentinel.HeartbeatFile), raw, 0o644))
	}
	forge(last.Seq + 1)
	w := NewWatcher(pol, d.outbox, time.Now, verifier)
	if tr := w.Observe(); tr != nil {
		t.Fatalf("triggered at once: %+v", tr)
	}
	if len(w.Ignored) != 1 || !strings.Contains(w.Ignored[0], "no attestation") {
		t.Fatalf("ignored %v", w.Ignored)
	}
	if w.State != "waiting for the primary's first heartbeat" {
		t.Fatalf("state %q", w.State)
	}
	// A forged compromise report is ignored the same way.
	fake, err := sentinel.SignCompromise(sentinel.Compromise{Sentinel: sentinel.KeyID(pub), DetectedAt: time.Now().UTC(),
		Tripped: []sentinel.Trip{{Wire: "path", Target: "/etc/passwd", Got: "changed"}}, Last: last.Last}, d.sentinelKey)
	must(t, err)
	raw, err := json.Marshal(fake)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(d.outbox, sentinel.CompromiseFile), raw, 0o644))
	if tr := w.Observe(); tr != nil {
		t.Fatalf("a forged report triggered: %+v", tr)
	}
	must(t, os.Remove(filepath.Join(d.outbox, sentinel.CompromiseFile)))

	// The genuine, attested heartbeat put back: it counts; the forgeries
	// after it do not move the clock, and the timeout fires on silence.
	must(t, os.WriteFile(filepath.Join(d.outbox, sentinel.HeartbeatFile), lastRaw, 0o644))
	if tr := w.Observe(); tr != nil || w.State != "watching" {
		t.Fatalf("trigger %+v state %q", tr, w.State)
	}
	forge(last.Seq + 2)
	time.Sleep(1100 * time.Millisecond)
	forge(last.Seq + 3)
	tr := w.Observe()
	if tr == nil || tr.Kind != TriggerHeartbeatTimeout || tr.Heartbeat.Seq != last.Seq {
		t.Fatalf("trigger %+v", tr)
	}
	if !tr.PrimaryMeasurement.Equal(primary.Measurement()) {
		t.Fatalf("trigger attested by %x", tr.PrimaryMeasurement)
	}
	// The genome chosen is the one the genuine word names, attested.
	choice, why, err := Choose(d.outbox, pol, *tr, escrowTag(d), verifier)
	must(t, err)
	if why != "" || choice.Record.Generation != chain[0].Generation || choice.Record.BundleSHA256 != last.Last.BundleSHA256 {
		t.Fatalf("choice %+v: %q", choice.Record, why)
	}
}

// A record the primary's TEE did not vouch for — sealed by a sentinel
// without an attestor, or on another TEE — is not restored under a
// pinning policy.
func TestPinnedPrimaryRestoresOnlyAttestedGenomes(t *testing.T) {
	d := newDrill(t)
	primary, verifier := primaryTEE(t)
	// Generation 0 sealed without the chip's word; then the sentinel is
	// restarted with it, and generation 1 carries it.
	ctx, cancel := context.WithCancel(context.Background())
	results := d.runSentinel(ctx)
	d.waitChain(1)
	cancel()
	<-results
	writeModel(t, d.state, "weights v2", 1.5, -2)
	ctx, cancel = context.WithCancel(context.Background())
	results = d.attested(ctx, primary)
	chain := d.waitChain(2)
	cancel()
	<-results
	pol := d.pinned(primary)
	hb, raw, err := sentinel.ReadHeartbeat(d.outbox, d.sentinelKey.Public().(ed25519.PublicKey))
	must(t, err)
	tr := Trigger{Kind: TriggerHeartbeatTimeout, At: hb.At.Add(time.Second), Heartbeat: &hb, Evidence: raw}

	// Generation 1 is attested and chosen.
	choice, why, err := Choose(d.outbox, pol, tr, escrowTag(d), verifier)
	must(t, err)
	if why != "" || choice.Record.Generation != 1 {
		t.Fatalf("choice %+v: %q", choice.Record, why)
	}
	// With generation 1 hidden, the last word names it still: nothing older
	// is vouched for by the chip, and the outbox is not trusted past it.
	must(t, os.Remove(filepath.Join(d.outbox, sentinel.RecordName(1))))
	choice, why, err = Choose(d.outbox, pol, tr, escrowTag(d), verifier)
	must(t, err)
	if why == "" || choice.Record.Generation != 0 && choice.Record.KeyID != "" {
		t.Fatalf("chose %+v: %q", choice.Record, why)
	}
	found := false
	for _, r := range choice.SetAside {
		if r.File == sentinel.RecordName(0) && strings.Contains(r.Reason, "no attestation") {
			found = true
		}
	}
	if !found {
		t.Fatalf("generation 0 was not set aside for its missing attestation: %+v", choice.SetAside)
	}
	// Another TEE's word is not the primary's.
	other, otherVerifier := func() (*tee.Simulated, tee.Verifier) {
		p, err := tee.NewSimulated([]byte("primary-v2"), bytes.Repeat([]byte{0x22}, 32))
		must(t, err)
		return p, tee.NewSimulatedVerifier(p.PublicKey(), p.Measurement())
	}()
	_ = other
	if _, why, err := Choose(d.outbox, pol, tr, escrowTag(d), otherVerifier); err != nil || why == "" {
		t.Fatalf("chosen under another TEE's verifier: %q %v", why, err)
	}
	_ = chain
}

// Nothing past the sentinel's last word is restored: a record added to
// the outbox after it is set aside, and an outbox that holds the named
// generation as another bundle is not trusted at all.
func TestChainIsTrustedOnlyToTheSentinelsLastWord(t *testing.T) {
	d := newDrill(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := d.runSentinel(ctx)
	d.waitChain(1)
	writeModel(t, d.state, "weights v2", 1.5, -2)
	chain := d.waitChain(2)
	must(t, os.WriteFile(d.canary, []byte("touched"), 0o600))
	<-results
	pub := d.sentinelKey.Public().(ed25519.PublicKey)
	c, raw, err := sentinel.ReadCompromise(d.outbox, pub)
	must(t, err)
	tr := Trigger{Kind: TriggerCompromise, At: c.DetectedAt, Compromise: &c, Evidence: raw}
	pol := d.policy()

	choice, why, err := Choose(d.outbox, pol, tr, escrowTag(d), nil)
	must(t, err)
	if why != "" || choice.Record.Generation != 1 {
		t.Fatalf("choice %+v: %q", choice.Record, why)
	}

	// The thief, with the seed, appends generation 2 after the report.
	rec := chain[1]
	rec.Generation, rec.Bundle, rec.Escrow, rec.ParentBundleSHA256 = 2, sentinel.BundleName(2), sentinel.EscrowName(2), chain[1].BundleSHA256
	rec.Signature = nil
	rec, err = sentinel.SignRecord(rec, d.sentinelKey)
	must(t, err)
	raw, err = json.Marshal(rec)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(d.outbox, sentinel.RecordName(2)), raw, 0o644))
	choice, why, err = Choose(d.outbox, pol, tr, escrowTag(d), nil)
	must(t, err)
	if why != "" || choice.Record.Generation != 1 || *choice.ChainEnd != 2 {
		t.Fatalf("choice %+v: %q", choice.Record, why)
	}
	if len(choice.SetAside) == 0 || !strings.Contains(choice.SetAside[0].Reason, "after generation 1, the last the sentinel's compromise-report names") {
		t.Fatalf("set aside %+v", choice.SetAside)
	}

	// The thief replaces generation 1 with a bundle of their own: the
	// outbox contradicts the sentinel's word and nothing in it is trusted.
	must(t, os.Remove(filepath.Join(d.outbox, sentinel.RecordName(2))))
	forged := chain[1]
	forged.BundleSHA256 = strings.Repeat("f", 64)
	forged.Signature = nil
	forged, err = sentinel.SignRecord(forged, d.sentinelKey)
	must(t, err)
	raw, err = json.Marshal(forged)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(d.outbox, sentinel.RecordName(1)), raw, 0o644))
	choice, why, err = Choose(d.outbox, pol, tr, escrowTag(d), nil)
	must(t, err)
	if !strings.Contains(why, "contradicts the sentinel") || choice.Record.KeyID != "" {
		t.Fatalf("choice %+v: %q", choice.Record, why)
	}

	// A trigger whose record names no generation vouches for nothing.
	none := tr
	none.Compromise = &sentinel.Compromise{}
	if _, why, err := Choose(d.outbox, pol, none, escrowTag(d), nil); err != nil || !strings.Contains(why, "names no sealed generation") {
		t.Fatalf("why %q, %v", why, err)
	}
}

// `stopped` stands the authority down only for the policy's grace: a
// sentinel that does not come back is a trigger, on the record as such.
func TestStoppedSentinelIsOverdueAfterTheGrace(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	ctx, cancel := context.WithCancel(context.Background())
	results := d.runSentinel(ctx)
	chain := d.waitChain(1)
	cancel()
	<-results

	p := d.policy()
	p.Triggers.StoppedGraceSeconds = 1
	p, err := Sign(p, d.operator)
	must(t, err)
	d.coordinator(mustRegistry(t, d), mustAuthority(t))
	ex, err := New(Config{Policy: p, Outbox: d.outbox, Escrow: d.escrow, Coordinator: d.coord, Audit: d.audit, Events: d.audit.Events,
		IDs: &seqIDs{}, Clock: d.clock(), Poll: 20 * time.Millisecond, ConfirmWait: 20 * time.Second})
	must(t, err)
	// Standing down first, then overdue.
	w := NewWatcher(p, d.outbox, time.Now, nil)
	if tr := w.Observe(); tr != nil || !strings.Contains(w.State, "standing down for") {
		t.Fatalf("trigger %+v state %q", tr, w.State)
	}
	start := time.Now()
	rep, err := ex.Run(context.Background())
	must(t, err)
	if rep.Status != StatusRestored || rep.Trigger.Kind != TriggerStoppedOverdue || rep.Genome.Generation != chain[0].Generation {
		t.Fatalf("report %+v", rep)
	}
	if since := time.Since(start); since < time.Second {
		t.Fatalf("failed over %s after the stop, inside the 1s grace", since)
	}
	if dp := decidedPayloadOf(t, d.audit.Events()); dp.Trigger != TriggerStoppedOverdue {
		t.Fatalf("decision %+v", dp)
	}

	// The sentinel comes back within the grace: the clock is reset.
	d2 := newDrill(t)
	ctx, cancel = context.WithCancel(context.Background())
	results = d2.runSentinel(ctx)
	d2.waitChain(1)
	cancel()
	<-results
	p2 := d2.policy()
	p2.Triggers.StoppedGraceSeconds = 1
	p2, err = Sign(p2, d2.operator)
	must(t, err)
	w = NewWatcher(p2, d2.outbox, time.Now, nil)
	if tr := w.Observe(); tr != nil {
		t.Fatalf("trigger %+v", tr)
	}
	time.Sleep(600 * time.Millisecond)
	ctx, cancel = context.WithCancel(context.Background())
	results = d2.runSentinel(ctx)
	// The returning sentinel's first watching heartbeat, whenever the
	// scheduler lets it write one (well inside the grace).
	pub := d2.sentinelKey.Public().(ed25519.PublicKey)
	back := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if h, _, err := sentinel.ReadHeartbeat(d2.outbox, pub); err == nil && h.Status == sentinel.StatusWatching {
			back = true
			break
		}
	}
	if !back {
		t.Fatal("the returning sentinel wrote no watching heartbeat")
	}
	if tr := w.Observe(); tr != nil || w.State != "watching" {
		t.Fatalf("trigger %+v state %q", tr, w.State)
	}
	cancel()
	<-results
	time.Sleep(600 * time.Millisecond)
	if tr := w.Observe(); tr != nil {
		t.Fatalf("triggered %s into a fresh stop: %+v", "600ms", tr)
	}
}

func escrowTag(d *drill) string { return escrow.KeyTag(d.escrow.PublicKey()) }

func (d *drill) clock() shared_time.Clock { return shared_time.NewSystemClock() }
