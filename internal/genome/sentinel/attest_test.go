// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package sentinel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func simulatedPrimary(t *testing.T, descriptor string) (*tee.Simulated, tee.Verifier) {
	t.Helper()
	p, err := tee.NewSimulated([]byte(descriptor), bytes.Repeat([]byte{0x11}, 32))
	must(t, err)
	return p, tee.NewSimulatedVerifier(p.PublicKey(), p.Measurement())
}

// Every record can carry the primary TEE's report, bound to the record's
// content: it verifies as written, and not once a byte of the record is
// changed — even re-signed with the sentinel key, as a thief of the seed
// would.
func TestAttestedRecordsBindTheChipToTheContent(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	id := KeyID(pub)
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	link := &Link{Generation: 3, BundleSHA256: strings.Repeat("c", 64), SealedAt: now}
	primary, verifier := simulatedPrimary(t, "primary-v1")

	h := Heartbeat{Sentinel: id, Seq: 1, At: now, StartedAt: now, Status: StatusWatching, Last: link, Wires: 2}
	h, err = AttestHeartbeat(h, primary, tee.ProviderSimulated)
	must(t, err)
	if h.Attestation == nil || h.Attestation.Kind != "simulated" || len(h.Attestation.Evidence) == 0 {
		t.Fatalf("attestation %+v", h.Attestation)
	}
	h, err = SignHeartbeat(h, key)
	must(t, err)
	raw, err := encode(h)
	must(t, err)
	got, err := ParseHeartbeat(raw, pub)
	must(t, err)
	m, err := got.Attested(verifier)
	must(t, err)
	if !m.Equal(primary.Measurement()) {
		t.Fatalf("attested measurement %x, want the primary's %x", m, primary.Measurement())
	}

	// The seed stolen: the thief re-signs a changed record. The report
	// still binds the record as the chip saw it.
	forged := got
	forged.Seq = 2
	forged, err = SignHeartbeat(forged, key)
	must(t, err)
	if _, err := forged.Attested(verifier); err == nil {
		t.Fatal("a re-signed heartbeat kept its attestation")
	}
	stopped := got
	stopped.Status = StatusStopped
	stopped, err = SignHeartbeat(stopped, key)
	must(t, err)
	if _, err := stopped.Attested(verifier); err == nil {
		t.Fatal("a heartbeat turned to stopped kept its attestation")
	}

	// Evidence moved from one record to another does not fit it.
	other := Heartbeat{Sentinel: id, Seq: 9, At: now, StartedAt: now, Status: StatusWatching, Last: link, Wires: 2, Attestation: got.Attestation}
	other, err = SignHeartbeat(other, key)
	must(t, err)
	if _, err := other.Attested(verifier); err == nil {
		t.Fatal("another record verified with borrowed evidence")
	}

	// Tampered evidence, no evidence, no verifier, another TEE's verifier.
	tampered := got
	tampered.Attestation = &Attestation{Kind: "simulated", Evidence: append([]byte(nil), got.Attestation.Evidence...)}
	tampered.Attestation.Evidence[len(tampered.Attestation.Evidence)-1] ^= 1
	if _, err := tampered.Attested(verifier); err == nil {
		t.Fatal("tampered evidence verified")
	}
	plain, err := SignHeartbeat(Heartbeat{Sentinel: id, Seq: 1, At: now, StartedAt: now, Status: StatusWatching}, key)
	must(t, err)
	if _, err := plain.Attested(verifier); !errors.Is(err, ErrUnattested) {
		t.Fatalf("unattested: %v", err)
	}
	if _, err := got.Attested(nil); err == nil {
		t.Fatal("verified with no verifier")
	}
	_, otherVerifier := simulatedPrimary(t, "primary-v2")
	if _, err := got.Attested(otherVerifier); err == nil {
		t.Fatal("verified under another TEE's key")
	}

	// A malformed attestation is not signed, and does not parse.
	bad := got
	bad.Attestation = &Attestation{Kind: "no-such-tee", Evidence: []byte{1}}
	if _, err := SignHeartbeat(bad, key); err == nil {
		t.Fatal("signed an attestation of an unknown kind")
	}
	if _, err := ParseHeartbeat(bytes.Replace(raw, []byte(`"kind": "simulated"`), []byte(`"kind": "simulated", "x": 1`), 1), pub); err == nil {
		t.Fatal("an attestation with an unknown field parsed")
	}

	// Seal records and compromise reports carry it the same way.
	rec := SealRecord{Sentinel: id, Generation: 0, Bundle: BundleName(0), Escrow: EscrowName(0), BundleSHA256: strings.Repeat("a", 64), BundleBytes: 1,
		KeyID: "genome-aaaaaaaaaaaa-g0-bbbbbbbbbbbb", EscrowKey: "k", PayloadSHA256: "sha256:" + strings.Repeat("a", 64), SealedAt: now}
	rec, err = AttestRecord(rec, primary, tee.ProviderSimulated)
	must(t, err)
	rec, err = SignRecord(rec, key)
	must(t, err)
	if m, err := rec.Attested(verifier); err != nil || !m.Equal(primary.Measurement()) {
		t.Fatalf("record attested %x: %v", m, err)
	}
	rec.BundleSHA256 = strings.Repeat("b", 64)
	rec, err = SignRecord(rec, key)
	must(t, err)
	if _, err := rec.Attested(verifier); err == nil {
		t.Fatal("a record with its bundle digest changed kept its attestation")
	}
	c := Compromise{Sentinel: id, DetectedAt: now, Tripped: []Trip{{Wire: "path", Target: "/etc/x", Got: "b"}}, Last: link}
	c, err = AttestCompromise(c, primary, tee.ProviderSimulated)
	must(t, err)
	c, err = SignCompromise(c, key)
	must(t, err)
	if m, err := c.Attested(verifier); err != nil || !m.Equal(primary.Measurement()) {
		t.Fatalf("compromise attested %x: %v", m, err)
	}
	c.Last = &Link{Generation: 2, BundleSHA256: strings.Repeat("c", 64), SealedAt: now}
	c, err = SignCompromise(c, key)
	must(t, err)
	if _, err := c.Attested(verifier); err == nil {
		t.Fatal("a compromise report naming another last generation kept its attestation")
	}
}

// flakyProducer fails every Quote while broken.
type flakyProducer struct {
	*tee.Simulated
	broken bool
}

func (f *flakyProducer) Quote(nonce tee.Nonce) (tee.Evidence, error) {
	if f.broken {
		return nil, errors.New("configfs-tsm: read outblob: input/output error")
	}
	return f.Simulated.Quote(nonce)
}

// A sentinel with an attestor puts the chip's report on every record it
// writes. When the chip stops answering: no heartbeat is written (the
// sequence does not move — silence, which the authority times out on), a
// seal is not committed, and a compromise report still goes out.
func TestSentinelAttestsEveryRecord(t *testing.T) {
	r := newRig(t)
	primary, verifier := simulatedPrimary(t, "primary-v1")
	attestor := &flakyProducer{Simulated: primary}
	canary := filepath.Join(t.TempDir(), "canary")
	write(t, canary, "do not touch")
	cfg := r.config(&PathWire{Path: canary})
	cfg.Attestor, cfg.AttestorKind = attestor, tee.ProviderSimulated
	s, err := New(cfg)
	must(t, err)
	r.tickFor(s, 3*time.Second)

	chain := r.chain()
	if len(chain) != 1 {
		t.Fatalf("chain %+v", chain)
	}
	if m, err := chain[0].Attested(verifier); err != nil || !m.Equal(primary.Measurement()) {
		t.Fatalf("seal record attested %x: %v", m, err)
	}
	h := r.heartbeat()
	if m, err := h.Attested(verifier); err != nil || !m.Equal(primary.Measurement()) {
		t.Fatalf("heartbeat attested %x: %v", m, err)
	}
	seq := h.Seq

	// The chip stops answering: heartbeats stop, a change is not sealed.
	attestor.broken = true
	write(t, filepath.Join(r.state, "adapter.safetensors"), "weights v2")
	r.tickFor(s, 4*time.Second)
	if got := r.heartbeat().Seq; got != seq {
		t.Fatalf("heartbeat seq moved to %d without the chip", got)
	}
	if n := len(r.chain()); n != 1 {
		t.Fatalf("sealed generation %d without the chip", n-1)
	}
	entries, err := os.ReadDir(r.outbox)
	must(t, err)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") || e.Name() == BundleName(1) || e.Name() == EscrowName(1) {
			t.Errorf("left behind: %s", e.Name())
		}
	}

	// The chip answers again: the state is sealed, attested.
	attestor.broken = false
	r.tickFor(s, 4*time.Second)
	chain = r.chain()
	if len(chain) != 2 {
		t.Fatalf("chain %+v", chain)
	}
	if _, err := chain[1].Attested(verifier); err != nil {
		t.Fatal(err)
	}
	if got := r.heartbeat(); got.Seq <= seq || got.Last.Generation != 1 {
		t.Fatalf("heartbeat %+v", got)
	}

	// A wire fires while the chip is silent: the report is written all
	// the same, unattested, and says so.
	attestor.broken = true
	write(t, canary, "touched")
	res, done := r.tickFor(s, time.Second)
	if !done || res.Outcome != OutcomeCompromised {
		t.Fatalf("result %+v done=%v", res, done)
	}
	c, _, err := ReadCompromise(r.outbox, r.pub)
	must(t, err)
	if _, err := c.Attested(verifier); !errors.Is(err, ErrUnattested) {
		t.Fatalf("compromise report: %v", err)
	}

	// The attestor and its kind go together.
	cfg.AttestorKind = ""
	if _, err := New(cfg); err == nil {
		t.Fatal("an attestor without a kind was accepted")
	}
}
