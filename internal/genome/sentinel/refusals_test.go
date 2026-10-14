// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package sentinel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// offlineChip is a TEE whose quotes never come.
type offlineChip struct{}

func (offlineChip) Quote(tee.Nonce) (tee.Evidence, error) { return nil, errors.New("chip offline") }
func (offlineChip) Measurement() tee.Measurement           { return tee.Measurement{} }

func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
}

func goodRecord(id string, now time.Time) SealRecord {
	return SealRecord{
		Sentinel: id, Generation: 1, Bundle: BundleName(1), Escrow: EscrowName(1),
		BundleSHA256: strings.Repeat("a", 64), BundleBytes: 1,
		KeyID: "genome-aaaaaaaaaaaa-g1-bbbbbbbbbbbb", EscrowKey: "k",
		PayloadSHA256: "sha256:" + strings.Repeat("a", 64), ParentBundleSHA256: strings.Repeat("b", 64),
		SealedAt: now,
	}
}

// Every field of a seal record is checked before the sentinel key signs it,
// and again before a reader trusts it.
func TestSealRecordRefusesEachDefect(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	id := KeyID(pub)
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	good := goodRecord(id, now)
	signed, err := SignRecord(good, key)
	must(t, err)
	must(t, verify(signed, pub))

	rows := map[string]func(r *SealRecord){
		"sentinel id":             func(r *SealRecord) { r.Sentinel = "sentinel-xyz" },
		"bundle name":             func(r *SealRecord) { r.Bundle = "other.genome" },
		"escrow name":             func(r *SealRecord) { r.Escrow = "other.escrow" },
		"bundle digest":           func(r *SealRecord) { r.BundleSHA256 = "zz" },
		"bundle size":             func(r *SealRecord) { r.BundleBytes = 0 },
		"genome key id":           func(r *SealRecord) { r.KeyID = "key" },
		"escrow key tag":          func(r *SealRecord) { r.EscrowKey = "" },
		"payload digest":          func(r *SealRecord) { r.PayloadSHA256 = "sha256:short" },
		"parent at generation 0":  func(r *SealRecord) { r.Generation, r.Bundle, r.Escrow = 0, BundleName(0), EscrowName(0) },
		"malformed parent digest": func(r *SealRecord) { r.ParentBundleSHA256 = "not-hex" },
		"sealed_at":               func(r *SealRecord) { r.SealedAt = time.Time{} },
		"attestation kind":        func(r *SealRecord) { r.Attestation = &Attestation{Kind: "abacus", Evidence: []byte{1}} },
		"attestation evidence":    func(r *SealRecord) { r.Attestation = &Attestation{Kind: string(tee.ProviderSimulated)} },
	}
	for name, edit := range rows {
		r := good
		edit(&r)
		if _, err := SignRecord(r, key); err == nil {
			t.Errorf("%s: signed", name)
		}
		r.Schema, r.Signature = SealSchema, signed.Signature
		if err := verify(r, pub); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	other := signed
	other.Schema = "vault-genome/seal-record/v0"
	if err := verify(other, pub); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Errorf("another schema verified: %v", err)
	}
}

func TestHeartbeatAndCompromiseRefuseEachDefect(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	id := KeyID(pub)
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	badLink := &Link{Generation: 1, BundleSHA256: "zz", SealedAt: now}
	badKind := &Attestation{Kind: "abacus", Evidence: []byte{1}}

	heartbeats := map[string]Heartbeat{
		"sentinel id":   {Sentinel: "sentinel-xyz", Seq: 1, At: now, StartedAt: now, Status: StatusWatching},
		"at":            {Sentinel: id, Seq: 1, StartedAt: now, Status: StatusWatching},
		"started_at":    {Sentinel: id, Seq: 1, At: now, Status: StatusWatching},
		"attestation":   {Sentinel: id, Seq: 1, At: now, StartedAt: now, Status: StatusWatching, Attestation: badKind},
		"last link":     {Sentinel: id, Seq: 1, At: now, StartedAt: now, Status: StatusWatching, Last: badLink},
		"other schema":  {Schema: "x", Sentinel: id, Seq: 1, At: now, StartedAt: now, Status: StatusWatching},
	}
	for name, h := range heartbeats {
		if name != "other schema" {
			if _, err := SignHeartbeat(h, key); err == nil {
				t.Errorf("heartbeat with bad %s: signed", name)
			}
		}
		if err := verify(h, pub); err == nil {
			t.Errorf("heartbeat with bad %s: verified", name)
		}
	}
	trip := []Trip{{Wire: "path", Target: "/etc/x", Got: "missing"}}
	compromises := map[string]Compromise{
		"sentinel id":  {Sentinel: "sentinel-xyz", DetectedAt: now, Tripped: trip},
		"detected_at":  {Sentinel: id, Tripped: trip},
		"attestation":  {Sentinel: id, DetectedAt: now, Tripped: trip, Attestation: badKind},
		"last link":    {Sentinel: id, DetectedAt: now, Tripped: trip, Last: badLink},
		"other schema": {Schema: "x", Sentinel: id, DetectedAt: now, Tripped: trip},
	}
	for name, c := range compromises {
		if name != "other schema" {
			if _, err := SignCompromise(c, key); err == nil {
				t.Errorf("compromise with bad %s: signed", name)
			}
		}
		if err := verify(c, pub); err == nil {
			t.Errorf("compromise with bad %s: verified", name)
		}
	}
}

func TestParsersRefuseWhatIsNotTheirRecord(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	h, err := SignHeartbeat(Heartbeat{Sentinel: KeyID(pub), Seq: 1, At: now, StartedAt: now, Status: StatusWatching}, key)
	must(t, err)
	raw, err := encode(h)
	must(t, err)

	if _, err := ParseHeartbeat(append(append([]byte(nil), raw...), []byte("{}")...), pub); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Errorf("trailing data: %v", err)
	}
	if _, err := ParseHeartbeat(bytes.Replace(raw, []byte(`"wires"`), []byte(`"wings"`), 1), pub); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("unknown field: %v", err)
	}
	if _, err := ParseHeartbeat(raw, otherPub); err == nil || !strings.Contains(err.Error(), "pinned sentinel") {
		t.Errorf("another pinned key: %v", err)
	}
	forged := h
	forged.Signature[0] ^= 1
	if err := verify(forged, pub); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("tampered signature: %v", err)
	}
	for _, raw := range [][]byte{[]byte("{"), []byte("[]"), []byte(`{"schema":1}`)} {
		if _, err := ParseRecord(raw, pub); err == nil {
			t.Errorf("record %q parsed", raw)
		}
		if _, err := ParseCompromise(raw, pub); err == nil {
			t.Errorf("compromise %q parsed", raw)
		}
	}
}

func TestAttestationRefusals(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	id := KeyID(pub)
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	primary, verifier := simulatedPrimary(t, "primary-v1")

	if _, err := AttestHeartbeat(Heartbeat{Sentinel: id}, primary, tee.ProviderSimulated); err == nil {
		t.Error("a malformed heartbeat was attested")
	}
	rec := goodRecord(id, now)
	if _, err := AttestRecord(rec, offlineChip{}, tee.ProviderSimulated); err == nil || !strings.Contains(err.Error(), "chip offline") {
		t.Errorf("an offline chip attested: %v", err)
	}
	if _, err := rec.Attested(verifier); !errors.Is(err, ErrUnattested) {
		t.Errorf("unattested record: %v", err)
	}
	attested, err := AttestRecord(rec, primary, tee.ProviderSimulated)
	must(t, err)
	if _, err := attested.Attested(nil); err == nil || !strings.Contains(err.Error(), "no verifier") {
		t.Errorf("no verifier: %v", err)
	}
	c, err := AttestCompromise(Compromise{Sentinel: id, DetectedAt: now, Tripped: []Trip{{Wire: "path", Target: "x", Got: "missing"}}}, primary, tee.ProviderSimulated)
	must(t, err)
	if _, err := c.Attested(verifier); err != nil {
		t.Errorf("attested compromise: %v", err)
	}
}

func TestReadChainSetsAsideWhatCannotBeRead(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	write(t, filepath.Join(dir, "gen-99999999999999999999.seal.json"), "{}")
	must(t, os.WriteFile(filepath.Join(dir, RecordName(1)), bytes.Repeat([]byte(" "), maxRecordBytes+1), 0o644))
	write(t, filepath.Join(dir, RecordName(2)), "not json")
	chain, rejected, err := ReadChain(dir, pub)
	must(t, err)
	if len(chain) != 0 || len(rejected) != 3 {
		t.Fatalf("chain %d, rejected %+v", len(chain), rejected)
	}
	reasons := map[string]string{}
	for _, r := range rejected {
		reasons[r.File] = r.Reason
	}
	for file, want := range map[string]string{
		"gen-99999999999999999999.seal.json": "out of range",
		RecordName(1):                        "over",
		RecordName(2):                        "decode",
	} {
		if !strings.Contains(reasons[file], want) {
			t.Errorf("%s rejected for %q, want %q", file, reasons[file], want)
		}
	}
}

func TestCheckGenomeNeedsBothFiles(t *testing.T) {
	r := newRig(t)
	s := r.sentinel()
	r.tickFor(s, 5*time.Second)
	rec := r.chain()[0]

	elsewhere := rec
	elsewhere.Bundle = BundleName(9)
	if _, _, err := CheckGenome(r.outbox, elsewhere); err == nil {
		t.Error("a record naming an absent bundle checked out")
	}
	must(t, os.Remove(filepath.Join(r.outbox, rec.Escrow)))
	if _, _, err := CheckGenome(r.outbox, rec); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("without its escrow file: %v", err)
	}
}

func TestWriteAtomicRefusals(t *testing.T) {
	dir := t.TempDir()
	must(t, writeAtomic(dir, "once", []byte("1"), true))
	if err := writeAtomic(dir, "once", []byte("2"), true); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("exclusive write over an existing file: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "once")); string(got) != "1" {
		t.Errorf("the existing file was overwritten: %q", got)
	}
	if err := writeAtomic(filepath.Join(dir, "absent"), "x", []byte("1"), false); err == nil {
		t.Error("wrote into a missing directory")
	}
	must(t, os.Mkdir(filepath.Join(dir, "taken"), 0o755))
	if err := writeAtomic(dir, "taken", []byte("1"), false); err == nil {
		t.Error("renamed a file over a directory")
	}
	if _, err := os.Lstat(filepath.Join(dir, ".taken.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temporary file was left behind: %v", err)
	}
	if err := syncDir(filepath.Join(dir, "absent")); err == nil {
		t.Error("synced a missing directory")
	}
}

func TestNewRefusesMoreConfigs(t *testing.T) {
	r := newRig(t)
	file := filepath.Join(t.TempDir(), "file")
	write(t, file, "x")
	for name, edit := range map[string]func(c *Config){
		"zero interval":       func(c *Config) { c.Interval = 0 },
		"negative settle":     func(c *Config) { c.Settle = -time.Second },
		"kind without chip":   func(c *Config) { c.AttestorKind = tee.ProviderSimulated },
		"outbox under a file": func(c *Config) { c.Outbox = filepath.Join(file, "outbox") },
		"wire on a missing path": func(c *Config) {
			c.Wires = []Wire{&PathWire{Path: filepath.Join(r.state, "absent")}}
		},
		"empty probe": func(c *Config) { c.Wires = []Wire{&ProbeWire{}} },
	} {
		cfg := r.config()
		edit(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := r.sentinel()
	if s.ID() != KeyID(r.pub) {
		t.Errorf("id %s, want %s", s.ID(), KeyID(r.pub))
	}
}

// State that cannot be read is not sealed; the sentinel keeps its heartbeat
// and tries again.
func TestUnreadableStateIsNotSealed(t *testing.T) {
	r := newRig(t)
	s := r.sentinel()
	must(t, os.RemoveAll(r.state))
	r.tickFor(s, 5*time.Second)
	if n := len(r.chain()); n != 0 {
		t.Fatalf("sealed %d generations of unreadable state", n)
	}
	if h := r.heartbeat(); h.Status != StatusWatching || h.Seq == 0 {
		t.Fatalf("heartbeat %+v", h)
	}
}

// A record that appears in the outbox behind the sentinel's back is never
// overwritten: the seal fails and the stranger stays as it was.
func TestSealNeverOverwritesARecord(t *testing.T) {
	r := newRig(t)
	s := r.sentinel()
	stranger := filepath.Join(r.outbox, RecordName(0))
	write(t, stranger, "stranger")
	r.tickFor(s, 5*time.Second)
	if got, _ := os.ReadFile(stranger); string(got) != "stranger" {
		t.Fatalf("the stranger was overwritten: %q", got)
	}
	chain, rejected, err := ReadChain(r.outbox, r.pub)
	must(t, err)
	if len(chain) != 0 || len(rejected) != 1 {
		t.Fatalf("chain %d, rejected %+v", len(chain), rejected)
	}
}

// With the outbox unwritable, the seal fails, the heartbeat cannot be
// written, and Run returns the error instead of pretending to watch.
func TestRunStopsWhenTheOutboxIsUnwritable(t *testing.T) {
	skipAsRoot(t)
	r := newRig(t)
	s := r.sentinel()
	must(t, os.Chmod(r.outbox, 0o500))
	t.Cleanup(func() { _ = os.Chmod(r.outbox, 0o755) })
	r.clock.advance(3 * time.Second)
	if _, err := s.Run(context.Background()); err == nil {
		t.Fatal("ran with an unwritable outbox")
	}
}

func TestRunTicksUntilCancelled(t *testing.T) {
	r := newRig(t)
	cfg := r.config()
	cfg.Interval = 5 * time.Millisecond
	cfg.Clock = time.Now
	s, err := New(cfg)
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result, 1)
	go func() {
		res, err := s.Run(ctx)
		must(t, err)
		done <- res
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		h, _, err := ReadHeartbeat(r.outbox, r.pub)
		if err == nil && h.Seq >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no third heartbeat within the deadline: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	res := <-done
	if res.Outcome != OutcomeStopped {
		t.Fatalf("outcome %s", res.Outcome)
	}
	if h := r.heartbeat(); h.Status != StatusStopped {
		t.Fatalf("closing heartbeat %+v", h)
	}
}

// A compromise is reported even when the chip will not attest it: the
// report is written unattested rather than not at all.
func TestCompromiseIsReportedWhenTheChipIsOffline(t *testing.T) {
	r := newRig(t)
	watched := filepath.Join(r.state, "genome.json")
	cfg := r.config(&PathWire{Path: watched})
	cfg.Attestor, cfg.AttestorKind = offlineChip{}, tee.ProviderSimulated
	s, err := New(cfg)
	must(t, err)
	write(t, watched, `{"step":2}`)
	res, done, err := s.tick()
	must(t, err)
	if !done || res.Outcome != OutcomeCompromised || res.Compromise == nil {
		t.Fatalf("result %+v", res)
	}
	c, _, err := ReadCompromise(r.outbox, r.pub)
	must(t, err)
	if c.Attestation != nil || len(c.Tripped) != 1 || c.Tripped[0].Target != watched {
		t.Fatalf("report %+v", c)
	}
}

func TestPathWireSeesWhatItCannotRead(t *testing.T) {
	skipAsRoot(t)
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	must(t, os.Mkdir(sub, 0o755))
	write(t, filepath.Join(sub, "x"), "x")
	write(t, filepath.Join(dir, "y"), "y")
	must(t, syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600))
	restore := func() {
		_ = os.Chmod(sub, 0o755)
		_ = os.Chmod(filepath.Join(dir, "y"), 0o644)
	}
	t.Cleanup(restore)

	w := &PathWire{Path: dir}
	must(t, w.Arm())
	if trip := w.Check(); trip != nil {
		t.Fatalf("armed wire tripped: %+v", trip)
	}
	must(t, os.Chmod(sub, 0o000))
	if trip := w.Check(); trip == nil || trip.Got != "unreadable" {
		t.Fatalf("unreadable directory: %+v", trip)
	}
	restore()
	must(t, os.Chmod(filepath.Join(dir, "y"), 0o000))
	if trip := w.Check(); trip == nil || trip.Got != "unreadable" {
		t.Fatalf("unreadable file in the directory: %+v", trip)
	}
	single := &PathWire{Path: filepath.Join(dir, "y")}
	if err := single.Arm(); err == nil {
		t.Fatal("armed on an unreadable file")
	}
	restore()
	must(t, single.Arm())
	must(t, os.Chmod(filepath.Join(dir, "y"), 0o000))
	if trip := single.Check(); trip == nil || trip.Got != "unreadable" {
		t.Fatalf("unreadable file: %+v", trip)
	}
}
