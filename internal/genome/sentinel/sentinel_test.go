// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package sentinel

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contentdir"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
)

// dirSource is the sentinel's view of a directory, as acpctl builds it.
type dirSource struct{ dir string }

func (d dirSource) Kind() string                 { return bundle.ContentDir }
func (d dirSource) Ref() string                  { return d.dir }
func (d dirSource) Fingerprint() (string, error) { return contentdir.Fingerprint(d.dir) }
func (d dirSource) Capture() bundle.Capture {
	return func(w io.Writer) (json.RawMessage, int64, error) {
		snap, n, err := contentdir.Capture(d.dir, w)
		if err != nil {
			return nil, 0, err
		}
		raw, err := json.Marshal(snap)
		return raw, n, err
	}
}

var execLookPath = exec.LookPath

// clock is a manual clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock                   { return &clock{t: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)} }
func write(t *testing.T, path, data string) {
	t.Helper()
	must(t, os.WriteFile(path, []byte(data), 0o644))
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func mustNot(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: want an error", what)
	}
}

type rig struct {
	t      *testing.T
	state  string
	outbox string
	key    ed25519.PrivateKey
	pub    ed25519.PublicKey
	escrow *ecdh.PrivateKey
	clock  *clock
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	esc, err := escrow.GenerateKey()
	must(t, err)
	r := &rig{t: t, state: t.TempDir(), outbox: filepath.Join(t.TempDir(), "outbox"), key: key, pub: pub, escrow: esc, clock: newClock()}
	write(t, filepath.Join(r.state, "adapter.safetensors"), "weights v1")
	write(t, filepath.Join(r.state, "genome.json"), `{"step":1}`)
	return r
}

func (r *rig) config(wires ...Wire) Config {
	return Config{
		Source:   dirSource{r.state},
		Outbox:   r.outbox,
		Escrow:   r.escrow.PublicKey(),
		Key:      r.key,
		Wires:    wires,
		Interval: time.Second,
		Settle:   2 * time.Second,
		Clock:    r.clock.now,
	}
}

func (r *rig) sentinel(wires ...Wire) *Sentinel {
	r.t.Helper()
	s, err := New(r.config(wires...))
	must(r.t, err)
	return s
}

// tickFor ticks once a second for d.
func (r *rig) tickFor(s *Sentinel, d time.Duration) (Result, bool) {
	r.t.Helper()
	for end := r.clock.now().Add(d); !r.clock.now().After(end); r.clock.advance(time.Second) {
		res, done, err := s.tick()
		must(r.t, err)
		if done {
			return res, true
		}
	}
	return Result{}, false
}

func (r *rig) chain() []SealRecord {
	r.t.Helper()
	chain, rejected, err := ReadChain(r.outbox, r.pub)
	must(r.t, err)
	if len(rejected) > 0 {
		r.t.Fatalf("rejected: %+v", rejected)
	}
	return chain
}

func (r *rig) heartbeat() Heartbeat {
	r.t.Helper()
	h, _, err := ReadHeartbeat(r.outbox, r.pub)
	must(r.t, err)
	return h
}

// open recovers a generation's payload the way the release authority and
// the destination together would: key from escrow, then the bundle.
func (r *rig) open(rec SealRecord) []byte {
	r.t.Helper()
	_, env, err := CheckGenome(r.outbox, rec)
	must(r.t, err)
	dek, err := escrow.Open(env, r.escrow)
	must(r.t, err)
	blob, err := os.ReadFile(filepath.Join(r.outbox, rec.Bundle))
	must(r.t, err)
	payload, h, err := bundle.OpenBytes(blob, dek)
	must(r.t, err)
	if h.KeyID != rec.KeyID {
		r.t.Fatalf("opened %s, want %s", h.KeyID, rec.KeyID)
	}
	return payload
}

func TestSentinelSealsWhatSettlesAndChainsIt(t *testing.T) {
	r := newRig(t)
	s := r.sentinel()

	// Nothing is sealed before the state has been still for Settle.
	if _, done := r.tickFor(s, time.Second); done {
		t.Fatal("stopped early")
	}
	if n := len(r.chain()); n != 0 {
		t.Fatalf("sealed %d generations before the state settled", n)
	}
	r.tickFor(s, 2*time.Second)
	chain := r.chain()
	if len(chain) != 1 || chain[0].Generation != 0 || chain[0].ParentBundleSHA256 != "" {
		t.Fatalf("chain %+v", chain)
	}
	first := r.open(chain[0])

	// Unchanged state is not sealed again.
	r.tickFor(s, 5*time.Second)
	if n := len(r.chain()); n != 1 {
		t.Fatalf("resealed unchanged state: %d generations", n)
	}

	// A change is sealed as the next generation, once it settles.
	write(t, filepath.Join(r.state, "adapter.safetensors"), "weights v2")
	r.tickFor(s, time.Second)
	if n := len(r.chain()); n != 1 {
		t.Fatal("sealed a change before it settled")
	}
	r.tickFor(s, 3*time.Second)
	chain = r.chain()
	if len(chain) != 2 || chain[1].Generation != 1 || chain[1].ParentBundleSHA256 != chain[0].BundleSHA256 {
		t.Fatalf("chain %+v", chain)
	}
	if second := r.open(chain[1]); bytes.Equal(first, second) {
		t.Fatal("the second generation holds the first state")
	}
	id, _, err := CheckGenome(r.outbox, chain[1])
	must(t, err)
	if id.Header.ParentGeneration != 0 || id.Header.ParentPayloadSHA256 != strings.TrimPrefix(chain[0].PayloadSHA256, "sha256:") {
		t.Fatalf("header parent %+v", id.Header)
	}

	// A touched but unmodified file moves the fingerprint, not the chain.
	future := r.clock.now().Add(time.Hour)
	must(t, os.Chtimes(filepath.Join(r.state, "genome.json"), future, future))
	r.tickFor(s, 4*time.Second)
	if n := len(r.chain()); n != 2 {
		t.Fatalf("a touch sealed a new generation: %d", n)
	}

	h := r.heartbeat()
	if h.Status != StatusWatching || h.Last == nil || h.Last.Generation != 1 || h.Last.BundleSHA256 != chain[1].BundleSHA256 || h.Wires != 0 {
		t.Fatalf("heartbeat %+v", h)
	}

	// Nothing the sentinel wrote holds a key: only ciphertext and records.
	entries, err := os.ReadDir(r.outbox)
	must(t, err)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("staging file left behind: %s", e.Name())
		}
	}
}

func TestHeartbeatsRiseAcrossRestarts(t *testing.T) {
	r := newRig(t)
	s := r.sentinel()
	r.tickFor(s, 3*time.Second)
	seq := r.heartbeat().Seq
	if seq < 3 {
		t.Fatalf("seq %d after four ticks", seq)
	}
	s = r.sentinel()
	r.tickFor(s, 0)
	if got := r.heartbeat().Seq; got != seq+1 {
		t.Fatalf("seq after restart %d, want %d", got, seq+1)
	}
	if n := len(r.chain()); n != 1 {
		t.Fatalf("a restart over unchanged state sealed again: %d", n)
	}
}

func TestSentinelResumesItsChain(t *testing.T) {
	r := newRig(t)
	r.tickFor(r.sentinel(), 3*time.Second)
	write(t, filepath.Join(r.state, "adapter.safetensors"), "weights v2")
	s := r.sentinel()
	r.tickFor(s, 3*time.Second)
	chain := r.chain()
	if len(chain) != 2 || chain[1].ParentBundleSHA256 != chain[0].BundleSHA256 {
		t.Fatalf("chain after restart %+v", chain)
	}
}

func TestTripwireStopsSealingAndReports(t *testing.T) {
	r := newRig(t)
	canary := filepath.Join(t.TempDir(), "canary")
	write(t, canary, "do not touch")
	s := r.sentinel(&PathWire{Path: canary})
	r.tickFor(s, 3*time.Second)
	sealed := r.chain()
	if len(sealed) != 1 {
		t.Fatalf("chain %+v", sealed)
	}

	// The intruder changes the state and touches the canary in the same
	// tick: the wire is checked first, and the tampered state is not sealed.
	write(t, filepath.Join(r.state, "adapter.safetensors"), "tampered")
	r.clock.advance(10 * time.Second)
	write(t, canary, "touched")
	res, done := r.tickFor(s, 0)
	if !done || res.Outcome != OutcomeCompromised || res.Compromise == nil {
		t.Fatalf("result %+v", res)
	}
	if n := len(r.chain()); n != 1 {
		t.Fatalf("sealed after the wire fired: %d generations", n)
	}
	c, _, err := ReadCompromise(r.outbox, r.pub)
	must(t, err)
	if len(c.Tripped) != 1 || c.Tripped[0].Wire != "path" || c.Tripped[0].Target != canary || c.Tripped[0].Got == c.Tripped[0].Want {
		t.Fatalf("report %+v", c)
	}
	if c.Last == nil || c.Last.BundleSHA256 != sealed[0].BundleSHA256 || !c.DetectedAt.Equal(r.clock.now()) {
		t.Fatalf("report names %+v at %v", c.Last, c.DetectedAt)
	}
	if h := r.heartbeat(); h.Status != StatusCompromised {
		t.Fatalf("final heartbeat %+v", h)
	}

	// A compromise closes the outbox.
	_, err = New(r.config())
	if err == nil || !strings.Contains(err.Error(), "compromise report") {
		t.Fatalf("restart on a closed outbox: %v", err)
	}
}

func TestProbeWire(t *testing.T) {
	sh, err := execLookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	flag := filepath.Join(t.TempDir(), "healthy")
	write(t, flag, "")
	w := &ProbeWire{Argv: []string{sh, "-c", "test -e " + flag + " || { echo intrusion; exit 7; }"}}
	must(t, w.Arm())
	if trip := w.Check(); trip != nil {
		t.Fatalf("clean probe tripped: %+v", trip)
	}
	must(t, os.Remove(flag))
	trip := w.Check()
	if trip == nil || trip.Got != "exit 7" || trip.Detail != "intrusion" {
		t.Fatalf("trip %+v", trip)
	}
	mustNot(t, w.Arm(), "arming a failing probe")

	slow := &ProbeWire{Argv: []string{sh, "-c", "sleep 5"}, Timeout: 100 * time.Millisecond}
	if trip := slow.Check(); trip == nil || !strings.HasPrefix(trip.Got, "timeout") {
		t.Fatalf("slow probe: %+v", trip)
	}
	gone := &ProbeWire{Argv: []string{filepath.Join(t.TempDir(), "no-such-probe")}}
	if trip := gone.Check(); trip == nil || trip.Got != "error" {
		t.Fatalf("missing probe: %+v", trip)
	}
	mustNot(t, (&ProbeWire{}).Arm(), "an empty probe")
}

func TestPathWireSeesEveryChange(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"content":  func(t *testing.T, dir string) { write(t, filepath.Join(dir, "a"), "changed") },
		"mode":     func(t *testing.T, dir string) { must(t, os.Chmod(filepath.Join(dir, "a"), 0o600)) },
		"new file": func(t *testing.T, dir string) { write(t, filepath.Join(dir, "sub", "dropped"), "tool") },
		"removed":  func(t *testing.T, dir string) { must(t, os.Remove(filepath.Join(dir, "a"))) },
		"symlink": func(t *testing.T, dir string) {
			must(t, os.Remove(filepath.Join(dir, "link")))
			must(t, os.Symlink("/elsewhere", filepath.Join(dir, "link")))
		},
		"dir mode": func(t *testing.T, dir string) { must(t, os.Chmod(filepath.Join(dir, "sub"), 0o700)) },
		"whole":    func(t *testing.T, dir string) { must(t, os.RemoveAll(dir)) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "watched")
			must(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
			write(t, filepath.Join(dir, "a"), "original")
			must(t, os.Symlink("/target", filepath.Join(dir, "link")))
			w := &PathWire{Path: dir}
			must(t, w.Arm())
			if trip := w.Check(); trip != nil {
				t.Fatalf("untouched tree tripped: %+v", trip)
			}
			change(t, dir)
			if trip := w.Check(); trip == nil {
				t.Fatal("change not seen")
			}
		})
	}
	mustNot(t, (&PathWire{Path: filepath.Join(t.TempDir(), "absent")}).Arm(), "arming a missing path")
	file := filepath.Join(t.TempDir(), "f")
	write(t, file, "x")
	w := &PathWire{Path: file}
	must(t, w.Arm())
	must(t, os.Remove(file))
	if trip := w.Check(); trip == nil || trip.Got != "missing" {
		t.Fatalf("removed file: %+v", trip)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	r := newRig(t)
	cfg := r.config()
	cfg.Clock, cfg.Settle, cfg.Interval = time.Now, 0, 10*time.Millisecond
	s, err := New(cfg)
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			if h, _, err := ReadHeartbeat(r.outbox, r.pub); err == nil && h.Last != nil {
				cancel()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	res, err := s.Run(ctx)
	must(t, err)
	if res.Outcome != OutcomeStopped || res.Generations != 1 || res.Last == nil {
		t.Fatalf("result %+v", res)
	}
	if h := r.heartbeat(); h.Status != StatusStopped {
		t.Fatalf("last heartbeat %+v", h)
	}
}

func TestParentStartsAFreshOutbox(t *testing.T) {
	r := newRig(t)
	r.tickFor(r.sentinel(), 3*time.Second)
	parent := r.chain()[0]
	id, _, err := CheckGenome(r.outbox, parent)
	must(t, err)

	// The state is restored on another machine, which starts its own
	// outbox continuing the chain.
	r2 := newRig(t)
	r2.state = r.state
	write(t, filepath.Join(r2.state, "adapter.safetensors"), "trained further")
	cfg := r2.config()
	cfg.Parent = &id
	s, err := New(cfg)
	must(t, err)
	r2.tickFor(s, 3*time.Second)
	chain := r2.chain()
	if len(chain) != 1 || chain[0].Generation != 1 || chain[0].ParentBundleSHA256 != parent.BundleSHA256 {
		t.Fatalf("chain %+v", chain)
	}
	// A parent is refused for an outbox that already has a chain.
	cfg.Parent = &id
	_, err = New(cfg)
	mustNot(t, err, "a parent for a non-empty outbox")
}

func TestOutboxWithForeignRecordsIsRefused(t *testing.T) {
	r := newRig(t)
	r.tickFor(r.sentinel(), 3*time.Second)
	// Another sentinel's record lands in this outbox.
	other := newRig(t)
	other.outbox = r.outbox
	_, err := New(other.config())
	if err == nil || !strings.Contains(err.Error(), "not this sentinel's chain") {
		t.Fatalf("foreign outbox: %v", err)
	}
}

func TestOutboxWhoseNewestGenomeIsDamagedIsRefused(t *testing.T) {
	r := newRig(t)
	r.tickFor(r.sentinel(), 3*time.Second)
	f, err := os.OpenFile(filepath.Join(r.outbox, BundleName(0)), os.O_WRONLY|os.O_APPEND, 0)
	must(t, err)
	_, err = f.Write([]byte("x"))
	must(t, err)
	must(t, f.Close())
	_, err = New(r.config())
	if err == nil || !strings.Contains(err.Error(), "does not check out") {
		t.Fatalf("damaged outbox: %v", err)
	}
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	r := newRig(t)
	for name, mutate := range map[string]func(*Config){
		"no source":   func(c *Config) { c.Source = nil },
		"no outbox":   func(c *Config) { c.Outbox = "" },
		"no escrow":   func(c *Config) { c.Escrow = nil },
		"no key":      func(c *Config) { c.Key = nil },
		"no interval": func(c *Config) { c.Interval = 0 },
		"bad settle":  func(c *Config) { c.Settle = -1 },
		"bad wire":    func(c *Config) { c.Wires = []Wire{&PathWire{Path: filepath.Join(t.TempDir(), "absent")}} },
	} {
		cfg := r.config()
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadChainSetsAsideWhatDoesNotLink(t *testing.T) {
	r := newRig(t)
	s := r.sentinel()
	for i := range 4 {
		write(t, filepath.Join(r.state, "adapter.safetensors"), "weights "+string(rune('a'+i)))
		r.tickFor(s, 3*time.Second)
	}
	if n := len(r.chain()); n != 4 {
		t.Fatalf("chain of %d", n)
	}

	// Removing generation 2's record breaks the chain there: 0 and 1
	// remain, 3 is set aside. A missing record can only roll the chain
	// back, never add to it.
	must(t, os.Remove(filepath.Join(r.outbox, RecordName(2))))
	chain, rejected, err := ReadChain(r.outbox, r.pub)
	must(t, err)
	if len(chain) != 2 || len(rejected) != 1 || rejected[0].File != RecordName(3) {
		t.Fatalf("chain %d, rejected %+v", len(chain), rejected)
	}

	// A record edited after signing is set aside, as is one under another
	// file name, one from another sentinel, and a file that is not JSON.
	raw, err := os.ReadFile(filepath.Join(r.outbox, RecordName(1)))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(r.outbox, RecordName(1)), bytes.Replace(raw, []byte(`"generation": 1`), []byte(`"generation": 1 `), 1), 0o644))
	edited := bytes.Replace(raw, []byte("gen-000001.genome\""), []byte("gen-000001.genome\" "), 1)
	var rec SealRecord
	must(t, json.Unmarshal(raw, &rec))
	rec.BundleBytes++
	tampered, err := json.Marshal(rec)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(r.outbox, RecordName(1)), tampered, 0o644))
	must(t, os.WriteFile(filepath.Join(r.outbox, RecordName(7)), edited, 0o644))
	other := newRig(t)
	forged, err := SignRecord(SealRecord{
		Sentinel: KeyID(other.pub), Generation: 8, Bundle: BundleName(8), BundleSHA256: strings.Repeat("a", 64), BundleBytes: 1,
		KeyID: "genome-aaaaaaaaaaaa-g8-bbbbbbbbbbbb", Escrow: EscrowName(8), EscrowKey: "k", PayloadSHA256: "sha256:" + strings.Repeat("a", 64),
		ParentBundleSHA256: strings.Repeat("b", 64), SealedAt: r.clock.now(),
	}, other.key)
	must(t, err)
	raw8, err := encode(forged)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(r.outbox, RecordName(8)), raw8, 0o644))
	must(t, os.WriteFile(filepath.Join(r.outbox, RecordName(9)), []byte("not json"), 0o644))
	chain, rejected, err = ReadChain(r.outbox, r.pub)
	must(t, err)
	if len(chain) != 1 || chain[0].Generation != 0 {
		t.Fatalf("chain %+v", chain)
	}
	reasons := map[string]string{}
	for _, rj := range rejected {
		reasons[rj.File] = rj.Reason
	}
	for file, want := range map[string]string{
		RecordName(1): "signature does not verify",
		RecordName(3): "chain breaks",
		RecordName(7): "the file is generation 7",
		RecordName(8): "signed by " + KeyID(other.pub),
		RecordName(9): "decode",
	} {
		if !strings.Contains(reasons[file], want) {
			t.Errorf("%s: reason %q, want %q", file, reasons[file], want)
		}
	}
}

func TestCheckGenomeTrustsOnlyTheRecord(t *testing.T) {
	r := newRig(t)
	s := r.sentinel()
	r.tickFor(s, 3*time.Second)
	write(t, filepath.Join(r.state, "adapter.safetensors"), "weights v2")
	r.tickFor(s, 3*time.Second)
	chain := r.chain()

	// The escrow envelope of another generation.
	env0, err := os.ReadFile(filepath.Join(r.outbox, EscrowName(0)))
	must(t, err)
	env1, err := os.ReadFile(filepath.Join(r.outbox, EscrowName(1)))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(r.outbox, EscrowName(1)), env0, 0o644))
	if _, _, err := CheckGenome(r.outbox, chain[1]); err == nil || !strings.Contains(err.Error(), "escrows key") {
		t.Fatalf("swapped envelope: %v", err)
	}
	must(t, os.WriteFile(filepath.Join(r.outbox, EscrowName(1)), env1, 0o644))

	// Another generation's bundle under this one's name.
	b0, err := os.ReadFile(filepath.Join(r.outbox, BundleName(0)))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(r.outbox, BundleName(1)), b0, 0o644))
	if _, _, err := CheckGenome(r.outbox, chain[1]); err == nil || !strings.Contains(err.Error(), "hashes to") {
		t.Fatalf("swapped bundle: %v", err)
	}
	// A record whose digest matches a bundle whose header differs.
	rec := chain[0]
	rec.KeyID = chain[1].KeyID
	if _, _, err := CheckGenome(r.outbox, rec); err == nil || !strings.Contains(err.Error(), "header") {
		t.Fatalf("header mismatch: %v", err)
	}
	must(t, os.Remove(filepath.Join(r.outbox, EscrowName(0))))
	if _, _, err := CheckGenome(r.outbox, chain[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing envelope: %v", err)
	}
}

func TestRecordsVerifyOnlyAsSigned(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	id := KeyID(pub)
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	link := &Link{Generation: 3, BundleSHA256: strings.Repeat("c", 64), SealedAt: now}

	h, err := SignHeartbeat(Heartbeat{Sentinel: id, Seq: 1, At: now, StartedAt: now, Status: StatusWatching, Last: link, Wires: 2}, key)
	must(t, err)
	raw, err := encode(h)
	must(t, err)
	got, err := ParseHeartbeat(raw, pub)
	must(t, err)
	if got.Seq != 1 || got.Last.Generation != 3 {
		t.Fatalf("heartbeat %+v", got)
	}
	for name, edit := range map[string][2]string{
		"status": {`"watching"`, `"stopped"`},
		"seq":    {`"seq": 1`, `"seq": 2`},
		"extra":  {`"wires": 2`, `"wires": 2, "note": "x"`},
	} {
		if _, err := ParseHeartbeat(bytes.Replace(raw, []byte(edit[0]), []byte(edit[1]), 1), pub); err == nil {
			t.Errorf("heartbeat with %s edited verified", name)
		}
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	if _, err := ParseHeartbeat(raw, otherPub); err == nil {
		t.Error("heartbeat verified under another key")
	}

	c, err := SignCompromise(Compromise{Sentinel: id, DetectedAt: now, Tripped: []Trip{{Wire: "path", Target: "/etc/x", Want: "a", Got: "b"}}, Last: link}, key)
	must(t, err)
	raw, err = encode(c)
	must(t, err)
	if _, err := ParseCompromise(raw, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCompromise(bytes.Replace(raw, []byte(`"/etc/x"`), []byte(`"/etc/y"`), 1), pub); err == nil {
		t.Error("edited compromise report verified")
	}

	// Malformed records are refused before any signature is made.
	for name, bad := range map[string]signable{
		"heartbeat without seq":   Heartbeat{Sentinel: id, At: now, StartedAt: now, Status: StatusWatching},
		"unknown status":          Heartbeat{Sentinel: id, Seq: 1, At: now, StartedAt: now, Status: "fine"},
		"compromise without trip": Compromise{Sentinel: id, DetectedAt: now},
		"bad link":                Heartbeat{Sentinel: id, Seq: 1, At: now, StartedAt: now, Status: StatusWatching, Last: &Link{}},
		"record without parent":   SealRecord{Sentinel: id, Generation: 1, Bundle: BundleName(1), Escrow: EscrowName(1), BundleSHA256: strings.Repeat("a", 64), BundleBytes: 1, KeyID: "genome-aaaaaaaaaaaa-g1-bbbbbbbbbbbb", EscrowKey: "k", PayloadSHA256: "sha256:" + strings.Repeat("a", 64), SealedAt: now},
		"record, wrong file":      SealRecord{Sentinel: id, Generation: 0, Bundle: BundleName(1), Escrow: EscrowName(0), BundleSHA256: strings.Repeat("a", 64), BundleBytes: 1, KeyID: "genome-aaaaaaaaaaaa-g0-bbbbbbbbbbbb", EscrowKey: "k", PayloadSHA256: "sha256:" + strings.Repeat("a", 64), SealedAt: now},
	} {
		if _, err := signatureOver(bad, key); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	// A record naming another sentinel is not signed with this key.
	if _, err := SignHeartbeat(Heartbeat{Sentinel: KeyID(otherPub), Seq: 1, At: now, StartedAt: now, Status: StatusWatching}, key); err == nil {
		t.Error("signed a heartbeat for another sentinel")
	}
}

func TestReadersRefuseWhatIsNotARecord(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	if _, _, err := ReadHeartbeat(dir, pub); !errors.Is(err, ErrAbsent) {
		t.Fatalf("absent heartbeat: %v", err)
	}
	must(t, os.Mkdir(filepath.Join(dir, CompromiseFile), 0o755))
	if _, _, err := ReadCompromise(dir, pub); err == nil || errors.Is(err, ErrAbsent) {
		t.Fatalf("a directory as a report: %v", err)
	}
	must(t, os.WriteFile(filepath.Join(dir, HeartbeatFile), bytes.Repeat([]byte(" "), maxRecordBytes+1), 0o644))
	if _, _, err := ReadHeartbeat(dir, pub); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("oversized heartbeat: %v", err)
	}
	if _, _, err := ReadChain(filepath.Join(dir, "absent"), pub); err == nil {
		t.Fatal("chain of a missing outbox")
	}
}
