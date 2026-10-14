// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/crosscloud"
	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/restorer"
	"github.com/vault-genome/vaultgenome-core/internal/contentdir"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// --- the primary's state: a model genome as the vg_genome worker writes it

func f32b64(vals ...float32) string {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// writeModel writes a model genome whose one fixture expects vals, with
// adapter weights w.
func writeModel(t *testing.T, dir, w string, vals ...float32) {
	t.Helper()
	fx, err := json.Marshal(map[string]any{"schema": "vault-genome/lora-fixtures/v1", "fixtures": []map[string]any{
		{"id": "fx-000", "critical": true, "expected": map[string]any{"dtype": "f32", "shape": []int{len(vals)}, "raw_b64": f32b64(vals...)}},
	}})
	must(t, err)
	sum := sha256.Sum256(fx)
	g, err := json.Marshal(map[string]any{
		"schema":   "vault-genome/lora-genome/v1",
		"base":     map[string]any{"name": "base", "manifest": map[string]any{"files": map[string]string{"model.safetensors": "sha256:00"}, "digest": "sha256:base"}},
		"adapter":  map[string]any{"dir": "adapter", "weights_sha256": "sha256:cd"},
		"fixtures": map[string]any{"file": "fixtures.json", "sha256": "sha256:" + hex.EncodeToString(sum[:])},
	})
	must(t, err)
	must(t, os.MkdirAll(filepath.Join(dir, "adapter"), 0o755))
	for name, data := range map[string]string{"genome.json": string(g), "fixtures.json": string(fx), "adapter/adapter_model.safetensors": w} {
		must(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644))
	}
}

// door answers the gate with outputs, as the model restored on the standby
// would compute them.
func door(t *testing.T, vals ...float32) []string {
	t.Helper()
	resp, err := json.Marshal(map[string]any{"outputs": map[string]any{
		"fx-000": map[string]any{"dtype": "f32", "shape": []int{len(vals)}, "raw_b64": f32b64(vals...)},
	}})
	must(t, err)
	p := filepath.Join(t.TempDir(), "resp.json")
	must(t, os.WriteFile(p, resp, 0o644))
	return []string{"sh", "-c", `cat >/dev/null; [ -f "$1/genome.json" ] && cat "` + p + `"`, "door", restorer.GenomePlaceholder}
}

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

// freezable is a source a test can freeze: the primary hangs mid-tick and
// writes nothing more, as a machine that died or froze would.
type freezable struct {
	dirSource
	frozen atomic.Bool
	thawed chan struct{}
}

func (f *freezable) Fingerprint() (string, error) {
	if f.frozen.Load() {
		<-f.thawed
	}
	return f.dirSource.Fingerprint()
}

// --- the release authority's audit log and identifiers

type memAudit struct {
	mu     sync.Mutex
	events []audit_event.AuditEvent
}

func (m *memAudit) Emit(kind audit_event.Kind, payload []byte, _ ids.SessionID, _ ids.ManifestID, req ids.RequestID) (ids.AuditEventID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := ids.AuditEventID(fmt.Sprintf("evt-%d", len(m.events)+1))
	m.events = append(m.events, audit_event.AuditEvent{EventID: id, Kind: kind, Payload: payload, RequestID: req})
	return id, nil
}

func (m *memAudit) Events() []audit_event.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]audit_event.AuditEvent(nil), m.events...)
}

func (m *memAudit) kinds() []audit_event.Kind {
	var out []audit_event.Kind
	for _, e := range m.Events() {
		out = append(out, e.Kind)
	}
	return out
}

type seqIDs struct{ n atomic.Int64 }

func (s *seqIDs) NewRequestID() (ids.RequestID, error) {
	return ids.RequestID(fmt.Sprintf("req-%d", s.n.Add(1))), nil
}
func (s *seqIDs) NewDecisionID() (ids.DecisionID, error) {
	return ids.DecisionID(fmt.Sprintf("dec-%d", s.n.Add(1))), nil
}

// --- the drill: primary, standby and release authority in one process

type drill struct {
	t        *testing.T
	state    string
	outbox   string
	restores string
	canary   string

	sentinelKey ed25519.PrivateKey
	escrow      *ecdh.PrivateKey
	operator    ed25519.PrivateKey
	standby     *tee.Simulated
	srv         *httptest.Server
	audit       *memAudit
	coord       *kms.Coordinator
	stop        revocation.List
}

func newDrill(t *testing.T, gateVals ...float32) *drill {
	t.Helper()
	d := &drill{t: t, state: t.TempDir(), outbox: filepath.Join(t.TempDir(), "outbox"), restores: t.TempDir(), audit: &memAudit{}}
	must(t, os.MkdirAll(d.outbox, 0o755))
	writeModel(t, d.state, "weights v1", 1.5, -2)
	d.canary = filepath.Join(t.TempDir(), "canary")
	must(t, os.WriteFile(d.canary, []byte("no process reads this"), 0o600))
	var err error
	_, d.sentinelKey, err = ed25519.GenerateKey(rand.Reader)
	must(t, err)
	d.escrow, err = escrow.GenerateKey()
	must(t, err)
	_, d.operator, err = ed25519.GenerateKey(rand.Reader)
	must(t, err)
	clock := shared_time.NewSystemClock()

	// The release authority's signing key; the standby pins its public half.
	authority := keys.NewInMemoryStore(clock)
	_, err = authority.RegisterSigningFromSeed("authority-1", keys.PurposeSigningAuthority, bytes.Repeat([]byte{9}, 32))
	must(t, err)

	// The standby: an acp-bootstrap whose bundle directory is the primary's
	// outbox, replicated — here, the same directory.
	d.standby, err = tee.NewSimulated([]byte("standby-v1"), bytes.Repeat([]byte{4}, 32))
	must(t, err)
	keystore := keys.NewInMemoryStore(clock)
	var gate *restorer.GateConfig
	if len(gateVals) > 0 {
		gate = &restorer.GateConfig{Command: door(t, gateVals...), Tolerance: equivalence.Tolerance{Atol: 1e-2, Rtol: 1e-3}, Timeout: 30 * time.Second, Required: true}
	}
	rest, err := restorer.New(restorer.Config{BundleDir: d.outbox, RestoreDir: d.restores, Keys: keystore, Erase: keystore.EraseSealing,
		TEE: d.standby, Kind: tee.ProviderSimulated, Clock: clock, Rescan: 20 * time.Millisecond, Gate: gate, Logger: slog.New(slog.DiscardHandler)})
	must(t, err)
	receiver, err := crosscloud.NewReceiver(crosscloud.Config{SourceAuthorityKeys: authority, LocalTEE: d.standby, Kind: tee.ProviderSimulated,
		Registrar: keystore, Clock: clock, OnDelivery: rest.Delivered})
	must(t, err)
	handler, err := crosscloud.NewHTTPHandler(crosscloud.HTTPHandlerConfig{Receiver: receiver, BearerToken: "drill-token", Logger: slog.New(slog.DiscardHandler)})
	must(t, err)
	mux := http.NewServeMux()
	for path, h := range handler.Routes() {
		mux.HandleFunc(path, h)
	}
	for path, h := range rest.Routes("drill-token") {
		mux.HandleFunc(path, h)
	}
	d.srv = httptest.NewServer(mux)
	t.Cleanup(d.srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go rest.Run(ctx)

	// The release authority: verifies the standby's TEE, allow-lists it,
	// and releases under the operator's stop list and the failover policy.
	measurement := d.standby.Measurement()
	registry, err := tee.NewRegistry([]tee.RegistrySpec{{Provider: tee.ProviderSimulated, Spec: tee.VerifierSpec{
		Provider: tee.ProviderSimulated, ExpectedMeasurement: measurement, AttestorPubKey: d.standby.PublicKey()}}})
	must(t, err)
	d.stop = revocation.List{Serial: 1}
	d.coordinator(registry, authority)
	return d
}

func (d *drill) coordinator(registry *tee.Registry, authority *keys.InMemoryStore) {
	allow, err := kms.NewAllowListPolicy("allow-v1", map[tee.Provider][][]byte{tee.ProviderSimulated: {d.standby.Measurement()[:]}})
	must(d.t, err)
	transport := kms.NewHTTPTransport(kms.HTTPTransportConfig{HTTPClient: d.srv.Client(), BearerToken: "drill-token", RequestTimeout: 10 * time.Second})
	d.coord, err = kms.NewCoordinator(kms.Config{
		AuditChain:  d.audit,
		Signer:      authority,
		Verifiers:   registry,
		Policy:      revocation.NewGate(NewGate(allow, d.policy()), d.stop),
		Transport:   transport,
		IDGenerator: &seqIDs{},
		NonceSource: func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			return b, err
		},
		Clock:        shared_time.NewSystemClock(),
		SigningKeyID: "authority-1",
		Receipts:     transport,
	})
	must(d.t, err)
}

func (d *drill) policy() Policy {
	m := d.standby.Measurement()
	p, err := Sign(Policy{
		Serial:            7,
		IssuedAt:          time.Now().Add(-time.Minute).UTC(),
		NotAfter:          time.Now().Add(time.Hour).UTC(),
		SentinelPublicKey: d.sentinelKey.Public().(ed25519.PublicKey),
		Standby:           Standby{Kind: string(tee.ProviderSimulated), Endpoint: d.srv.URL, Measurements: []string{hex.EncodeToString(m[:])}},
		Triggers:          Triggers{CompromiseReport: true, HeartbeatTimeoutSeconds: 1},
		RequireGate:       "EQUIVALENT",
		SigningKeyID:      "operator-1",
	}, d.operator)
	must(d.t, err)
	return p
}

func (d *drill) executor(p Policy) (*Executor, error) {
	return New(Config{
		Policy: p, Outbox: d.outbox, Escrow: d.escrow, Coordinator: d.coord, Audit: d.audit, Events: d.audit.Events,
		IDs: &seqIDs{}, Clock: shared_time.NewSystemClock(), Poll: 20 * time.Millisecond, ConfirmWait: 20 * time.Second,
	})
}

// runSentinel starts the primary's sentinel; the returned channel yields
// its result.
func (d *drill) runSentinel(ctx context.Context) <-chan sentinel.Result {
	return d.runSentinelOn(ctx, dirSource{d.state})
}

func (d *drill) runSentinelOn(ctx context.Context, src sentinel.Source) <-chan sentinel.Result {
	d.t.Helper()
	s, err := sentinel.New(sentinel.Config{
		Source: src, Outbox: d.outbox, Escrow: d.escrow.PublicKey(), Key: d.sentinelKey,
		Wires: []sentinel.Wire{&sentinel.PathWire{Path: d.canary}}, Interval: 20 * time.Millisecond, Settle: 40 * time.Millisecond,
	})
	must(d.t, err)
	// The sentinel stops, at the latest, when the test does — and the test
	// waits for it, so it never outlives the test that started it.
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

// waitChain waits for the outbox chain to reach n generations.
func (d *drill) waitChain(n int) []sentinel.SealRecord {
	d.t.Helper()
	pub := d.sentinelKey.Public().(ed25519.PublicKey)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		chain, _, err := sentinel.ReadChain(d.outbox, pub)
		must(d.t, err)
		if len(chain) >= n {
			return chain
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.t.Fatalf("the chain did not reach %d generations", n)
	return nil
}

func (d *drill) restored(kid string) string {
	d.t.Helper()
	b, err := os.ReadFile(filepath.Join(d.restores, kid, "adapter", "adapter_model.safetensors"))
	must(d.t, err)
	return string(b)
}

func decidedPayloadOf(t *testing.T, events []audit_event.AuditEvent) decidedPayload {
	t.Helper()
	for _, e := range events {
		if e.Kind == audit_event.KindFailoverDecided {
			var p decidedPayload
			must(t, json.Unmarshal(e.Payload, &p))
			return p
		}
	}
	t.Fatal("no FAILOVER_DECIDED on record")
	return decidedPayload{}
}

// The drill: the primary trains, its sentinel seals every state; an
// intruder touches the canary and tampers with the model; the release
// authority fails over, under the operator's policy, to the last genome
// sealed before the intrusion — and the standby restores it, gates it and
// signs for it.
func TestFailoverOnCompromise(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	ex, err := d.executor(d.policy())
	must(t, err)
	reports := make(chan Report, 1)
	go func() {
		rep, err := ex.Run(context.Background())
		if err != nil {
			t.Errorf("executor: %v", err)
		}
		reports <- rep
	}()

	results := d.runSentinel(context.Background())
	d.waitChain(1)
	writeModel(t, d.state, "weights v2", 1.5, -2)
	chain := d.waitChain(2)

	// The intrusion: the canary is touched, then the model is tampered with.
	must(t, os.WriteFile(d.canary, []byte("read by an intruder"), 0o600))
	res := <-results
	writeModel(t, d.state, "weights planted by the intruder", 9, 9)
	if res.Outcome != sentinel.OutcomeCompromised || res.Last == nil || res.Last.Generation != 1 {
		t.Fatalf("sentinel %+v", res)
	}

	rep := <-reports
	if rep.Status != StatusRestored {
		t.Fatalf("report %+v", rep)
	}
	if rep.Trigger.Kind != TriggerCompromise || len(rep.Trigger.Tripped) != 1 || rep.Trigger.Tripped[0].Target != d.canary {
		t.Fatalf("trigger %+v", rep.Trigger)
	}
	if rep.Genome == nil || rep.Genome.Generation != 1 || rep.Genome.KeyID != chain[1].KeyID || rep.Genome.BundleSHA256 != chain[1].BundleSHA256 {
		t.Fatalf("genome %+v, want generation 1 %s", rep.Genome, chain[1].KeyID)
	}
	if got := d.restored(chain[1].KeyID); got != "weights v2" {
		t.Fatalf("the standby restored %q", got)
	}
	if rep.Restore == nil || rep.Restore.Gate == nil || rep.Restore.Gate.Level != "EXACT" || rep.Restore.RequiredGate != "EQUIVALENT" {
		t.Fatalf("restore %+v", rep.Restore)
	}
	if !strings.Contains(rep.Release.PolicyVersion, ";failover=7;revocation=1") {
		t.Fatalf("policy version %q", rep.Release.PolicyVersion)
	}
	if tm := rep.Timing; tm == nil || tm.RPOSeconds <= 0 || tm.FailoverSeconds <= 0 || tm.RTOSeconds < tm.FailoverSeconds {
		t.Fatalf("timing %+v", rep.Timing)
	}

	// On the record, in order: the decision, then an ordinary release under
	// the decision ID it names, then the confirmed restore.
	want := []audit_event.Kind{audit_event.KindFailoverDecided, audit_event.KindCrossCloudHandshakeInitiated,
		audit_event.KindCrossCloudAttestationVerified, audit_event.KindKeyReleaseAuthorized, audit_event.KindCrossCloudRestoreCompleted}
	if got := d.audit.kinds(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("audit %v, want %v", got, want)
	}
	p := decidedPayloadOf(t, d.audit.Events())
	if p.Decision != DecisionFailover || p.DecisionID != rep.Decision.DecisionID || *p.Generation != 1 || p.PolicySerial != 7 || *p.ReportedLast != 1 || *p.ChainEnd != 1 {
		t.Fatalf("decision %+v", p)
	}
	rel, err := kms.FindAuthorizedRelease(d.audit.Events(), p.DecisionID)
	must(t, err)
	if len(rel.KeyIDs) != 1 || string(rel.KeyIDs[0]) != chain[1].KeyID {
		t.Fatalf("released %v", rel.KeyIDs)
	}

	// The policy is spent: failing over again takes a new one.
	if _, err := d.executor(d.policy()); err == nil || !strings.Contains(err.Error(), "already carried out") {
		t.Fatalf("second executor: %v", err)
	}
}

// A primary that dies without a word: its heartbeat stops rising, and the
// authority fails over once the policy's timeout has passed.
func TestFailoverOnLostHeartbeat(t *testing.T) {
	d := newDrill(t, 1.5, -2)
	ctx, cancel := context.WithCancel(context.Background())
	src := &freezable{dirSource: dirSource{d.state}, thawed: make(chan struct{})}
	results := d.runSentinelOn(ctx, src)
	t.Cleanup(func() { close(src.thawed); cancel(); <-results })
	chain := d.waitChain(1)
	ex, err := d.executor(d.policy())
	must(t, err)
	reports := make(chan Report, 1)
	go func() {
		rep, err := ex.Run(context.Background())
		if err != nil {
			t.Errorf("executor: %v", err)
		}
		reports <- rep
	}()
	time.Sleep(100 * time.Millisecond) // the executor sees the heartbeat rise

	// The machine goes down mid-stride: nothing more is written.
	src.frozen.Store(true)

	rep := <-reports
	if rep.Status != StatusRestored || rep.Trigger.Kind != TriggerHeartbeatTimeout || rep.Genome.Generation != chain[0].Generation {
		t.Fatalf("report %+v", rep)
	}
	if rep.Timing.DetectSeconds < 1 {
		t.Fatalf("failed over %.3fs after the last heartbeat, inside the 1s timeout", rep.Timing.DetectSeconds)
	}
	if got := d.restored(chain[0].KeyID); got != "weights v1" {
		t.Fatalf("restored %q", got)
	}
}

// A sentinel stopped by its operator says so; the authority stands down.
func TestStoppedSentinelIsNoFailure(t *testing.T) {
	d := newDrill(t)
	ctx, cancel := context.WithCancel(context.Background())
	results := d.runSentinel(ctx)
	d.waitChain(1)
	cancel()
	<-results
	w := NewWatcher(d.policy(), d.outbox, time.Now, nil)
	wctx, wcancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer wcancel()
	if tr, err := w.Watch(wctx, 20*time.Millisecond, nil); tr != nil || err == nil {
		t.Fatalf("triggered on a stopped sentinel: %+v", tr)
	}
	if !strings.Contains(w.State, "standing down") {
		t.Fatalf("state %q", w.State)
	}
	if n := len(d.audit.Events()); n != 0 {
		t.Fatalf("%d audit events for no decision", n)
	}
}

// Records only count when the pinned sentinel signed them: a forged
// compromise report moves nothing.
func TestForgedReportIsIgnored(t *testing.T) {
	d := newDrill(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.runSentinel(ctx)
	d.waitChain(1)
	_, forger, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	fake, err := sentinel.SignCompromise(sentinel.Compromise{Sentinel: sentinel.KeyID(forger.Public().(ed25519.PublicKey)),
		DetectedAt: time.Now().UTC(), Tripped: []sentinel.Trip{{Wire: "path", Target: "/etc/passwd", Got: "changed"}}}, forger)
	must(t, err)
	raw, err := json.Marshal(fake)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(d.outbox, sentinel.CompromiseFile), raw, 0o644))

	w := NewWatcher(d.policy(), d.outbox, time.Now, nil)
	wctx, wcancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer wcancel()
	if tr, _ := w.Watch(wctx, 20*time.Millisecond, nil); tr != nil {
		t.Fatalf("a forged report triggered a failover: %+v", tr)
	}
	if len(w.Ignored) == 0 || !strings.Contains(w.Ignored[0], "signed by") {
		t.Fatalf("ignored %v", w.Ignored)
	}
}

// A genome older than the policy allows is not restored: the decision to
// decline is on the record, and no key moves.
func TestFailoverDeclinedPastTheRPOBound(t *testing.T) {
	d := newDrill(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := d.runSentinel(ctx)
	d.waitChain(1)
	time.Sleep(1100 * time.Millisecond) // the only genome ages past the bound
	must(t, os.WriteFile(d.canary, []byte("touched"), 0o600))
	<-results

	p := d.policy()
	p.MaxRPOSeconds = 1
	p, err := Sign(p, d.operator)
	must(t, err)
	d.coordinator(mustRegistry(t, d), mustAuthority(t))
	ex, err := d.executor(p)
	must(t, err)
	rep, err := ex.Run(context.Background())
	must(t, err)
	if rep.Status != StatusDeclined || !strings.Contains(rep.Decision.Reason, "at most 1s") {
		t.Fatalf("report %+v", rep)
	}
	if got := d.audit.kinds(); len(got) != 1 || got[0] != audit_event.KindFailoverDecided {
		t.Fatalf("audit %v", got)
	}
	if dp := decidedPayloadOf(t, d.audit.Events()); dp.Decision != DecisionDeclined || dp.DecisionID != "" {
		t.Fatalf("decision %+v", dp)
	}
	// A decline does not spend the policy.
	if _, err := d.executor(p); err != nil {
		t.Fatalf("policy spent by a decline: %v", err)
	}
}

// The operator stop overrides the failover policy: the standby itself is
// refused, and the refusal is on the record.
func TestOperatorStopHaltsAFailover(t *testing.T) {
	d := newDrill(t)
	d.stop = revocation.List{Serial: 2, StopAll: true, Reason: "incident review"}
	d.coordinator(mustRegistry(t, d), mustAuthority(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := d.runSentinel(ctx)
	d.waitChain(1)
	must(t, os.WriteFile(d.canary, []byte("touched"), 0o600))
	<-results
	ex, err := d.executor(d.policy())
	must(t, err)
	rep, err := ex.Run(context.Background())
	if err == nil || rep.Status != StatusFailed || !strings.Contains(rep.Error, "operator stop") {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	got := d.audit.kinds()
	if got[0] != audit_event.KindFailoverDecided || got[len(got)-1] != audit_event.KindKeyReleaseDenied {
		t.Fatalf("audit %v", got)
	}
}

func mustRegistry(t *testing.T, d *drill) *tee.Registry {
	t.Helper()
	r, err := tee.NewRegistry([]tee.RegistrySpec{{Provider: tee.ProviderSimulated, Spec: tee.VerifierSpec{
		Provider: tee.ProviderSimulated, ExpectedMeasurement: d.standby.Measurement(), AttestorPubKey: d.standby.PublicKey()}}})
	must(t, err)
	return r
}

func mustAuthority(t *testing.T) *keys.InMemoryStore {
	t.Helper()
	a := keys.NewInMemoryStore(shared_time.NewSystemClock())
	_, err := a.RegisterSigningFromSeed("authority-1", keys.PurposeSigningAuthority, bytes.Repeat([]byte{9}, 32))
	must(t, err)
	return a
}

// A trigger under a policy that has expired is declined, on the record.
func TestExpiredPolicyDeclines(t *testing.T) {
	d := newDrill(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := d.runSentinel(ctx)
	d.waitChain(1)
	must(t, os.WriteFile(d.canary, []byte("touched"), 0o600))
	<-results
	p := d.policy()
	p.IssuedAt = time.Now().Add(-2 * time.Hour).UTC()
	p.NotAfter = time.Now().Add(-time.Second).UTC()
	p, err := Sign(p, d.operator)
	must(t, err)
	d.coordinator(mustRegistry(t, d), mustAuthority(t))
	ex, err := d.executor(p)
	must(t, err)
	rep, err := ex.Run(context.Background())
	must(t, err)
	if rep.Status != StatusDeclined || !strings.Contains(rep.Decision.Reason, "expired") {
		t.Fatalf("report %+v", rep)
	}
	if got := d.audit.kinds(); len(got) != 1 || got[0] != audit_event.KindFailoverDecided {
		t.Fatalf("audit %v", got)
	}
	if _, err := New(Config{Policy: d.policy()}); err == nil {
		t.Fatal("incomplete config accepted")
	}
}
