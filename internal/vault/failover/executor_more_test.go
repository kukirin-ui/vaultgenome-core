// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// A trigger that carries no record of the sentinel's vouches for nothing:
// the outbox is read but no generation in it can be chosen. An outbox
// that cannot be read at all is an error, not a reason.
func TestTriggerWithoutARecordVouchesForNothing(t *testing.T) {
	sPub, _ := operatorKey(t)
	p := testPolicy(sPub)
	tr := Trigger{Kind: TriggerHeartbeatTimeout, At: t0}
	if tr.reportedLast() != nil {
		t.Fatal("a bare trigger names a generation")
	}

	choice, why, err := Choose(t.TempDir(), p, tr, "escrow-x", nil)
	must(t, err)
	if !strings.Contains(why, "holds no genome") || choice.ChainEnd != nil || choice.Record.KeyID != "" {
		t.Fatalf("empty outbox: %+v %q", choice, why)
	}

	_, _, err = Choose(filepath.Join(t.TempDir(), "missing"), p, tr, "escrow-x", nil)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing outbox: %v", err)
	}
}

// heartbeat writes a heartbeat signed by the sentinel key into outbox.
func heartbeat(t *testing.T, outbox string, key ed25519.PrivateKey, seq uint64, status string, at time.Time) {
	t.Helper()
	h, err := sentinel.SignHeartbeat(sentinel.Heartbeat{
		Sentinel: sentinel.KeyID(key.Public().(ed25519.PublicKey)), Seq: seq, At: at, StartedAt: at.Add(-time.Minute), Status: status, Wires: 1,
	}, key)
	must(t, err)
	raw, err := json.Marshal(h)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(outbox, sentinel.HeartbeatFile), raw, 0o644))
}

// The heartbeat's sequence only rises: an older heartbeat put back is
// noted once and moves nothing. A heartbeat that says `compromised` is a
// compromise trigger on its own when the report itself is missing, and
// only when the policy acts on compromise reports.
func TestWatcherReadsTheHeartbeatsSequenceAndStatus(t *testing.T) {
	sPub, sKey, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	outbox := t.TempDir()
	now := t0.Add(time.Hour)
	clock := func() time.Time { return now }

	w := NewWatcher(testPolicy(sPub), outbox, clock, nil)
	if tr := w.Observe(); tr != nil || w.State != "waiting for the primary's first heartbeat" {
		t.Fatalf("trigger %+v state %q", tr, w.State)
	}
	heartbeat(t, outbox, sKey, 5, sentinel.StatusWatching, now)
	if tr := w.Observe(); tr != nil || w.State != "watching" || w.hb.Seq != 5 {
		t.Fatalf("trigger %+v state %q", tr, w.State)
	}

	heartbeat(t, outbox, sKey, 3, sentinel.StatusWatching, now)
	for i := 0; i < 2; i++ {
		if tr := w.Observe(); tr != nil || w.hb.Seq != 5 {
			t.Fatalf("an older heartbeat moved the watcher: %+v %+v", tr, w.hb)
		}
	}
	if len(w.Ignored) != 1 || w.Ignored[0] != sentinel.HeartbeatFile+": sequence 3 after 5: an older heartbeat was put back" {
		t.Fatalf("ignored %v", w.Ignored)
	}

	// The same sequence again is neither newer nor older: nothing to note.
	heartbeat(t, outbox, sKey, 5, sentinel.StatusWatching, now)
	if tr := w.Observe(); tr != nil || len(w.Ignored) != 1 {
		t.Fatalf("trigger %+v ignored %v", tr, w.Ignored)
	}

	// `compromised` without a report: the heartbeat is the trigger.
	heartbeat(t, outbox, sKey, 6, sentinel.StatusCompromised, now)
	tr := w.Observe()
	if tr == nil || tr.Kind != TriggerCompromise || tr.Compromise != nil || tr.Heartbeat == nil || tr.Heartbeat.Seq != 6 || !tr.At.Equal(now) {
		t.Fatalf("trigger %+v", tr)
	}
	if len(tr.Ignored) != 1 {
		t.Fatalf("the trigger does not carry what was ignored: %v", tr.Ignored)
	}

	// A policy that does not act on compromise reports keeps watching.
	quiet := testPolicy(sPub)
	quiet.Triggers = Triggers{HeartbeatTimeoutSeconds: 30}
	w = NewWatcher(quiet, outbox, clock, nil)
	if tr := w.Observe(); tr != nil || w.State != "watching" {
		t.Fatalf("trigger %+v state %q", tr, w.State)
	}
	now = now.Add(31 * time.Second)
	if tr := w.Observe(); tr == nil || tr.Kind != TriggerHeartbeatTimeout {
		t.Fatalf("trigger %+v", tr)
	}
}

// Under a policy that pins the primary to one measurement, a record the
// chip attested under another is not the primary's: the watcher ignores
// it and the chooser sets it aside.
func TestPinnedPrimaryRefusesAnotherMeasurement(t *testing.T) {
	d := newDrill(t)
	primary, verifier := primaryTEE(t)
	ctx, cancel := context.WithCancel(context.Background())
	results := d.attested(ctx, primary)
	chain := d.waitChain(1)
	cancel()
	<-results

	other := hex.EncodeToString(bytesOf(0x33, 32))
	pol := d.pinned(primary, func(p *Policy) { p.Primary.Measurements = []string{other} })
	want := "measurement " + hex.EncodeToString(primary.Measurement()) + ", which the policy does not pin as the primary"

	w := NewWatcher(pol, d.outbox, time.Now, verifier)
	if tr := w.Observe(); tr != nil || w.State != "waiting for the primary's first heartbeat" {
		t.Fatalf("trigger %+v state %q", tr, w.State)
	}
	if len(w.Ignored) != 1 || !strings.Contains(w.Ignored[0], want) {
		t.Fatalf("ignored %v", w.Ignored)
	}

	hb, raw, err := sentinel.ReadHeartbeat(d.outbox, d.sentinelKey.Public().(ed25519.PublicKey))
	must(t, err)
	tr := Trigger{Kind: TriggerHeartbeatTimeout, At: hb.At.Add(time.Second), Heartbeat: &hb, Evidence: raw}
	choice, why, err := Choose(d.outbox, pol, tr, escrowTag(d), verifier)
	must(t, err)
	if why == "" || choice.Record.KeyID != "" {
		t.Fatalf("chose %+v: %q", choice.Record, why)
	}
	if len(choice.SetAside) != 1 || choice.SetAside[0].File != sentinel.RecordName(chain[0].Generation) || !strings.Contains(choice.SetAside[0].Reason, want) {
		t.Fatalf("set aside %+v", choice.SetAside)
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// compromised runs a drill's sentinel to one generation and trips it,
// returning the trigger the authority observes.
func compromised(t *testing.T, gateVals ...float32) (*drill, Trigger) {
	t.Helper()
	d := newDrill(t, gateVals...)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	results := d.runSentinel(ctx)
	d.waitChain(1)
	must(t, os.WriteFile(d.canary, []byte("touched"), 0o600))
	if res := <-results; res.Outcome != sentinel.OutcomeCompromised {
		t.Fatalf("sentinel %+v", res)
	}
	tr := NewWatcher(d.policy(), d.outbox, time.Now, nil).Observe()
	if tr == nil || tr.Kind != TriggerCompromise {
		t.Fatalf("trigger %+v", tr)
	}
	return d, *tr
}

// A genome escrowed to another authority, or sealed inside the policy's
// quarantine, is set aside with its reason; with nothing left the
// failover is declined on the record and no key moves.
func TestChooseSetsAsideWhatItCannotRestore(t *testing.T) {
	d, tr := compromised(t)
	pol := d.policy()

	choice, why, err := Choose(d.outbox, pol, tr, "escrow-of-another-authority", nil)
	must(t, err)
	if !strings.Contains(why, "no genome in the verified chain was sealed by") || choice.Record.KeyID != "" {
		t.Fatalf("choice %+v: %q", choice.Record, why)
	}
	if len(choice.SetAside) != 1 || !strings.Contains(choice.SetAside[0].Reason, "its key is escrowed to "+escrowTag(d)+", not to this authority's escrow-of-another-authority") {
		t.Fatalf("set aside %+v", choice.SetAside)
	}

	quarantine := pol
	quarantine.QuarantineSeconds = 3600
	quarantine, err = Sign(quarantine, d.operator)
	must(t, err)
	choice, why, err = Choose(d.outbox, quarantine, tr, escrowTag(d), nil)
	must(t, err)
	if !strings.Contains(why, "no genome in the verified chain was sealed by") || choice.Record.KeyID != "" {
		t.Fatalf("choice %+v: %q", choice.Record, why)
	}
	if len(choice.SetAside) != 1 || !strings.Contains(choice.SetAside[0].Reason, "after the cutoff") {
		t.Fatalf("set aside %+v", choice.SetAside)
	}

	ex, err := d.executor(quarantine)
	must(t, err)
	rep, err := ex.Failover(context.Background(), tr)
	must(t, err)
	if rep.Status != StatusDeclined || rep.Genome != nil || len(rep.SetAside) != 1 || rep.Decision.DecisionID != "" {
		t.Fatalf("report %+v", rep)
	}
	if got := d.audit.kinds(); len(got) != 1 || got[0] != audit_event.KindFailoverDecided {
		t.Fatalf("audit %v", got)
	}
}

// An executor whose context has already ended watches nothing and reports
// nothing.
func TestRunReturnsWhenTheContextEnds(t *testing.T) {
	d := newDrill(t)
	ex, err := d.executor(d.policy())
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := ex.Run(ctx)
	if !errors.Is(err, context.Canceled) || rep.Status != "" || rep.Trigger != nil {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	if n := len(d.audit.Events()); n != 0 {
		t.Fatalf("%d audit events for no trigger", n)
	}
}

type failingIDs struct{}

func (failingIDs) NewRequestID() (ids.RequestID, error) { return "", errors.New("id source down") }
func (failingIDs) NewDecisionID() (ids.DecisionID, error) {
	return "", errors.New("id source down")
}

// refusingAudit is a log that refuses one kind of record.
type refusingAudit struct {
	*memAudit
	refuse audit_event.Kind
}

func (a *refusingAudit) Emit(kind audit_event.Kind, payload []byte, s ids.SessionID, m ids.ManifestID, req ids.RequestID) (ids.AuditEventID, error) {
	if kind == a.refuse {
		return "", errors.New("audit log refused the record")
	}
	return a.memAudit.Emit(kind, payload, s, m, req)
}

// A failover that cannot be put on the record is not carried out: no
// decision id, no record, no key released.
func TestFailoverStopsWhenTheDecisionCannotBeRecorded(t *testing.T) {
	d, tr := compromised(t)
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"outbox unreadable": {func(c *Config) { c.Outbox = filepath.Join(t.TempDir(), "gone") }, "no such file"},
		"no decision id":    {func(c *Config) { c.IDs = failingIDs{} }, "id source down"},
		"record refused":    {func(c *Config) { c.Audit = &refusingAudit{memAudit: d.audit, refuse: audit_event.KindFailoverDecided} }, "audit log refused the record"},
	} {
		cfg := Config{Policy: d.policy(), Outbox: d.outbox, Escrow: d.escrow, Coordinator: d.coord, Audit: d.audit, Events: d.audit.Events,
			IDs: &seqIDs{}, Clock: shared_time.NewSystemClock(), Poll: 20 * time.Millisecond, ConfirmWait: time.Second}
		tc.mutate(&cfg)
		ex, err := New(cfg)
		must(t, err)
		rep, err := ex.Failover(context.Background(), tr)
		if err == nil || !strings.Contains(err.Error(), tc.want) || rep.Status != StatusFailed || rep.Error != err.Error() {
			t.Fatalf("%s: report %+v, err %v", name, rep, err)
		}
		if rep.Decision != nil || rep.Release != nil {
			t.Fatalf("%s: a decision or release in a report that never got on the record: %+v", name, rep)
		}
		if n := len(d.audit.Events()); n != 0 {
			t.Fatalf("%s: %d audit events", name, n)
		}
	}
	// The policy is not spent by what was never decided.
	if _, err := d.executor(d.policy()); err != nil {
		t.Fatalf("policy spent: %v", err)
	}
}

// stuckReceipts answers every receipt request with "not yet", and can end
// the executor's context the first time it is asked.
type stuckReceipts struct {
	cancel context.CancelFunc
	asked  int
}

func (s *stuckReceipts) FetchRestoreReceipt(context.Context, string, ids.KeyID) (receipt.Signed, error) {
	s.asked++
	if s.cancel != nil {
		s.cancel()
	}
	return receipt.Signed{}, shared_errors.Operational(shared_errors.CodeResourceExhausted, "restore not complete", nil)
}

// withReceipts rebuilds the drill's coordinator with receipts fetched by r.
func (d *drill) withReceipts(r kms.ReceiptFetcher) {
	d.t.Helper()
	allow, err := kms.NewAllowListPolicy("allow-v1", map[tee.Provider][][]byte{tee.ProviderSimulated: {d.standby.Measurement()[:]}})
	must(d.t, err)
	transport := kms.NewHTTPTransport(kms.HTTPTransportConfig{HTTPClient: d.srv.Client(), BearerToken: "drill-token", RequestTimeout: 10 * time.Second})
	d.coord, err = kms.NewCoordinator(kms.Config{
		AuditChain: d.audit, Signer: mustAuthority(d.t), Verifiers: mustRegistry(d.t, d),
		Policy: revocation.NewGate(NewGate(allow, d.policy()), d.stop), Transport: transport, IDGenerator: &seqIDs{},
		NonceSource: func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			return b, err
		},
		Clock: shared_time.NewSystemClock(), SigningKeyID: "authority-1", Receipts: r,
	})
	must(d.t, err)
}

// Once the key is released, the failover stands or falls on the standby's
// receipt: a receipt that never comes within the confirm wait, a context
// that ends while waiting, a log that lost the release, and a receipt
// without the gate verdict the policy requires each fail the run after
// the release is on the record.
func TestFailoverFailsOnWhatFollowsTheRelease(t *testing.T) {
	for name, tc := range map[string]struct {
		arrange func(t *testing.T, d *drill, cfg *Config) (context.Context, *stuckReceipts)
		want    string
		asked   func(int) bool
	}{
		"receipt never comes": {
			arrange: func(t *testing.T, d *drill, cfg *Config) (context.Context, *stuckReceipts) {
				stuck := &stuckReceipts{}
				d.withReceipts(stuck)
				cfg.Coordinator, cfg.ConfirmWait = d.coord, 100*time.Millisecond
				return context.Background(), stuck
			},
			want: "restore not complete", asked: func(n int) bool { return n >= 1 },
		},
		"context ends while waiting": {
			arrange: func(t *testing.T, d *drill, cfg *Config) (context.Context, *stuckReceipts) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				stuck := &stuckReceipts{cancel: cancel}
				d.withReceipts(stuck)
				cfg.Coordinator, cfg.ConfirmWait = d.coord, time.Minute
				return ctx, stuck
			},
			want: context.Canceled.Error(), asked: func(n int) bool { return n == 1 },
		},
		"release missing from the log": {
			arrange: func(t *testing.T, d *drill, cfg *Config) (context.Context, *stuckReceipts) {
				cfg.Events = func() []audit_event.AuditEvent { return nil }
				return context.Background(), nil
			},
			want: "no authorized release",
		},
		"no gate verdict": {
			arrange: func(t *testing.T, d *drill, cfg *Config) (context.Context, *stuckReceipts) {
				return context.Background(), nil
			},
			want: "no gate verdict",
		},
	} {
		t.Run(name, func(t *testing.T) {
			d, tr := compromised(t)
			cfg := Config{Policy: d.policy(), Outbox: d.outbox, Escrow: d.escrow, Coordinator: d.coord, Audit: d.audit, Events: d.audit.Events,
				IDs: &seqIDs{}, Clock: shared_time.NewSystemClock(), Poll: 20 * time.Millisecond, ConfirmWait: 20 * time.Second}
			ctx, stuck := tc.arrange(t, d, &cfg)
			ex, err := New(cfg)
			must(t, err)
			rep, err := ex.Failover(ctx, tr)
			if err == nil || !strings.Contains(err.Error(), tc.want) || rep.Status != StatusFailed || rep.Error != err.Error() {
				t.Fatalf("report %+v, err %v", rep, err)
			}
			if rep.Decision == nil || rep.Decision.DecisionID == "" || rep.Release == nil || rep.Release.TokenID == "" || rep.Restore != nil {
				t.Fatalf("report %+v", rep)
			}
			want := []audit_event.Kind{audit_event.KindFailoverDecided, audit_event.KindCrossCloudHandshakeInitiated,
				audit_event.KindCrossCloudAttestationVerified, audit_event.KindKeyReleaseAuthorized}
			got := d.audit.kinds()
			if len(got) < len(want) || strings.Join(kindNames(got[:len(want)]), ",") != strings.Join(kindNames(want), ",") {
				t.Fatalf("audit %v", got)
			}
			for _, k := range got {
				if k == audit_event.KindCrossCloudRestoreCompleted {
					t.Fatalf("a restore confirmed on the record: %v", got)
				}
			}
			if tc.asked != nil && !tc.asked(stuck.asked) {
				t.Fatalf("receipts asked %d times", stuck.asked)
			}
			// A failover decided and not completed spends the policy.
			if _, err := d.executor(d.policy()); err == nil || !strings.Contains(err.Error(), "already carried out") {
				t.Fatalf("policy not spent: %v", err)
			}
			d.awaitStandby(rep.Genome.KeyID)
		})
	}
}

// awaitStandby waits until the standby has finished restoring kid, one way
// or the other, so the test's directories are not removed under it.
func (d *drill) awaitStandby(kid string) {
	d.t.Helper()
	transport := kms.NewHTTPTransport(kms.HTTPTransportConfig{HTTPClient: d.srv.Client(), BearerToken: "drill-token", RequestTimeout: 5 * time.Second})
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		_, err := transport.FetchRestoreReceipt(context.Background(), d.srv.URL, ids.KeyID(kid))
		if err == nil || !shared_errors.Is(err, shared_errors.CategoryOperational) {
			return
		}
	}
	d.t.Fatalf("the standby did not finish restoring %s", kid)
}

func kindNames(kinds []audit_event.Kind) []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}
