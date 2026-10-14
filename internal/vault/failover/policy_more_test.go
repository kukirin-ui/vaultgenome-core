// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// An executor is not built on wiring it cannot run with: every missing
// dependency, a non-positive poll or confirm wait, and a policy that does
// not validate are each refused by name.
func TestNewRefusesIncompleteWiring(t *testing.T) {
	sPub, _ := operatorKey(t)
	_, op := operatorKey(t)
	signed, err := Sign(testPolicy(sPub), op)
	must(t, err)
	key, err := escrow.GenerateKey()
	must(t, err)
	base := func() Config {
		return Config{
			Policy: signed, Outbox: t.TempDir(), Escrow: key, Coordinator: &kms.Coordinator{}, Audit: &memAudit{},
			Events: (&memAudit{}).Events, IDs: &seqIDs{}, Clock: shared_time.NewSystemClock(), Poll: time.Millisecond, ConfirmWait: time.Second,
		}
	}
	if _, err := New(base()); err != nil {
		t.Fatalf("complete wiring refused: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"no outbox":         {func(c *Config) { c.Outbox = "" }, "required"},
		"no escrow key":     {func(c *Config) { c.Escrow = nil }, "required"},
		"no coordinator":    {func(c *Config) { c.Coordinator = nil }, "required"},
		"no audit":          {func(c *Config) { c.Audit = nil }, "required"},
		"no events":         {func(c *Config) { c.Events = nil }, "required"},
		"no ids":            {func(c *Config) { c.IDs = nil }, "required"},
		"no clock":          {func(c *Config) { c.Clock = nil }, "required"},
		"zero poll":         {func(c *Config) { c.Poll = 0 }, "poll and confirm wait must be positive"},
		"negative poll":     {func(c *Config) { c.Poll = -time.Second }, "poll and confirm wait must be positive"},
		"zero confirm wait": {func(c *Config) { c.ConfirmWait = 0 }, "poll and confirm wait must be positive"},
		"policy serial 0":   {func(c *Config) { c.Policy.Serial = 0 }, "serial must be at least 1"},
		"policy no trigger": {func(c *Config) { c.Policy.Triggers = Triggers{} }, "names no trigger"},
	} {
		c := base()
		tc.mutate(&c)
		ex, err := New(c)
		if ex != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: executor %v, err %v, want %q", name, ex, err, tc.want)
		}
	}
}

// A policy that decodes but does not validate is refused before its
// signature is looked at: the refusal names the field, not the signature.
func TestParseRefusesAPolicyThatDoesNotValidate(t *testing.T) {
	opPub, op := operatorKey(t)
	sPub, _ := operatorKey(t)
	for name, tc := range map[string]struct {
		mutate func(*Policy)
		want   string
	}{
		"serial 0":       {func(p *Policy) { p.Serial = 0 }, "serial must be at least 1"},
		"no trigger":     {func(p *Policy) { p.Triggers = Triggers{} }, "names no trigger"},
		"negative rpo":   {func(p *Policy) { p.MaxRPOSeconds = -1 }, "durations must not be negative"},
		"bad gate":       {func(p *Policy) { p.RequireGate = "CLOSE" }, "require_gate"},
		"no measurement": {func(p *Policy) { p.Standby.Measurements = nil }, "at least one measurement"},
	} {
		signed, err := Sign(testPolicy(sPub), op)
		must(t, err)
		tc.mutate(&signed)
		raw, err := json.Marshal(signed)
		must(t, err)
		_, err = Parse(raw, opPub, "operator-1")
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "signature") {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if _, err := Parse([]byte(`{"serial":`), opPub, "operator-1"); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("truncated policy: %v", err)
	}
}

// Only failover decisions spend a policy: the key releases and restore
// confirmations around them, whatever their payloads, are passed over.
func TestCheckNotSpentReadsOnlyDecisions(t *testing.T) {
	sPub, _ := operatorKey(t)
	p := testPolicy(sPub)
	others := []audit_event.AuditEvent{
		{EventID: "evt-1", Kind: audit_event.KindKeyReleaseAuthorized, Payload: []byte(`{"decision":"failover","policy_serial":7}`)},
		{EventID: "evt-2", Kind: audit_event.KindCrossCloudRestoreCompleted, Payload: []byte("{")},
		{EventID: "evt-3", Kind: audit_event.KindKeyReleaseDenied, Payload: []byte(`{"policy_serial":99}`)},
	}
	must(t, CheckNotSpent(p, others))
	spent := append(others, decided(t, DecisionFailover, 7))
	if err := CheckNotSpent(p, spent); err == nil || !strings.Contains(err.Error(), "evt-failover") {
		t.Fatalf("spent policy among other events: %v", err)
	}
}
