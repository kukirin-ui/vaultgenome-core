// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

var t0 = time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)

func standbyMeasurement() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

func testPolicy(sentinelPub ed25519.PublicKey) Policy {
	return Policy{
		Serial:            7,
		IssuedAt:          t0,
		NotAfter:          t0.Add(30 * 24 * time.Hour),
		SentinelPublicKey: sentinelPub,
		Standby: Standby{
			Kind:         string(tee.ProviderSimulated),
			Endpoint:     "https://standby.example:8443",
			Measurements: []string{hex.EncodeToString(standbyMeasurement())},
		},
		Triggers:     Triggers{CompromiseReport: true, HeartbeatTimeoutSeconds: 30},
		RequireGate:  "EQUIVALENT",
		SigningKeyID: "operator-1",
	}
}

func operatorKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestPolicySignsAndVerifies(t *testing.T) {
	opPub, op := operatorKey(t)
	sPub, _ := operatorKey(t)
	signed, err := Sign(testPolicy(sPub), op)
	must(t, err)
	raw, err := json.Marshal(signed)
	must(t, err)
	got, err := Parse(raw, opPub, "operator-1")
	must(t, err)
	if got.Serial != 7 || !bytes.Equal(got.SentinelPublicKey, sPub) {
		t.Fatalf("parsed %+v", got)
	}
	if _, sid := got.Sentinel(); !strings.HasPrefix(sid, "sentinel-") {
		t.Fatalf("sentinel id %s", sid)
	}

	edited := bytes.Replace(raw, []byte(`"https://standby.example:8443"`), []byte(`"https://elsewhere.example"`), 1)
	if _, err := Parse(edited, opPub, "operator-1"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("edited endpoint: %v", err)
	}
	if _, err := Parse(raw, opPub, "operator-2"); err == nil {
		t.Fatal("verified for another operator key id")
	}
	otherPub, _ := operatorKey(t)
	if _, err := Parse(raw, otherPub, "operator-1"); err == nil {
		t.Fatal("verified under another key")
	}
	if _, err := Parse(append(raw[:len(raw)-1], []byte(`,"extra":1}`)...), opPub, "operator-1"); err == nil {
		t.Fatal("unknown field accepted")
	}
	if !bytes.Equal(got.Digest(), signed.Digest()) || bytes.Equal(got.Digest(), testPolicy(sPub).Digest()) {
		t.Fatal("digest does not name the signed policy")
	}
}

func TestPolicyValidation(t *testing.T) {
	_, op := operatorKey(t)
	sPub, _ := operatorKey(t)
	for name, mutate := range map[string]func(*Policy){
		"serial 0":           func(p *Policy) { p.Serial = 0 },
		"no expiry":          func(p *Policy) { p.NotAfter = p.IssuedAt },
		"short sentinel key": func(p *Policy) { p.SentinelPublicKey = sPub[:31] },
		"no trigger":         func(p *Policy) { p.Triggers = Triggers{} },
		"negative timeout":   func(p *Policy) { p.Triggers.HeartbeatTimeoutSeconds = -1 },
		"negative rpo":       func(p *Policy) { p.MaxRPOSeconds = -1 },
		"bad gate":           func(p *Policy) { p.RequireGate = "CLOSE" },
		"no signer":          func(p *Policy) { p.SigningKeyID = "" },
		"unknown kind":       func(p *Policy) { p.Standby.Kind = "quantum" },
		"plain http":         func(p *Policy) { p.Standby.Endpoint = "http://standby.example" },
		"relative endpoint":  func(p *Policy) { p.Standby.Endpoint = "/v1" },
		"no measurement":     func(p *Policy) { p.Standby.Measurements = nil },
		"upper-case hex":     func(p *Policy) { p.Standby.Measurements = []string{strings.ToUpper(p.Standby.Measurements[0])} },
		"short measurement":  func(p *Policy) { p.Standby.Measurements = []string{"abcd"} },
		"wrong schema":       func(p *Policy) { p.Schema = "v0" },
	} {
		p := testPolicy(sPub)
		mutate(&p)
		if _, err := Sign(p, op); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	p := testPolicy(sPub)
	p.Standby.Endpoint = "http://127.0.0.1:8443"
	if _, err := Sign(p, op); err != nil {
		t.Errorf("loopback http refused: %v", err)
	}
}

func TestPolicyScope(t *testing.T) {
	sPub, _ := operatorKey(t)
	p := testPolicy(sPub)
	if !p.Allows(tee.ProviderSimulated, standbyMeasurement()) {
		t.Fatal("the standby is not allowed")
	}
	if p.Allows(tee.ProviderGCPSEVSNP, standbyMeasurement()) || p.Allows(tee.ProviderSimulated, bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("a destination other than the standby is allowed")
	}
	must(t, p.ActiveAt(t0.Add(time.Hour)))
	if err := p.ActiveAt(p.NotAfter); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("at expiry: %v", err)
	}
	if err := p.ActiveAt(t0.Add(-time.Hour)); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("before issue: %v", err)
	}
}

func decided(t *testing.T, decision string, serial uint64) audit_event.AuditEvent {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"decision": decision, "policy_serial": serial})
	must(t, err)
	return audit_event.AuditEvent{EventID: ids.AuditEventID("evt-" + decision), Kind: audit_event.KindFailoverDecided, Payload: raw}
}

func TestPolicyIsSpentByItsFailover(t *testing.T) {
	sPub, _ := operatorKey(t)
	p := testPolicy(sPub)
	must(t, CheckNotSpent(p, nil))
	// A declined trigger does not spend the policy.
	must(t, CheckNotSpent(p, []audit_event.AuditEvent{decided(t, DecisionDeclined, 7)}))
	if err := CheckNotSpent(p, []audit_event.AuditEvent{decided(t, DecisionFailover, 7)}); err == nil || !strings.Contains(err.Error(), "already carried out") {
		t.Fatalf("spent policy: %v", err)
	}
	if err := CheckNotSpent(p, []audit_event.AuditEvent{decided(t, DecisionDeclined, 9)}); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("older policy: %v", err)
	}
	bad := audit_event.AuditEvent{EventID: "evt-x", Kind: audit_event.KindFailoverDecided, Payload: []byte("{")}
	if err := CheckNotSpent(p, []audit_event.AuditEvent{bad}); err == nil {
		t.Fatal("undecodable event accepted")
	}
}

func TestGateReleasesOnlyToTheStandby(t *testing.T) {
	sPub, _ := operatorKey(t)
	p := testPolicy(sPub)
	other := bytes.Repeat([]byte{0x11}, 32)
	allow, err := kms.NewAllowListPolicy("allow-v1", map[tee.Provider][][]byte{tee.ProviderSimulated: {standbyMeasurement(), other}})
	must(t, err)
	// As sagvd composes it: the operator stop in front, the failover policy
	// inside it, the allow-list innermost.
	g := revocation.NewGate(NewGate(allow, p), revocation.List{Serial: 3})

	v, err := g.AuthorizeKeyRelease(tee.ProviderSimulated, standbyMeasurement(), "d", []ids.KeyID{"k"})
	must(t, err)
	if !v.Authorized {
		t.Fatalf("standby refused: %s", v.Reason)
	}
	v, err = g.AuthorizeKeyRelease(tee.ProviderSimulated, other, "d", []ids.KeyID{"k"})
	must(t, err)
	if v.Authorized || !strings.Contains(v.Reason, "only to its standby") {
		t.Fatalf("allow-listed non-standby: %+v", v)
	}
	if got := g.PolicyVersion(); got != "allow-v1;failover=7;revocation=3" {
		t.Fatalf("policy version %q", got)
	}
	// The operator stop still refuses the standby itself.
	stopped := revocation.NewGate(NewGate(allow, p), revocation.List{Serial: 4, StopAll: true, Reason: "drill over"})
	v, err = stopped.AuthorizeKeyRelease(tee.ProviderSimulated, standbyMeasurement(), "d", []ids.KeyID{"k"})
	must(t, err)
	if v.Authorized || !strings.Contains(v.Reason, "operator stop") {
		t.Fatalf("stopped standby: %+v", v)
	}
	// Serial anti-rollback still finds the stop serial.
	raw, err := json.Marshal(map[string]string{"policy_version": g.PolicyVersion()})
	must(t, err)
	if revocation.HighestSerial([]audit_event.AuditEvent{{Kind: audit_event.KindKeyReleaseAuthorized, Payload: raw}}) != 3 {
		t.Fatal("the stop serial is no longer readable from the policy version")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
