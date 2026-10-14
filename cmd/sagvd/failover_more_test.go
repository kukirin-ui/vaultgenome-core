// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
)

// The rest of what failover refuses before it arms: a config it cannot
// run under, an operator key it cannot read, material it cannot load, a
// policy that has expired; and a report it cannot write is an error even
// when the watch itself ended cleanly.
func TestFailoverCmd_RefusesMoreBeforeWatching(t *testing.T) {
	f := newFailoverFixture(t)
	good := f.policy(t, string(tee.ProviderSimulated), f.operator)
	expired := f.policyFile(t, f.signedPolicy(t, string(tee.ProviderSimulated), f.operator, func(p *failover.Policy) {
		p.IssuedAt, p.NotAfter = time.Now().Add(-2*time.Hour).UTC(), time.Now().Add(-time.Hour).UTC()
	}))
	invalid := *f
	invalid.cfg.TEE.Provider = "vmware"
	invalid.write(t, "invalid.json")
	noOperatorKey := *f
	noOperatorKey.cfg.CrossCloud.OperatorStop.PublicKeyPath = filepath.Join(f.dir, "absent.pub")
	noOperatorKey.write(t, "nokey.json")
	noPeer := *f
	noPeer.cfg.TEE.Peer.MeasurementPath = filepath.Join(f.dir, "absent")
	noPeer.write(t, "nopeer.json")
	// A registry that knows the standby and a TDX kind the policy pins as
	// the primary: the standby verifies, the primary cannot be verified.
	meas := makeMeasurementHex(0x55)
	twoKinds := *f
	twoKinds.cfg.CrossCloud.VerifierRegistryPath = writeFile(t, f.dir, "registry-two.json", []byte(`{"verifiers":[{"provider":"simulated","attestor_pubkey_path":"`+
		writeFile(t, f.dir, "attestor2.pub", generateEd25519PubRaw(t))+`","expected_measurement_hex":"`+meas+`"},{"provider":"gcp-tdx","expected_measurement_hex":"`+strings.Repeat("ab", 48)+`"}]}`))
	twoKinds.write(t, "twokinds.json")
	tdxPrimary := f.policyFile(t, f.signedPolicy(t, string(tee.ProviderSimulated), f.operator, func(p *failover.Policy) {
		p.Primary = &failover.Primary{Kind: string(tee.ProviderGCPTDX), Measurements: []string{strings.Repeat("ab", 48)}}
	}))

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"invalid config":       {[]string{"-config", invalid.cfgPath, "-policy", good, "-outbox", f.outbox}, "failover: config validation"},
		"operator key missing": {[]string{"-config", noOperatorKey.cfgPath, "-policy", good, "-outbox", f.outbox}, "crosscloud.operator_stop.public_key_path"},
		"materials missing":    {[]string{"-config", noPeer.cfgPath, "-policy", good, "-outbox", f.outbox}, "tee.peer.measurement_path"},
		"expired policy":       {[]string{"-config", f.cfgPath, "-policy", expired, "-outbox", f.outbox}, "expired"},
		"primary unverifiable": {[]string{"-config", twoKinds.cfgPath, "-policy", tdxPrimary, "-outbox", f.outbox}, "no verifier this build can run for it"},
	} {
		t.Run(name, func(t *testing.T) {
			code, err := runFailoverCmd(context.Background(), tc.args)
			require.Equal(t, failoverExitFailed, code)
			require.ErrorContains(t, err, tc.want)
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := runFailoverCmd(ctx, []string{"-config", f.cfgPath, "-policy", good, "-outbox", f.outbox, "-poll", "20ms", "-report", filepath.Join(f.dir, "missing", "report.json")})
	require.ErrorContains(t, err, "no such file")

	// Without -report the report is printed and nowhere else.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	var code int
	printed := captureStdout(t, func() {
		code, err = runFailoverCmd(ctx2, []string{"-config", f.cfgPath, "-policy", good, "-outbox", f.outbox, "-poll", "20ms"})
	})
	require.NoError(t, err)
	require.Equal(t, failoverExitRestored, code)
	require.Contains(t, printed, `"status": "stopped"`)
}

// compromiseReport writes a compromise report signed by the sentinel key
// into the outbox.
func compromiseReport(t *testing.T, outbox string, spub ed25519.PublicKey, spriv ed25519.PrivateKey) {
	t.Helper()
	report := sentinel.Compromise{
		Sentinel: sentinel.KeyID(spub), DetectedAt: time.Now().Add(-time.Minute).UTC(),
		Tripped: []sentinel.Trip{{Wire: "path", Target: "/srv/models/current", Want: "sha256:" + hex.EncodeToString(make([]byte, 32)), Got: "missing"}},
	}
	report, err := sentinel.SignCompromise(report, spriv)
	require.NoError(t, err)
	raw, err := json.Marshal(report)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(outbox, sentinel.CompromiseFile), raw, 0o644))
}

// A compromise report from the pinned sentinel is a trigger. The outbox
// holds no genome that sentinel sealed, so the failover is declined on
// the record — FAILOVER_DECIDED, with the reason — and the command exits 3
// with the report written, the standby never contacted.
func TestFailoverCmd_DeclinesWhenTheOutboxHoldsNoGenome(t *testing.T) {
	f := newFailoverFixture(t)
	spub, spriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pol := f.signedPolicy(t, string(tee.ProviderSimulated), f.operator, func(p *failover.Policy) { p.SentinelPublicKey = spub })
	compromiseReport(t, f.outbox, spub, spriv)

	reportPath := filepath.Join(f.dir, "report.json")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var code int
	printed := captureStdout(t, func() {
		code, err = runFailoverCmd(ctx, []string{"-config", f.cfgPath, "-policy", f.policyFile(t, pol), "-outbox", f.outbox, "-poll", "20ms", "-report", reportPath})
	})
	require.NoError(t, err)
	require.Equal(t, failoverExitDeclined, code)
	var out failoverOutput
	require.NoError(t, json.Unmarshal([]byte(printed), &out), printed)
	require.Equal(t, failover.StatusDeclined, out.Status)
	require.NotNil(t, out.Decision)
	require.Equal(t, failover.DecisionDeclined, out.Decision.Decision)
	require.Contains(t, out.Decision.Reason, "holds no genome")
	require.Equal(t, 1, out.AuditChainLength, "the declined decision is the one record")
	require.Len(t, out.AuditTip, 64)
	require.Equal(t, uint64(1), out.StopSerial)
	written, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.JSONEq(t, printed, string(written))

	xcc, err := LoadCrossCloudMaterials(f.cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	defer func() { _ = xcc.Close() }()
	require.Len(t, xcc.AuditChain.Events(), 1)
	require.Equal(t, "FAILOVER_DECIDED", string(xcc.AuditChain.Events()[0].Kind))

	// A decision taken but a report that cannot be written is a failure
	// the exit code reports, after the decision went on the record.
	g := newFailoverFixture(t)
	compromiseReport(t, g.outbox, spub, spriv)
	gpol := g.signedPolicy(t, string(tee.ProviderSimulated), g.operator, func(p *failover.Policy) { p.SentinelPublicKey = spub })
	captureStdout(t, func() {
		code, err = runFailoverCmd(ctx, []string{"-config", g.cfgPath, "-policy", g.policyFile(t, gpol), "-outbox", g.outbox, "-poll", "20ms", "-report", filepath.Join(g.dir, "missing", "report.json")})
	})
	require.Equal(t, failoverExitFailed, code)
	require.ErrorContains(t, err, "no such file")
}

// A pinned primary is verified only by a kind this build can verify, with
// measurements that are hex, from anchors the registry holds for it.
func TestPrimaryVerifier_Refusals(t *testing.T) {
	f := newFailoverFixture(t)
	pin := func(kind string, measurements ...string) failover.Policy {
		return failover.Policy{Primary: &failover.Primary{Kind: kind, Measurements: measurements}}
	}
	_, err := primaryVerifier(f.cfg, pin("vmware", makeMeasurementHex(0x55)))
	require.ErrorContains(t, err, "primary kind")
	_, err = primaryVerifier(f.cfg, pin(string(tee.ProviderSimulated), "not-hex"))
	require.ErrorContains(t, err, "primary measurement")

	meas := makeMeasurementHex(0x55)
	f.cfg.CrossCloud.VerifierRegistryPath = writeFile(t, f.dir, "registry-tdx.json", []byte(`{"verifiers":[{"provider":"gcp-tdx","expected_measurement_hex":"`+meas+`"}]}`))
	_, err = primaryVerifier(f.cfg, pin(string(tee.ProviderGCPTDX), meas))
	require.ErrorContains(t, err, "no verifier this build can run for it")
	f.cfg.CrossCloud.VerifierRegistryPath = filepath.Join(f.dir, "absent.json")
	_, err = primaryVerifier(f.cfg, pin(string(tee.ProviderSimulated), meas))
	require.ErrorContains(t, err, "verifier_registry_path")
	require.ErrorContains(t, preflightFailover(f.cfg, shared_time.NewSystemClock(), pin(string(tee.ProviderSimulated), meas)), "verifier_registry_path")
}
