// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
)

type failoverFixture struct {
	dir      string
	cfg      Config
	cfgPath  string
	operator ed25519.PrivateKey
	outbox   string
}

// newFailoverFixture writes a sagvd config that passes validation, with
// cross-cloud release to a simulated destination, an escrow key and an
// operator key.
func newFailoverFixture(t *testing.T) *failoverFixture {
	t.Helper()
	dir := t.TempDir()
	f := &failoverFixture{dir: dir, outbox: filepath.Join(dir, "outbox")}
	require.NoError(t, os.MkdirAll(f.outbox, 0o755))
	xc := simulatedCrossCloudConfig(t, dir)
	// Real key material: the executor loads the authority's keys, the
	// escrow key among them, before it watches.
	f.cfg = newMaterialFixture(t).cfg
	f.cfg.CrossCloud = xc.CrossCloud
	f.cfg.Keys.AuditSigning = xc.Keys.AuditSigning
	f.operator = withAuditLog(t, dir, &f.cfg) // a fresh operator key the test holds
	esc, err := escrow.GenerateKey()
	require.NoError(t, err)
	f.cfg.CrossCloud.KeyEscrowPath = writeFile(t, dir, "escrow.key", esc.Bytes())
	require.NoError(t, os.Chmod(f.cfg.CrossCloud.KeyEscrowPath, 0o600))
	f.write(t, "sagvd.json")
	return f
}

func (f *failoverFixture) write(t *testing.T, name string) {
	t.Helper()
	raw, err := json.Marshal(f.cfg)
	require.NoError(t, err)
	f.cfgPath = writeFile(t, f.dir, name, raw)
}

// policy signs a failover policy to the simulated destination the config
// trusts (or another kind), with key.
func (f *failoverFixture) policy(t *testing.T, kind string, key ed25519.PrivateKey) string {
	t.Helper()
	spub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p, err := failover.Sign(failover.Policy{
		Serial:            4,
		IssuedAt:          time.Now().Add(-time.Minute).UTC(),
		NotAfter:          time.Now().Add(time.Hour).UTC(),
		SentinelPublicKey: spub,
		Standby:           failover.Standby{Kind: kind, Endpoint: "https://standby.example:8443", Measurements: []string{makeMeasurementHex(0x55)}},
		Triggers:          failover.Triggers{CompromiseReport: true, HeartbeatTimeoutSeconds: 60},
		RequireGate:       "EQUIVALENT",
		SigningKeyID:      "operator-test",
	}, key)
	require.NoError(t, err)
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	return writeFile(t, f.dir, "failover-"+kind+".json", raw)
}

func TestFailoverCmd_RefusesBeforeWatching(t *testing.T) {
	f := newFailoverFixture(t)
	good := f.policy(t, string(tee.ProviderSimulated), f.operator)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	forged := f.policy(t, string(tee.ProviderSimulated), stranger)
	unverifiable := f.policy(t, string(tee.ProviderGCPSEVSNP), f.operator)

	disabled := *f
	disabled.cfg.CrossCloud.Enabled = false
	disabled.write(t, "disabled.json")
	noEscrow := *f
	noEscrow.cfg.CrossCloud.KeyEscrowPath = ""
	noEscrow.write(t, "no-escrow.json")

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no flags":       {nil, "-config, -policy and -outbox required"},
		"bad poll":       {[]string{"-config", f.cfgPath, "-policy", good, "-outbox", f.outbox, "-poll", "0s"}, "must be positive"},
		"missing config": {[]string{"-config", filepath.Join(f.dir, "absent.json"), "-policy", good, "-outbox", f.outbox}, "absent.json"},
		"disabled":       {[]string{"-config", disabled.cfgPath, "-policy", good, "-outbox", f.outbox}, "crosscloud.enabled=false"},
		"no escrow":      {[]string{"-config", noEscrow.cfgPath, "-policy", good, "-outbox", f.outbox}, "key_escrow_path required"},
		"forged policy":  {[]string{"-config", f.cfgPath, "-policy", forged, "-outbox", f.outbox}, "does not verify under the operator key"},
		"missing policy": {[]string{"-config", f.cfgPath, "-policy", filepath.Join(f.dir, "none.json"), "-outbox", f.outbox}, "-policy"},
		"no verifier":    {[]string{"-config", f.cfgPath, "-policy", unverifiable, "-outbox", f.outbox}, "no verifier for it"},
		"undefined flag": {[]string{"-key-file", "x"}, "flag provided but not defined"},
	} {
		t.Run(name, func(t *testing.T) {
			code, err := runFailoverCmd(context.Background(), tc.args)
			require.Equal(t, failoverExitFailed, code)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// Armed and watching an outbox where nothing happens: stopping it is not a
// failure, and it says it stopped.
func TestFailoverCmd_WatchesUntilStopped(t *testing.T) {
	f := newFailoverFixture(t)
	report := filepath.Join(f.dir, "report.json")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	code, err := runFailoverCmd(ctx, []string{"-config", f.cfgPath, "-policy", f.policy(t, string(tee.ProviderSimulated), f.operator),
		"-outbox", f.outbox, "-poll", "20ms", "-report", report})
	require.NoError(t, err)
	require.Equal(t, failoverExitRestored, code)
	raw, err := os.ReadFile(report)
	require.NoError(t, err)
	var out failoverOutput
	require.NoError(t, json.Unmarshal(raw, &out))
	require.Equal(t, "stopped", out.Status)
	require.Equal(t, uint64(4), out.PolicySerial)
	require.True(t, strings.HasPrefix(out.Sentinel, "sentinel-"))
}

// A policy that already carried out a failover does not arm again.
func TestFailoverCmd_RefusesASpentPolicy(t *testing.T) {
	f := newFailoverFixture(t)
	path := f.policy(t, string(tee.ProviderSimulated), f.operator)
	xcc, err := LoadCrossCloudMaterials(f.cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	_, err = xcc.AuditEmitter.Emit(audit_event.KindFailoverDecided, []byte(`{"decision":"failover","policy_serial":4}`), "", "", "")
	require.NoError(t, err)
	require.NoError(t, xcc.Close())
	code, err := runFailoverCmd(context.Background(), []string{"-config", f.cfgPath, "-policy", path, "-outbox", f.outbox})
	require.Equal(t, failoverExitFailed, code)
	require.ErrorContains(t, err, "already carried out a failover")
}
