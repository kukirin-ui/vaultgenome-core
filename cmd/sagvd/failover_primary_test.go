// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

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

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
)

// The primary's verifier is built from the policy's pin and the anchors
// the registry holds for that kind: a simulated primary by its attestation
// key at any pinned measurement, a SEV-SNP one by the registry's AMD chain
// at the pinned measurements; a kind the registry does not know has no
// anchors to borrow.
func TestPrimaryVerifierFromThePolicyAndTheRegistry(t *testing.T) {
	f := newFailoverFixture(t)
	primary, err := tee.NewSimulated([]byte("primary-v1"), bytes.Repeat([]byte{0x41}, 32))
	require.NoError(t, err)
	other, err := tee.NewSimulated([]byte("primary-v2"), bytes.Repeat([]byte{0x41}, 32))
	require.NoError(t, err)
	pin := func(p *failover.Policy) {
		p.Primary = &failover.Primary{Kind: string(tee.ProviderSimulated), AttestorPublicKey: primary.PublicKey(),
			Measurements: []string{hex.EncodeToString(primary.Measurement()), hex.EncodeToString(other.Measurement())}}
	}
	pol := f.signedPolicy(t, string(tee.ProviderSimulated), f.operator, pin)
	v, err := primaryVerifier(f.cfg, pol)
	require.NoError(t, err)
	require.NotNil(t, v)

	// A record attested by the primary verifies; by the other measurement
	// too (both pinned); by another key, not.
	pub, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	now := time.Now().UTC()
	h := sentinel.Heartbeat{Sentinel: sentinel.KeyID(pub), Seq: 1, At: now, StartedAt: now, Status: sentinel.StatusWatching}
	h, err = sentinel.AttestHeartbeat(h, primary, tee.ProviderSimulated)
	require.NoError(t, err)
	h, err = sentinel.SignHeartbeat(h, key)
	require.NoError(t, err)
	m, err := h.Attested(v)
	require.NoError(t, err)
	require.True(t, m.Equal(primary.Measurement()))
	require.True(t, pol.PrimaryAllows(m))
	h2, err := sentinel.AttestHeartbeat(sentinel.Heartbeat{Sentinel: sentinel.KeyID(pub), Seq: 2, At: now, StartedAt: now, Status: sentinel.StatusWatching}, other, tee.ProviderSimulated)
	require.NoError(t, err)
	h2, err = sentinel.SignHeartbeat(h2, key)
	require.NoError(t, err)
	m, err = h2.Attested(v)
	require.NoError(t, err)
	require.True(t, m.Equal(other.Measurement()))
	stranger, err := tee.NewSimulated([]byte("primary-v1"), bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	h3, err := sentinel.AttestHeartbeat(sentinel.Heartbeat{Sentinel: sentinel.KeyID(pub), Seq: 3, At: now, StartedAt: now, Status: sentinel.StatusWatching}, stranger, tee.ProviderSimulated)
	require.NoError(t, err)
	h3, err = sentinel.SignHeartbeat(h3, key)
	require.NoError(t, err)
	_, err = h3.Attested(v)
	require.Error(t, err)

	// No pin: no verifier. A SEV-SNP pin: the registry's chain.
	v, err = primaryVerifier(f.cfg, f.signedPolicy(t, string(tee.ProviderSimulated), f.operator))
	require.NoError(t, err)
	require.Nil(t, v)
	chain := filepath.Join(f.dir, "amd-chain.pem")
	require.NoError(t, os.WriteFile(chain, []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"), 0o644))
	f.cfg.CrossCloud.VerifierRegistryPath = writeFile(t, f.dir, "registry-sev.json", []byte(`{"verifiers":[{"provider":"gcp-sev-snp","expected_measurement_hex":"`+makeMeasurementHex(0x55)+`","amd_cert_chain_path":"`+chain+`"}]}`))
	sev := f.signedPolicy(t, string(tee.ProviderSimulated), f.operator, func(p *failover.Policy) {
		p.Primary = &failover.Primary{Kind: string(tee.ProviderGCPSEVSNP), Measurements: []string{hex.EncodeToString(bytes.Repeat([]byte{7}, 48))}}
	})
	v, err = primaryVerifier(f.cfg, sev)
	require.NoError(t, err)
	require.IsType(t, &tee.GCPSEVVerifier{}, v)
	_, err = primaryVerifier(f.cfg, pol)
	require.ErrorContains(t, err, "no simulated entry")

	// Armed with a pinned primary, the executor says so and watches.
	f.cfg.CrossCloud.VerifierRegistryPath = simulatedCrossCloudConfig(t, t.TempDir()).CrossCloud.VerifierRegistryPath
	f.write(t, "sagvd-pinned.json")
	report := filepath.Join(f.dir, "report.json")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	code, err := runFailoverCmd(ctx, []string{"-config", f.cfgPath, "-policy", f.policyFile(t, pol), "-outbox", f.outbox, "-poll", "20ms", "-report", report})
	require.NoError(t, err)
	require.Equal(t, failoverExitRestored, code)
	raw, err := os.ReadFile(report)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"status": "stopped"`)

	// anyVerifier with nothing behind it refuses.
	_, err = anyVerifier(nil).Verify(nil, nil)
	require.ErrorContains(t, err, "no verifier")
}

// signedPolicy signs a policy to the simulated standby with key, mutated.
func (f *failoverFixture) signedPolicy(t *testing.T, kind string, key ed25519.PrivateKey, mutate ...func(*failover.Policy)) failover.Policy {
	t.Helper()
	_, spub, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	p := failover.Policy{
		Serial:            4,
		IssuedAt:          time.Now().Add(-time.Minute).UTC(),
		NotAfter:          time.Now().Add(time.Hour).UTC(),
		SentinelPublicKey: spub.Public().(ed25519.PublicKey),
		Standby:           failover.Standby{Kind: kind, Endpoint: "https://standby.example:8443", Measurements: []string{makeMeasurementHex(0x55)}},
		Triggers:          failover.Triggers{CompromiseReport: true, HeartbeatTimeoutSeconds: 60},
		RequireGate:       "EQUIVALENT",
		SigningKeyID:      "operator-test",
	}
	for _, m := range mutate {
		m(&p)
	}
	signed, err := failover.Sign(p, key)
	require.NoError(t, err)
	return signed
}

func (f *failoverFixture) policyFile(t *testing.T, p failover.Policy) string {
	t.Helper()
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	return writeFile(t, f.dir, "failover-"+strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")+".json", raw)
}
