// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	"github.com/vault-genome/vaultgenome-core/internal/observability/teemetrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// The local TEE producer is built per tee.provider: a hardware provider
// off its hardware says so, an unknown one is refused, and the simulated
// one needs its seed.
func TestBuildTEEProducer_Refusals(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "seed")
	require.NoError(t, os.WriteFile(seed, bytes.Repeat([]byte{9}, 32), 0o600))
	for name, tc := range map[string]struct {
		cfg  TEEConfig
		want string
	}{
		"invalid provider":       {TEEConfig{Provider: "vmware"}, "sagvd: tee.provider:"},
		"unsupported provider":   {TEEConfig{Provider: "aws-nitro"}, "is not available in this build"},
		"tdx off a TDX guest":    {TEEConfig{Provider: "gcp-tdx", TSMReportDir: filepath.Join(dir, "no-tsm")}, "tee.provider=gcp-tdx"},
		"azure without command":  {TEEConfig{Provider: "azure-cgpu"}, "tee.provider=azure-cgpu"},
		"simulated seed missing": {TEEConfig{WorkloadDescriptor: "w", SeedPath: filepath.Join(dir, "absent")}, "read tee.seed_path"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := buildTEEProducer(tc.cfg)
			require.ErrorContains(t, err, tc.want)
		})
	}
	provider, p, err := buildTEEProducer(TEEConfig{WorkloadDescriptor: "sagvd-test", SeedPath: seed})
	require.NoError(t, err)
	require.Equal(t, tee.ProviderSimulated, provider)
	require.True(t, p.Measurement().Equal(tee.MeasurementOf([]byte("sagvd-test"))))
}

// The peer verifier is built per tee.peer.provider, pinned to the
// measurement the hardware reports: 32 bytes for a simulated peer, 48 for
// SEV-SNP, TDX and Azure; each kind's anchors are required and read.
func TestBuildPeerVerifier_PerProvider(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	m32, m48 := write("m32", bytes.Repeat([]byte{1}, 32)), write("m48", bytes.Repeat([]byte{2}, 48))
	key := write("peer.pub", bytes.Repeat([]byte{3}, 32))
	chain := write("chain.pem", []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"))
	absent := filepath.Join(dir, "absent")

	for name, tc := range map[string]struct {
		cfg  PeerTEEConfig
		want string
	}{
		"invalid provider":          {PeerTEEConfig{Provider: "vmware", MeasurementPath: m32}, "tee.peer.provider:"},
		"unsupported provider":      {PeerTEEConfig{Provider: "aws-nitro", MeasurementPath: m48}, "no verifier this build can run end to end"},
		"measurement missing":       {PeerTEEConfig{MeasurementPath: absent, PublicKeyPath: key}, "read tee.peer.measurement_path"},
		"simulated key missing":     {PeerTEEConfig{MeasurementPath: m32, PublicKeyPath: absent}, "read tee.peer.public_key_path"},
		"sev-snp chain missing":     {PeerTEEConfig{Provider: "gcp-sev-snp", MeasurementPath: m48, AMDCertChainPath: absent}, "read tee.peer.amd_cert_chain_path"},
		"tdx 32-byte measurement":   {PeerTEEConfig{Provider: "gcp-tdx", MeasurementPath: m32}, "48-byte TDX measurement"},
		"tdx TCB status unknown":    {PeerTEEConfig{Provider: "gcp-tdx", MeasurementPath: m48, AcceptableTCBStatuses: []string{"Fine"}}, "build verifier for tee.peer.provider=gcp-tdx"},
		"azure 32-byte measurement": {PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: m32, AMDCertChainPath: chain}, "48-byte SEV-SNP launch measurement"},
		"azure chain missing":       {PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: m48, AMDCertChainPath: absent}, "read tee.peer.amd_cert_chain_path"},
		"azure bad pcr digests":     {PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: m48, AMDCertChainPath: chain, PCRDigests: []string{"zz"}}, "tee.peer.pcr_digests"},
		"azure root file missing": {PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: m48, AMDCertChainPath: chain,
			GPUPolicy: &GPUPolicyConfig{Evaluation: "both", NVIDIARIMRootPath: absent}}, "tee.peer.gpu_policy.nvidia_rim_root_path"},
		"azure chain not a chain": {PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: m48, AMDCertChainPath: chain}, "build verifier for tee.peer.provider=azure-cgpu"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := buildPeerVerifier(tc.cfg)
			require.ErrorContains(t, err, tc.want)
		})
	}

	provider, v, err := buildPeerVerifier(PeerTEEConfig{Provider: "gcp-tdx", MeasurementPath: m48, PCSCacheDir: dir, AcceptableTCBStatuses: []string{tee.TCBUpToDate}})
	require.NoError(t, err)
	require.Equal(t, tee.ProviderGCPTDX, provider)
	require.IsType(t, &tee.GCPTDXVerifier{}, v)
	provider, v, err = buildPeerVerifier(PeerTEEConfig{MeasurementPath: m32, PublicKeyPath: key})
	require.NoError(t, err)
	require.Equal(t, tee.ProviderSimulated, provider)
	require.IsType(t, &tee.SimulatedVerifier{}, v)
}

// InstrumentTEE puts the metrics recorder around the producer and the
// verifier, so a quote is counted; without a recorder, or without
// materials, nothing changes.
func TestMaterials_InstrumentTEE(t *testing.T) {
	sim, err := tee.NewSimulated([]byte("instrumented"), bytes.Repeat([]byte{4}, 32))
	require.NoError(t, err)
	verifier := tee.NewSimulatedVerifier(sim.PublicKey(), sim.Measurement())
	m := &materials{Producer: sim, Verifier: verifier, Provider: tee.ProviderSimulated}

	m.InstrumentTEE(nil, "simulated")
	require.Same(t, sim, m.Producer, "no recorder: the producer is the chip's own")
	var none *materials
	none.InstrumentTEE(teemetrics.New(metrics.NewRegistry()), "simulated") // nothing to wrap

	registry := metrics.NewRegistry()
	m.InstrumentTEE(teemetrics.New(registry), "simulated")
	require.NotSame(t, sim, m.Producer)
	require.True(t, m.Producer.Measurement().Equal(sim.Measurement()), "the wrapper answers for the chip")
	ev, err := m.Producer.Quote(bytes.Repeat([]byte{5}, tee.NonceMinBytes))
	require.NoError(t, err)
	got, err := m.Verifier.Verify(ev, bytes.Repeat([]byte{5}, tee.NonceMinBytes))
	require.NoError(t, err)
	require.True(t, got.Equal(sim.Measurement()))
	var rendered bytes.Buffer
	require.NoError(t, registry.WriteMetricsTo(&rendered))
	require.Contains(t, rendered.String(), `vg_tee_attestation_total{provider="simulated",result="success",role="produce"} 1`)
	require.Contains(t, rendered.String(), `vg_tee_attestation_total{provider="simulated",result="success",role="verify"} 1`)

	// Only the producer, when there is no verifier to wrap.
	solo := &materials{Producer: sim}
	solo.InstrumentTEE(teemetrics.New(metrics.NewRegistry()), "simulated")
	require.NotSame(t, sim, solo.Producer)
	require.Nil(t, solo.Verifier)
}

type failingCloser struct{ err error }

func (c failingCloser) Close() error { return c.err }

// Close releases everything the materials hold open and reports what
// would not close, once; a missing file is named by its config field.
func TestMaterials_CloseAndReadExactly(t *testing.T) {
	m := &materials{closers: []io.Closer{failingCloser{errors.New("device busy")}, failingCloser{nil}}}
	require.ErrorContains(t, m.Close(), "device busy")
	require.Nil(t, m.closers)
	require.NoError(t, m.Close(), "nothing left to close")

	_, err := readExactly(filepath.Join(t.TempDir(), "absent"), 32, "tee.seed_path")
	require.ErrorContains(t, err, `read tee.seed_path`)
	require.True(t, errors.Is(err, os.ErrNotExist))
}

// The materials refuse a worker registry they cannot read, before any key
// is registered.
func TestLoadMaterials_RegistryMissing(t *testing.T) {
	f := newMaterialFixture(t)
	f.cfg.Workers.RegistryPath = filepath.Join(f.dir, "absent.json")
	_, err := LoadMaterials(f.cfg, shared_time.NewSystemClock())
	require.ErrorContains(t, err, "read worker registry")
	require.True(t, strings.Contains(err.Error(), "absent.json"))
}
