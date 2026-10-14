// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Off its host a hardware producer cannot be built, and the refusal says
// what is missing: configfs-tsm for a SEV-SNP or TDX guest, tpm2-tools
// for an Azure confidential GPU VM. A family this build has no producer
// for is refused by name, as is a provider nobody knows.
func TestBuildTEEProducer_Refusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		cfg  TEEConfig
		want []string
	}{
		"tdx without configfs-tsm": {TEEConfig{Provider: "gcp-tdx", TSMReportDir: filepath.Join(dir, "no-such-tsm")},
			[]string{"tee.provider=gcp-tdx", "configfs-tsm"}},
		"sev-snp without configfs-tsm": {TEEConfig{Provider: "gcp-sev-snp", TSMReportDir: filepath.Join(dir, "no-such-tsm")},
			[]string{"tee.provider=gcp-sev-snp", "configfs-tsm"}},
		"azure-cgpu without tpm2-tools": {TEEConfig{Provider: "azure-cgpu", GPUAttestCommand: []string{"/opt/nvidia/attest"}, TPM2ToolsDir: dir},
			[]string{"tee.provider=azure-cgpu", "tpm2_nvread"}},
		"a family without a producer here": {TEEConfig{Provider: "aws-nitro"}, []string{`tee.provider "aws-nitro" is not available in this build`}},
		"unknown provider":                 {TEEConfig{Provider: "enclave?"}, []string{"acp-compute: tee.provider:", "unknown provider"}},
		"simulated without its seed":       {TEEConfig{Provider: "simulated", SeedPath: filepath.Join(dir, "absent.seed")}, []string{"read tee.seed_path"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			provider, producer, err := buildTEEProducer(tc.cfg)
			require.Error(t, err)
			for _, w := range tc.want {
				require.ErrorContains(t, err, w)
			}
			require.Empty(t, provider)
			require.Nil(t, producer)
		})
	}
}

// askARKChainPEM is a throwaway two-certificate chain shaped like AMD's:
// a self-signed root (the ARK) and an intermediate it signed (the ASK).
func askARKChainPEM(t *testing.T) []byte {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ARK"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	inter := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test ASK"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, inter, rootCert, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	var out bytes.Buffer
	require.NoError(t, pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: interDER}))
	require.NoError(t, pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	return out.Bytes()
}

// A TDX peer is pinned by its 48-byte measurement and held to Intel's TCB
// statuses; an Azure confidential GPU peer by its launch measurement, the
// AMD chain of its product, the GPU policy and, when the operator pins
// it, what its vTPM measured at boot. Both verifiers are built here with
// no hardware and no network, and refuse what they cannot be built from.
func TestBuildPeerVerifier_TDXAndAzurePeers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	meas48 := write("peer48.meas", bytes.Repeat([]byte{0x77}, 48))
	meas32 := write("peer32.meas", bytes.Repeat([]byte{0x77}, 32))
	chain := write("chain.pem", askARKChainPEM(t))
	garbage := write("garbage.pem", []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"))
	rimRoot := write("rim-root.pem", []byte(tee.NVIDIARIMRootPEM))

	provider, v, err := buildPeerVerifier(PeerTEEConfig{Provider: "gcp-tdx", MeasurementPath: meas48,
		PCSCacheDir: filepath.Join(dir, "pcs"), AcceptableTCBStatuses: []string{tee.TCBUpToDate, tee.TCBSWHardeningNeeded}})
	require.NoError(t, err)
	require.Equal(t, tee.ProviderGCPTDX, provider)
	require.IsType(t, &tee.GCPTDXVerifier{}, v)

	azure := PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: meas48, AMDCertChainPath: chain,
		VCEKCacheDir: filepath.Join(dir, "vcek"), NRASCacheDir: filepath.Join(dir, "nras"), PCRDigests: []string{testPCRDigestHex},
		GPUPolicy: &GPUPolicyConfig{Evaluation: "both", HWModels: []string{"GH100"}, NVIDIARIMRootPath: rimRoot, RIMCacheDir: filepath.Join(dir, "rim")}}
	provider, v, err = buildPeerVerifier(azure)
	require.NoError(t, err)
	require.Equal(t, tee.ProviderAzureCGPU, provider)
	require.IsType(t, &tee.AzureCGPUVerifier{}, v)

	withAzure := func(mutate func(p *PeerTEEConfig)) PeerTEEConfig {
		p := azure
		mutate(&p)
		return p
	}
	for name, tc := range map[string]struct {
		cfg  PeerTEEConfig
		want string
	}{
		"tdx with a 32-byte measurement": {PeerTEEConfig{Provider: "gcp-tdx", MeasurementPath: meas32}, "48-byte TDX measurement"},
		"tdx with a status Intel never clears": {PeerTEEConfig{Provider: "gcp-tdx", MeasurementPath: meas48, AcceptableTCBStatuses: []string{tee.TCBRevoked}},
			"build verifier for tee.peer.provider=gcp-tdx"},
		"azure with a 32-byte measurement":       {withAzure(func(p *PeerTEEConfig) { p.MeasurementPath = meas32 }), "48-byte SEV-SNP launch measurement"},
		"azure without its chain file":           {withAzure(func(p *PeerTEEConfig) { p.AMDCertChainPath = filepath.Join(dir, "absent.pem") }), "read tee.peer.amd_cert_chain_path"},
		"azure with a chain that is not ASK+ARK": {withAzure(func(p *PeerTEEConfig) { p.AMDCertChainPath = garbage }), "build verifier for tee.peer.provider=azure-cgpu"},
		"azure with a malformed PCR digest":      {withAzure(func(p *PeerTEEConfig) { p.PCRDigests = []string{"zz"} }), `tee.peer.pcr_digests: "zz"`},
		"azure with a RIM root that is not there": {withAzure(func(p *PeerTEEConfig) {
			p.GPUPolicy = &GPUPolicyConfig{Evaluation: "both", NVIDIARIMRootPath: filepath.Join(dir, "absent.pem")}
		}), "tee.peer.gpu_policy.nvidia_rim_root_path"},
		"a family with no verifier here": {PeerTEEConfig{Provider: "aws-nitro", MeasurementPath: meas48}, "no verifier this build can run end to end"},
		"unknown provider":               {PeerTEEConfig{Provider: "sgx?", MeasurementPath: meas48}, "acp-compute: tee.peer.provider:"},
		"missing measurement file":       {PeerTEEConfig{Provider: "gcp-tdx", MeasurementPath: filepath.Join(dir, "absent.meas")}, "read tee.peer.measurement_path"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			provider, v, err := buildPeerVerifier(tc.cfg)
			require.ErrorContains(t, err, tc.want)
			require.Empty(t, provider)
			require.Nil(t, v)
		})
	}
}

// A file that is not there is reported under the config field that names
// it; a 64-byte measurement is read whole.
func TestReadExactlyAndReadMeasurement_NameTheField(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := readExactly(filepath.Join(dir, "absent"), 32, "tee.seed_path")
	require.ErrorContains(t, err, "read tee.seed_path")
	_, err = readMeasurement(filepath.Join(dir, "absent"), "tee.peer.measurement_path")
	require.ErrorContains(t, err, "read tee.peer.measurement_path")

	p := filepath.Join(dir, "peer.meas")
	require.NoError(t, os.WriteFile(p, bytes.Repeat([]byte{0x11}, 64), 0o600))
	m, err := readMeasurement(p, "tee.peer.measurement_path")
	require.NoError(t, err)
	require.Len(t, m, 64)
}
