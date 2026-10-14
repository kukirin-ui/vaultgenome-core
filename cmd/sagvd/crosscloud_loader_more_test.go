// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

func TestCrossCloudMaterials_CloseIsNilSafe(t *testing.T) {
	var none *crossCloudMaterials
	require.NoError(t, none.Close())
	require.NoError(t, (&crossCloudMaterials{}).Close(), "nothing opened, nothing to close")
}

func TestLoadOperatorStop_ListMissing(t *testing.T) {
	dir := t.TempDir()
	cfg := OperatorStopConfig{KeyID: "operator-test", PublicKeyPath: writeFile(t, dir, "op.pub", generateEd25519PubRaw(t)), ListPath: filepath.Join(dir, "absent.json")}
	_, err := loadOperatorStop(cfg)
	require.ErrorContains(t, err, "list_path")
	require.ErrorContains(t, err, "without a valid list nothing is released")
	cfg.PublicKeyPath = filepath.Join(dir, "absent.pub")
	_, err = loadOperatorStop(cfg)
	require.ErrorContains(t, err, "public_key_path")
}

// Every input the cross-cloud materials need is checked before the first
// one is used: a missing registry, allow list, transport certificate,
// audit seed, audit log directory or stop list stops the load.
func TestLoadCrossCloudMaterials_Refusals(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	for name, tc := range map[string]struct {
		mutate func(c *Config)
		want   string
	}{
		"registry missing":   {func(c *Config) { c.CrossCloud.VerifierRegistryPath = absent }, "read verifier_registry_path"},
		"allow list missing": {func(c *Config) { c.CrossCloud.PolicyAllowListPath = absent }, "read policy_allow_list_path"},
		"transport cert missing": {func(c *Config) {
			c.CrossCloud.TransportTLS = TLSClientConfig{Enabled: true, ClientCert: absent, ClientKey: absent, CABundle: absent}
		}, "load mTLS client cert/key"},
		"audit seed missing":    {func(c *Config) { c.Keys.AuditSigning.SeedPath = absent }, "keys.audit_signing.seed_path"},
		"audit log dir missing": {func(c *Config) { c.CrossCloud.AuditLogPath = filepath.Join(absent, "xcc.db") }, "open crosscloud.audit_log_path"},
		"stop list missing":     {func(c *Config) { c.CrossCloud.OperatorStop.ListPath = absent }, "crosscloud.operator_stop"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := simulatedCrossCloudConfig(t, t.TempDir())
			tc.mutate(&cfg)
			_, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// The verifier registry names each destination kind's anchors; what a
// kind needs is required, what it cannot use is refused, and a kind this
// build cannot verify end to end is not trusted with releases.
func TestLoadVerifierSpecs_Refusals(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent")
	chain := writeFile(t, dir, "chain.pem", []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"))
	meas := strings.Repeat("ab", 48)
	n := 0
	entry := func(fields string) string {
		n++
		return writeFile(t, dir, fmt.Sprintf("registry-%d.json", n), []byte(`{"verifiers":[{`+fields+`}]}`))
	}
	for name, tc := range map[string]struct {
		path string
		want string
	}{
		"not json":              {writeFile(t, dir, "broken.json", []byte("{")), "decode verifier_registry_path"},
		"attestor key missing":  {entry(`"provider":"simulated","expected_measurement_hex":"` + strings.Repeat("01", 32) + `","attestor_pubkey_path":"` + absent + `"`), "attestor_pubkey_path"},
		"sev-snp no chain":      {entry(`"provider":"gcp-sev-snp","expected_measurement_hex":"` + meas + `"`), "gcp-sev-snp requires amd_cert_chain_path"},
		"sev-snp chain missing": {entry(`"provider":"gcp-sev-snp","expected_measurement_hex":"` + meas + `","amd_cert_chain_path":"` + absent + `"`), "amd_cert_chain_path:"},
		"azure no chain":        {entry(`"provider":"azure-cgpu","expected_measurement_hex":"` + meas + `"`), "azure-cgpu requires amd_cert_chain_path"},
		"azure chain missing":   {entry(`"provider":"azure-cgpu","expected_measurement_hex":"` + meas + `","amd_cert_chain_path":"` + absent + `"`), "amd_cert_chain_path:"},
		"azure bad digests":     {entry(`"provider":"azure-cgpu","expected_measurement_hex":"` + meas + `","amd_cert_chain_path":"` + chain + `","pcr_digests":["zz"]`), "pcr_digests"},
		"azure bad policy":      {entry(`"provider":"azure-cgpu","expected_measurement_hex":"` + meas + `","amd_cert_chain_path":"` + chain + `","gpu_policy":{"evaluation":"trust-me"}`), "gpu_policy.evaluation"},
		"azure root missing":    {entry(`"provider":"azure-cgpu","expected_measurement_hex":"` + meas + `","amd_cert_chain_path":"` + chain + `","gpu_policy":{"evaluation":"both","nvidia_device_root_path":"` + absent + `"}`), "nvidia_device_root_path"},
		"unsupported kind":      {entry(`"provider":"aws-nitro","expected_measurement_hex":"` + meas + `"`), "no verifier this build can run end to end"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadVerifierSpecs(tc.path, true)
			require.ErrorContains(t, err, tc.want)
		})
	}

	specs, err := loadVerifierSpecs(entry(`"provider":"gcp-tdx","expected_measurement_hex":"`+meas+`","pcs_url":"https://pcs.example","pcs_cache_dir":"`+dir+`","acceptable_tcb_statuses":["UpToDate"]`), false)
	require.NoError(t, err)
	require.Len(t, specs, 1)
	require.Equal(t, tee.ProviderGCPTDX, specs[0].Provider)
	require.Equal(t, tee.GCPTDXVerifierConfig{PCSURL: "https://pcs.example", PCSCacheDir: dir, AcceptableTCBStatuses: []string{"UpToDate"}}, specs[0].Spec.GCPTDX)
	specs, err = loadVerifierSpecs(entry(`"provider":"azure-cgpu","expected_measurement_hex":"`+meas+`","amd_cert_chain_path":"`+chain+`","nras_jwks_url":"https://nras.example","pcr_digests":["`+strings.Repeat("00", 32)+`"]`), false)
	require.NoError(t, err)
	require.Equal(t, tee.ProviderAzureCGPU, specs[0].Provider)
	require.Equal(t, "https://nras.example", specs[0].Spec.AzureCGPU.NRASJWKSURL)
	require.Len(t, specs[0].Spec.AzureCGPU.AcceptablePCRDigests, 1)
	require.NotEmpty(t, specs[0].Spec.AzureCGPU.AMDRootPEM)
}

// An attestor key file is raw 32 bytes or a PEM SubjectPublicKeyInfo of an
// Ed25519 key; a PEM that does not decode, or does not parse, is named.
func TestLoadAttestorPubKey_PEMShapes(t *testing.T) {
	dir := t.TempDir()
	_, err := loadAttestorPubKey(writeFile(t, dir, "broken.pem", []byte("-----BEGIN PUBLIC KEY-----\nnot base64 and no end\n")))
	require.ErrorContains(t, err, "invalid PEM")
	notPKIX := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a SubjectPublicKeyInfo")})
	_, err = loadAttestorPubKey(writeFile(t, dir, "notpkix.pem", notPKIX))
	require.ErrorContains(t, err, "parse PKIX")
	got, err := loadAttestorPubKey(writeFile(t, dir, "good.pem", generateEd25519PubPEM(t)))
	require.NoError(t, err)
	require.Len(t, got, 32)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	_, err = loadAttestorPubKey(writeFile(t, dir, "ec.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	require.ErrorContains(t, err, "want ed25519.PublicKey")
}

func TestLoadAllowListPolicy_ReadAndDecode(t *testing.T) {
	dir := t.TempDir()
	_, err := loadAllowListPolicy("v1", filepath.Join(dir, "absent.json"))
	require.ErrorContains(t, err, "read policy_allow_list_path")
	_, err = loadAllowListPolicy("v1", writeFile(t, dir, "broken.json", []byte("{")))
	require.ErrorContains(t, err, "decode policy_allow_list_path")
}

// The transport to a destination carries the operator's client
// certificate when mTLS is on, and refuses to be built without it.
func TestBuildHTTPTransport_TLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := selfSignedPair(t, dir, "xcc-client")
	_, otherKey := selfSignedPair(t, dir, "other")
	absent := filepath.Join(dir, "absent")
	notPEM := writeFile(t, dir, "not.pem", []byte("nothing"))

	for name, tc := range map[string]struct {
		cfg  TLSClientConfig
		want string
	}{
		"cert missing":   {TLSClientConfig{Enabled: true, ClientCert: absent, ClientKey: key, CABundle: cert}, "load mTLS client cert/key"},
		"key missing":    {TLSClientConfig{Enabled: true, ClientCert: cert, ClientKey: absent, CABundle: cert}, "crosscloud.transport_tls.client_key"},
		"key mismatched": {TLSClientConfig{Enabled: true, ClientCert: cert, ClientKey: otherKey, CABundle: cert}, "load mTLS client cert/key"},
		"bundle missing": {TLSClientConfig{Enabled: true, ClientCert: cert, ClientKey: key, CABundle: absent}, "read mTLS ca_bundle"},
		"bundle not PEM": {TLSClientConfig{Enabled: true, ClientCert: cert, ClientKey: key, CABundle: notPEM}, "contained no valid PEM certificates"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildHTTPTransport(TEEConfig{}, CrossCloudConfig{TransportTLS: tc.cfg})
			require.ErrorContains(t, err, tc.want)
		})
	}
	tx, err := buildHTTPTransport(TEEConfig{}, CrossCloudConfig{RequestTimeoutSeconds: 2, TransportTLS: TLSClientConfig{Enabled: true, ClientCert: cert, ClientKey: key, CABundle: cert, ServerName: "standby.internal"}})
	require.NoError(t, err)
	require.NotNil(t, tx)
	tc, err := buildClientTLSConfig(TEEConfig{}, TLSClientConfig{Enabled: true, ClientCert: cert, ClientKey: key, CABundle: cert, ServerName: "standby.internal"})
	require.NoError(t, err)
	require.Equal(t, "standby.internal", tc.ServerName)
	require.Len(t, tc.Certificates, 1)
}
