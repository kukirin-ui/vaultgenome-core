// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// validateTEE checks the local provider and the peer pin as a pair of
// choices: every field belongs to one provider, and a field set for
// another is named; what each provider needs is required.
func TestValidateTEE_FieldsBelongToTheirProvider(t *testing.T) {
	sim := minimalValidConfig().TEE
	hardware := func(provider string) TEEConfig {
		c := sim
		c.Provider, c.SeedPath, c.InsecureSimulation = provider, "", false
		if provider == "azure-cgpu" {
			c.GPUAttestCommand = []string{"gpu-token"}
		}
		return c
	}
	peer := func(provider string, mutate func(p *PeerTEEConfig)) TEEConfig {
		c := sim
		c.Peer = PeerTEEConfig{Provider: provider, MeasurementPath: "/m"}
		if provider == "gcp-sev-snp" || provider == "azure-cgpu" {
			c.Peer.AMDCertChainPath = "/chain.pem"
		}
		if mutate != nil {
			mutate(&c.Peer)
		}
		return c
	}
	for name, tc := range map[string]struct {
		cfg  TEEConfig
		want string
	}{
		"simulated, acknowledged": {sim, ""},
		"provider invalid":        {func() TEEConfig { c := sim; c.Provider = "vmware"; return c }(), "tee.provider invalid"},
		"provider unsupported":    {func() TEEConfig { c := hardware("aws-nitro"); return c }(), "is not available in this build"},
		"simulated without seed":  {func() TEEConfig { c := sim; c.SeedPath = ""; return c }(), "tee.seed_path required"},
		"simulated unacknowledged": {func() TEEConfig { c := sim; c.InsecureSimulation = false; return c }(),
			"set tee.insecure_simulation=true"},
		"simulated with tsm dir":      {func() TEEConfig { c := sim; c.TSMReportDir = "/sys/kernel/config/tsm/report"; return c }(), "tsm_report_dir applies to gcp-sev-snp and gcp-tdx only"},
		"simulated with sev device":   {func() TEEConfig { c := sim; c.SEVGuestDevice = "/dev/sev-guest"; return c }(), "sev_guest_device applies to gcp-sev-snp only"},
		"simulated with tpm tools":    {func() TEEConfig { c := sim; c.TPM2ToolsDir = "/opt/tpm2"; return c }(), "tpm2_tools_dir and ak_handle apply to azure-cgpu only"},
		"sev-snp":                     {hardware("gcp-sev-snp"), ""},
		"sev-snp with a seed":         {func() TEEConfig { c := hardware("gcp-sev-snp"); c.SeedPath = "/seed"; return c }(), "seed_path applies to the simulated provider only"},
		"sev-snp acknowledged":        {func() TEEConfig { c := hardware("gcp-sev-snp"); c.InsecureSimulation = true; return c }(), "insecure_simulation applies to the simulated provider only"},
		"tdx":                         {hardware("gcp-tdx"), ""},
		"tdx with sev device":         {func() TEEConfig { c := hardware("gcp-tdx"); c.SEVGuestDevice = "/dev/sev-guest"; return c }(), "sev_guest_device applies to gcp-sev-snp only"},
		"azure-cgpu":                  {hardware("azure-cgpu"), ""},
		"azure-cgpu with a seed":      {func() TEEConfig { c := hardware("azure-cgpu"); c.SeedPath = "/seed"; return c }(), "apply to the simulated provider only"},
		"azure-cgpu with tsm dir":     {func() TEEConfig { c := hardware("azure-cgpu"); c.TSMReportDir = "/tsm"; return c }(), "do not apply to azure-cgpu"},
		"azure-cgpu bad seal pcrs":    {func() TEEConfig { c := hardware("azure-cgpu"); c.VTPMSealPCRs = "sha1:0"; return c }(), "tee.vtpm_seal_pcrs"},
		"azure-cgpu good seal pcrs":   {func() TEEConfig { c := hardware("azure-cgpu"); c.VTPMSealPCRs = "sha256:0,7"; return c }(), ""},
		"azure-cgpu without command":  {func() TEEConfig { c := hardware("azure-cgpu"); c.GPUAttestCommand = nil; return c }(), "tee.gpu_attest_command required"},
		"no peer measurement":         {func() TEEConfig { c := sim; c.Peer.MeasurementPath = ""; return c }(), "tee.peer.measurement_path required"},
		"peer provider invalid":       {peer("vmware", nil), "tee.peer.provider invalid"},
		"peer provider unsupported":   {peer("aws-nitro", nil), "no verifier this build can run end to end"},
		"simulated peer without key":  {func() TEEConfig { c := sim; c.Peer.PublicKeyPath = ""; return c }(), "tee.peer.public_key_path required"},
		"simulated peer with amd":     {func() TEEConfig { c := sim; c.Peer.VCEKCacheDir = "/cache"; return c }(), "apply to a gcp-sev-snp or azure-cgpu peer only"},
		"simulated peer with pcs":     {func() TEEConfig { c := sim; c.Peer.PCSURL = "https://pcs"; return c }(), "apply to a gcp-tdx peer only"},
		"simulated peer with nras":    {func() TEEConfig { c := sim; c.Peer.NRASJWKSURL = "https://nras"; return c }(), "apply to an azure-cgpu peer only"},
		"sev-snp peer":                {peer("gcp-sev-snp", nil), ""},
		"sev-snp peer with key":       {peer("gcp-sev-snp", func(p *PeerTEEConfig) { p.PublicKeyPath = "/k" }), "signed by the chip's VCEK"},
		"sev-snp peer without chain":  {peer("gcp-sev-snp", func(p *PeerTEEConfig) { p.AMDCertChainPath = "" }), "amd_cert_chain_path required when tee.peer.provider=gcp-sev-snp"},
		"sev-snp peer with pcs":       {peer("gcp-sev-snp", func(p *PeerTEEConfig) { p.PCSCacheDir = "/c" }), "apply to a gcp-tdx peer only"},
		"tdx peer":                    {peer("gcp-tdx", nil), ""},
		"tdx peer with key":           {peer("gcp-tdx", func(p *PeerTEEConfig) { p.PublicKeyPath = "/k" }), "a TDX quote chains to the Intel SGX Root CA"},
		"tdx peer with amd":           {peer("gcp-tdx", func(p *PeerTEEConfig) { p.MinReportedTCB = 3 }), "apply to a gcp-sev-snp or azure-cgpu peer only"},
		"azure-cgpu peer":             {peer("azure-cgpu", func(p *PeerTEEConfig) { p.PCRDigests = []string{strings.Repeat("ab", 32)} }), ""},
		"azure-cgpu peer with key":    {peer("azure-cgpu", func(p *PeerTEEConfig) { p.PublicKeyPath = "/k" }), "an Azure confidential GPU VM's report"},
		"azure-cgpu peer no chain":    {peer("azure-cgpu", func(p *PeerTEEConfig) { p.AMDCertChainPath = "" }), "amd_cert_chain_path required when tee.peer.provider=azure-cgpu"},
		"azure-cgpu peer with pcs":    {peer("azure-cgpu", func(p *PeerTEEConfig) { p.AcceptableTCBStatuses = []string{"UpToDate"} }), "apply to a gcp-tdx peer only"},
		"azure-cgpu peer bad policy":  {peer("azure-cgpu", func(p *PeerTEEConfig) { p.GPUPolicy = &GPUPolicyConfig{Evaluation: "trust-me"} }), "tee.peer.gpu_policy.evaluation"},
		"azure-cgpu peer bad digests": {peer("azure-cgpu", func(p *PeerTEEConfig) { p.PCRDigests = []string{"zz"} }), "tee.peer.pcr_digests"},
	} {
		t.Run(name, func(t *testing.T) {
			errs := validateTEE(tc.cfg)
			if tc.want == "" {
				require.Empty(t, errs, "%v", errors.Join(errs...))
				return
			}
			require.ErrorContains(t, errors.Join(errs...), tc.want)
		})
	}
}

// The remaining structural checks of Validate, one field at a time.
func TestValidate_RemainingRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(c *Config)
		want   string
	}{
		"http_api address": {func(c *Config) { c.HTTPAPI.ListenAddress = "no-port" }, "http_api.listen_address invalid"},
		"operator stop partial": {func(c *Config) { c.OperatorStop = OperatorStopConfig{KeyID: "op-1"} },
			"operator_stop.kid, public_key_path and list_path are all required"},
		"evidence age negative":   {func(c *Config) { c.Runtime.EvidenceMaxAgeSeconds = -1 }, "runtime.evidence_max_age_seconds must be >= 0"},
		"gate tolerance negative": {func(c *Config) { c.Genome.Gate.Rtol = -1 }, "genome.gate.atol and rtol must be >= 0"},
		"outliers negative":       {func(c *Config) { c.Genome.Gate.MaxNonCriticalOutliers = -1 }, "max_non_critical_outliers must be >= 0"},
		"bf16 negative":           {func(c *Config) { c.Genome.Gate.Bfloat16 = &GateTolerance{Atol: -1} }, "genome.gate.bfloat16.atol and rtol must be >= 0"},
		"bundle dir relative":     {func(c *Config) { c.Genome.BundleDir = "genomes" }, "must be an absolute path"},
		"audit log without key":   {func(c *Config) { c.Audit.LogPath = "/var/lib/sagvd/rp.db" }, "keys.audit_signing.kid and seed_path required when audit.log_path is set"},
		"one log for two holders": {func(c *Config) {
			c.Audit.LogPath = "/var/lib/sagvd/one.db"
			c.Keys.AuditSigning = SigningKeyConfig{KeyID: "a", SeedPath: "/s"}
			c.CrossCloud.AuditLogPath = "/var/lib/sagvd/../sagvd/one.db"
		}, "must be different files"},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			tc.mutate(&c)
			require.ErrorContains(t, c.Validate(), tc.want)
		})
	}

	// And what passes: a whole operator stop, a bfloat16 table, gate jobs
	// with their audit log in its own file.
	c := minimalValidConfig()
	c.OperatorStop = OperatorStopConfig{KeyID: "op-1", PublicKeyPath: "/op.pub", ListPath: "/stop.json"}
	c.Genome.Gate.Bfloat16 = &GateTolerance{Atol: 0.1, Rtol: 0.01}
	c.Genome.BundleDir = t.TempDir()
	c.Audit.LogPath = filepath.Join(t.TempDir(), "rp.db")
	c.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: "/audit.seed"}
	c.CrossCloud.AuditLogPath = filepath.Join(t.TempDir(), "xcc.db")
	require.NoError(t, c.Validate())
	require.True(t, c.OperatorStopEnabled())
	require.Contains(t, c.PolicyVersion(), "bf16-atol=0.1;bf16-rtol=0.01", "the bfloat16 table is part of the policy every session is pinned to")
}

func TestTEEConfig_SEVDevice(t *testing.T) {
	require.Equal(t, DefaultSEVGuestDevice, TEEConfig{}.SEVDevice())
	require.Equal(t, "/dev/sev-guest-1", TEEConfig{SEVGuestDevice: "/dev/sev-guest-1"}.SEVDevice())
}

// The GPU claims policy the verifier gets is the operator's, field for
// field; no policy is the strict default.
func TestGPUPolicyConfig_Policy(t *testing.T) {
	var none *GPUPolicyConfig
	require.Equal(t, tee.GPUClaimsPolicy{}, none.policy())
	g := &GPUPolicyConfig{AllowSecureBootOff: true, AllowDebug: true, AllowUnsignedRIM: true, HWModels: []string{"GH100"}, DriverVersions: []string{"570.1"}, VBIOSVersions: []string{"96.00"}}
	require.Equal(t, tee.GPUClaimsPolicy{AllowSecureBootOff: true, AllowDebug: true, AllowUnsignedRIM: true,
		AcceptableHWModels: []string{"GH100"}, AcceptableDriverVersions: []string{"570.1"}, AcceptableVBIOSVersions: []string{"96.00"}}, g.policy())
}
