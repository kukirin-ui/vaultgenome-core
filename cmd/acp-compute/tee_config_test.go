// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// The sev-guest device the sealer opens is the operator's when named and
// the kernel's default otherwise.
func TestTEEConfig_SEVDevice(t *testing.T) {
	t.Parallel()
	require.Equal(t, DefaultSEVGuestDevice, TEEConfig{}.SEVDevice())
	require.Equal(t, "/dev/sev-guest-1", TEEConfig{SEVGuestDevice: "/dev/sev-guest-1"}.SEVDevice())
}

// testPCRDigestHex is a well-formed 32-byte PCR digest.
const testPCRDigestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Each hardware provider, local or peer, takes its own fields and refuses
// the others': the config says what attests and what is pinned, and a
// field left over from another family is a mistake the operator hears
// about before anything dials.
func TestConfig_Validate_HardwareProviderFields(t *testing.T) {
	t.Parallel()
	hardwareLocal := func(c *Config, provider string) {
		c.TEE.Provider = provider
		c.TEE.SeedPath = ""
		c.TEE.InsecureSimulation = false
	}
	azureLocal := func(c *Config) {
		hardwareLocal(c, "azure-cgpu")
		c.TEE.GPUAttestCommand = []string{"/opt/nvidia/attest", "--nonce"}
	}
	hardwarePeer := func(c *Config, provider string) {
		c.TEE.Peer.Provider = provider
		c.TEE.Peer.PublicKeyPath = ""
	}
	for name, tc := range map[string]struct {
		mutate func(c *Config)
		want   []string // empty: the config is valid
	}{
		"tdx clean": {func(c *Config) {
			hardwareLocal(c, "gcp-tdx")
			c.TEE.TSMReportDir = "/sys/kernel/config/tsm/report"
			c.TEE.VTPMSealPCRs = "sha256:0,1,2,3,4,5,6,7"
		}, nil},
		"tdx with simulated leftovers": {func(c *Config) { c.TEE.Provider = "gcp-tdx" },
			[]string{"tee.seed_path applies to the simulated provider", "tee.insecure_simulation applies to the simulated provider"}},
		"azure clean": {func(c *Config) {
			azureLocal(c)
			c.TEE.TPM2ToolsDir = "/usr/bin"
			c.TEE.AKHandle = "0x81000001"
		}, nil},
		"azure with simulated leftovers": {func(c *Config) {
			c.TEE.Provider = "azure-cgpu"
			c.TEE.GPUAttestCommand = []string{"/opt/nvidia/attest"}
		}, []string{"tee.seed_path and tee.insecure_simulation apply to the simulated provider only"}},
		"azure with a tsm dir": {func(c *Config) {
			azureLocal(c)
			c.TEE.TSMReportDir = "/sys/kernel/config/tsm/report"
		}, []string{"tee.tsm_report_dir does not apply to azure-cgpu"}},
		"azure without the attest command": {func(c *Config) { hardwareLocal(c, "azure-cgpu") },
			[]string{"tee.gpu_attest_command required when tee.provider=azure-cgpu"}},
		"attest command on simulated": {func(c *Config) { c.TEE.GPUAttestCommand = []string{"/opt/nvidia/attest"} },
			[]string{"tee.gpu_attest_command, tpm2_tools_dir and ak_handle apply to azure-cgpu only"}},
		"tpm2 dir on sev-snp": {func(c *Config) {
			hardwareLocal(c, "gcp-sev-snp")
			c.TEE.TPM2ToolsDir = "/usr/bin"
		}, []string{"apply to azure-cgpu only"}},
		"ak handle on tdx": {func(c *Config) {
			hardwareLocal(c, "gcp-tdx")
			c.TEE.AKHandle = "0x81000001"
		}, []string{"apply to azure-cgpu only"}},

		"tdx peer clean": {func(c *Config) {
			hardwarePeer(c, "gcp-tdx")
			c.TEE.Peer.PCSURL = "https://pccs.example"
			c.TEE.Peer.PCSCacheDir = "/var/lib/acp/pcs"
			c.TEE.Peer.AcceptableTCBStatuses = []string{"UpToDate", "SWHardeningNeeded"}
		}, nil},
		"tdx peer with a key": {func(c *Config) { c.TEE.Peer.Provider = "gcp-tdx" },
			[]string{"tee.peer.public_key_path applies to a simulated peer only; a TDX quote"}},
		"tdx peer with AMD fields": {func(c *Config) {
			hardwarePeer(c, "gcp-tdx")
			c.TEE.Peer.AMDKDSURL = "https://kds.example"
		}, []string{"apply to a gcp-sev-snp or azure-cgpu peer only"}},
		"simulated peer with PCS fields": {func(c *Config) { c.TEE.Peer.PCSURL = "https://pccs.example" },
			[]string{"tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"}},
		"sev-snp peer with PCS fields": {func(c *Config) {
			hardwarePeer(c, "gcp-sev-snp")
			c.TEE.Peer.AMDCertChainPath = "/x/chain.pem"
			c.TEE.Peer.PCSCacheDir = "/var/lib/acp/pcs"
		}, []string{"apply to a gcp-tdx peer only"}},
		"azure peer clean": {func(c *Config) {
			hardwarePeer(c, "azure-cgpu")
			c.TEE.Peer.AMDCertChainPath = "/x/genoa.pem"
			c.TEE.Peer.VCEKCacheDir = "/var/lib/acp/vcek"
			c.TEE.Peer.NRASJWKSURL = "https://nras.example/jwks"
			c.TEE.Peer.NRASCacheDir = "/var/lib/acp/nras"
			c.TEE.Peer.GPUPolicy = &GPUPolicyConfig{Evaluation: "both", HWModels: []string{"GH100"}}
			c.TEE.Peer.PCRDigests = []string{testPCRDigestHex}
		}, nil},
		"azure peer with a key": {func(c *Config) {
			c.TEE.Peer.Provider = "azure-cgpu"
			c.TEE.Peer.AMDCertChainPath = "/x/genoa.pem"
		}, []string{"an Azure confidential GPU VM's report is signed by the chip's VCEK"}},
		"azure peer without the chain": {func(c *Config) { hardwarePeer(c, "azure-cgpu") },
			[]string{"tee.peer.amd_cert_chain_path required when tee.peer.provider=azure-cgpu"}},
		"azure peer with PCS fields": {func(c *Config) {
			hardwarePeer(c, "azure-cgpu")
			c.TEE.Peer.AMDCertChainPath = "/x/genoa.pem"
			c.TEE.Peer.AcceptableTCBStatuses = []string{"UpToDate"}
		}, []string{"apply to a gcp-tdx peer only"}},
		"NRAS fields on a simulated peer": {func(c *Config) { c.TEE.Peer.NRASJWKSURL = "https://nras.example/jwks" },
			[]string{"tee.peer.nras_jwks_url, nras_cache_dir, gpu_policy and pcr_digests apply to an azure-cgpu peer only"}},
		"PCR digests on a sev-snp peer": {func(c *Config) {
			hardwarePeer(c, "gcp-sev-snp")
			c.TEE.Peer.AMDCertChainPath = "/x/chain.pem"
			c.TEE.Peer.PCRDigests = []string{testPCRDigestHex}
		}, []string{"apply to an azure-cgpu peer only"}},
		"malformed PCR digest": {func(c *Config) {
			hardwarePeer(c, "azure-cgpu")
			c.TEE.Peer.AMDCertChainPath = "/x/genoa.pem"
			c.TEE.Peer.PCRDigests = []string{"zz"}
		}, []string{`tee.peer.pcr_digests: "zz" is not a 32-byte hex digest`}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := goodConfig()
			tc.mutate(&c)
			err := c.Validate()
			if len(tc.want) == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, w := range tc.want {
				require.ErrorContains(t, err, w)
			}
		})
	}
}

// A RIM root file the policy names must be there to be read.
func TestGPUPolicyConfig_ApplyRefusesAMissingRIMRoot(t *testing.T) {
	t.Parallel()
	g := &GPUPolicyConfig{Evaluation: "both", NVIDIARIMRootPath: filepath.Join(t.TempDir(), "missing.pem")}
	var cfg tee.AzureCGPUVerifierConfig
	require.ErrorContains(t, g.apply(&cfg), "gpu_policy.nvidia_rim_root_path")
}
