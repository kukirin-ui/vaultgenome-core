// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// A host whose TEE gives no sealing key seals to its vTPM: the sealer the
// materials hand out for gcp-tdx and azure-cgpu is the vTPM sealer, bound
// to the PCRs the operator names.
func TestTEESealer_VTPMForTDXAndAzureCGPU(t *testing.T) {
	t.Parallel()
	for name, producer := range map[string]tee.Producer{
		"gcp-tdx":    &tee.GCPTDXProducer{},
		"azure-cgpu": &tee.AzureCGPUProducer{},
	} {
		t.Run(name, func(t *testing.T) {
			m := &materials{Producer: producer, tee: TEEConfig{TPM2ToolsDir: "/opt/tpm2", VTPMSealPCRs: "sha256:0,1,2,3,4,5,6,7"}}
			s, err := m.TEESealer()
			require.NoError(t, err)
			v, ok := s.(*tee.VTPMSealer)
			require.True(t, ok, "%T", s)
			require.Equal(t, "sha256:0,1,2,3,4,5,6,7", v.PCRs())
			again, err := m.TEESealer()
			require.NoError(t, err)
			require.Same(t, s, again, "one sealer per materials")

			bad := &materials{Producer: producer, tee: TEEConfig{VTPMSealPCRs: "sha1:0"}}
			_, err = bad.TEESealer()
			require.ErrorContains(t, err, "vtpm_seal_pcrs")
		})
	}
	none := &materials{Producer: &tee.GCPTDXProducer{}}
	s, err := none.TEESealer()
	require.NoError(t, err)
	require.Equal(t, tee.DefaultVTPMSealPCRs, s.(*tee.VTPMSealer).PCRs(), "the default selection when the operator names none")
}

func TestConfig_VTPMSealPCRs_PerProvider(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(c *Config)
		want   string
	}{
		"simulated": {func(c *Config) { c.TEE.VTPMSealPCRs = "sha256:0,1" }, "applies to gcp-tdx and azure-cgpu only"},
		"sev-snp": {func(c *Config) {
			c.TEE.Provider, c.TEE.SeedPath, c.TEE.InsecureSimulation = "gcp-sev-snp", "", false
			c.TEE.VTPMSealPCRs = "sha256:0,1"
		}, "applies to gcp-tdx and azure-cgpu only"},
		"tdx, a bad selection": {func(c *Config) {
			c.TEE.Provider, c.TEE.SeedPath, c.TEE.InsecureSimulation = "gcp-tdx", "", false
			c.TEE.VTPMSealPCRs = "sha1:0"
		}, "tee.vtpm_seal_pcrs"},
		"tdx, a good selection": {func(c *Config) {
			c.TEE.Provider, c.TEE.SeedPath, c.TEE.InsecureSimulation = "gcp-tdx", "", false
			c.TEE.VTPMSealPCRs = "sha256:0,1,2,3,4,5,6,7"
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			c := minimalValidConfig()
			tc.mutate(&c)
			err := c.Validate()
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.want)
		})
	}
}
