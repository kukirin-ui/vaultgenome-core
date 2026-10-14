// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// The vault's GPU policy names whose evaluation the worker's verdict rests
// on: NVIDIA's (the default), both, or the verifier's own — refused by
// this build, which does not verify the manifests' signatures.
func TestGPUPolicyConfig_Evaluation(t *testing.T) {
	var none *GPUPolicyConfig
	require.NoError(t, none.validate())
	for _, ok := range []string{"", "nras", "both"} {
		require.NoError(t, (&GPUPolicyConfig{Evaluation: ok}).validate(), ok)
	}
	require.ErrorContains(t, (&GPUPolicyConfig{Evaluation: "own"}).validate(), "XML signatures")
	require.ErrorContains(t, (&GPUPolicyConfig{Evaluation: "nvidia-plus"}).validate(), "one of nras, both")

	dir := t.TempDir()
	root := filepath.Join(dir, "root.pem")
	require.NoError(t, os.WriteFile(root, []byte(tee.NVIDIARIMRootPEM), 0o600))
	g := &GPUPolicyConfig{Evaluation: "both", RIMServiceURL: "https://rim.example/v1/rim/", RIMCacheDir: dir, NVIDIARIMRootPath: root}
	var cfg tee.AzureCGPUVerifierConfig
	require.NoError(t, g.apply(&cfg))
	require.Equal(t, tee.GPUEvaluationBoth, cfg.GPUEvaluation)
	require.Equal(t, "https://rim.example/v1/rim/", cfg.RIMServiceURL)
	require.Equal(t, dir, cfg.RIMCacheDir)
	require.Equal(t, []byte(tee.NVIDIARIMRootPEM), cfg.NVIDIARIMRootPEM)
	require.Nil(t, cfg.NVIDIADeviceRootPEM, "the pinned device root stays")
	g.NVIDIADeviceRootPath = filepath.Join(dir, "missing.pem")
	require.ErrorContains(t, g.apply(&cfg), "nvidia_device_root_path")
	require.NoError(t, none.apply(&cfg))
	require.Equal(t, tee.GPUClaimsPolicy{}, none.policy())
	require.Equal(t, []string{"GH100"}, (&GPUPolicyConfig{HWModels: []string{"GH100"}}).policy().AcceptableHWModels)
}

// A vault peer that asks for "own" is refused at validation.
func TestConfig_RefusesOwnGPUEvaluationInThisBuild(t *testing.T) {
	c := goodConfig()
	c.TEE.Peer.Provider = "azure-cgpu"
	c.TEE.Peer.MeasurementPath = "/m"
	c.TEE.Peer.AMDCertChainPath = "/c"
	c.TEE.Peer.GPUPolicy = &GPUPolicyConfig{Evaluation: "own"}
	require.ErrorContains(t, c.Validate(), "gpu_policy.evaluation")
	c.TEE.Peer.GPUPolicy.Evaluation = "both"
	if err := c.Validate(); err != nil {
		require.NotContains(t, err.Error(), "gpu_policy.evaluation")
	}
}
