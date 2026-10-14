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

// The GPU policy names whose evaluation the verdict rests on: NVIDIA's
// (the default), both, or the verifier's own; and whether that evaluation
// asks NVIDIA's OCSP responder about the chain (ocsp, the default, or off
// — only where there is an evaluation of our own).
func TestGPUPolicyConfig_Evaluation(t *testing.T) {
	var none *GPUPolicyConfig
	require.NoError(t, none.validate())
	for _, ok := range []string{"", "nras", "both", "own"} {
		require.NoError(t, (&GPUPolicyConfig{Evaluation: ok}).validate(), ok)
	}
	require.ErrorContains(t, (&GPUPolicyConfig{Evaluation: "nvidia-plus"}).validate(), "one of nras, both, own")
	for _, ok := range []string{"", "ocsp", "off"} {
		require.NoError(t, (&GPUPolicyConfig{Evaluation: "both", Revocation: ok}).validate(), ok)
		require.NoError(t, (&GPUPolicyConfig{Evaluation: "own", Revocation: ok, OCSPURL: "http://ocsp.example"}).validate(), ok)
	}
	require.ErrorContains(t, (&GPUPolicyConfig{Evaluation: "both", Revocation: "crl"}).validate(), "one of ocsp, off")
	require.ErrorContains(t, (&GPUPolicyConfig{Evaluation: "nras", Revocation: "ocsp"}).validate(), "apply to the verifier's own evaluation")
	require.ErrorContains(t, (&GPUPolicyConfig{OCSPURL: "http://ocsp.example"}).validate(), "apply to the verifier's own evaluation")

	dir := t.TempDir()
	root := filepath.Join(dir, "root.pem")
	require.NoError(t, os.WriteFile(root, []byte(tee.NVIDIADeviceRootPEM), 0o600))
	g := &GPUPolicyConfig{Evaluation: "both", RIMServiceURL: "https://rim.example/v1/rim/", RIMCacheDir: dir, NVIDIADeviceRootPath: root, Revocation: "off", OCSPURL: "http://ocsp.example"}
	var cfg tee.AzureCGPUVerifierConfig
	require.NoError(t, g.apply(&cfg))
	require.Equal(t, tee.GPUEvaluationBoth, cfg.GPUEvaluation)
	require.Equal(t, tee.GPURevocationOff, cfg.GPURevocation)
	require.Equal(t, "http://ocsp.example", cfg.OCSPURL)
	require.Equal(t, "https://rim.example/v1/rim/", cfg.RIMServiceURL)
	require.Equal(t, dir, cfg.RIMCacheDir)
	require.Equal(t, []byte(tee.NVIDIADeviceRootPEM), cfg.NVIDIADeviceRootPEM)
	require.Nil(t, cfg.NVIDIARIMRootPEM, "the pinned RIM root stays")
	g.NVIDIARIMRootPath = filepath.Join(dir, "missing.pem")
	require.ErrorContains(t, g.apply(&cfg), "nvidia_rim_root_path")
	require.NoError(t, none.apply(&cfg))
}

// A peer entry that asks for "own" is admitted at validation (the
// verifier verifies the manifests' signatures); a revocation setting
// without an evaluation of our own is refused there, before any
// handshake.
func TestConfig_AdmitsOwnGPUEvaluationAndValidatesRevocation(t *testing.T) {
	c := minimalValidConfig()
	c.TEE.Provider = "azure-cgpu"
	c.TEE.GPUAttestCommand = []string{"gpu-token"}
	c.TEE.Peer = PeerTEEConfig{Provider: "azure-cgpu", MeasurementPath: "/m", AMDCertChainPath: "/c", GPUPolicy: &GPUPolicyConfig{Evaluation: "own"}}
	if err := c.Validate(); err != nil {
		require.NotContains(t, err.Error(), "gpu_policy.evaluation")
	}
	c.TEE.Peer.GPUPolicy = &GPUPolicyConfig{Evaluation: "nras", Revocation: "ocsp"}
	require.ErrorContains(t, c.Validate(), "gpu_policy.revocation")
}
