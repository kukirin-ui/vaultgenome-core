// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func TestPeerDetailLogFields(t *testing.T) {
	t.Parallel()
	require.Nil(t, peerDetailLogFields(nil), "a verifier with nothing beyond the measurement adds nothing")

	complete := tee.GPUEvaluation{ReportParsed: true, NonceMatch: true, ChainVerified: true, FWIDMatch: true, SignatureVerified: true,
		DriverRIM:         tee.RIMStatus{Fetched: true, VersionMatch: true, ChainVerified: true, SignatureVerified: true},
		VBIOSRIM:          tee.RIMStatus{Fetched: true, VersionMatch: true, ChainVerified: true, SignatureVerified: true},
		MeasurementsMatch: true, HWModel: "GH100"}
	d := &tee.AttestationDetail{Provider: tee.ProviderAzureCGPU, Product: "Genoa", PCRSelection: "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14",
		GPUs:        []tee.GPUVerdict{{Key: "GPU-0", HWModel: "GH100", DriverVersion: "580.95.05", VBIOSVersion: "96.00.9F.00.01", Issuer: "own evaluation"}},
		Evaluations: []tee.GPUEvaluation{complete, {ReportParsed: true}}}
	fields := peerDetailLogFields(d)
	require.Equal(t, []any{
		"peer_provider", "azure-cgpu",
		"peer_product", "Genoa",
		"peer_pcrs", "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14",
		"peer_gpus", "GPU-0 GH100 driver 580.95.05 vbios 96.00.9F.00.01 (own evaluation)",
		"peer_gpu_evaluations", "1/2 complete",
	}, fields)

	// A platform without GPUs says only what it has.
	require.Equal(t, []any{"peer_provider", "gcp-tdx"}, peerDetailLogFields(&tee.AttestationDetail{Provider: tee.ProviderGCPTDX}))
}
