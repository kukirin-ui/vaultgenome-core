// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The capture from a live Azure NCC H100 v5 Confidential VM
// (scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z): the HCL
// report from the vTPM, a TPM quote by the HCL attestation key with the
// capture's challenge in extraData, NVIDIA's tokens for the same challenge,
// the JWKS they verify under, and the VCEK and Genoa chain Azure served for
// the chip. Everything the verifier needs, offline.
const azureCGPUCapture = "../../../scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z"

// azureCGPUCaptureNonce is what the capture hashed into the challenge:
// extraData = SHA-256(nonce), the binding the producer and verifier use.
const azureCGPUCaptureNonce = "vault-genome cgpu 20260916T133506Z challenge 1"

func azureCGPUCapturedEvidence(t *testing.T) (Evidence, []byte) {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(azureCGPUCapture, name))
		if err != nil {
			t.Skip("azure-cgpu capture not present: " + name)
		}
		return b
	}
	ev, err := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: read("hcl-report.bin"),
		QuoteMessage: read("quote1.msg"), QuoteSignature: read("quote1.sig"), GPUToken: read("nras-response.json")})
	require.NoError(t, err)
	return Evidence(ev), read("cert-chain.pem")
}

func azureCGPUCapturedVerifier(t *testing.T, chain []byte, mutate func(*AzureCGPUVerifierConfig)) *AzureCGPUVerifier {
	t.Helper()
	// The VCEK Azure's IMDS served for this chip stands in for AMD KDS;
	// NVIDIA's key set as captured stands in for the network.
	vcekPEM, err := os.ReadFile(filepath.Join(azureCGPUCapture, "vcek.pem"))
	require.NoError(t, err)
	block, _ := pem.Decode(vcekPEM)
	require.NotNil(t, block)
	oldFetch, oldGet := amdKDSGetVCEKFor, nrasHTTPGet
	t.Cleanup(func() { amdKDSGetVCEKFor, nrasHTTPGet = oldFetch, oldGet })
	amdKDSGetVCEKFor = func(_ string, product string, _ [64]byte, _ uint64) ([]byte, error) {
		require.Equal(t, "Genoa", product, "an NCC H100 v5 is a Genoa chip")
		return block.Bytes, nil
	}
	nrasHTTPGet = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	cache := t.TempDir()
	jwks, err := os.ReadFile(filepath.Join(azureCGPUCapture, "nras-jwks.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cache, "nras-jwks.json"), jwks, 0o600))
	cfg := AzureCGPUVerifierConfig{AMDRootPEM: chain, NRASCacheDir: cache, VCEKCacheDir: t.TempDir(),
		Now: func() time.Time { return time.Date(2026, 9, 16, 13, 36, 0, 0, time.UTC) },
		// Revocation is checked in its own tests (nvidia_ocsp_test.go), from
		// NVIDIA's stored answers; the captured verifier leaves it off so no
		// test reaches for the responder.
		GPURevocation: GPURevocationOff}
	if mutate != nil {
		mutate(&cfg)
	}
	hcl, err := parseHCLReport(func() []byte { b, _ := os.ReadFile(filepath.Join(azureCGPUCapture, "hcl-report.bin")); return b }())
	require.NoError(t, err)
	m, err := MeasurementFromBytes(hcl.SNP.Measurement[:])
	require.NoError(t, err)
	v, err := NewAzureCGPUVerifier(nil, m, cfg)
	require.NoError(t, err)
	return v
}

func TestAzureCGPUVerifierAcceptsTheCapturedConfidentialGPUVM(t *testing.T) {
	ev, chain := azureCGPUCapturedEvidence(t)
	v := azureCGPUCapturedVerifier(t, chain, nil)
	verdict, err := v.VerifyEvidence(ev, Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err)
	require.Equal(t, "Genoa", verdict.Product)
	require.Len(t, verdict.GPUs, 1)
	require.Equal(t, "GH100", verdict.GPUs[0].HWModel)
	require.Equal(t, "595.71.05", verdict.GPUs[0].DriverVersion)
	require.Equal(t, "96.00.9F.00.04", verdict.GPUs[0].VBIOSVersion)
	require.Equal(t, "https://nras.attestation.nvidia.com", verdict.GPUs[0].Issuer)
	require.Equal(t, uint16(tpmAlgSHA256), verdict.PCRSelections[0].HashAlg)
	require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, verdict.PCRSelections[0].PCRs)

	// Pinned to what it is.
	strict := azureCGPUCapturedVerifier(t, chain, func(c *AzureCGPUVerifierConfig) {
		c.GPU = GPUClaimsPolicy{AcceptableHWModels: []string{"GH100"}, AcceptableDriverVersions: []string{"595.71.05"}, AcceptableVBIOSVersions: []string{"96.00.9F.00.04"}}
		c.MinReportedTCB = 0x0A
	})
	_, err = strict.Verify(ev, Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err)

	// The boot measured into the vTPM, pinned by its PCR digest.
	pcrPinned := azureCGPUCapturedVerifier(t, chain, func(c *AzureCGPUVerifierConfig) { c.AcceptablePCRDigests = [][]byte{verdict.PCRDigest} })
	_, err = pcrPinned.Verify(ev, Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err)
	otherBoot := azureCGPUCapturedVerifier(t, chain, func(c *AzureCGPUVerifierConfig) { c.AcceptablePCRDigests = [][]byte{make([]byte, 32)} })
	_, err = otherBoot.Verify(ev, Nonce(azureCGPUCaptureNonce))
	require.ErrorContains(t, err, "PCR digest")

	// Refusals on the genuine evidence.
	_, err = v.Verify(ev, Nonce("vault-genome cgpu 20260916T133506Z challenge 2"))
	require.ErrorContains(t, err, "TPM quote does not bind challenger nonce")
	other := azureCGPUCapturedVerifier(t, chain, func(c *AzureCGPUVerifierConfig) { c.GPU.AcceptableDriverVersions = []string{"550.90.07"} })
	_, err = other.Verify(ev, Nonce(azureCGPUCaptureNonce))
	require.ErrorContains(t, err, "driver")
	later := azureCGPUCapturedVerifier(t, chain, func(c *AzureCGPUVerifierConfig) {
		c.Now = func() time.Time { return time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC) }
	})
	_, err = later.Verify(ev, Nonce(azureCGPUCaptureNonce))
	require.ErrorContains(t, err, "expired")
	milan, err := os.ReadFile("../../../scripts/hardware-test/azure-sev-snp/live-evidence/cert_chain.pem")
	if err == nil {
		wrongRoot := azureCGPUCapturedVerifier(t, milan, nil)
		_, err = wrongRoot.Verify(ev, Nonce(azureCGPUCaptureNonce))
		require.ErrorContains(t, err, "AMD chain", "a Genoa VCEK does not chain to the Milan ASK")
	}
}
