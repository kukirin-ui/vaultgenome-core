// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The captured evidence with what NVIDIA was given beside its tokens: the
// report and the certificate chain of the GPU (gpu-evidence.json, the
// request the capture sent to NRAS).
func azureCGPUCapturedEvidenceWithReport(t *testing.T) (Evidence, []byte) {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(azureCGPUCapture, name))
		if err != nil {
			t.Skip("azure-cgpu capture not present: " + name)
		}
		return b
	}
	var sent struct {
		Evidence []gpuEvidenceItem `json:"evidence_list"`
	}
	require.NoError(t, json.Unmarshal(read("gpu-evidence.json"), &sent))
	require.Len(t, sent.Evidence, 1)
	ev, err := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: read("hcl-report.bin"),
		QuoteMessage: read("quote1.msg"), QuoteSignature: read("quote1.sig"), GPUToken: read("nras-response.json"), GPUEvidence: sent.Evidence})
	require.NoError(t, err)
	return Evidence(ev), read("cert-chain.pem")
}

// both is a captured verifier whose policy requires the verifier's own
// evaluation beside NVIDIA's, with the manifests served locally.
func azureCGPUBothVerifier(t *testing.T, chain []byte) *AzureCGPUVerifier {
	t.Helper()
	srv, _ := rimServer(t)
	return azureCGPUCapturedVerifier(t, chain, func(c *AzureCGPUVerifierConfig) {
		c.GPUEvaluation = GPUEvaluationBoth
		c.RIMServiceURL = srv.URL + "/v1/rim/"
		c.RIMCacheDir = t.TempDir()
	})
}

func TestAzureCGPUVerifier_OwnEvaluationBesideNVIDIAs(t *testing.T) {
	ev, chain := azureCGPUCapturedEvidenceWithReport(t)
	v := azureCGPUBothVerifier(t, chain)
	verdict, err := v.VerifyEvidence(ev, Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err)
	require.Len(t, verdict.GPUs, 1)
	require.Len(t, verdict.Evaluations, 1)
	e := verdict.Evaluations[0]
	require.True(t, e.Complete(), "%+v", e)
	require.True(t, e.NonceMatch && e.ChainVerified && e.FWIDMatch && e.SignatureVerified && e.MeasurementsMatch)
	require.Equal(t, verdict.GPUs[0].DriverVersion, e.DriverVersion)
	require.Equal(t, verdict.GPUs[0].VBIOSVersion, e.VBIOSVersion)
	require.True(t, e.RIMSignaturesVerified(), "both manifests' XML signatures verified under the certificates chained to NVIDIA's CoRIM root")
	require.True(t, e.DriverRIM.SignatureVerified && e.VBIOSRIM.SignatureVerified)

	// The same evidence under the default policy: NVIDIA's word alone,
	// nothing evaluated here.
	plain := azureCGPUCapturedVerifier(t, chain, nil)
	verdict, err = plain.VerifyEvidence(ev, Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err)
	require.Empty(t, verdict.Evaluations)
}

func TestAzureCGPUVerifier_OwnEvaluationRefusesWhatNVIDIAWouldNotSee(t *testing.T) {
	ev, chain := azureCGPUCapturedEvidenceWithReport(t)
	v := azureCGPUBothVerifier(t, chain)

	// No report in the evidence: an older producer, or one that dropped it.
	var env azureCGPUEvidence
	require.NoError(t, json.Unmarshal(ev, &env))
	env.GPUEvidence = nil
	without, err := json.Marshal(env)
	require.NoError(t, err)
	_, err = v.VerifyEvidence(Evidence(without), Nonce(azureCGPUCaptureNonce))
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeAttestationDenied, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "gpu_evidence")

	// A report whose measurement was changed: NVIDIA's tokens still verify
	// (they are for the report NVIDIA saw), the own evaluation refuses.
	require.NoError(t, json.Unmarshal(ev, &env))
	env.GPUEvidence[0].Report = append([]byte(nil), env.GPUEvidence[0].Report...)
	env.GPUEvidence[0].Report[60] ^= 0x01
	tampered, err := json.Marshal(env)
	require.NoError(t, err)
	_, err = v.VerifyEvidence(Evidence(tampered), Nonce(azureCGPUCaptureNonce))
	require.Error(t, err)
	require.ErrorContains(t, err, "own evaluation")
	require.ErrorContains(t, err, "signature")

	// A report for another nonce.
	require.NoError(t, json.Unmarshal(ev, &env))
	_, err = v.VerifyEvidence(Evidence(ev), Nonce("another challenge"))
	require.Error(t, err, "NVIDIA's tokens are for the capture's challenge too")

	// Two reports for one GPU NVIDIA spoke for.
	require.NoError(t, json.Unmarshal(ev, &env))
	env.GPUEvidence = append(env.GPUEvidence, env.GPUEvidence[0])
	two, err := json.Marshal(env)
	require.NoError(t, err)
	_, err = v.VerifyEvidence(Evidence(two), Nonce(azureCGPUCaptureNonce))
	require.ErrorContains(t, err, "2 reports")
}

// Under "own" the verdict rests on this verifier's evaluation alone: no
// NVIDIA token is needed, and the policy's pins are held against what
// the report and the manifests say.
func TestAzureCGPUVerifier_OwnAlone(t *testing.T) {
	ev, chain := azureCGPUCapturedEvidenceWithReport(t)
	srv, _ := rimServer(t)
	own := func(mutate func(*AzureCGPUVerifierConfig)) *AzureCGPUVerifier {
		return azureCGPUCapturedVerifier(t, chain, func(c *AzureCGPUVerifierConfig) {
			c.GPUEvaluation = GPUEvaluationOwn
			c.RIMServiceURL = srv.URL + "/v1/rim/"
			c.RIMCacheDir = t.TempDir()
			if mutate != nil {
				mutate(c)
			}
		})
	}
	verdict, err := own(nil).VerifyEvidence(ev, Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err)
	require.Len(t, verdict.Evaluations, 1)
	require.True(t, verdict.Evaluations[0].Complete())
	require.Len(t, verdict.GPUs, 1)
	require.Equal(t, "own evaluation", verdict.GPUs[0].Issuer)
	require.Equal(t, "GH100", verdict.GPUs[0].HWModel, "the model from the chain's per-model identity CA")
	require.Equal(t, verdict.Evaluations[0].DriverVersion, verdict.GPUs[0].DriverVersion)

	// No NVIDIA token at all: still a verdict under "own", none under "both".
	var env azureCGPUEvidence
	require.NoError(t, json.Unmarshal(ev, &env))
	env.GPUToken = nil
	without, err := json.Marshal(env)
	require.NoError(t, err)
	_, err = own(nil).VerifyEvidence(Evidence(without), Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err, "own: NVIDIA is not on the path")
	_, err = azureCGPUBothVerifier(t, chain).VerifyEvidence(Evidence(without), Nonce(azureCGPUCaptureNonce))
	require.Error(t, err, "both: NVIDIA's tokens are required")

	// The policy's pins are held against the report.
	_, err = own(func(c *AzureCGPUVerifierConfig) {
		c.GPU = GPUClaimsPolicy{AcceptableDriverVersions: []string{"999.0.0"}}
	}).VerifyEvidence(ev, Nonce(azureCGPUCaptureNonce))
	require.ErrorContains(t, err, "driver")
	_, err = own(func(c *AzureCGPUVerifierConfig) { c.GPU = GPUClaimsPolicy{AcceptableHWModels: []string{"GB200"}} }).VerifyEvidence(ev, Nonce(azureCGPUCaptureNonce))
	require.ErrorContains(t, err, "hw model")

	// A changed measurement: refused on the evaluation alone.
	require.NoError(t, json.Unmarshal(ev, &env))
	env.GPUEvidence[0].Report = append([]byte(nil), env.GPUEvidence[0].Report...)
	env.GPUEvidence[0].Report[60] ^= 0x01
	tampered, err := json.Marshal(env)
	require.NoError(t, err)
	_, err = own(nil).VerifyEvidence(Evidence(tampered), Nonce(azureCGPUCaptureNonce))
	require.ErrorContains(t, err, "own evaluation")
}

func TestAzureCGPUVerifier_RefusesAnUnknownEvaluationPolicy(t *testing.T) {
	_, chain := azureCGPUCapturedEvidenceWithReport(t)
	for name, mutate := range map[string]func(*AzureCGPUVerifierConfig){
		"unknown": func(c *AzureCGPUVerifierConfig) { c.GPUEvaluation = "nvidia-and-friends" },
		"bad root": func(c *AzureCGPUVerifierConfig) {
			c.GPUEvaluation = GPUEvaluationOwn
			c.NVIDIADeviceRootPEM = []byte("not a certificate")
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := AzureCGPUVerifierConfig{AMDRootPEM: chain}
			mutate(&cfg)
			_, err := NewAzureCGPUVerifier(nil, Measurement(make([]byte, 48)), cfg)
			require.Error(t, err)
		})
	}
}

func TestParseGPUAttestOutput_BothContracts(t *testing.T) {
	nras, err := os.ReadFile(filepath.Join(azureCGPUCapture, "nras-response.json"))
	if err != nil {
		t.Skip("azure-cgpu capture not present")
	}
	token, items, err := parseGPUAttestOutput(nras)
	require.NoError(t, err, "NVIDIA's response alone: the older contract")
	require.JSONEq(t, string(nras), string(token))
	require.Empty(t, items)

	sent, err := os.ReadFile(filepath.Join(azureCGPUCapture, "gpu-evidence.json"))
	require.NoError(t, err)
	var req struct {
		Evidence []json.RawMessage `json:"evidence_list"`
	}
	require.NoError(t, json.Unmarshal(sent, &req))
	full, err := json.Marshal(map[string]any{"nras": json.RawMessage(nras), "gpu_evidence": req.Evidence})
	require.NoError(t, err)
	token, items, err = parseGPUAttestOutput(full)
	require.NoError(t, err)
	require.JSONEq(t, string(nras), string(token))
	require.Len(t, items, 1)
	require.NotEmpty(t, items[0].Report)
	require.NotEmpty(t, items[0].CertChain)
	_, err = ParseGPUReport(items[0].Report)
	require.NoError(t, err, "the report decodes from NVIDIA's base64")

	_, _, err = parseGPUAttestOutput([]byte(`{"nras": {}, "gpu_evidence": [{"evidence": "AA=="}]}`))
	require.Error(t, err)
	_, _, err = parseGPUAttestOutput([]byte(`not json`))
	require.Error(t, err)
}
