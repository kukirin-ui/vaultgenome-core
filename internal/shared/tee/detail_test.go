// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The confidential GPU verifier says what it checked beside the
// measurement: the chip, the vTPM quote's PCRs, the GPU NVIDIA's token
// vouched for and this verifier's own evaluation of its report — on the
// captured H100 evidence, complete.
func TestVerifyDetailed_AzureCGPUSaysWhatItChecked(t *testing.T) {
	ev, chain := azureCGPUCapturedEvidenceWithReport(t)
	v := azureCGPUBothVerifier(t, chain)

	m, d, err := VerifyDetailed(v, ev, Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err)
	require.NotNil(t, d)
	plain, err := v.Verify(ev, Nonce(azureCGPUCaptureNonce))
	require.NoError(t, err)
	require.True(t, plain.Equal(m), "the detailed verification returns the same measurement")

	require.Equal(t, ProviderAzureCGPU, d.Provider)
	require.Equal(t, "Genoa", d.Product)
	require.Len(t, d.ChipIDHex, 128)
	require.NotZero(t, d.ReportedTCB)
	require.Contains(t, d.PCRSelection, "sha256:")
	require.NotEmpty(t, d.PCRDigestHex)
	require.Len(t, d.GPUs, 1)
	require.Len(t, d.Evaluations, 1)
	require.Equal(t, "GPU-0", d.GPUs[0].Key)
	require.NotEmpty(t, d.GPUs[0].Issuer, "who vouched for the GPU is on the record")
	require.Equal(t, d.GPUs[0].DriverVersion, d.Evaluations[0].DriverVersion)
	require.True(t, d.Evaluations[0].Complete(), "%+v", d.Evaluations[0])
	require.Equal(t, "GH100", d.Evaluations[0].HWModel)

	// The record is JSON for the audit payload, field by field.
	raw, err := json.Marshal(d)
	require.NoError(t, err)
	for _, key := range []string{`"provider":"azure-cgpu"`, `"product":"Genoa"`, `"pcr_selection":"sha256:`, `"gpus":[{"key":"GPU-0"`,
		`"hw_model":"GH100"`, `"driver_version":"`, `"evaluations":[{"report_parsed":true`, `"signature_verified":true`, `"measurements_match":true`} {
		require.Contains(t, string(raw), key)
	}
}

// A verifier with nothing beyond the measurement to say gives no detail,
// and the measurement is the one Verify gives.
func TestVerifyDetailed_PlainVerifierHasNoDetail(t *testing.T) {
	t.Parallel()
	p, err := NewSimulated([]byte("worker"), bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	v := NewSimulatedVerifier(p.PublicKey(), p.Measurement())
	nonce := make(Nonce, NonceMinBytes)
	ev, err := p.Quote(nonce)
	require.NoError(t, err)

	m, d, err := VerifyDetailed(v, ev, nonce)
	require.NoError(t, err)
	require.Nil(t, d)
	require.True(t, p.Measurement().Equal(m))

	_, d, err = VerifyDetailed(v, ev, make(Nonce, NonceMinBytes+1))
	require.Error(t, err, "a refusal is a refusal with no detail")
	require.Nil(t, d)
}

// A verifier with detail hands it through the helper, and a refusal
// carries none.
func TestVerifyDetailed_DetailedVerifierHandsItsDetailThrough(t *testing.T) {
	t.Parallel()
	want := &AttestationDetail{Provider: ProviderAzureCGPU, Product: "Genoa", GPUs: []GPUVerdict{{Key: "GPU-0", HWModel: "GH100", Issuer: "own evaluation"}}}
	dv := detailedStub{m: MeasurementOf([]byte("x")), d: want}
	m, d, err := VerifyDetailed(dv, Evidence("ev"), make(Nonce, NonceMinBytes))
	require.NoError(t, err)
	require.Equal(t, want, d)
	require.True(t, dv.m.Equal(m))

	_, d, err = VerifyDetailed(detailedStub{err: errRefused}, Evidence("ev"), make(Nonce, NonceMinBytes))
	require.ErrorIs(t, err, errRefused)
	require.Nil(t, d)
}

type detailedStub struct {
	m   Measurement
	d   *AttestationDetail
	err error
}

func (s detailedStub) Verify(_ Evidence, _ Nonce) (Measurement, error) { return s.m, s.err }
func (s detailedStub) VerifyDetailed(_ Evidence, _ Nonce) (Measurement, *AttestationDetail, error) {
	if s.err != nil {
		return nil, nil, s.err
	}
	return s.m, s.d, nil
}

var errRefused = errorString("refused")

type errorString string

func (e errorString) Error() string { return string(e) }
