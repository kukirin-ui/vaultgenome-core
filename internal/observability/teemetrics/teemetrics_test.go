// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package teemetrics_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	"github.com/vault-genome/vaultgenome-core/internal/observability/teemetrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// stubProducer is a minimal Producer that always returns the given
// evidence + error. Tests use it to drive the wrapper without spinning
// up a real adapter or simulator.
type stubProducer struct {
	measurement tee.Measurement
	ev          tee.Evidence
	err         error
}

func (s *stubProducer) Quote(_ tee.Nonce) (tee.Evidence, error) { return s.ev, s.err }
func (s *stubProducer) Measurement() tee.Measurement            { return s.measurement }

type stubVerifier struct {
	measurement tee.Measurement
	err         error
}

func (s *stubVerifier) Verify(_ tee.Evidence, _ tee.Nonce) (tee.Measurement, error) {
	return s.measurement, s.err
}

type stubSealer struct {
	sealOut   []byte
	unsealOut []byte
	sealErr   error
	unsealErr error
}

func (s *stubSealer) Seal(_, _ []byte) ([]byte, error)   { return s.sealOut, s.sealErr }
func (s *stubSealer) Unseal(_, _ []byte) ([]byte, error) { return s.unsealOut, s.unsealErr }

func TestRecorder_WrapProducer_RecordsSuccessAndError(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)

	good := rec.WrapProducer("aws-nitro", &stubProducer{ev: []byte("ev"), err: nil})
	bad := rec.WrapProducer("aws-nitro", &stubProducer{err: errors.New("nsm denied")})

	for i := 0; i < 3; i++ {
		_, _ = good.Quote(make(tee.Nonce, tee.NonceMinBytes))
	}
	for i := 0; i < 2; i++ {
		_, _ = bad.Quote(make(tee.Nonce, tee.NonceMinBytes))
	}

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	require.Contains(t, out,
		`vg_tee_attestation_total{provider="aws-nitro",result="success",role="produce"} 3`)
	require.Contains(t, out,
		`vg_tee_attestation_total{provider="aws-nitro",result="error",role="produce"} 2`)
	// Histogram count line must exist even though we don't pin the
	// exact latency value (it varies per run).
	require.Contains(t, out,
		`vg_tee_attestation_duration_seconds_count{provider="aws-nitro",role="produce"} 5`)
}

func TestRecorder_WrapVerifier_DistinguishesRole(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)

	v := rec.WrapVerifier("azure-sgx", &stubVerifier{measurement: tee.MeasurementOf([]byte("x"))})
	for i := 0; i < 4; i++ {
		_, _ = v.Verify([]byte("ev"), make(tee.Nonce, tee.NonceMinBytes))
	}

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	// role=verify, NOT produce — the verifier wrapper must label correctly.
	require.Contains(t, out,
		`vg_tee_attestation_total{provider="azure-sgx",result="success",role="verify"} 4`)
	require.NotContains(t, out, `role="produce"`)
}

func TestRecorder_WrapSealer_RecordsSealAndUnseal(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)

	s := rec.WrapSealer("gcp-sev-snp", &stubSealer{
		sealOut:   []byte("sealed"),
		unsealOut: []byte("plain"),
	})

	for i := 0; i < 5; i++ {
		_, _ = s.Seal([]byte("pt"), []byte("aad"))
	}
	for i := 0; i < 3; i++ {
		_, _ = s.Unseal([]byte("sealed"), []byte("aad"))
	}

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	require.Contains(t, out,
		`vg_tee_sealing_total{op="seal",provider="gcp-sev-snp",result="success"} 5`)
	require.Contains(t, out,
		`vg_tee_sealing_total{op="unseal",provider="gcp-sev-snp",result="success"} 3`)
	require.Contains(t, out,
		`vg_tee_sealing_duration_seconds_count{op="seal",provider="gcp-sev-snp"} 5`)
	require.Contains(t, out,
		`vg_tee_sealing_duration_seconds_count{op="unseal",provider="gcp-sev-snp"} 3`)
}

func TestRecorder_WrapSealer_TracksUnsealErrors(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)

	s := rec.WrapSealer("intel-sgx-dcap", &stubSealer{
		unsealErr: errors.New("AAD mismatch"),
	})
	_, err := s.Unseal([]byte("ct"), []byte("aad"))
	require.Error(t, err)

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	require.Contains(t, buf.String(),
		`vg_tee_sealing_total{op="unseal",provider="intel-sgx-dcap",result="error"} 1`)
}

func TestRecorder_RecordCapability(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)

	rec.RecordCapability("simulated", true)
	rec.RecordCapability("aws-nitro", false)
	rec.RecordCapability("aws-nitro", false)

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	require.Contains(t, out, `vg_tee_capability_total{available="true",provider="simulated"} 1`)
	require.Contains(t, out, `vg_tee_capability_total{available="false",provider="aws-nitro"} 2`)
}

func TestRecorder_WrapProducer_PreservesMeasurement(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)

	want := tee.MeasurementOf([]byte("preserved-measurement"))
	wrapped := rec.WrapProducer("simulated", &stubProducer{measurement: want, ev: []byte("ev")})
	require.Equal(t, want, wrapped.Measurement())
}

func TestRecorder_WrapNilSafe(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)
	require.Nil(t, rec.WrapProducer("simulated", nil))
	require.Nil(t, rec.WrapVerifier("simulated", nil))
	require.Nil(t, rec.WrapSealer("simulated", nil))
}

func TestRecorder_FullPipelineOnSimulator(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)

	// Build a real simulated TEE and wrap it. This is the closest we
	// can get to "live integration" without hardware: every code path
	// the wrapper instruments runs against a working backend.
	seed := bytes.Repeat([]byte{0x42}, 32)
	sim, err := tee.NewSimulated([]byte("teemetrics-int"), seed)
	require.NoError(t, err)
	verifier := tee.NewSimulatedVerifier(sim.PublicKey(), sim.Measurement())

	p := rec.WrapProducer("simulated", sim)
	v := rec.WrapVerifier("simulated", verifier)
	s := rec.WrapSealer("simulated", sim)

	nonce := bytes.Repeat([]byte{0xA1}, tee.NonceMinBytes)
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	got, err := v.Verify(ev, nonce)
	require.NoError(t, err)
	require.Equal(t, sim.Measurement(), got)

	sealed, err := s.Seal([]byte("payload"), []byte("aad"))
	require.NoError(t, err)
	plain, err := s.Unseal(sealed, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), plain)

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	// All four code paths recorded one observation.
	require.Contains(t, out, `vg_tee_attestation_total{provider="simulated",result="success",role="produce"} 1`)
	require.Contains(t, out, `vg_tee_attestation_total{provider="simulated",result="success",role="verify"} 1`)
	require.Contains(t, out, `vg_tee_sealing_total{op="seal",provider="simulated",result="success"} 1`)
	require.Contains(t, out, `vg_tee_sealing_total{op="unseal",provider="simulated",result="success"} 1`)
	// Histogram +Inf bucket for each role/op exists.
	require.True(t, strings.Contains(out, `_bucket{le="+Inf",provider="simulated",role="produce"} 1`))
}

type stubDetailedVerifier struct {
	stubVerifier
	detail *tee.AttestationDetail
}

func (s *stubDetailedVerifier) VerifyDetailed(_ tee.Evidence, _ tee.Nonce) (tee.Measurement, *tee.AttestationDetail, error) {
	return s.measurement, s.detail, s.err
}

// The wrapper hands the inner verifier's detail through — the audit
// record must not lose the GPU evaluation to the metrics wrapper — and
// counts the verification once, as verify.
func TestRecorder_WrapVerifier_KeepsTheDetail(t *testing.T) {
	t.Parallel()
	r := metrics.NewRegistry()
	rec := teemetrics.New(r)
	want := &tee.AttestationDetail{Provider: tee.ProviderAzureCGPU, Product: "Genoa"}

	v := rec.WrapVerifier("azure-cgpu", &stubDetailedVerifier{stubVerifier: stubVerifier{measurement: tee.MeasurementOf([]byte("x"))}, detail: want})
	m, d, err := tee.VerifyDetailed(v, []byte("ev"), make(tee.Nonce, tee.NonceMinBytes))
	require.NoError(t, err)
	require.Equal(t, want, d)
	require.True(t, tee.MeasurementOf([]byte("x")).Equal(m))

	plain := rec.WrapVerifier("simulated", &stubVerifier{measurement: tee.MeasurementOf([]byte("y"))})
	_, d, err = tee.VerifyDetailed(plain, []byte("ev"), make(tee.Nonce, tee.NonceMinBytes))
	require.NoError(t, err)
	require.Nil(t, d, "a plain inner verifier has no detail to hand through")

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	require.Contains(t, buf.String(), `vg_tee_attestation_total{provider="azure-cgpu",result="success",role="verify"} 1`)
	require.Contains(t, buf.String(), `vg_tee_attestation_total{provider="simulated",result="success",role="verify"} 1`)
}
