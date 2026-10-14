// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package teemetrics

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Recorder owns the TEE-related metric families. Construct exactly one
// per daemon process; pass it to every WrapXxx call site.
type Recorder struct {
	attestTotal    *metrics.Counter
	attestDuration *metrics.Histogram
	sealTotal      *metrics.Counter
	sealDuration   *metrics.Histogram
	capabilityHits *metrics.Counter
}

// New registers every TEE-related metric with the supplied registry.
// Panics if any of the metric names collide with existing entries —
// caller is responsible for using a fresh registry per daemon.
func New(r *metrics.Registry) *Recorder {
	return &Recorder{
		attestTotal: r.NewCounter(
			"vg_tee_attestation_total",
			"Count of TEE attestation operations (Quote + Verify) by provider, role, and outcome.",
		),
		attestDuration: r.NewHistogram(
			"vg_tee_attestation_duration_seconds",
			"Latency of TEE attestation operations in seconds, by provider and role.",
			metrics.DefaultLatencyBuckets,
		),
		sealTotal: r.NewCounter(
			"vg_tee_sealing_total",
			"Count of TEE sealing operations (Seal + Unseal) by provider, op, and outcome.",
		),
		sealDuration: r.NewHistogram(
			"vg_tee_sealing_duration_seconds",
			"Latency of TEE sealing operations in seconds, by provider and op.",
			metrics.DefaultLatencyBuckets,
		),
		capabilityHits: r.NewCounter(
			"vg_tee_capability_total",
			"Count of TEE capability probes (true=available, false=unavailable) by provider.",
		),
	}
}

// RecordCapability is called by the daemon at startup when probing
// which TEE backends are available on this host. Surfaces the same
// information operators see in startup logs — useful when an SRE asks
// "did the SGX driver register correctly on that node?" without having
// to grep journals.
func (r *Recorder) RecordCapability(provider string, available bool) {
	val := "false"
	if available {
		val = "true"
	}
	r.capabilityHits.Inc(
		metrics.Label{Name: "provider", Value: provider},
		metrics.Label{Name: "available", Value: val},
	)
}

// WrapProducer returns a Producer that records vg_tee_attestation_*
// metrics around every Quote call. Measurement() is a cheap accessor;
// it is not instrumented to keep cardinality tight.
func (r *Recorder) WrapProducer(provider string, p tee.Producer) tee.Producer {
	if p == nil {
		return nil
	}
	return &instrumentedProducer{provider: provider, inner: p, rec: r}
}

// WrapVerifier returns a Verifier that records vg_tee_attestation_*
// metrics around every Verify call.
func (r *Recorder) WrapVerifier(provider string, v tee.Verifier) tee.Verifier {
	if v == nil {
		return nil
	}
	return &instrumentedVerifier{provider: provider, inner: v, rec: r}
}

// WrapSealer returns a Sealer that records vg_tee_sealing_* metrics
// around every Seal and Unseal call.
func (r *Recorder) WrapSealer(provider string, s tee.Sealer) tee.Sealer {
	if s == nil {
		return nil
	}
	return &instrumentedSealer{provider: provider, inner: s, rec: r}
}

// ---- producer wrapper -----------------------------------------------------

type instrumentedProducer struct {
	provider string
	inner    tee.Producer
	rec      *Recorder
}

func (p *instrumentedProducer) Quote(nonce tee.Nonce) (tee.Evidence, error) {
	start := time.Now()
	ev, err := p.inner.Quote(nonce)
	p.rec.observeAttest(p.provider, "produce", time.Since(start), err)
	return ev, err
}

func (p *instrumentedProducer) Measurement() tee.Measurement {
	return p.inner.Measurement()
}

// ---- verifier wrapper -----------------------------------------------------

type instrumentedVerifier struct {
	provider string
	inner    tee.Verifier
	rec      *Recorder
}

func (v *instrumentedVerifier) Verify(ev tee.Evidence, nonce tee.Nonce) (tee.Measurement, error) {
	start := time.Now()
	m, err := v.inner.Verify(ev, nonce)
	v.rec.observeAttest(v.provider, "verify", time.Since(start), err)
	return m, err
}

// VerifyDetailed keeps the inner verifier's detail (tee.DetailedVerifier)
// beside the measurement; a plain inner verifier gives none.
func (v *instrumentedVerifier) VerifyDetailed(ev tee.Evidence, nonce tee.Nonce) (tee.Measurement, *tee.AttestationDetail, error) {
	start := time.Now()
	m, d, err := tee.VerifyDetailed(v.inner, ev, nonce)
	v.rec.observeAttest(v.provider, "verify", time.Since(start), err)
	return m, d, err
}

// ---- sealer wrapper -------------------------------------------------------

type instrumentedSealer struct {
	provider string
	inner    tee.Sealer
	rec      *Recorder
}

func (s *instrumentedSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	start := time.Now()
	out, err := s.inner.Seal(plaintext, aad)
	s.rec.observeSeal(s.provider, "seal", time.Since(start), err)
	return out, err
}

func (s *instrumentedSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	start := time.Now()
	out, err := s.inner.Unseal(sealed, aad)
	s.rec.observeSeal(s.provider, "unseal", time.Since(start), err)
	return out, err
}

// ---- shared observation helpers ------------------------------------------

func (r *Recorder) observeAttest(provider, role string, dur time.Duration, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	r.attestTotal.Inc(
		metrics.Label{Name: "provider", Value: provider},
		metrics.Label{Name: "result", Value: result},
		metrics.Label{Name: "role", Value: role},
	)
	r.attestDuration.Observe(dur.Seconds(),
		metrics.Label{Name: "provider", Value: provider},
		metrics.Label{Name: "role", Value: role},
	)
}

func (r *Recorder) observeSeal(provider, op string, dur time.Duration, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	r.sealTotal.Inc(
		metrics.Label{Name: "op", Value: op},
		metrics.Label{Name: "provider", Value: provider},
		metrics.Label{Name: "result", Value: result},
	)
	r.sealDuration.Observe(dur.Seconds(),
		metrics.Label{Name: "op", Value: op},
		metrics.Label{Name: "provider", Value: provider},
	)
}

// Compile-time interface conformance.
var (
	_ tee.Producer = (*instrumentedProducer)(nil)
	_ tee.Verifier = (*instrumentedVerifier)(nil)
	_ tee.Sealer   = (*instrumentedSealer)(nil)
)
