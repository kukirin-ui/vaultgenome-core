// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// AttestationDetail is what a verifier can say about verified Evidence
// beyond the Measurement: the platform the evidence named and, for a
// confidential GPU host, the GPUs NVIDIA's tokens vouched for and this
// verifier's own evaluations of their reports (ADR 0021). It goes on the
// audit record that admits the peer (TRUST_EVALUATED) or releases a key
// to it (CROSS_CLOUD_ATTESTATION_VERIFIED), so the record says what was
// checked, not only that a measurement matched. Nil when the verifier
// has nothing beyond the measurement to say.
type AttestationDetail struct {
	Provider    Provider `json:"provider"`
	Product     string   `json:"product,omitempty"`
	ChipIDHex   string   `json:"chip_id_hex,omitempty"`
	ReportedTCB uint64   `json:"reported_tcb,omitempty"`
	// PCRSelection and PCRDigestHex are the vTPM quote's bank and PCRs
	// and the digest over them the pin was held against.
	PCRSelection string `json:"pcr_selection,omitempty"`
	PCRDigestHex string `json:"pcr_digest_hex,omitempty"`
	// GPUs are the GPUs the verdict rests on, each with who vouched for
	// it: NVIDIA's token or the verifier's own evaluation.
	GPUs []GPUVerdict `json:"gpus,omitempty"`
	// Evaluations are the verifier's own evaluations of the GPUs'
	// reports, one per report, when the policy asked for them.
	Evaluations []GPUEvaluation `json:"evaluations,omitempty"`
}

// DetailedVerifier is a Verifier that can also say what it verified.
type DetailedVerifier interface {
	Verifier
	// VerifyDetailed is Verify with the detail beside the measurement.
	VerifyDetailed(evidence Evidence, nonce Nonce) (Measurement, *AttestationDetail, error)
}

// VerifyDetailed verifies evidence with v and returns the detail when v
// can give one; a plain Verifier gives none.
func VerifyDetailed(v Verifier, evidence Evidence, nonce Nonce) (Measurement, *AttestationDetail, error) {
	if dv, ok := v.(DetailedVerifier); ok {
		return dv.VerifyDetailed(evidence, nonce)
	}
	m, err := v.Verify(evidence, nonce)
	return m, nil, err
}
