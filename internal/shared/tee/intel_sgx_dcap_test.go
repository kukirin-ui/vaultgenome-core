// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"strings"
	"testing"
)

// TestIntelSGXProducer_RequiresEnclaveSOPath.
func TestIntelSGXProducer_RequiresEnclaveSOPath(t *testing.T) {
	t.Parallel()
	_, err := NewIntelSGXProducer(IntelSGXProducerConfig{})
	if err == nil {
		t.Fatal("expected error when enclave_so_path missing")
	}
}

// TestIntelSGXVerifier_RequiresPCCSURL — bare-metal mode requires it.
func TestIntelSGXVerifier_RequiresPCCSURL(t *testing.T) {
	t.Parallel()
	_, err := NewIntelSGXVerifier(nil, Measurement{}, IntelSGXVerifierConfig{})
	if err == nil {
		t.Fatal("expected error when pccs_url empty")
	}
	if !strings.Contains(err.Error(), "pccs_url") {
		t.Errorf("error should mention pccs_url; got %q", err.Error())
	}
}

// TestIntelSGXVerifier_AcceptsValidConfig.
func TestIntelSGXVerifier_AcceptsValidConfig(t *testing.T) {
	t.Parallel()
	v, err := NewIntelSGXVerifier(nil, Measurement{}, IntelSGXVerifierConfig{
		PCCSURL:   "https://pccs.bank.example/sgx/certification/v4",
		MinISVSVN: 3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
}

// TestIntelSGXVerifier_NonceFloor.
func TestIntelSGXVerifier_NonceFloor(t *testing.T) {
	t.Parallel()
	v, _ := NewIntelSGXVerifier(nil, Measurement{}, IntelSGXVerifierConfig{
		PCCSURL: "https://pccs.example",
	})
	_, err := v.Verify(Evidence(make([]byte, 1000)), Nonce(make([]byte, NonceMinBytes-1)))
	if err == nil {
		t.Fatal("expected nonce-too-short error")
	}
}

// TestIntelSGXSealer_RejectsUnknownPolicy.
func TestIntelSGXSealer_RejectsUnknownPolicy(t *testing.T) {
	t.Parallel()
	_, err := NewIntelSGXSealer(0, SGXSealPolicy(0), "")
	if err == nil {
		t.Fatal("expected error on unknown policy")
	}
}

// TestIntelSGXSealer_AcceptsBothPolicies.
func TestIntelSGXSealer_AcceptsBothPolicies(t *testing.T) {
	t.Parallel()
	for _, policy := range []SGXSealPolicy{SGXSealMRENCLAVE, SGXSealMRSIGNER} {
		s, err := NewIntelSGXSealer(1, policy, "")
		if err != nil {
			t.Errorf("policy %v: unexpected error %v", policy, err)
		}
		if s == nil {
			t.Errorf("policy %v: expected non-nil sealer", policy)
		}
	}
}

// TestIntelSGXCapability_StableSignal.
func TestIntelSGXCapability_StableSignal(t *testing.T) {
	t.Parallel()
	a1, r1 := intelSGXCapability()
	a2, r2 := intelSGXCapability()
	if a1 != a2 || r1 != r2 {
		t.Errorf("capability unstable")
	}
}

// TestIntelSGX_InterfaceConformance.
func TestIntelSGX_InterfaceConformance(t *testing.T) {
	t.Parallel()
	var _ Producer = (*IntelSGXProducer)(nil)
	var _ Verifier = (*IntelSGXVerifier)(nil)
	var _ Sealer = (*IntelSGXSealer)(nil)
}
