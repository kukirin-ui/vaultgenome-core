// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"strings"
	"testing"
)

// TestAzureSGXProducer_RequiresEnclaveSOPath enforces required config.
func TestAzureSGXProducer_RequiresEnclaveSOPath(t *testing.T) {
	t.Parallel()
	_, err := NewAzureSGXProducer(AzureSGXProducerConfig{})
	if err == nil {
		t.Fatal("expected Structural error when enclave_so_path missing")
	}
	if !strings.Contains(err.Error(), "enclave_so_path") {
		t.Errorf("error should mention missing field; got %q", err.Error())
	}
}

// TestAzureSGXVerifier_RequiresMAAEndpointInMAAMode pins config-mode contract.
func TestAzureSGXVerifier_RequiresMAAEndpointInMAAMode(t *testing.T) {
	t.Parallel()
	_, err := NewAzureSGXVerifier(nil, Measurement{}, AzureSGXVerifierConfig{
		Mode: AzureSGXModeMAA,
	})
	if err == nil {
		t.Fatal("expected error when MAA mode but maa_endpoint empty")
	}
}

// TestAzureSGXVerifier_RequiresPCCSURLInDCAPMode pins config-mode contract.
func TestAzureSGXVerifier_RequiresPCCSURLInDCAPMode(t *testing.T) {
	t.Parallel()
	_, err := NewAzureSGXVerifier(nil, Measurement{}, AzureSGXVerifierConfig{
		Mode: AzureSGXModeDCAP,
	})
	if err == nil {
		t.Fatal("expected error when DCAP mode but pccs_url empty")
	}
}

// TestAzureSGXVerifier_AcceptsDefaultedConfig — MAA mode with endpoint set.
func TestAzureSGXVerifier_AcceptsDefaultedConfig(t *testing.T) {
	t.Parallel()
	v, err := NewAzureSGXVerifier(nil, Measurement{}, AzureSGXVerifierConfig{
		Mode:        AzureSGXModeMAA,
		MAAEndpoint: "https://sharedeus.eus.attest.azure.net",
	})
	if err != nil {
		t.Fatalf("constructor failed: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
}

// TestAzureSGXVerifier_NonceFloor enforces R-10 nonce minimum.
func TestAzureSGXVerifier_NonceFloor(t *testing.T) {
	t.Parallel()
	v, _ := NewAzureSGXVerifier(nil, Measurement{}, AzureSGXVerifierConfig{
		Mode:        AzureSGXModeMAA,
		MAAEndpoint: "https://test.example.net",
	})
	_, err := v.Verify(Evidence(make([]byte, 1000)), Nonce(make([]byte, NonceMinBytes-1)))
	if err == nil {
		t.Fatal("expected nonce-too-short error")
	}
}

// TestAzureSGXVerifier_RejectsUnknownMode catches typos in config.
func TestAzureSGXVerifier_RejectsUnknownMode(t *testing.T) {
	t.Parallel()
	v, _ := NewAzureSGXVerifier(nil, Measurement{}, AzureSGXVerifierConfig{
		Mode:        AzureSGXModeMAA,
		MAAEndpoint: "https://test.example.net",
	})
	// Manually corrupt mode after construction.
	v.cfg.Mode = "typo-mode"
	_, err := v.Verify(Evidence(make([]byte, 1000)), Nonce(make([]byte, NonceMinBytes)))
	if err == nil {
		t.Fatal("expected error on unknown mode")
	}
}

// TestAzureSGXSealer_RejectsUnknownPolicy guards the policy enum.
func TestAzureSGXSealer_RejectsUnknownPolicy(t *testing.T) {
	t.Parallel()
	_, err := NewAzureSGXSealer(0, SGXSealPolicy(99), "test-kid")
	if err == nil {
		t.Fatal("expected error on unknown SGXSealPolicy")
	}
}

// TestAzureSGXCapability_NoSGXDevice — host without SGX should report so.
func TestAzureSGXCapability_NoSGXDevice(t *testing.T) {
	t.Parallel()
	available, reason := azureSGXCapability()
	if reason == "" {
		t.Error("capability check must return diagnostic")
	}
	// On a typical CI machine SGX devices are absent; in that case we
	// should report not-available. If devices ARE present (rare in CI),
	// available=true is also valid.
	_ = available
}

// TestAzureSGX_InterfaceConformance.
func TestAzureSGX_InterfaceConformance(t *testing.T) {
	t.Parallel()
	var _ Producer = (*AzureSGXProducer)(nil)
	var _ Verifier = (*AzureSGXVerifier)(nil)
	var _ Sealer = (*AzureSGXSealer)(nil)
}
