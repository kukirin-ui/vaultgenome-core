// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"strings"
	"testing"
)

// TestParseProvider_Valid checks every defined provider name parses.
func TestParseProvider_Valid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  Provider
	}{
		{"simulated", ProviderSimulated},
		{"SIMULATED", ProviderSimulated},
		{" simulated ", ProviderSimulated},
		{"aws-nitro", ProviderAWSNitro},
		{"AWS-NITRO", ProviderAWSNitro},
		{"azure-sgx", ProviderAzureSGX},
		{"gcp-sev-snp", ProviderGCPSEVSNP},
		{"intel-sgx-dcap", ProviderIntelSGXDCAP},
		{"gcp-tdx", ProviderGCPTDX},
		{"azure-cgpu", ProviderAzureCGPU},
	}
	for _, c := range cases {
		got, err := ParseProvider(c.input)
		if err != nil {
			t.Errorf("ParseProvider(%q): unexpected error %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseProvider(%q): got %q, want %q", c.input, got, c.want)
		}
	}
}

// TestParseProvider_Invalid checks rejection paths.
func TestParseProvider_Invalid(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"unknown",
		"sgx",
		"aws_nitro",      // wrong separator
		"intel sgx dcap", // wrong separator
	}
	for _, c := range cases {
		_, err := ParseProvider(c)
		if err == nil {
			t.Errorf("ParseProvider(%q): expected error, got nil", c)
		}
	}
}

// TestAllProviders_StableOrder pins the order Capability/UI iteration uses.
func TestAllProviders_StableOrder(t *testing.T) {
	t.Parallel()
	got := AllProviders()
	want := []Provider{
		ProviderSimulated,
		ProviderAWSNitro,
		ProviderAzureSGX,
		ProviderGCPSEVSNP,
		ProviderIntelSGXDCAP,
		ProviderGCPTDX,
		ProviderAzureCGPU,
	}
	if len(got) != len(want) {
		t.Fatalf("AllProviders length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllProviders[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestCapability_AlwaysReturnsReason ensures the diagnostic string is
// never empty — operators rely on this in startup logs.
func TestCapability_AlwaysReturnsReason(t *testing.T) {
	t.Parallel()
	for _, p := range AllProviders() {
		_, reason := Capability(p)
		if reason == "" {
			t.Errorf("Capability(%q): empty reason — must always be human-readable", p)
		}
	}
}

// TestCapability_SimulatedAlwaysAvailable checks the dev backend has zero
// hardware preconditions.
func TestCapability_SimulatedAlwaysAvailable(t *testing.T) {
	t.Parallel()
	available, _ := Capability(ProviderSimulated)
	if !available {
		t.Error("Capability(simulated): expected available=true")
	}
}

// TestBuildProducer_RejectsUnknownProvider — defence against silent fallback.
func TestBuildProducer_RejectsUnknownProvider(t *testing.T) {
	t.Parallel()
	_, err := BuildProducer(ProducerSpec{Provider: "made-up-tee"})
	if err == nil {
		t.Fatal("BuildProducer(unknown): expected error, got nil")
	}
}

// TestBuildProducer_SimulatedRequiresSeedBytes pins the API contract:
// daemon must read seed file before calling BuildProducer for simulated.
func TestBuildProducer_SimulatedRequiresSeedBytes(t *testing.T) {
	t.Parallel()
	_, err := BuildProducer(ProducerSpec{
		Provider:           ProviderSimulated,
		WorkloadDescriptor: []byte("test-workload"),
		SeedPath:           "/var/lib/vault-genome/secrets/sagvd/tee_seed",
		// SeedBytes intentionally nil to test the error path.
	})
	if err == nil {
		t.Fatal("expected error when SeedPath set but SeedBytes nil")
	}
	if !strings.Contains(err.Error(), "SeedBytes") {
		t.Errorf("error message should mention SeedBytes; got %q", err.Error())
	}
}

// TestBuildProducer_SimulatedHappyPath constructs simulated successfully.
func TestBuildProducer_SimulatedHappyPath(t *testing.T) {
	t.Parallel()
	seed := make([]byte, 32) // crypto.Ed25519SeedSize
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	p, err := BuildProducer(ProducerSpec{
		Provider:           ProviderSimulated,
		WorkloadDescriptor: []byte("test-workload"),
		SeedBytes:          seed,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil Producer")
	}
	if p.Measurement().IsZero() {
		t.Error("expected non-zero measurement from simulated TEE")
	}
}
