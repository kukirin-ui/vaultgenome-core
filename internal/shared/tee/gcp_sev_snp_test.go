// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"strings"
	"testing"
)

// TestGCPSEVProducer_RejectsBadVMPL enforces VMPL 0..3 range.
func TestGCPSEVProducer_RejectsBadVMPL(t *testing.T) {
	t.Parallel()
	_, err := NewGCPSEVProducer(GCPSEVProducerConfig{
		TSMReportDir: t.TempDir(),
		VMPL:         99,
	})
	if err == nil {
		t.Fatal("expected error on invalid VMPL")
	}
	if !strings.Contains(err.Error(), "vmpl") {
		t.Errorf("error should mention vmpl; got %q", err.Error())
	}
}

// TestGCPSEVProducer_AbsentTSMFails ensures Confidential VM enforcement.
func TestGCPSEVProducer_AbsentTSMFails(t *testing.T) {
	t.Parallel()
	_, err := NewGCPSEVProducer(GCPSEVProducerConfig{
		TSMReportDir: "/nonexistent/tsm/report",
	})
	if err == nil {
		t.Fatal("expected error when configfs-tsm is absent")
	}
	if !strings.Contains(err.Error(), "Confidential VM") {
		t.Errorf("error should educate operator; got %q", err.Error())
	}
}

// TestGCPSEVVerifier_NonceFloor enforces R-10.
func TestGCPSEVVerifier_NonceFloor(t *testing.T) {
	t.Parallel()
	v, err := NewGCPSEVVerifier(nil, Measurement{}, GCPSEVVerifierConfig{})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	_, err = v.Verify(Evidence(make([]byte, 2000)), Nonce(make([]byte, NonceMinBytes-1)))
	if err == nil {
		t.Fatal("expected nonce-too-short error")
	}
}

// TestGCPSEVVerifier_DefaultsAMDKDS sets the AMD KDS URL when blank.
func TestGCPSEVVerifier_DefaultsAMDKDS(t *testing.T) {
	t.Parallel()
	v, err := NewGCPSEVVerifier(nil, Measurement{}, GCPSEVVerifierConfig{})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if v.cfg.AMDKDSURL == "" {
		t.Error("AMDKDSURL should be defaulted to https://kdsintf.amd.com")
	}
}

// TestGCPSEVVerifier_RejectsTooShortReport enforces 1184-byte SEV-SNP report size.
func TestGCPSEVVerifier_RejectsTooShortReport(t *testing.T) {
	t.Parallel()
	v, _ := NewGCPSEVVerifier(nil, Measurement{}, GCPSEVVerifierConfig{})
	_, err := v.Verify(Evidence(make([]byte, 100)), Nonce(make([]byte, NonceMinBytes)))
	if err == nil {
		t.Fatal("expected too-short error for evidence < 1184 bytes")
	}
}

// TestGCPSEVCapability_StableSignal.
func TestGCPSEVCapability_StableSignal(t *testing.T) {
	t.Parallel()
	a1, r1 := gcpSEVCapability()
	a2, r2 := gcpSEVCapability()
	if a1 != a2 || r1 != r2 {
		t.Errorf("capability unstable: (%v,%q) vs (%v,%q)", a1, r1, a2, r2)
	}
}

// TestGCPSEV_InterfaceConformance.
func TestGCPSEV_InterfaceConformance(t *testing.T) {
	t.Parallel()
	var _ Producer = (*GCPSEVProducer)(nil)
	var _ Verifier = (*GCPSEVVerifier)(nil)
	var _ Sealer = (*GCPSEVSealer)(nil)
}
