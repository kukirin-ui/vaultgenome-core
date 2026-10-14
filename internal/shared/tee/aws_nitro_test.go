// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"strings"
	"testing"
)

// TestAWSNitroProducer_RejectsOversizedUserData enforces the 1024-byte cap.
func TestAWSNitroProducer_RejectsOversizedUserData(t *testing.T) {
	t.Parallel()
	cfg := AWSNitroProducerConfig{
		NSMDevicePath: "/dev/nsm",
		UserData:      make([]byte, 1025),
	}
	_, err := NewAWSNitroProducer(cfg)
	if err == nil {
		t.Fatal("expected Structural error for oversized user_data")
	}
	if !strings.Contains(err.Error(), "1024") {
		t.Errorf("error should mention size limit; got %q", err.Error())
	}
}

// TestAWSNitroProducer_AbsentDeviceFails ensures startup-time diagnostic
// when running outside an enclave.
func TestAWSNitroProducer_AbsentDeviceFails(t *testing.T) {
	t.Parallel()
	cfg := AWSNitroProducerConfig{
		NSMDevicePath: "/nonexistent/nsm-device",
	}
	_, err := NewAWSNitroProducer(cfg)
	if err == nil {
		t.Fatal("expected error when NSM device absent")
	}
	if !strings.Contains(err.Error(), "Nitro Enclave") {
		t.Errorf("error should educate operator; got %q", err.Error())
	}
}

// TestAWSNitroVerifier_RequiresMinimumNonce enforces R-10 nonce floor.
func TestAWSNitroVerifier_RequiresMinimumNonce(t *testing.T) {
	t.Parallel()
	v, err := NewAWSNitroVerifier(nil, Measurement{}, AWSNitroVerifierConfig{})
	if err != nil {
		t.Fatalf("constructor failed: %v", err)
	}
	_, err = v.Verify(Evidence(make([]byte, 100)), Nonce(make([]byte, NonceMinBytes-1)))
	if err == nil {
		t.Fatal("expected nonce-too-short error")
	}
}

// TestAWSNitroVerifier_RejectsTooShortEvidence rejects malformed COSE.
func TestAWSNitroVerifier_RejectsTooShortEvidence(t *testing.T) {
	t.Parallel()
	v, err := NewAWSNitroVerifier(nil, Measurement{}, AWSNitroVerifierConfig{})
	if err != nil {
		t.Fatalf("constructor failed: %v", err)
	}
	_, err = v.Verify(Evidence(make([]byte, 32)), Nonce(make([]byte, NonceMinBytes)))
	if err == nil {
		t.Fatal("expected too-short error")
	}
}

// TestAWSNitroSealer_RejectsMissingKeyARN enforces required config.
func TestAWSNitroSealer_RejectsMissingKeyARN(t *testing.T) {
	t.Parallel()
	s := NewAWSNitroSealer("", "us-east-1", Measurement{})
	_, err := s.Seal([]byte("plaintext"), nil)
	if err == nil {
		t.Fatal("expected config error when kms_key_arn empty")
	}
}

// TestAWSNitroCapability_StableSignal produces the same answer twice.
func TestAWSNitroCapability_StableSignal(t *testing.T) {
	t.Parallel()
	a1, r1 := awsNitroCapability()
	a2, r2 := awsNitroCapability()
	if a1 != a2 || r1 != r2 {
		t.Errorf("capability check unstable: (%v,%q) vs (%v,%q)", a1, r1, a2, r2)
	}
}

// TestAWSNitro_InterfaceConformance — compile-time + runtime check.
func TestAWSNitro_InterfaceConformance(t *testing.T) {
	t.Parallel()
	var _ Producer = (*AWSNitroProducer)(nil)
	var _ Verifier = (*AWSNitroVerifier)(nil)
	var _ Sealer = (*AWSNitroSealer)(nil)
}
