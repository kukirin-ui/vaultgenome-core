// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// makeSimulatedSpec builds a RegistrySpec for the simulator suitable
// for round-trip tests. The simulator is the only TEE backend that
// constructs without hardware; all other backends are exercised in
// integration tests gated by build tags.
func makeSimulatedSpec(t *testing.T, descriptor string) RegistrySpec {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	measurement := MeasurementOf([]byte(descriptor))
	return RegistrySpec{
		Provider: ProviderSimulated,
		Spec: VerifierSpec{
			Provider:            ProviderSimulated,
			AttestorPubKey:      pub,
			ExpectedMeasurement: measurement,
		},
	}
}

func TestRegistry_NewRegistry_HappyPath(t *testing.T) {
	t.Parallel()
	spec := makeSimulatedSpec(t, "vault-genome-test")
	r, err := NewRegistry([]RegistrySpec{spec})
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, 1, r.Len())
	require.True(t, r.Has(ProviderSimulated))
}

func TestRegistry_NewRegistry_EmptySpecList(t *testing.T) {
	t.Parallel()
	r, err := NewRegistry(nil)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, 0, r.Len())

	r2, err := NewRegistry([]RegistrySpec{})
	require.NoError(t, err)
	require.Equal(t, 0, r2.Len())
}

func TestRegistry_NewRegistry_DuplicateProviderRejected(t *testing.T) {
	t.Parallel()
	spec1 := makeSimulatedSpec(t, "vault-genome-test")
	spec2 := makeSimulatedSpec(t, "vault-genome-test-2")
	_, err := NewRegistry([]RegistrySpec{spec1, spec2})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.Contains(t, err.Error(), "duplicate provider")
}

func TestRegistry_NewRegistry_EmptyProviderRejected(t *testing.T) {
	t.Parallel()
	bad := RegistrySpec{
		Provider: "",
		Spec:     VerifierSpec{Provider: ""},
	}
	_, err := NewRegistry([]RegistrySpec{bad})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.Contains(t, err.Error(), "Provider is empty")
}

func TestRegistry_NewRegistry_ProviderMismatchRejected(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	// Outer Provider says Simulated; inner Spec.Provider says AWS Nitro.
	bad := RegistrySpec{
		Provider: ProviderSimulated,
		Spec: VerifierSpec{
			Provider:            ProviderAWSNitro,
			AttestorPubKey:      pub,
			ExpectedMeasurement: MeasurementOf([]byte("x")),
		},
	}
	_, err = NewRegistry([]RegistrySpec{bad})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.Contains(t, err.Error(), "does not match")
}

func TestRegistry_Resolve_Found(t *testing.T) {
	t.Parallel()
	spec := makeSimulatedSpec(t, "vault-genome-test")
	r, err := NewRegistry([]RegistrySpec{spec})
	require.NoError(t, err)

	v, err := r.Resolve(ProviderSimulated)
	require.NoError(t, err)
	require.NotNil(t, v)
}

func TestRegistry_Resolve_NotFound(t *testing.T) {
	t.Parallel()
	spec := makeSimulatedSpec(t, "vault-genome-test")
	r, err := NewRegistry([]RegistrySpec{spec})
	require.NoError(t, err)

	_, err = r.Resolve(ProviderAWSNitro)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.Contains(t, err.Error(), "not registered")
	require.Contains(t, err.Error(), string(ProviderSimulated)) // diagnostic lists available
}

func TestRegistry_Resolve_NilRegistry(t *testing.T) {
	t.Parallel()
	var r *Registry
	_, err := r.Resolve(ProviderSimulated)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestRegistry_Providers_StableSortedOrder(t *testing.T) {
	t.Parallel()
	// Build a registry with one entry; verify Providers() returns it.
	spec := makeSimulatedSpec(t, "vault-genome-test")
	r, err := NewRegistry([]RegistrySpec{spec})
	require.NoError(t, err)

	provs := r.Providers()
	require.Equal(t, []Provider{ProviderSimulated}, provs)

	// Calling Providers() multiple times returns identical results
	// (no map-iteration nondeterminism).
	for i := 0; i < 100; i++ {
		require.Equal(t, []Provider{ProviderSimulated}, r.Providers())
	}
}

func TestRegistry_Providers_NilRegistry(t *testing.T) {
	t.Parallel()
	var r *Registry
	require.Nil(t, r.Providers())
}

func TestRegistry_Has(t *testing.T) {
	t.Parallel()
	spec := makeSimulatedSpec(t, "vault-genome-test")
	r, err := NewRegistry([]RegistrySpec{spec})
	require.NoError(t, err)

	require.True(t, r.Has(ProviderSimulated))
	require.False(t, r.Has(ProviderAWSNitro))

	var nilReg *Registry
	require.False(t, nilReg.Has(ProviderSimulated))
}

func TestRegistry_Len(t *testing.T) {
	t.Parallel()
	r0, err := NewRegistry(nil)
	require.NoError(t, err)
	require.Equal(t, 0, r0.Len())

	spec := makeSimulatedSpec(t, "vault-genome-test")
	r1, err := NewRegistry([]RegistrySpec{spec})
	require.NoError(t, err)
	require.Equal(t, 1, r1.Len())

	var nilReg *Registry
	require.Equal(t, 0, nilReg.Len())
}

// TestRegistry_VerifierRoundTrip ensures the Verifier surfaced by the
// registry is the same one BuildVerifier produces, by exercising the
// happy-path Quote → Resolve → Verify cycle.
func TestRegistry_VerifierRoundTrip(t *testing.T) {
	t.Parallel()
	descriptor := []byte("vault-genome-roundtrip")
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	measurement := MeasurementOf(descriptor)

	// Build a Producer with the same key/measurement.
	producer, err := NewSimulated(descriptor, priv.Seed())
	require.NoError(t, err)

	// Sanity: the Producer should attest to the measurement we expect.
	require.Equal(t, measurement, producer.Measurement())

	// Build a Registry with a Verifier configured for that same measurement.
	rspec := RegistrySpec{
		Provider: ProviderSimulated,
		Spec: VerifierSpec{
			Provider:            ProviderSimulated,
			AttestorPubKey:      pub,
			ExpectedMeasurement: measurement,
		},
	}
	r, err := NewRegistry([]RegistrySpec{rspec})
	require.NoError(t, err)

	// Use the registered Verifier to validate Evidence.
	verifier, err := r.Resolve(ProviderSimulated)
	require.NoError(t, err)

	nonce := make([]byte, NonceMinBytes)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	evidence, err := producer.Quote(nonce)
	require.NoError(t, err)

	gotMeasurement, err := verifier.Verify(evidence, nonce)
	require.NoError(t, err)
	require.Equal(t, measurement, gotMeasurement)
}
