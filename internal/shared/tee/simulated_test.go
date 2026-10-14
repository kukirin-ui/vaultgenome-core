// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

func newSim(t *testing.T) *Simulated {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize)
	s, err := NewSimulated([]byte("workload-v1"), seed)
	require.NoError(t, err)
	return s
}

// Every nonce in this file satisfies NonceMinBytes (16 B). That floor is
// part of the frozen R-10 interface contract (00_Bootstrap_Contracts_Doctrine
// §15), so the tests exercise the producer / verifier under the same
// discipline that a real TDX / SGX / SEV backend will be held to in V2.

func TestSimulated_Attest_RoundTrip(t *testing.T) {
	t.Parallel()
	s := newSim(t)
	v := NewSimulatedVerifier(s.PublicKey(), s.Measurement())

	nonce := Nonce([]byte("fresh-challenge-bytes-xyz"))
	ev, err := s.Quote(nonce)
	require.NoError(t, err)

	m, err := v.Verify(ev, nonce)
	require.NoError(t, err)
	require.Equal(t, s.Measurement(), m)
}

func TestSimulated_Attest_ReplayRejected(t *testing.T) {
	t.Parallel()
	s := newSim(t)
	v := NewSimulatedVerifier(s.PublicKey(), s.Measurement())

	ev, err := s.Quote(Nonce([]byte("nonce-A-0123456789ab")))
	require.NoError(t, err)

	// Verifier challenges with a different nonce — evidence no longer valid.
	_, err = v.Verify(ev, Nonce([]byte("nonce-B-0123456789ab")))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestSimulated_Attest_WrongMeasurementRejected(t *testing.T) {
	t.Parallel()
	s := newSim(t)
	// Verifier expects a different workload's measurement.
	expected := MeasurementOf([]byte("different-workload"))
	v := NewSimulatedVerifier(s.PublicKey(), expected)

	nonce := Nonce(bytes.Repeat([]byte{0xAB}, NonceMinBytes))
	ev, err := s.Quote(nonce)
	require.NoError(t, err)

	_, err = v.Verify(ev, nonce)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestSimulated_Attest_WrongAttestorRejected(t *testing.T) {
	t.Parallel()
	s1 := newSim(t)
	s2Seed := bytes.Repeat([]byte{0x17}, crypto.Ed25519SeedSize)
	s2, err := NewSimulated([]byte("workload-v1"), s2Seed)
	require.NoError(t, err)

	// Verifier accepts s2's public key but receives s1's evidence.
	v := NewSimulatedVerifier(s2.PublicKey(), s1.Measurement())
	nonce := Nonce(bytes.Repeat([]byte{0xCD}, NonceMinBytes))
	ev, err := s1.Quote(nonce)
	require.NoError(t, err)

	_, err = v.Verify(ev, nonce)
	require.Error(t, err)
}

func TestSimulated_Attest_TamperedEvidenceRejected(t *testing.T) {
	t.Parallel()
	s := newSim(t)
	v := NewSimulatedVerifier(s.PublicKey(), s.Measurement())
	nonce := Nonce([]byte("nonce-z-0123456789ab"))
	ev, err := s.Quote(nonce)
	require.NoError(t, err)

	tampered := append([]byte(nil), ev...)
	// Flip a byte in the signature region (tail).
	tampered[len(tampered)-1] ^= 0x01
	_, err = v.Verify(tampered, nonce)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// TestSimulated_Attest_ShortNonceRejected pins the iteration-5 R-10
// hardening: both the producer and the verifier reject nonces below
// NonceMinBytes Structurally, so a caller can never accidentally weaken
// replay protection by passing a truncated challenge.
func TestSimulated_Attest_ShortNonceRejected(t *testing.T) {
	t.Parallel()
	s := newSim(t)
	v := NewSimulatedVerifier(s.PublicKey(), s.Measurement())

	// Producer rejects under-length nonce.
	shortNonce := Nonce(bytes.Repeat([]byte{0x11}, NonceMinBytes-1))
	_, err := s.Quote(shortNonce)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// Build a legitimate quote first; then the verifier independently
	// rejects a same-length-but-too-short challenger nonce — this is the
	// defense-in-depth path.
	okNonce := Nonce(bytes.Repeat([]byte{0x22}, NonceMinBytes))
	ev, err := s.Quote(okNonce)
	require.NoError(t, err)

	_, err = v.Verify(ev, shortNonce)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestSimulated_Seal_RoundTrip(t *testing.T) {
	t.Parallel()
	s := newSim(t)
	pt := []byte("component-material")
	aad := []byte("session=S1;manifest=M1;component=C1")

	sealed, err := s.Seal(pt, aad)
	require.NoError(t, err)

	got, err := s.Unseal(sealed, aad)
	require.NoError(t, err)
	require.Equal(t, pt, got)
}

func TestSimulated_Unseal_WrongAADRejected(t *testing.T) {
	t.Parallel()
	s := newSim(t)
	sealed, err := s.Seal([]byte("pt"), []byte("aad-1"))
	require.NoError(t, err)
	_, err = s.Unseal(sealed, []byte("aad-2"))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestMeasurementOf_Deterministic(t *testing.T) {
	t.Parallel()
	m1 := MeasurementOf([]byte("x"))
	m2 := MeasurementOf([]byte("x"))
	require.Equal(t, m1, m2)

	m3 := MeasurementOf([]byte("y"))
	require.NotEqual(t, m1, m3)
}

func TestMeasurement_IsZero(t *testing.T) {
	t.Parallel()
	var zero Measurement
	require.True(t, zero.IsZero())

	m := MeasurementOf([]byte("anything"))
	require.False(t, m.IsZero())
}

func TestMeasurementFromBytes_ValidatesLength(t *testing.T) {
	t.Parallel()
	_, err := MeasurementFromBytes([]byte{0x01, 0x02})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	good := make([]byte, crypto.HashSize)
	_, err = MeasurementFromBytes(good)
	require.NoError(t, err)
}
