// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Reusable Producer / Verifier / Sealer contract test suite.
//
// Purpose (iteration 5 R-10 hardening — 00_Bootstrap_Contracts_Doctrine
// §15). The interface surface in /internal/shared/tee is explicitly
// frozen for the V1 MVP and for the V2 production backend. When the
// Stage D simulated backend is replaced by a real TDX / SGX / SEV
// implementation, the swap must be surgical: only the constructor
// changes, all call sites keep working. This file encodes the full
// contract so the V2 backend has a drop-in conformance harness: run
// RunProducerVerifierContract + RunSealerContract against the new
// backend and a passing build is the contract of the interface.
//
// The tests live in the _test package to exercise the interface from
// outside — mirroring how trust / keys / disclosure call into /shared/tee.
//
// Each sub-contract takes a factory closure instead of a concrete
// instance so that every case in the suite gets a FRESH backend; this
// prevents cross-test state leakage (e.g., a sealing-key cache) from
// masking a bug.

// producerFactory builds a Producer + the Verifier the challenger needs
// to check its Evidence. Separate from the production constructor so the
// factory can pre-wire whatever out-of-band trust the backend needs
// (public key + measurement for the simulator; real root-of-trust
// material for a TDX backend).
type producerFactory func(t *testing.T) (tee.Producer, tee.Verifier)

// sealerFactory builds a Sealer. Ciphertext produced by one Sealer must
// be openable by a second Sealer of the "same" backend identity — real
// TEEs model this explicitly (the hardware sealing key survives a reset
// if the measurement is unchanged). The factory therefore returns a
// builder too, so cross-instance unsealing can be exercised.
type sealerFactory func(t *testing.T) (tee.Sealer, func(t *testing.T) tee.Sealer)

// RunProducerVerifierContract runs every test that any Producer /
// Verifier pair must pass. Call this from the backend-specific _test.go.
// It is factored into sub-tests so a failing backend reports the exact
// case.
func RunProducerVerifierContract(t *testing.T, newPair producerFactory) {
	t.Helper()
	t.Run("RoundTrip", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		nonce := tee.Nonce(bytes.Repeat([]byte{0xA1}, tee.NonceMinBytes))

		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		m, err := v.Verify(ev, nonce)
		require.NoError(t, err)
		require.Equal(t, p.Measurement(), m)
	})

	t.Run("NonceMinBytes_ProducerRejectsShort", func(t *testing.T) {
		t.Parallel()
		p, _ := newPair(t)
		short := tee.Nonce(bytes.Repeat([]byte{0xB2}, tee.NonceMinBytes-1))
		_, err := p.Quote(short)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	})

	t.Run("NonceMinBytes_VerifierRejectsShort", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		// Producer-side nonce is legal; challenger-side nonce is not.
		goodNonce := tee.Nonce(bytes.Repeat([]byte{0xC3}, tee.NonceMinBytes))
		ev, err := p.Quote(goodNonce)
		require.NoError(t, err)
		short := tee.Nonce(bytes.Repeat([]byte{0xD4}, tee.NonceMinBytes-1))
		_, err = v.Verify(ev, short)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	})

	t.Run("ReplayRejected", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		n1 := tee.Nonce(bytes.Repeat([]byte{0xE5}, tee.NonceMinBytes))
		n2 := tee.Nonce(bytes.Repeat([]byte{0xF6}, tee.NonceMinBytes))
		ev, err := p.Quote(n1)
		require.NoError(t, err)
		_, err = v.Verify(ev, n2)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	})

	t.Run("TamperedEvidenceRejected", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		nonce := tee.Nonce(bytes.Repeat([]byte{0x07}, tee.NonceMinBytes))
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		// Tamper in the signature tail — the last byte is always part of
		// the signature regardless of the backend's concrete framing.
		tampered := append(tee.Evidence(nil), ev...)
		tampered[len(tampered)-1] ^= 0x01
		_, err = v.Verify(tampered, nonce)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	})

	t.Run("MeasurementMatchesProducer", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		nonce := tee.Nonce(bytes.Repeat([]byte{0x18}, tee.NonceMinBytes))
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		m, err := v.Verify(ev, nonce)
		require.NoError(t, err)
		require.False(t, m.IsZero(),
			"measurement returned by Verify must be populated")
		require.Equal(t, p.Measurement(), m,
			"measurement returned by Verify must match producer's claim")
	})
}

// RunSealerContract runs every test that any Sealer must pass. Callable
// from the backend-specific test file exactly like RunProducerVerifierContract.
func RunSealerContract(t *testing.T, newPair sealerFactory) {
	t.Helper()
	t.Run("RoundTrip", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		pt := []byte("payload-alpha-01234567")
		aad := []byte("session=S;manifest=M;component=C")
		sealed, err := s.Seal(pt, aad)
		require.NoError(t, err)
		got, err := s.Unseal(sealed, aad)
		require.NoError(t, err)
		require.Equal(t, pt, got)
	})

	t.Run("WrongAADRejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		sealed, err := s.Seal([]byte("pt"), []byte("aad-correct"))
		require.NoError(t, err)
		_, err = s.Unseal(sealed, []byte("aad-tampered"))
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	})

	t.Run("TamperedCiphertextRejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		sealed, err := s.Seal(bytes.Repeat([]byte{0x5A}, 64), []byte("aad"))
		require.NoError(t, err)
		// Flip a byte in the ciphertext region (past the nonce prefix).
		tampered := append([]byte(nil), sealed...)
		idx := len(tampered) / 2
		tampered[idx] ^= 0x01
		_, err = s.Unseal(tampered, []byte("aad"))
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	})

	t.Run("DistinctNoncePerSeal", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		pt := []byte("same-plaintext")
		aad := []byte("same-aad")
		a, err := s.Seal(pt, aad)
		require.NoError(t, err)
		b, err := s.Seal(pt, aad)
		require.NoError(t, err)
		// Sealing the same (pt, aad) twice MUST produce different bytes
		// (fresh nonce). A ciphertext collision here would be a
		// catastrophic nonce-reuse bug under AES-GCM.
		require.False(t, bytes.Equal(a, b),
			"Sealer must produce distinct ciphertext per call "+
				"(fresh nonce); identical output means nonce reuse")
	})

	t.Run("UnsealTruncatedRejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		sealed, err := s.Seal([]byte("pt"), []byte("aad"))
		require.NoError(t, err)
		// Drop the last byte — the resulting blob must not decrypt.
		_, err = s.Unseal(sealed[:len(sealed)-1], []byte("aad"))
		require.Error(t, err)
	})
}

// ---- Apply the contract to the Simulated backend ---------------------------

// These two entry points anchor the iteration-5 doctrine: the simulated
// backend is a first-class implementation of the frozen interface, and
// the same suite must also run (unchanged) against the V2 real-hardware
// backend the moment it lands. Adding a new backend means writing one
// new test file that calls these two functions with its own factory —
// nothing else changes.

func TestContract_Simulated_ProducerVerifier(t *testing.T) {
	t.Parallel()
	RunProducerVerifierContract(t, func(t *testing.T) (tee.Producer, tee.Verifier) {
		t.Helper()
		seed := bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize)
		s, err := tee.NewSimulated([]byte("contract-workload"), seed)
		require.NoError(t, err)
		v := tee.NewSimulatedVerifier(s.PublicKey(), s.Measurement())
		return s, v
	})
}

func TestContract_Simulated_Sealer(t *testing.T) {
	t.Parallel()
	RunSealerContract(t, func(t *testing.T) (tee.Sealer, func(t *testing.T) tee.Sealer) {
		t.Helper()
		seed := bytes.Repeat([]byte{0x55}, crypto.Ed25519SeedSize)
		s, err := tee.NewSimulated([]byte("contract-workload"), seed)
		require.NoError(t, err)
		rebuild := func(t *testing.T) tee.Sealer {
			t.Helper()
			s2, err := tee.NewSimulated([]byte("contract-workload"), seed)
			require.NoError(t, err)
			return s2
		}
		return s, rebuild
	})
}
