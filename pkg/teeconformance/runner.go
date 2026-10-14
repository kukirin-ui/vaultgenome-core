// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package teeconformance

import (
	"bytes"
	"testing"
)

// RunProducerVerifierContract runs every Producer/Verifier sub-test
// against the supplied factory. Every sub-test gets a freshly-built
// pair, eliminating cross-test state leakage. Sub-tests are run in
// parallel via t.Parallel().
//
// Pass criteria:
//
//   - RoundTrip: producer.Quote → verifier.Verify returns the producer's
//     declared measurement.
//   - NonceFloor_Producer: producer rejects a nonce shorter than
//     NonceMinBytes.
//   - NonceFloor_Verifier: verifier rejects a nonce shorter than
//     NonceMinBytes (a defence-in-depth check; producer-side already
//     blocks the path, but verifiers MUST refuse to be the weak link).
//   - Replay: verify with a different nonce than the one the producer
//     bound MUST fail.
//   - Tamper: flipping the last byte of the evidence MUST cause Verify
//     to fail.
//   - MeasurementStability: the value returned by Verify MUST equal
//     producer.Measurement(), be 32, 48 or 64 bytes long, and not be
//     all zero.
func RunProducerVerifierContract(t *testing.T, newPair ProducerFactory) {
	t.Helper()

	t.Run("RoundTrip", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		nonce := bytes.Repeat([]byte{0xA1}, NonceMinBytes)

		ev, err := p.Quote(nonce)
		if err != nil {
			t.Fatalf("Quote: %v", err)
		}
		got, err := v.Verify(ev, nonce)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !bytes.Equal(got, p.Measurement()) {
			t.Errorf("verifier returned %x, producer claims %x", got, p.Measurement())
		}
	})

	t.Run("NonceFloor_Producer", func(t *testing.T) {
		t.Parallel()
		p, _ := newPair(t)
		short := bytes.Repeat([]byte{0xB2}, NonceMinBytes-1)
		_, err := p.Quote(short)
		if err == nil {
			t.Fatal("expected producer to reject short nonce")
		}
	})

	t.Run("NonceFloor_Verifier", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		// The Quote-side nonce is legal; the verifier-side nonce is not.
		good := bytes.Repeat([]byte{0xC3}, NonceMinBytes)
		ev, err := p.Quote(good)
		if err != nil {
			t.Fatalf("Quote: %v", err)
		}
		short := bytes.Repeat([]byte{0xD4}, NonceMinBytes-1)
		_, err = v.Verify(ev, short)
		if err == nil {
			t.Fatal("expected verifier to reject short nonce")
		}
	})

	t.Run("Replay", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		producerNonce := bytes.Repeat([]byte{0xE5}, NonceMinBytes)
		challengerNonce := bytes.Repeat([]byte{0xF6}, NonceMinBytes)
		ev, err := p.Quote(producerNonce)
		if err != nil {
			t.Fatalf("Quote: %v", err)
		}
		_, err = v.Verify(ev, challengerNonce)
		if err == nil {
			t.Fatal("expected replay rejection (nonce mismatch)")
		}
	})

	t.Run("Tamper", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		nonce := bytes.Repeat([]byte{0x07}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		if err != nil {
			t.Fatalf("Quote: %v", err)
		}
		tampered := append([]byte(nil), ev...)
		tampered[len(tampered)-1] ^= 0x01
		_, err = v.Verify(tampered, nonce)
		if err == nil {
			t.Fatal("expected tampered evidence to be rejected")
		}
	})

	t.Run("MeasurementStability", func(t *testing.T) {
		t.Parallel()
		p, v := newPair(t)
		nonce := bytes.Repeat([]byte{0x18}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		if err != nil {
			t.Fatalf("Quote: %v", err)
		}
		m, err := v.Verify(ev, nonce)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !ValidMeasurementLen(len(m)) {
			t.Errorf("verifier returned a %d-byte measurement; want 32, 48 or 64 bytes, carried whole", len(m))
		}
		if len(bytes.Trim(m, "\x00")) == 0 {
			t.Errorf("verifier returned an all-zero measurement")
		}
		if !bytes.Equal(m, p.Measurement()) {
			t.Errorf("Verify returned %x, want producer's %x", m, p.Measurement())
		}
	})
}

// RunSealerContract runs every Sealer sub-test against the supplied
// factory. Sub-tests cover:
//
//   - RoundTrip: Seal then Unseal returns the original plaintext.
//   - WrongAAD: unseal with mismatched AAD MUST fail.
//   - Tamper: flipping a byte in the ciphertext region MUST cause
//     unseal to fail.
//   - DistinctNoncePerSeal: sealing the same (pt, aad) twice MUST
//     produce distinct ciphertext (no nonce reuse).
//   - Truncation: dropping the last byte MUST cause unseal to fail.
//   - CrossInstance: a sealer rebuilt with the same identity MUST be
//     able to unseal blobs produced by the original (real hardware
//     property: sealing key survives process restart).
func RunSealerContract(t *testing.T, newPair SealerFactory) {
	t.Helper()

	t.Run("RoundTrip", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		pt := []byte("payload-alpha-01234567")
		aad := []byte("session=S;manifest=M;component=C")
		sealed, err := s.Seal(pt, aad)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		got, err := s.Unseal(sealed, aad)
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("plaintext mismatch")
		}
	})

	t.Run("WrongAAD", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		sealed, err := s.Seal([]byte("pt"), []byte("aad-correct"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		_, err = s.Unseal(sealed, []byte("aad-tampered"))
		if err == nil {
			t.Fatal("expected unseal to reject mismatched AAD")
		}
	})

	t.Run("Tamper", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		sealed, err := s.Seal(bytes.Repeat([]byte{0x5A}, 64), []byte("aad"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		tampered := append([]byte(nil), sealed...)
		tampered[len(tampered)/2] ^= 0x01
		_, err = s.Unseal(tampered, []byte("aad"))
		if err == nil {
			t.Fatal("expected unseal to reject tampered ciphertext")
		}
	})

	t.Run("DistinctNoncePerSeal", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		pt := []byte("same-plaintext")
		aad := []byte("same-aad")
		a, err := s.Seal(pt, aad)
		if err != nil {
			t.Fatalf("Seal a: %v", err)
		}
		b, err := s.Seal(pt, aad)
		if err != nil {
			t.Fatalf("Seal b: %v", err)
		}
		if bytes.Equal(a, b) {
			t.Errorf("identical ciphertext for identical inputs — likely AES-GCM nonce reuse")
		}
	})

	t.Run("Truncation", func(t *testing.T) {
		t.Parallel()
		s, _ := newPair(t)
		sealed, err := s.Seal([]byte("pt"), []byte("aad"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		_, err = s.Unseal(sealed[:len(sealed)-1], []byte("aad"))
		if err == nil {
			t.Fatal("expected unseal to reject truncated blob")
		}
	})

	t.Run("CrossInstance", func(t *testing.T) {
		t.Parallel()
		s, rebuild := newPair(t)
		pt := []byte("cross-instance-payload")
		aad := []byte("cross-instance-aad")
		sealed, err := s.Seal(pt, aad)
		if err != nil {
			t.Fatalf("original Seal: %v", err)
		}
		rebuilt := rebuild(t)
		got, err := rebuilt.Unseal(sealed, aad)
		if err != nil {
			t.Fatalf("rebuilt Unseal: %v (sealing key not stable across rebuild?)", err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("cross-instance unseal returned wrong plaintext")
		}
	})
}
