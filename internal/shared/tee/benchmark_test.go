// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Benchmarks for the simulated TEE backend's hot paths. Used by the
// Performance Regression CI workflow (.github/workflows/bench.yml) to
// detect when a refactor silently makes attestation, sealing, or
// unsealing measurably slower.
//
// The simulated backend is the only backend we can benchmark on a
// hosted CI runner — real-hardware backends require physical SGX /
// SEV / Nitro that we don't have until Phase 2 budget. The simulated
// backend is the upper-bound performance ceiling: real hardware
// adds 10-100× overhead from device ioctls and crypto-coprocessor
// round-trips, so a regression in simulated performance is likely a
// regression in production performance.

import (
	"bytes"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

func benchmarkSimulator(b *testing.B) (*Simulated, *SimulatedVerifier, []byte) {
	b.Helper()
	seed := bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize)
	sim, err := NewSimulated([]byte("benchmark-workload"), seed)
	if err != nil {
		b.Fatalf("NewSimulated: %v", err)
	}
	verifier := NewSimulatedVerifier(sim.PublicKey(), sim.Measurement())
	nonce := bytes.Repeat([]byte{0xA1}, NonceMinBytes)
	return sim, verifier, nonce
}

// BenchmarkSimulated_Quote — Producer.Quote hot path. Measures
// Ed25519 sign + framing of an attestation envelope.
func BenchmarkSimulated_Quote(b *testing.B) {
	sim, _, nonce := benchmarkSimulator(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sim.Quote(nonce)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSimulated_Verify — Verifier.Verify hot path. Measures
// Ed25519 verify + framing decode.
func BenchmarkSimulated_Verify(b *testing.B) {
	sim, verifier, nonce := benchmarkSimulator(b)
	ev, err := sim.Quote(nonce)
	if err != nil {
		b.Fatalf("Quote: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := verifier.Verify(ev, nonce)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSimulated_Seal — Sealer.Seal hot path with realistic
// 1 KB payload. AES-256-GCM throughput.
func BenchmarkSimulated_Seal_1KB(b *testing.B) {
	sim, _, _ := benchmarkSimulator(b)
	pt := bytes.Repeat([]byte{0x77}, 1024)
	aad := []byte("session=alpha;manifest=M;component=C")
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		_, err := sim.Seal(pt, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSimulated_Unseal_1KB — Sealer.Unseal hot path.
func BenchmarkSimulated_Unseal_1KB(b *testing.B) {
	sim, _, _ := benchmarkSimulator(b)
	pt := bytes.Repeat([]byte{0x77}, 1024)
	aad := []byte("session=alpha;manifest=M;component=C")
	sealed, err := sim.Seal(pt, aad)
	if err != nil {
		b.Fatalf("Seal: %v", err)
	}
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		_, err := sim.Unseal(sealed, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSimulated_Seal_64KB — sealing throughput at the larger
// payload size that sessions exchange.
func BenchmarkSimulated_Seal_64KB(b *testing.B) {
	sim, _, _ := benchmarkSimulator(b)
	pt := bytes.Repeat([]byte{0x55}, 64*1024)
	aad := []byte("session=beta;manifest=M;component=C")
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		_, err := sim.Seal(pt, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}
