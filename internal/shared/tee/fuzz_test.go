// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Native-Go fuzzing harnesses for the TEE parsers. The tests use Go
// 1.18+ `testing.F` so they run as ordinary unit tests in CI (with the
// minimal seed corpus) and can be exercised more deeply in
// developer / scheduled environments via `go test -fuzz=...`.
//
// Targets:
//
//   - FuzzSimulatedVerifier_Verify_NoPanic — verifier MUST never panic
//     regardless of input shape; either accept legitimate evidence or
//     return a typed error.
//   - FuzzSimulatedRoundTrip — Quote+Verify must round-trip cleanly
//     for every (workload-descriptor, seed, nonce) triple where the
//     nonce meets NonceMinBytes.
//   - FuzzFakeAttestation_Parse_NoPanic — the fake-hardware envelope
//     parser used by integration tests MUST also not panic on
//     adversarial bytes.
//
// Why fuzz parsers without real CBOR/COSE libraries? In Phase 2 the
// stub helpers (`parseCOSESign1`, `decodeNitroAttestationDoc`, …) get
// replaced by real CBOR + COSE + x509 parsing. Those will be the
// highest-risk parsers in the binary. We can't fuzz them today (no
// such code exists), but we CAN fuzz the parsers that *are* shipping
// today — the simulated verifier and the test envelope — to establish
// a CI rhythm for the project. When the real parsers land, adding
// additional fuzz targets is a one-line copy-paste of the pattern
// established here.

import (
	"bytes"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// FuzzSimulatedVerifier_Verify_NoPanic asserts the verifier never
// panics regardless of input. A crash here is a denial-of-service
// vector — an attacker who can submit attestation evidence to sagvd
// could otherwise crash the daemon.
func FuzzSimulatedVerifier_Verify_NoPanic(f *testing.F) {
	// Seed corpus: legitimate evidence + adversarial mutations.
	seed := bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize)
	sim, err := NewSimulated([]byte("fuzz-seed"), seed)
	if err != nil {
		f.Fatalf("seed setup: %v", err)
	}
	verifier := NewSimulatedVerifier(sim.PublicKey(), sim.Measurement())

	good, err := sim.Quote(bytes.Repeat([]byte{0xA1}, NonceMinBytes))
	if err != nil {
		f.Fatalf("seed quote: %v", err)
	}
	// f.Add accepts only primitive types (string / []byte / numeric);
	// tee.Evidence and tee.Nonce are aliases that the fuzzer rejects
	// even though they're []byte underneath. We pass plain []byte and
	// convert inside the fuzz function.
	f.Add([]byte(good), bytes.Repeat([]byte{0xA1}, NonceMinBytes))
	f.Add([]byte{}, []byte{})
	f.Add([]byte("SAGV-TEE-SIM-V1"), []byte{0xFF})
	// Truncated form right after the magic — exercises the
	// length-decode path.
	f.Add(append([]byte("SAGV-TEE-SIM-V1"), 0x00, 0x00, 0x00, 0x10), []byte{})

	f.Fuzz(func(t *testing.T, evidence []byte, nonce []byte) {
		// The verifier MUST NOT panic. Any error return is acceptable;
		// a panic is a fuzz-found bug.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Verify panicked: %v\nevidence=%x\nnonce=%x", r, evidence, nonce)
			}
		}()
		_, _ = verifier.Verify(Evidence(evidence), Nonce(nonce))
	})
}

// FuzzSimulatedRoundTrip asserts that for any legal nonce, the
// produced evidence round-trips through the verifier and recovers the
// expected measurement. Tests both the producer's framing and the
// verifier's parsing in a single closed loop.
func FuzzSimulatedRoundTrip(f *testing.F) {
	f.Add([]byte("workload-descriptor-α"), bytes.Repeat([]byte{0x01}, crypto.Ed25519SeedSize), bytes.Repeat([]byte{0xA1}, NonceMinBytes))
	f.Add([]byte(""), bytes.Repeat([]byte{0x55}, crypto.Ed25519SeedSize), bytes.Repeat([]byte{0xB2}, 32))
	f.Add([]byte{0xFF, 0xFE, 0xFD}, bytes.Repeat([]byte{0xC3}, crypto.Ed25519SeedSize), bytes.Repeat([]byte{0xC3}, NonceMinBytes))

	f.Fuzz(func(t *testing.T, descriptor, seed, nonce []byte) {
		// Constraints the API enforces — fuzzer skips inputs that
		// can't legally produce a round-trip.
		if len(seed) != crypto.Ed25519SeedSize {
			t.Skip("seed must be exactly 32 bytes")
		}
		if len(nonce) < NonceMinBytes {
			t.Skip("nonce below minimum")
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("round-trip panicked: %v\ndescriptor=%x\nseed=%x\nnonce=%x", r, descriptor, seed, nonce)
			}
		}()

		sim, err := NewSimulated(descriptor, seed)
		if err != nil {
			// Constructor failures are acceptable; fuzzer stops here.
			t.Skip(err.Error())
		}
		verifier := NewSimulatedVerifier(sim.PublicKey(), sim.Measurement())
		ev, err := sim.Quote(Nonce(nonce))
		if err != nil {
			t.Skip("Quote rejected legal-looking input: " + err.Error())
		}
		got, err := verifier.Verify(ev, Nonce(nonce))
		if err != nil {
			t.Fatalf("round-trip failed at Verify: %v", err)
		}
		if !got.Equal(sim.Measurement()) {
			t.Fatalf("measurement diverged: got %x want %x", got, sim.Measurement())
		}
	})
}

// FuzzFakeAttestation_Parse_NoPanic asserts the test-only fake
// envelope parser (used by integration_test.go to drive the
// Phase-2-stub TEE adapters) cannot be made to panic. Even though the
// fake never runs in production, hardening it ensures the test
// harness stays reliable under future schema evolution.
func FuzzFakeAttestation_Parse_NoPanic(f *testing.F) {
	fh := newFakeHardware(f, "fuzz-fake")
	good := fh.signAttestation("fuzz", make([]byte, NonceMinBytes), nil)

	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte("VG-FAKE-TEE-v1\x00"))                                 // magic only
	f.Add(append([]byte("VG-FAKE-TEE-v1\x00"), 0xFF, 0xFF, 0xFF, 0xFF)) // huge length declared
	f.Add(append([]byte("WRONG-MAGIC-XX-X\x00"), good[16:]...))         // mismatched magic

	f.Fuzz(func(t *testing.T, blob []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseAttestation panicked: %v\nblob=%x", r, blob)
			}
		}()
		_, _ = fh.parseAttestation(blob)
	})
}
