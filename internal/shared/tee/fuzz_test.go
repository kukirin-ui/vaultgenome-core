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
// The Nitro verifier's CBOR and COSE_Sign1 parsers (aws_nitro_cbor.go,
// aws_nitro_cose.go) are the first in-house parsers on the path an
// unauthenticated peer's bytes take before any signature is checked;
// FuzzCBORDecode_NoPanic and FuzzAWSNitroVerifier_Verify_NoPanic hold
// them to the same rule as the simulated verifier: any error, never a
// panic.

import (
	"bytes"
	"testing"
	"time"

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

// FuzzCBORDecode_NoPanic: the CBOR decoder returns an error or an item,
// never panics, and never reads past its input.
func FuzzCBORDecode_NoPanic(f *testing.F) {
	chain := newNitroTestChain(f, time.Now())
	good := chain.sign(f, nitroTestDoc{Nonce: bytes.Repeat([]byte{0xA1}, NonceMinBytes)})
	f.Add(good)
	f.Add(good[:len(good)/2])
	f.Add([]byte{})
	f.Add([]byte{0xd2, 0x84})             // tag 18, array of four, nothing after
	f.Add([]byte{0x9f, 0x01, 0xff})       // indefinite array
	f.Add([]byte{0xbf, 0x61, 0x61, 0x01}) // indefinite map
	f.Add([]byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // 2^64-1 byte string
	f.Add(bytes.Repeat([]byte{0x81}, 64))                               // deep nesting

	f.Fuzz(func(t *testing.T, in []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("cborDecode panicked: %v\nin=%x", r, in)
			}
		}()
		_, _ = cborDecode(in)
	})
}

// FuzzAWSNitroVerifier_Verify_NoPanic: the whole verifier — envelope,
// document, chain, signature, policy — on arbitrary bytes.
func FuzzAWSNitroVerifier_Verify_NoPanic(f *testing.F) {
	now := time.Now()
	chain := newNitroTestChain(f, now)
	nonce := bytes.Repeat([]byte{0xA1}, NonceMinBytes)
	pcr0 := nitroPCR("fuzz", 0)
	good := chain.sign(f, nitroTestDoc{Timestamp: now, Nonce: nonce, PCRs: map[int][]byte{0: pcr0}})
	v, err := NewAWSNitroVerifier(nil, pcr0, AWSNitroVerifierConfig{PinnedRoots: [][]byte{chain.rootDER}, Now: func() time.Time { return now }})
	if err != nil {
		f.Fatalf("verifier: %v", err)
	}
	if _, err := v.Verify(good, nonce); err != nil {
		f.Fatalf("seed must verify: %v", err)
	}
	f.Add(good, nonce)
	f.Add(good[:len(good)-1], nonce)
	f.Add(good, []byte{})
	f.Add(chain.sign(f, nitroTestDoc{Timestamp: now, DetachPayload: true}), nonce)
	f.Add(chain.sign(f, nitroTestDoc{Timestamp: now, ExtraField: true}), nonce)

	f.Fuzz(func(t *testing.T, evidence, nonce []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Verify panicked: %v\nevidence=%x\nnonce=%x", r, evidence, nonce)
			}
		}()
		_, _ = v.Verify(Evidence(evidence), Nonce(nonce))
	})
}
