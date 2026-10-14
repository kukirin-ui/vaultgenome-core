// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package teeconformance

// NonceMinBytes is the minimum acceptable length of a challenge nonce.
// The floor (16 bytes / 128 bits) matches RFC 9334 §10.1 recommendations
// for remote-attestation evidence. See doc.go and ADR-0001 for the
// rationale.
//
// Conformant Producer.Quote and Verifier.Verify implementations MUST
// reject nonces shorter than this length. The conformance suite has
// dedicated sub-tests asserting both reject paths.
const NonceMinBytes = 16

// Measurement is the TEE's cryptographic measurement of the workload
// code running inside it — an SGX MRENCLAVE, an SEV-SNP MEASUREMENT, a
// Nitro PCR0. It is carried whole, at the length the hardware reports:
// 32 bytes (SHA-256), 48 bytes (SHA-384, as SEV-SNP and Nitro report)
// or 64 bytes (SHA-512). Conformance does not constrain how the value
// is computed — only that its length is one ValidMeasurementLen accepts
// and that the verifier returns exactly the bytes the producer declares.
// Truncating a measurement to fit a narrower type is non-conformant: it
// would let two different workloads share an identity (ADR 0007).
type Measurement []byte

// ValidMeasurementLen reports whether n is a measurement length the
// platform pins in full: 32, 48 or 64 bytes.
func ValidMeasurementLen(n int) bool {
	return n == 32 || n == 48 || n == 64
}

// Nonce is challenger-supplied fresh randomness. Producers bind it into
// the evidence so a verifier can confirm the quote is fresh, not a
// replay of a past attestation. The conformance suite supplies nonces
// of exactly NonceMinBytes bytes for the round-trip path and shorter
// nonces for the floor-rejection path.
type Nonce []byte

// Evidence is the opaque, TEE-signed blob a verifier inspects to decide
// whether the producer is a genuine TEE running the expected workload.
// The conformance suite treats evidence bytes as opaque — the only
// tampering test flips one byte at the end of the blob, on the
// assumption that real adapters end the evidence with a signature
// region that cannot tolerate any single-bit corruption.
type Evidence []byte

// Producer is the TEE-side capability of generating attestation evidence.
// Implementations issue a quote that authenticates the running workload
// under a challenger-supplied Nonce.
type Producer interface {
	// Quote returns Evidence that authenticates the current workload
	// under the given Nonce.
	Quote(nonce Nonce) (Evidence, error)

	// Measurement returns the measurement this Producer will attest to.
	// Returned value MUST be stable for the lifetime of the Producer
	// (no per-call recomputation).
	Measurement() Measurement
}

// Verifier is the challenger-side capability of validating Evidence and
// extracting the Measurement it attests to.
type Verifier interface {
	// Verify checks Evidence against Nonce and returns the Measurement
	// the TEE is attesting to. A failure (replay, tamper, malformed
	// evidence, measurement mismatch) MUST return a non-nil error.
	Verify(evidence Evidence, nonce Nonce) (Measurement, error)
}

// Sealer is the TEE-side capability of sealing a plaintext so that only
// this TEE, running the same measurement, can unseal it. Real hardware
// expresses this via a hardware sealing key; the contract requires
// that AAD is authenticated (mismatched AAD MUST fail unseal) and that
// every Seal call produces a fresh nonce so identical plaintext + AAD
// inputs produce distinct outputs.
type Sealer interface {
	// Seal authenticates aad and encrypts plaintext, returning an
	// opaque sealed blob. Each call MUST use a fresh nonce internally
	// (no AES-GCM nonce reuse).
	Seal(plaintext, aad []byte) (sealed []byte, err error)

	// Unseal reverses Seal. MUST return a non-nil error when:
	//   - aad differs from the original sealing-time AAD, or
	//   - the sealed blob has been truncated, modified, or comes from
	//     a different sealing identity.
	Unseal(sealed, aad []byte) (plaintext []byte, err error)
}

// ProducerFactory builds a fresh Producer + matching Verifier pair. The
// factory pattern is mandatory — sub-tests in RunProducerVerifierContract
// rely on cross-test isolation; sharing state between cases would
// mask bugs that only manifest on a fresh adapter instance.
type ProducerFactory func(t Tester) (Producer, Verifier)

// SealerFactory builds a Sealer plus a closure that constructs a SECOND
// Sealer with the same identity as the first (so cross-instance unseal
// can be exercised — real hardware models this explicitly: the
// hardware sealing key survives a process restart if the measurement
// is unchanged).
type SealerFactory func(t Tester) (Sealer, func(t Tester) Sealer)

// Tester is the subset of *testing.T this package needs. Defined as an
// interface so callers can substitute a stub in their own meta-tests
// or run the suite from non-testing contexts (e.g., a pre-flight check
// in an installer).
type Tester interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Fatal(args ...any)
}
