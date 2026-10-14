// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package teeconformance is the public conformance test harness for any
// Trusted Execution Environment (TEE) backend that wants to claim
// compatibility with the Vault Genome [Producer / Verifier / Sealer]
// interface contract.
//
// # Why this exists
//
// Vault Genome ships five reference TEE backends (AWS Nitro Enclaves,
// Azure Confidential Computing, GCP Confidential VMs, Intel SGX bare
// metal, and a software-only simulator) — see ADR-0001 and ADR-0002 in
// the docs/adr directory. The interface they satisfy is patentable IP;
// the conformance test suite is the executable definition of that
// interface.
//
// Third parties — security researchers, niche-TEE hardware vendors,
// application teams running Vault Genome on a future CPU generation
// (Intel TDX, AMD SEV-NP, ARM Realms, NVIDIA H100 confidential
// compute) — can drop their own adapter against the interfaces in
// this package, run the conformance suite, and surface a known answer
// to the question "is my adapter behaviourally equivalent to Vault
// Genome's reference backends?". Passing the suite is the only
// concrete claim of compatibility this project endorses.
//
// # How to use
//
// Implement the [Producer], [Verifier], and [Sealer] interfaces in
// your own package. Then in a Go test:
//
//	import "github.com/vault-genome/vaultgenome-core/pkg/teeconformance"
//
//	func TestMyAdapter_Conformance(t *testing.T) {
//	    teeconformance.RunProducerVerifierContract(t, func(t *testing.T) (teeconformance.Producer, teeconformance.Verifier) {
//	        // ... build a fresh producer + verifier pair for each subtest
//	        return myProducer, myVerifier
//	    })
//	    teeconformance.RunSealerContract(t, func(t *testing.T) (teeconformance.Sealer, func(t *testing.T) teeconformance.Sealer) {
//	        // ... build a fresh sealer + a "rebuild" closure that returns
//	        //     a sealer with the *same* identity (sealing key) so
//	        //     cross-instance unsealing can be exercised
//	        return mySealer, rebuildSealer
//	    })
//	}
//
// The factory closure pattern keeps each sub-test isolated — no shared
// state between cases, so a bug in case N+1 is not masked by case N.
//
// # What the contract guarantees
//
// Passing the suite proves your adapter satisfies, for the V1 frozen
// contract:
//
//   - Round-trip: every Quote can be Verified back to the producer's
//     Measurement, carried whole (32, 48 or 64 bytes).
//   - Replay protection: a fresh nonce is rejected if it doesn't match
//     the one bound into the evidence.
//   - Tamper rejection: a flipped byte in the signature region MUST
//     fail Verify.
//   - Nonce floor: producers and verifiers MUST reject nonces shorter
//     than NonceMinBytes (16 bytes / 128-bit RFC 9334 §10.1 floor).
//   - AAD binding: sealed material MUST not unseal under tampered AAD.
//   - Distinct nonce per seal: sealing the same plaintext + AAD twice
//     MUST produce distinct ciphertext (no AES-GCM nonce reuse).
//   - Truncation rejection: dropping the last byte of a sealed blob
//     MUST cause unseal to fail.
//
// Things the suite does NOT prove:
//
//   - Side-channel resistance of the underlying primitives.
//   - Correctness of the wire format the evidence happens to use.
//     Tests operate on opaque bytes; if your evidence is a CBOR
//     COSE_Sign1 doc and you mis-encode field 5, this suite won't
//     catch it. Wire-format conformance is a separate concern.
//   - Performance characteristics. Benchmarks live in your own
//     package; the conformance suite only checks correctness.
//
// # Versioning
//
// This package follows the V1 frozen contract — the test surface is
// deliberately stable across versions of the parent module. One
// amendment landed before the first tagged release: Measurement
// became a variable-length byte slice (ADR 0007), because a fixed
// 32-byte array could not carry the 48-byte measurements SEV-SNP and
// Nitro report. A future
// V2 contract amendment (only via ADR amendment) would land as
// teeconformance/v2 alongside this package; the V1 surface here will
// keep accepting V1-conformant adapters indefinitely.
package teeconformance
