// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"encoding/binary"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Simulated is a software emulation of a TEE. It is EXPLICITLY NOT a
// real TEE: the root of trust is an in-process Ed25519 key pair, not a
// hardware-protected key. It is suitable for doctrine demonstration, CI,
// and unit tests. It MUST NOT be used in production deployments — the
// production build plugs in a real TDX / SEV / SGX backend that implements
// the Producer / Verifier / Sealer interfaces.
//
// The `interface surface` is what persists across the MVP → production
// boundary.
type Simulated struct {
	measurement Measurement
	pub         crypto.PublicKey
	priv        crypto.PrivateKey
	sealingKey  []byte // 32 bytes, derived from measurement in MVP
}

// simulatedEvidence is the on-the-wire shape of simulated Evidence.
//
//	[0:32]                  measurement bytes
//	[32:32+len(nonce)]      nonce
//	[32+len(nonce):...]     Ed25519 signature over (measurement || nonce)
//
// Laid out explicitly so the verifier reads the same bytes the producer
// signs. The nonce length is encoded so framing is unambiguous.
const simulatedEvidenceMagic = "SAGV-TEE-SIM-V1"

// NewSimulated constructs a Simulated TEE with a deterministic
// measurement derived from workloadDescriptor. If seed is non-nil, the
// attestation signing key is deterministic — useful in tests.
func NewSimulated(workloadDescriptor []byte, seed []byte) (*Simulated, error) {
	m := MeasurementOf(workloadDescriptor)

	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	var err error
	if seed == nil {
		pub, priv, err = crypto.GenerateEd25519(nil)
	} else {
		if len(seed) != crypto.Ed25519SeedSize {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"tee: seed must be 32 bytes",
				nil,
			)
		}
		pub, priv, err = crypto.Ed25519FromSeed(seed)
	}
	if err != nil {
		return nil, err
	}

	// Derive a sealing key deterministically from the measurement. In the
	// real TEE this would be the hardware-unique sealing key; here we use
	// SHA-256(measurement || "sealing-key") which is explicitly weak (the
	// key is recoverable given the measurement) but preserves the shape
	// of the API.
	sealing := crypto.SHA256Slice(append(append([]byte(nil), m[:]...), []byte("sealing-key")...))

	return &Simulated{
		measurement: m,
		pub:         pub,
		priv:        priv,
		sealingKey:  sealing,
	}, nil
}

// PublicKey returns the Ed25519 public key that verifies this simulator's
// Evidence. A real verifier in production would get this through an
// out-of-band trust anchor (root of trust); the simulator exposes it
// directly.
func (s *Simulated) PublicKey() crypto.PublicKey {
	return s.pub
}

// Measurement returns the fixed measurement this simulator attests to.
func (s *Simulated) Measurement() Measurement {
	return s.measurement
}

// Quote implements Producer. The evidence is a simple framed structure:
// magic || nonce-length (4 bytes BE) || nonce || measurement || signature.
//
// Contract: nonce must carry at least NonceMinBytes of entropy. A shorter
// nonce is rejected Structurally so callers who wire a truncated
// challenge cannot accidentally weaken the replay bound.
func (s *Simulated) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"tee: nonce must be at least NonceMinBytes of entropy",
			nil,
		)
	}

	signedBlob := append(append([]byte(nil), s.measurement[:]...), nonce...)
	sig, err := crypto.Sign(s.priv, signedBlob)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteString(simulatedEvidenceMagic)
	var nlen [4]byte
	binary.BigEndian.PutUint32(nlen[:], uint32(len(nonce)))
	buf.Write(nlen[:])
	buf.Write(nonce)
	buf.Write(s.measurement[:])
	buf.Write(sig)
	return buf.Bytes(), nil
}

// Seal implements Sealer. AAD binds sealed material to external context
// (session, manifest, component identity).
func (s *Simulated) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce, ct, err := crypto.Seal(s.sealingKey, plaintext, aad, nil)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// Unseal reverses Seal.
func (s *Simulated) Unseal(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < crypto.GCMNonceSize+crypto.GCMTagSize {
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"tee: sealed blob too short",
			nil,
		)
	}
	nonce := sealed[:crypto.GCMNonceSize]
	ct := sealed[crypto.GCMNonceSize:]
	return crypto.Open(s.sealingKey, nonce, ct, aad)
}

// ---- simulated verifier ----------------------------------------------------

// SimulatedVerifier verifies Evidence produced by a specific Simulated
// instance. The verifier needs only the attestor's public key and the
// measurement it expects (the expected measurement acts as the policy
// "this code, and no other").
type SimulatedVerifier struct {
	attestorPub crypto.PublicKey
	expected    Measurement
}

// NewSimulatedVerifier builds a SimulatedVerifier.
func NewSimulatedVerifier(attestorPub crypto.PublicKey, expected Measurement) *SimulatedVerifier {
	return &SimulatedVerifier{attestorPub: attestorPub, expected: expected}
}

// Verify implements Verifier.
//
// Contract: the challenger-supplied nonce must itself meet NonceMinBytes.
// This is a defense-in-depth check: the Quote path already enforces the
// floor on the producer side, so a Verify-side violation means the
// challenger is re-using a degenerate nonce and must be stopped here.
// The bound is the same constant, so Producer and Verifier never drift.
func (v *SimulatedVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	var zero Measurement
	if len(nonce) < NonceMinBytes {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"tee: challenger nonce must be at least NonceMinBytes of entropy",
			nil,
		)
	}
	const magic = simulatedEvidenceMagic
	if len(ev) < len(magic)+4 {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"tee: evidence too short",
			nil,
		)
	}
	if string(ev[:len(magic)]) != magic {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"tee: evidence magic mismatch",
			nil,
		)
	}
	off := len(magic)
	nlen := binary.BigEndian.Uint32(ev[off : off+4])
	off += 4
	// Bounds check uses uint64 to defeat the uint32-overflow attack
	// that fuzzing surfaced (`nlen + HashSize + SigSize` wrapping
	// around uint32 to a small number when nlen is near 2^32-1, which
	// would let a crafted blob bypass the truncation check and crash
	// at the slice expression below).
	totalNeeded := uint64(nlen) + uint64(crypto.HashSize) + uint64(crypto.Ed25519SignatureSize)
	if nlen == 0 || uint64(len(ev)-off) < totalNeeded {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"tee: evidence truncated",
			nil,
		)
	}
	nonceBytes := ev[off : off+int(nlen)]
	off += int(nlen)
	mBytes := ev[off : off+crypto.HashSize]
	off += crypto.HashSize
	sig := ev[off : off+crypto.Ed25519SignatureSize]

	// Nonce must match challenger's nonce exactly.
	if !bytes.Equal(nonceBytes, nonce) {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"tee: evidence nonce mismatch (replay?)",
			nil,
		)
	}

	// Measurement must match expected.
	m := append(Measurement(nil), mBytes...)
	if !m.Equal(v.expected) {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"tee: measurement differs from expected (wrong workload)",
			nil,
		)
	}

	// Signature must verify under attestor public key.
	signed := append(append([]byte(nil), mBytes...), nonceBytes...)
	if err := crypto.Verify(v.attestorPub, signed, sig); err != nil {
		return zero, err
	}
	return m, nil
}

// Ensure Simulated satisfies Producer and Sealer at compile time.
var (
	_ Producer = (*Simulated)(nil)
	_ Sealer   = (*Simulated)(nil)
	_ Verifier = (*SimulatedVerifier)(nil)
)
