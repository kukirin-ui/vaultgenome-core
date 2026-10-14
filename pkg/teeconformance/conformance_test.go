// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package teeconformance_test

// Self-test for the conformance suite.
//
// Implements a minimal reference Producer/Verifier/Sealer trio using
// stdlib Ed25519 + AES-GCM, then runs the public RunProducerVerifierContract
// and RunSealerContract against it. A passing build is the first-line
// evidence that the suite itself is correctly wired — third-party
// adapter authors can read this file as a 100-line worked example of
// what a conformant TEE adapter looks like in code.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/vault-genome/vaultgenome-core/pkg/teeconformance"
)

// ---- reference adapter -----------------------------------------------------

type refProducer struct {
	measurement teeconformance.Measurement
	priv        ed25519.PrivateKey
}

type refVerifier struct {
	measurement teeconformance.Measurement
	pub         ed25519.PublicKey
}

type refSealer struct {
	key []byte // 32 bytes derived from the workload identity
}

const refMagic = "REF-CONFORMANCE-V1\x00"

// measure derives a reference measurement of the given width, the way
// hardware reports one: SHA-256 (32 bytes), SHA-384 (48, as SEV-SNP and
// Nitro) or SHA-512 (64).
func measure(width int, workload []byte) teeconformance.Measurement {
	switch width {
	case 48:
		m := sha512.Sum384(workload)
		return m[:]
	case 64:
		m := sha512.Sum512(workload)
		return m[:]
	default:
		m := sha256.Sum256(workload)
		return m[:]
	}
}

func newRefBackend(t testing.TB, label string, width int) (*refProducer, *refVerifier, *refSealer, func() *refSealer) {
	t.Helper()
	seed := sha256.Sum256([]byte("ref-seed-" + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	measurement := measure(width, []byte("ref-workload-"+label))

	keyDigest := sha256.Sum256(append([]byte("ref-sealing-key-"), measurement...))
	sealingKey := make([]byte, 32)
	copy(sealingKey, keyDigest[:])

	p := &refProducer{measurement: measurement, priv: priv}
	v := &refVerifier{measurement: measurement, pub: pub}
	s := &refSealer{key: sealingKey}
	rebuild := func() *refSealer { return &refSealer{key: append([]byte(nil), sealingKey...)} }
	return p, v, s, rebuild
}

// Quote produces evidence: refMagic || nonce-len(BE32) || nonce ||
// measurement-len(BE32) || measurement || ed25519(measurement || nonce).
func (p *refProducer) Quote(nonce teeconformance.Nonce) (teeconformance.Evidence, error) {
	if len(nonce) < teeconformance.NonceMinBytes {
		return nil, errors.New("ref: nonce below floor")
	}
	signedBlob := append(append([]byte(nil), p.measurement...), nonce...)
	sig := ed25519.Sign(p.priv, signedBlob)

	var buf bytes.Buffer
	buf.WriteString(refMagic)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(nonce)))
	buf.Write(n[:])
	buf.Write(nonce)
	binary.BigEndian.PutUint32(n[:], uint32(len(p.measurement)))
	buf.Write(n[:])
	buf.Write(p.measurement)
	buf.Write(sig)
	return buf.Bytes(), nil
}

func (p *refProducer) Measurement() teeconformance.Measurement {
	return p.measurement
}

func (v *refVerifier) Verify(ev teeconformance.Evidence, nonce teeconformance.Nonce) (teeconformance.Measurement, error) {
	if len(nonce) < teeconformance.NonceMinBytes {
		return nil, errors.New("ref: nonce below floor")
	}
	if len(ev) < len(refMagic)+4 || string(ev[:len(refMagic)]) != refMagic {
		return nil, errors.New("ref: not reference evidence")
	}
	rest := ev[len(refMagic):]
	field := func() ([]byte, bool) { // len(BE32) || bytes
		if len(rest) < 4 {
			return nil, false
		}
		n := uint64(binary.BigEndian.Uint32(rest))
		if uint64(len(rest)-4) < n {
			return nil, false
		}
		b := rest[4 : 4+n]
		rest = rest[4+n:]
		return b, true
	}
	gotNonce, ok1 := field()
	mBytes, ok2 := field()
	if !ok1 || !ok2 || len(rest) != ed25519.SignatureSize {
		return nil, errors.New("ref: truncated")
	}
	if !bytes.Equal(gotNonce, nonce) {
		return nil, errors.New("ref: nonce mismatch (replay?)")
	}
	signedBlob := append(append([]byte(nil), mBytes...), gotNonce...)
	if !ed25519.Verify(v.pub, signedBlob, rest) {
		return nil, errors.New("ref: signature invalid")
	}
	if !bytes.Equal(mBytes, v.measurement) {
		return nil, errors.New("ref: unexpected measurement")
	}
	return append(teeconformance.Measurement(nil), mBytes...), nil
}

func (s *refSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return append(nonce, ct...), nil
}

func (s *refSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("ref: sealed truncated")
	}
	nonce := sealed[:aead.NonceSize()]
	ct := sealed[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, aad)
}

// ---- conformance harness invocation ---------------------------------------

// The suite accepts every measurement width hardware reports.
func TestConformance_ReferenceBackend_ProducerVerifier(t *testing.T) {
	t.Parallel()
	for _, width := range []int{32, 48, 64} {
		t.Run(fmt.Sprintf("%d-byte measurement", width), func(t *testing.T) {
			t.Parallel()
			teeconformance.RunProducerVerifierContract(t, func(tt teeconformance.Tester) (teeconformance.Producer, teeconformance.Verifier) {
				gt, ok := tt.(*testing.T)
				if !ok {
					tt.Fatal("expected *testing.T")
				}
				p, v, _, _ := newRefBackend(gt, "prod-verifier", width)
				return p, v
			})
		})
	}
}

func TestConformance_ReferenceBackend_Sealer(t *testing.T) {
	t.Parallel()
	teeconformance.RunSealerContract(t, func(t teeconformance.Tester) (teeconformance.Sealer, func(t teeconformance.Tester) teeconformance.Sealer) {
		gt, ok := t.(*testing.T)
		if !ok {
			t.Fatal("expected *testing.T")
		}
		_, _, s, rebuild := newRefBackend(gt, "sealer", 32)
		rebuildAdapter := func(t teeconformance.Tester) teeconformance.Sealer {
			return rebuild()
		}
		return s, rebuildAdapter
	})
}

// TestConformance_DirectVerify confirms the reference adapter produces
// evidence the reference verifier accepts on the round-trip path
// outside of the conformance harness — a sanity check that the example
// is also a working example.
func TestConformance_DirectVerify(t *testing.T) {
	t.Parallel()
	p, v, _, _ := newRefBackend(t, "direct", 48)
	nonce := bytes.Repeat([]byte{0x42}, teeconformance.NonceMinBytes)
	ev, err := p.Quote(nonce)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	got, err := v.Verify(ev, nonce)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !bytes.Equal(got, p.Measurement()) || len(got) != 48 {
		t.Errorf("measurement mismatch: got %d bytes %x", len(got), got)
	}
}
