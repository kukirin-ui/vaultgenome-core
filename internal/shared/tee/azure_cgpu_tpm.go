// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// A TPM 2.0 quote (TPM2_Quote): the TPMS_ATTEST structure the vTPM
// signs, read by its layout, and its signature checked under the
// attestation key. The caller's challenge rides in extraData; the PCRs
// quoted and their digest are recorded for the operator.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	tpmGeneratedValue = 0xFF544347 // TPM_GENERATED_VALUE
	tpmSTAttestQuote  = 0x8018     // TPM_ST_ATTEST_QUOTE
	tpmAlgSHA256      = 0x000B
	tpmAlgSHA384      = 0x000C
)

// tpmQuote is a parsed TPMS_ATTEST of type quote.
type tpmQuote struct {
	Raw             []byte
	QualifiedSigner []byte
	ExtraData       []byte
	Clock           uint64
	ResetCount      uint32
	RestartCount    uint32
	Safe            bool
	FirmwareVersion uint64
	PCRSelections   []tpmPCRSelection
	PCRDigest       []byte
}

// tpmPCRSelection is one bank of the quote's PCR selection.
type tpmPCRSelection struct {
	HashAlg uint16
	PCRs    []int
}

// String names the bank and its PCRs the way tpm2-tools does: sha256:0,1,2.
func (s tpmPCRSelection) String() string {
	name := fmt.Sprintf("alg-%#x", s.HashAlg)
	switch s.HashAlg {
	case tpmAlgSHA256:
		name = "sha256"
	case tpmAlgSHA384:
		name = "sha384"
	case 0x0004:
		name = "sha1"
	}
	parts := make([]string, len(s.PCRs))
	for i, p := range s.PCRs {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return name + ":" + strings.Join(parts, ",")
}

type tpmReader struct {
	b   []byte
	off int
	err error
}

func (r *tpmReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = fmt.Errorf("TPMS_ATTEST truncated at offset %d (need %d bytes)", r.off, n)
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}
func (r *tpmReader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *tpmReader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *tpmReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *tpmReader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *tpmReader) sized() []byte {
	n := r.u16()
	return append([]byte(nil), r.take(int(n))...)
}

// parseTPMQuote reads a TPMS_ATTEST and refuses anything but a quote.
func parseTPMQuote(msg []byte) (*tpmQuote, error) {
	r := &tpmReader{b: msg}
	q := &tpmQuote{Raw: append([]byte(nil), msg...)}
	if magic := r.u32(); r.err == nil && magic != tpmGeneratedValue {
		return nil, fmt.Errorf("TPMS_ATTEST magic %#x, want TPM_GENERATED_VALUE %#x: not produced by a TPM", magic, tpmGeneratedValue)
	}
	if typ := r.u16(); r.err == nil && typ != tpmSTAttestQuote {
		return nil, fmt.Errorf("TPMS_ATTEST type %#x, want TPM_ST_ATTEST_QUOTE %#x", typ, tpmSTAttestQuote)
	}
	q.QualifiedSigner = r.sized()
	q.ExtraData = r.sized()
	q.Clock = r.u64()
	q.ResetCount = r.u32()
	q.RestartCount = r.u32()
	q.Safe = r.u8() != 0
	q.FirmwareVersion = r.u64()
	count := r.u32()
	if r.err == nil && count > 16 {
		return nil, fmt.Errorf("TPML_PCR_SELECTION count %d", count)
	}
	for i := 0; i < int(count) && r.err == nil; i++ {
		sel := tpmPCRSelection{HashAlg: r.u16()}
		size := int(r.u8())
		bits := r.take(size)
		for byteIdx, b := range bits {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<bit) != 0 {
					sel.PCRs = append(sel.PCRs, byteIdx*8+bit)
				}
			}
		}
		q.PCRSelections = append(q.PCRSelections, sel)
	}
	q.PCRDigest = r.sized()
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(msg) {
		return nil, fmt.Errorf("TPMS_ATTEST has %d trailing bytes", len(msg)-r.off)
	}
	if len(q.PCRSelections) == 0 || len(q.PCRDigest) == 0 {
		return nil, errors.New("TPMS_ATTEST quotes no PCRs")
	}
	return q, nil
}

// verifyTPMQuoteSignature checks sig over SHA-256(msg) under the
// attestation key: RSASSA-PKCS1-v1_5 (the vTPM's default scheme), or
// RSASSA-PSS with the hash-length salt. A raw signature is expected (the
// bytes of the RSA signature, not a TPMT_SIGNATURE envelope).
func verifyTPMQuoteSignature(ak *rsa.PublicKey, msg, sig []byte) error {
	if ak == nil {
		return errors.New("no attestation key")
	}
	if len(sig) != ak.Size() {
		return fmt.Errorf("signature is %d bytes, the attestation key %d", len(sig), ak.Size())
	}
	digest := sha256.Sum256(msg)
	if rsa.VerifyPKCS1v15(ak, crypto.SHA256, digest[:], sig) == nil {
		return nil
	}
	if rsa.VerifyPSS(ak, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil {
		return nil
	}
	return errors.New("quote signature does not verify under the attestation key (RSASSA-PKCS1-v1_5 or RSASSA-PSS, SHA-256)")
}

// tpmQuoteExtraDataFor is what the producer puts in extraData and the
// verifier expects there: SHA-256(nonce), a fixed 32 bytes for a nonce of
// any length.
func tpmQuoteExtraDataFor(nonce []byte) [32]byte { return sha256.Sum256(nonce) }
