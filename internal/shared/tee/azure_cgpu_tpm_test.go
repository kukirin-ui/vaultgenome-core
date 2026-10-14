// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildTPMQuote marshals a TPMS_ATTEST of type quote over PCRs 0–7 of
// the SHA-256 bank with extraData, as a TPM would.
func buildTPMQuote(extraData []byte, pcrDigest []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, tpmGeneratedValue)
	b = binary.BigEndian.AppendUint16(b, tpmSTAttestQuote)
	signer := []byte{0x00, 0x0B, 1, 2, 3, 4}
	b = binary.BigEndian.AppendUint16(b, uint16(len(signer)))
	b = append(b, signer...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(extraData)))
	b = append(b, extraData...)
	b = binary.BigEndian.AppendUint64(b, 123456789) // clock
	b = binary.BigEndian.AppendUint32(b, 3)         // resetCount
	b = binary.BigEndian.AppendUint32(b, 0)         // restartCount
	b = append(b, 1)                                // safe
	b = binary.BigEndian.AppendUint64(b, 0x20240101)
	b = binary.BigEndian.AppendUint32(b, 1) // one selection
	b = binary.BigEndian.AppendUint16(b, tpmAlgSHA256)
	b = append(b, 3, 0xFF, 0x00, 0x00) // PCRs 0..7
	b = binary.BigEndian.AppendUint16(b, uint16(len(pcrDigest)))
	b = append(b, pcrDigest...)
	return b
}

func TestTPMQuoteParsesAndVerifiesUnderTheAttestationKey(t *testing.T) {
	ak, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	nonce := []byte("a challenge of at least sixteen bytes")
	extra := tpmQuoteExtraDataFor(nonce)
	digest := sha256.Sum256([]byte("pcrs"))
	msg := buildTPMQuote(extra[:], digest[:])
	q, err := parseTPMQuote(msg)
	require.NoError(t, err)
	require.Equal(t, extra[:], q.ExtraData)
	require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7}, q.PCRSelections[0].PCRs)
	require.Equal(t, uint16(tpmAlgSHA256), q.PCRSelections[0].HashAlg)
	require.Equal(t, digest[:], q.PCRDigest)
	require.True(t, q.Safe)

	sum := sha256.Sum256(msg)
	pkcs, err := rsa.SignPKCS1v15(rand.Reader, ak, crypto.SHA256, sum[:])
	require.NoError(t, err)
	require.NoError(t, verifyTPMQuoteSignature(&ak.PublicKey, msg, pkcs), "RSASSA-PKCS1-v1_5")
	pss, err := rsa.SignPSS(rand.Reader, ak, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	require.NoError(t, err)
	require.NoError(t, verifyTPMQuoteSignature(&ak.PublicKey, msg, pss), "RSASSA-PSS")

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	require.ErrorContains(t, verifyTPMQuoteSignature(&other.PublicKey, msg, pkcs), "does not verify")
	edited := append([]byte(nil), msg...)
	edited[10] ^= 0x01
	require.ErrorContains(t, verifyTPMQuoteSignature(&ak.PublicKey, edited, pkcs), "does not verify")
	require.ErrorContains(t, verifyTPMQuoteSignature(&ak.PublicKey, msg, pkcs[:100]), "signature is 100 bytes")
	require.ErrorContains(t, verifyTPMQuoteSignature(nil, msg, pkcs), "no attestation key")
}

func TestTPMQuoteRefusesWhatIsNotAQuote(t *testing.T) {
	extra := make([]byte, 32)
	msg := buildTPMQuote(extra, make([]byte, 32))
	notTPM := append([]byte(nil), msg...)
	binary.BigEndian.PutUint32(notTPM, 0x12345678)
	_, err := parseTPMQuote(notTPM)
	require.ErrorContains(t, err, "not produced by a TPM")

	certify := append([]byte(nil), msg...)
	binary.BigEndian.PutUint16(certify[4:], 0x8017) // TPM_ST_ATTEST_CERTIFY
	_, err = parseTPMQuote(certify)
	require.ErrorContains(t, err, "want TPM_ST_ATTEST_QUOTE")

	_, err = parseTPMQuote(msg[:20])
	require.ErrorContains(t, err, "truncated")

	_, err = parseTPMQuote(append(msg, 0))
	require.ErrorContains(t, err, "trailing")
}
