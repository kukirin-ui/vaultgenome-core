// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func x509MarshalPKIX(pub *rsa.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(pub) }
func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// azureCGPUFixture is a synthetic confidential GPU VM: an SNP report whose
// REPORT_DATA names a test vTPM attestation key, that key, and a fake
// NRAS. The AMD chain and the report signature are the real code paths
// with the network and the chip substituted.
type azureCGPUFixture struct {
	ak          *rsa.PrivateKey
	hcl         []byte
	measurement Measurement
	nras        *fakeNRAS
	now         time.Time
	chain       []byte
}

func newAzureCGPUFixture(t *testing.T) *azureCGPUFixture {
	t.Helper()
	chain, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", "hardware-test", "azure-sev-snp", "live-evidence", "cert_chain.pem"))
	if err != nil {
		t.Skip("azure live-evidence not present")
	}
	ak, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := base64.RawURLEncoding.EncodeToString(ak.PublicKey.N.Bytes())
	runtime, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{"kid": "HCLAkPub", "kty": "RSA", "e": "AQAB", "n": n, "key_ops": []string{"sign"}},
			{"kid": "HCLEkPub", "kty": "RSA", "e": "AQAB", "n": n, "key_ops": []string{"encrypt"}},
		},
		"vm-configuration": map[string]any{"secure-boot": true, "tpm-enabled": true},
		"user-data":        strings.Repeat("0", 128),
	})
	report := make([]byte, sevReportLen)
	binary.LittleEndian.PutUint32(report[0:], 3)                  // version 3
	binary.LittleEndian.PutUint64(report[sevOffPolicy:], 0x30000) // no DEBUG
	binary.LittleEndian.PutUint32(report[sevOffSigAlgo:], 1)
	sum := sha256.Sum256(runtime)
	copy(report[sevOffReportData:], sum[:])
	for i := range 48 {
		report[sevOffMeasurement+i] = byte(0xA0 + i)
	}
	binary.LittleEndian.PutUint64(report[sevOffReportedTCB:], 0x0B000000000000C0)
	report[sevOffCPUIDFam], report[sevOffCPUIDFam+1] = 0x19, 0x11 // Genoa
	for i := range 64 {
		report[sevOffChipID+i] = byte(i + 1)
	}
	var hcl []byte
	hcl = append(hcl, []byte("HCLA")...)
	hcl = append(hcl, make([]byte, hclHeaderLen-4)...)
	hcl = append(hcl, report...)
	rt := make([]byte, hclRuntimeHeaderLen)
	binary.LittleEndian.PutUint32(rt[0:], uint32(hclRuntimeHeaderLen+len(runtime)))
	binary.LittleEndian.PutUint32(rt[4:], hclRuntimeVersion)
	binary.LittleEndian.PutUint32(rt[8:], hclReportTypeSNP)
	binary.LittleEndian.PutUint32(rt[12:], hclHashTypeSHA256)
	binary.LittleEndian.PutUint32(rt[16:], uint32(len(runtime)))
	hcl = append(hcl, rt...)
	hcl = append(hcl, runtime...)
	m, _ := MeasurementFromBytes(report[sevOffMeasurement : sevOffMeasurement+48])
	return &azureCGPUFixture{ak: ak, hcl: hcl, measurement: m, nras: newFakeNRAS(t, "nv-eat-kid-test"), now: time.Date(2026, 9, 16, 14, 0, 0, 0, time.UTC), chain: chain}
}

// quote signs a TPM quote over PCRs with extraData under the test AK.
func (f *azureCGPUFixture) quote(t *testing.T, extraData []byte) (msg, sig []byte) {
	t.Helper()
	digest := sha256.Sum256([]byte("pcrs"))
	msg = buildTPMQuote(extraData, digest[:])
	sum := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.ak, crypto.SHA256, sum[:])
	require.NoError(t, err)
	return msg, sig
}

// evidence assembles the envelope a producer would for nonce.
func (f *azureCGPUFixture) evidence(t *testing.T, nonce []byte) Evidence {
	t.Helper()
	challenge := tpmQuoteExtraDataFor(nonce)
	msg, sig := f.quote(t, challenge[:])
	token := f.nras.response(t, hex.EncodeToString(challenge[:]), f.now)
	ev, err := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: f.hcl, QuoteMessage: msg, QuoteSignature: sig, GPUToken: token})
	require.NoError(t, err)
	return Evidence(ev)
}

// stubAMD makes the AMD side pass or fail without a chip or the network.
func stubAMD(t *testing.T, ok bool) {
	t.Helper()
	oldFetch, oldChain, oldSig := amdKDSGetVCEKFor, verifyAMDChain, verifySEVReportSignature
	t.Cleanup(func() { amdKDSGetVCEKFor, verifyAMDChain, verifySEVReportSignature = oldFetch, oldChain, oldSig })
	fetched := []string{}
	amdKDSGetVCEKFor = func(_ string, product string, _ [64]byte, _ uint64) ([]byte, error) {
		fetched = append(fetched, product)
		return []byte("vcek"), nil
	}
	verifyAMDChain = func(_ []byte, _ []byte) error { return nil }
	verifySEVReportSignature = func(_ *sevSNPReport, _ []byte) error {
		if ok {
			return nil
		}
		return errAzureTestSignature
	}
	t.Cleanup(func() {
		if len(fetched) > 0 {
			require.Equal(t, "Genoa", fetched[0], "the VCEK is asked of AMD KDS for the report's product")
		}
	})
}

var errAzureTestSignature = &testSignatureError{}

type testSignatureError struct{}

func (*testSignatureError) Error() string { return "ECDSA-P384 signature verification failed (test)" }

func azureCGPUVerifier(t *testing.T, f *azureCGPUFixture, mutate func(*AzureCGPUVerifierConfig)) *AzureCGPUVerifier {
	t.Helper()
	old := nrasHTTPGet
	t.Cleanup(func() { nrasHTTPGet = old })
	nrasHTTPGet = func(string) ([]byte, error) { return f.nras.jwks, nil }
	cfg := AzureCGPUVerifierConfig{AMDRootPEM: f.chain, VCEKCacheDir: t.TempDir(), NRASCacheDir: t.TempDir(), Now: func() time.Time { return f.now }}
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := NewAzureCGPUVerifier(nil, f.measurement, cfg)
	require.NoError(t, err)
	return v
}

func TestAzureCGPUVerifierAcceptsTheCompositeEvidence(t *testing.T) {
	f := newAzureCGPUFixture(t)
	stubAMD(t, true)
	v := azureCGPUVerifier(t, f, nil)
	nonce := Nonce("a return-path challenge, thirty-two bytes")
	verdict, err := v.VerifyEvidence(f.evidence(t, nonce), nonce)
	require.NoError(t, err)
	require.True(t, verdict.Measurement.Equal(f.measurement))
	require.Equal(t, "Genoa", verdict.Product)
	require.Len(t, verdict.GPUs, 1)
	require.Equal(t, "H100 NVL", verdict.GPUs[0].HWModel)
	require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7}, verdict.PCRSelections[0].PCRs)
	m, err := v.Verify(f.evidence(t, nonce), nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(f.measurement))
	_, err = os.Stat(filepath.Join(v.cfg.NRASCacheDir, "nras-jwks.json"))
	require.NoError(t, err, "NVIDIA's key set is kept")
}

func TestAzureCGPUVerifierRefusesWhatItShould(t *testing.T) {
	f := newAzureCGPUFixture(t)
	nonce := Nonce("a return-path challenge, thirty-two bytes")

	t.Run("a report the chip did not sign", func(t *testing.T) {
		stubAMD(t, false)
		_, err := azureCGPUVerifier(t, f, nil).Verify(f.evidence(t, nonce), nonce)
		require.ErrorContains(t, err, "report signature")
	})
	stubAMD(t, true)
	v := azureCGPUVerifier(t, f, nil)

	t.Run("another nonce", func(t *testing.T) {
		_, err := v.Verify(f.evidence(t, nonce), Nonce("some other challenge of enough bytes"))
		require.ErrorContains(t, err, "TPM quote does not bind challenger nonce")
	})
	t.Run("a quote by another key", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		challenge := tpmQuoteExtraDataFor(nonce)
		msg, _ := f.quote(t, challenge[:])
		sum := sha256.Sum256(msg)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, sum[:])
		ev, _ := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: f.hcl, QuoteMessage: msg, QuoteSignature: sig,
			GPUToken: f.nras.response(t, hex.EncodeToString(challenge[:]), f.now)})
		_, err := v.Verify(Evidence(ev), nonce)
		require.ErrorContains(t, err, "does not verify under the attestation key")
	})
	t.Run("runtime data the report does not vouch for", func(t *testing.T) {
		challenge := tpmQuoteExtraDataFor(nonce)
		msg, sig := f.quote(t, challenge[:])
		hcl := append([]byte(nil), f.hcl...)
		hcl[len(hcl)-5] ^= 0x01
		ev, _ := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: hcl, QuoteMessage: msg, QuoteSignature: sig,
			GPUToken: f.nras.response(t, hex.EncodeToString(challenge[:]), f.now)})
		_, err := v.Verify(Evidence(ev), nonce)
		require.ErrorContains(t, err, "not the SHA-256 of the runtime data")
	})
	t.Run("a GPU token for another challenge", func(t *testing.T) {
		challenge := tpmQuoteExtraDataFor(nonce)
		msg, sig := f.quote(t, challenge[:])
		ev, _ := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: f.hcl, QuoteMessage: msg, QuoteSignature: sig,
			GPUToken: f.nras.response(t, strings.Repeat("ab", 32), f.now)})
		_, err := v.Verify(Evidence(ev), nonce)
		require.ErrorContains(t, err, "replay")
	})
	t.Run("a GPU token NVIDIA did not sign", func(t *testing.T) {
		challenge := tpmQuoteExtraDataFor(nonce)
		msg, sig := f.quote(t, challenge[:])
		other := newFakeNRAS(t, "nv-eat-kid-test")
		ev, _ := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: f.hcl, QuoteMessage: msg, QuoteSignature: sig,
			GPUToken: other.response(t, hex.EncodeToString(challenge[:]), f.now)})
		_, err := v.Verify(Evidence(ev), nonce)
		require.ErrorContains(t, err, "GPU overall token")
	})
	t.Run("an expired GPU token", func(t *testing.T) {
		late := azureCGPUVerifier(t, f, func(c *AzureCGPUVerifierConfig) { c.Now = func() time.Time { return f.now.Add(3 * time.Hour) } })
		_, err := late.Verify(f.evidence(t, nonce), nonce)
		require.ErrorContains(t, err, "expired")
	})
	t.Run("a GPU the policy does not accept", func(t *testing.T) {
		strict := azureCGPUVerifier(t, f, func(c *AzureCGPUVerifierConfig) { c.GPU.AcceptableHWModels = []string{"H200"} })
		_, err := strict.Verify(f.evidence(t, nonce), nonce)
		require.ErrorContains(t, err, "hardware model")
	})
	t.Run("a PCR digest the policy does not name", func(t *testing.T) {
		pcrs := azureCGPUVerifier(t, f, func(c *AzureCGPUVerifierConfig) { c.AcceptablePCRDigests = [][]byte{make([]byte, 32)} })
		_, err := pcrs.Verify(f.evidence(t, nonce), nonce)
		require.ErrorContains(t, err, "PCR digest")
		digest := sha256.Sum256([]byte("pcrs"))
		pinned := azureCGPUVerifier(t, f, func(c *AzureCGPUVerifierConfig) { c.AcceptablePCRDigests = [][]byte{digest[:]} })
		_, err = pinned.Verify(f.evidence(t, nonce), nonce)
		require.NoError(t, err)
	})
	t.Run("a measurement not pinned", func(t *testing.T) {
		otherPin := make(Measurement, 48)
		w, err := NewAzureCGPUVerifier(nil, otherPin, AzureCGPUVerifierConfig{AMDRootPEM: f.chain, NRASCacheDir: v.cfg.NRASCacheDir, Now: v.cfg.Now})
		require.NoError(t, err)
		_, err = w.Verify(f.evidence(t, nonce), nonce)
		require.ErrorContains(t, err, "not in acceptable set")
	})
	t.Run("a debuggable guest", func(t *testing.T) {
		challenge := tpmQuoteExtraDataFor(nonce)
		msg, sig := f.quote(t, challenge[:])
		hcl := append([]byte(nil), f.hcl...)
		binary.LittleEndian.PutUint64(hcl[hclHeaderLen+sevOffPolicy:], 0x30000|sevPolicyDebug)
		ev, _ := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: hcl, QuoteMessage: msg, QuoteSignature: sig,
			GPUToken: f.nras.response(t, hex.EncodeToString(challenge[:]), f.now)})
		_, err := v.Verify(Evidence(ev), nonce)
		require.ErrorContains(t, err, "DEBUG")
	})
	t.Run("not an envelope", func(t *testing.T) {
		_, err := v.Verify(Evidence(f.hcl), nonce)
		require.ErrorContains(t, err, "envelope")
	})
	t.Run("no AMD chain, no verifier", func(t *testing.T) {
		_, err := NewAzureCGPUVerifier(nil, f.measurement, AzureCGPUVerifierConfig{})
		require.ErrorContains(t, err, "AMDRootPEM")
	})
}

func TestAzureCGPUProducerRunsTheToolsAndAssemblesTheEnvelope(t *testing.T) {
	f := newAzureCGPUFixture(t)
	stubAMD(t, true)
	akPEM := pemPublicKey(t, &f.ak.PublicKey)
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	var calls []string
	runCommand = func(_ time.Duration, argv ...string) ([]byte, error) {
		calls = append(calls, filepath.Base(argv[0]))
		switch filepath.Base(argv[0]) {
		case "tpm2_nvread":
			return f.hcl, nil
		case "tpm2_getcap":
			return []byte("- 0x81000000\n- 0x81000003\n"), nil
		case "tpm2_readpublic":
			handle := argv[2]
			out := argv[len(argv)-1]
			if handle == "0x81000003" {
				return nil, os.WriteFile(out, akPEM, 0o600)
			}
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			return nil, os.WriteFile(out, pemPublicKey(t, &other.PublicKey), 0o600)
		case "tpm2_quote":
			var msgPath, sigPath, q string
			for i := range argv {
				switch argv[i] {
				case "-m":
					msgPath = argv[i+1]
				case "-s":
					sigPath = argv[i+1]
				case "-q":
					q = argv[i+1]
				}
			}
			extra, _ := hex.DecodeString(q)
			msg, sig := f.quote(t, extra)
			require.NoError(t, os.WriteFile(msgPath, msg, 0o600))
			return nil, os.WriteFile(sigPath, sig, 0o600)
		case "gpu-token":
			return f.nras.response(t, argv[len(argv)-1], f.now), nil
		}
		return nil, os.ErrNotExist
	}
	p, err := NewAzureCGPUProducer(AzureCGPUProducerConfig{GPUAttestCommand: []string{"/usr/local/bin/gpu-token"}})
	require.NoError(t, err)
	require.Equal(t, "0x81000003", p.akHandle, "the persistent key that is HCLAkPub")
	require.True(t, p.Measurement().Equal(f.measurement))
	sel, digest := p.VTPMBoot()
	require.Equal(t, "sha256:0,1,2,3,4,5,6,7", sel[0].String())
	bootDigest := sha256.Sum256([]byte("pcrs"))
	require.Equal(t, bootDigest[:], digest, "what the vTPM measured of this boot, from the quote at construction")

	nonce := Nonce("a return-path challenge, thirty-two bytes")
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	v := azureCGPUVerifier(t, f, nil)
	verdict, err := v.VerifyEvidence(ev, nonce)
	require.NoError(t, err)
	require.Equal(t, "H100 NVL", verdict.GPUs[0].HWModel)
	require.Contains(t, calls, "tpm2_quote")
	require.Contains(t, calls, "gpu-token")

	require.NoError(t, p.Close())
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "closed")
	_, err = NewAzureCGPUProducer(AzureCGPUProducerConfig{})
	require.ErrorContains(t, err, "GPUAttestCommand")
}

func pemPublicKey(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := marshalPKIX(pub)
	require.NoError(t, err)
	return der
}

// marshalPKIX writes an RSA public key as tpm2_readpublic -f pem does.
func marshalPKIX(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509MarshalPKIX(pub)
	if err != nil {
		return nil, err
	}
	return pemEncode("PUBLIC KEY", der), nil
}
