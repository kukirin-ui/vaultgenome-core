// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

func requireStructuralErr(t *testing.T, err error, fragment string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), "category of %v", err)
	require.ErrorContains(t, err, fragment)
}

func requireIntegrityErr(t *testing.T, err error, fragment string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err), "category of %v", err)
	require.ErrorContains(t, err, fragment)
}

// On a host without the hardware every producer refuses to start, and
// says what it needs.
func TestBuildProducerRefusesWithoutTheHardware(t *testing.T) {
	teeFakeMu.Lock()
	t.Cleanup(teeFakeMu.Unlock)
	absent := filepath.Join(t.TempDir(), "absent")

	_, err := BuildProducer(ProducerSpec{Provider: ProviderSimulated, SeedPath: "/etc/seed"})
	requireStructuralErr(t, err, "SeedBytes")
	_, err = BuildProducer(ProducerSpec{Provider: Provider("abacus")})
	requireStructuralErr(t, err, "unknown provider")

	_, err = BuildProducer(ProducerSpec{Provider: ProviderAWSNitro, AWSNitro: AWSNitroProducerConfig{UserData: make([]byte, 1025)}})
	requireStructuralErr(t, err, "user_data")
	_, err = BuildProducer(ProducerSpec{Provider: ProviderAWSNitro, AWSNitro: AWSNitroProducerConfig{NSMDevicePath: absent}})
	requireStructuralErr(t, err, "open NSM device")

	_, err = BuildProducer(ProducerSpec{Provider: ProviderAzureSGX})
	requireStructuralErr(t, err, "enclave_so_path")
	_, err = BuildProducer(ProducerSpec{Provider: ProviderAzureSGX, AzureSGX: AzureSGXProducerConfig{EnclaveSOPath: absent}})
	requireStructuralErr(t, err, "load enclave")

	_, err = BuildProducer(ProducerSpec{Provider: ProviderIntelSGXDCAP})
	requireStructuralErr(t, err, "enclave_so_path")
	_, err = BuildProducer(ProducerSpec{Provider: ProviderIntelSGXDCAP, IntelSGX: IntelSGXProducerConfig{EnclaveSOPath: absent}})
	requireStructuralErr(t, err, "load enclave")

	_, err = BuildProducer(ProducerSpec{Provider: ProviderGCPSEVSNP, GCPSEV: GCPSEVProducerConfig{VMPL: 4}})
	requireStructuralErr(t, err, "vmpl")
	_, err = BuildProducer(ProducerSpec{Provider: ProviderGCPSEVSNP, GCPSEV: GCPSEVProducerConfig{TSMReportDir: absent}})
	requireStructuralErr(t, err, "configfs-tsm")

	_, err = BuildProducer(ProducerSpec{Provider: ProviderGCPTDX, GCPTDX: GCPTDXProducerConfig{TSMReportDir: absent}})
	requireStructuralErr(t, err, "configfs-tsm")

	_, err = BuildProducer(ProducerSpec{Provider: ProviderAzureCGPU})
	requireStructuralErr(t, err, "GPUAttestCommand")
	_, err = BuildProducer(ProducerSpec{Provider: ProviderAzureCGPU, AzureCGPU: AzureCGPUProducerConfig{GPUAttestCommand: []string{"gpu-token"}, TPM2ToolsDir: absent, Timeout: time.Second}})
	require.ErrorContains(t, err, "HCL report")
}

func TestBuildVerifierRefusesWhatItCannotConfigure(t *testing.T) {
	m := make(Measurement, 48)
	_, err := BuildVerifier(VerifierSpec{Provider: Provider("abacus")})
	requireStructuralErr(t, err, "unknown provider")
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderAzureSGX, ExpectedMeasurement: m})
	requireStructuralErr(t, err, "maa_endpoint")
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderAzureSGX, ExpectedMeasurement: m, AzureSGX: AzureSGXVerifierConfig{Mode: AzureSGXModeDCAP}})
	requireStructuralErr(t, err, "pccs_url")
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderIntelSGXDCAP, ExpectedMeasurement: m})
	requireStructuralErr(t, err, "pccs_url")
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderAzureCGPU, ExpectedMeasurement: m})
	requireStructuralErr(t, err, "AMDRootPEM")
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderGCPTDX, ExpectedMeasurement: m, GCPTDX: GCPTDXVerifierConfig{AcceptableTCBStatuses: []string{"Nonsense"}}})
	requireStructuralErr(t, err, "unknown TCB status")
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderGCPTDX, ExpectedMeasurement: m, GCPTDX: GCPTDXVerifierConfig{AcceptableTCBStatuses: []string{TCBOutOfDate}}})
	requireStructuralErr(t, err, "never accepted")
	_, err = BuildVerifier(VerifierSpec{Provider: ProviderGCPTDX, ExpectedMeasurement: m, GCPTDX: GCPTDXVerifierConfig{IntelRootPEM: []byte("junk")}})
	requireStructuralErr(t, err, "Intel root PEM")

	for _, p := range []Provider{ProviderSimulated, ProviderAWSNitro, ProviderGCPSEVSNP, ProviderGCPTDX} {
		v, err := BuildVerifier(VerifierSpec{Provider: p, ExpectedMeasurement: m, AzureSGX: AzureSGXVerifierConfig{MAAEndpoint: "https://maa.example"}})
		require.NoError(t, err, p)
		require.NotNil(t, v, p)
	}
	v, err := BuildVerifier(VerifierSpec{Provider: ProviderAzureSGX, ExpectedMeasurement: m, AzureSGX: AzureSGXVerifierConfig{MAAEndpoint: "https://maa.example"}})
	require.NoError(t, err)
	require.NotNil(t, v)
	v, err = BuildVerifier(VerifierSpec{Provider: ProviderIntelSGXDCAP, ExpectedMeasurement: m, IntelSGX: IntelSGXVerifierConfig{PCCSURL: "https://pccs.example"}})
	require.NoError(t, err)
	require.NotNil(t, v)
}

// Capability answers from what the host has; this test asks the host the
// same question so it holds on a laptop, in CI and inside a Confidential VM.
func TestCapabilityReportsWhatTheHostHas(t *testing.T) {
	exists := func(paths ...string) bool {
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return true
			}
		}
		return false
	}
	ok, reason := Capability(ProviderSimulated)
	require.True(t, ok)
	require.Contains(t, reason, "simulated")
	ok, reason = Capability(Provider("abacus"))
	require.False(t, ok)
	require.Contains(t, reason, "unknown provider")
	rows := []struct {
		provider Provider
		present  bool
		label    string
	}{
		{ProviderAWSNitro, exists("/dev/nsm"), "AWS Nitro"},
		{ProviderAzureSGX, exists("/dev/sgx_enclave", "/dev/isgx"), "Azure SGX"},
		{ProviderIntelSGXDCAP, exists("/dev/sgx_enclave", "/dev/isgx"), "Intel SGX"},
		{ProviderGCPSEVSNP, exists(DefaultTSMReportDir), "GCP SEV-SNP"},
		{ProviderGCPTDX, exists(DefaultTSMReportDir), "GCP TDX"},
	}
	for _, row := range rows {
		ok, reason := Capability(row.provider)
		require.Equal(t, row.present, ok, "%s: %s", row.provider, reason)
		require.Contains(t, reason, row.label)
	}
	ok, reason = Capability(ProviderAzureCGPU)
	require.Contains(t, reason, "Azure confidential GPU")
	if !exists("/dev/tpmrm0") {
		require.False(t, ok)
		require.Contains(t, reason, "tpmrm0")
	}
}

func TestRegistryRefusesAVerifierItCannotBuild(t *testing.T) {
	m := make(Measurement, 48)
	_, err := NewRegistry([]RegistrySpec{{Provider: "", Spec: VerifierSpec{}}})
	requireStructuralErr(t, err, "Provider is empty")
	_, err = NewRegistry([]RegistrySpec{{Provider: ProviderSimulated, Spec: VerifierSpec{Provider: ProviderAWSNitro}}})
	requireStructuralErr(t, err, "does not match")
	_, err = NewRegistry([]RegistrySpec{{Provider: ProviderAzureCGPU, Spec: VerifierSpec{Provider: ProviderAzureCGPU, ExpectedMeasurement: m}}})
	requireStructuralErr(t, err, "BuildVerifier failed")
	sim := RegistrySpec{Provider: ProviderSimulated, Spec: VerifierSpec{Provider: ProviderSimulated, ExpectedMeasurement: m}}
	_, err = NewRegistry([]RegistrySpec{sim, sim})
	requireStructuralErr(t, err, "duplicate provider")
	r, err := NewRegistry([]RegistrySpec{sim, {Provider: ProviderAWSNitro, Spec: VerifierSpec{Provider: ProviderAWSNitro, ExpectedMeasurement: m}}})
	require.NoError(t, err)
	require.Equal(t, []Provider{ProviderAWSNitro, ProviderSimulated}, r.Providers())
	require.True(t, r.Has(ProviderSimulated))
	require.False(t, r.Has(ProviderGCPTDX))
	require.Equal(t, 2, r.Len())
}

// Until a hardware backend is wired, every seam refuses with a message that
// names the work left, so no attestation can pass by default.
func TestUnwiredSeamsFailClosed(t *testing.T) {
	teeFakeMu.Lock()
	t.Cleanup(teeFakeMu.Unlock)
	refusals := map[string]func() error{
		"nsmDescribePCR":            func() error { _, err := nsmDescribePCR(nil, 0); return err },
		"nsmGetAttestationDoc":      func() error { _, err := nsmGetAttestationDoc(nil, nsmAttestationRequest{}); return err },
		"awsKMSEncrypt":             func() error { _, err := awsKMSEncrypt("", "", nil, nil); return err },
		"awsKMSDecrypt":             func() error { _, err := awsKMSDecrypt("", "", nil, nil); return err },
		"parseCOSESign1":            func() error { _, err := parseCOSESign1(nil); return err },
		"decodeNitroAttestationDoc": func() error { _, err := decodeNitroAttestationDoc(nil); return err },
		"verifyNitroCertChain":      func() error { _, err := verifyNitroCertChain(nil, nil, nil); return err },
		"verifyCOSESignature":       func() error { return verifyCOSESignature(nil, nil) },
		"sgxCreateEnclave":          func() error { _, err := sgxCreateEnclave(""); return err },
		"sgxDestroyEnclave":         func() error { return sgxDestroyEnclave(0) },
		"sgxGetMREnclave":           func() error { _, err := sgxGetMREnclave(0); return err },
		"sgxECallCreateReport":      func() error { _, err := sgxECallCreateReport(0, nil); return err },
		"dcapGetQuote":              func() error { _, err := dcapGetQuote(nil); return err },
		"dcapVerifyQuote":           func() error { _, err := dcapVerifyQuote(nil, nil); return err },
		"pccsFetchCollateral":       func() error { _, err := pccsFetchCollateral("", nil); return err },
		"sgxECallSealData":          func() error { _, err := sgxECallSealData(0, nil, nil, SGXSealMRENCLAVE); return err },
		"sgxECallUnsealData":        func() error { _, err := sgxECallUnsealData(0, nil, nil); return err },
		"maaSubmitQuote":            func() error { _, err := maaSubmitQuote("", nil, nil); return err },
		"verifyMAAJWT":              func() error { _, err := verifyMAAJWT(nil, nil, 0); return err },
		"httpGetWithCacheBust":      func() error { _, err := httpGetWithCacheBust(""); return err },
		"hsmWrap":                   func() error { _, err := hsmWrap("", nil); return err },
		"hsmUnwrap":                 func() error { _, err := hsmUnwrap("", nil); return err },
	}
	for name, call := range refusals {
		err := call()
		require.Error(t, err, name)
		require.Contains(t, err.Error(), "not yet wired", name)
	}
	require.False(t, isKMSAccessDenied(errors.New("anything")), "without the SDK no error is read as a KMS denial")
}

func TestAWSNitroProducerVerifierAndSealerRefusals(t *testing.T) {
	fh := newFakeHardware(t, "nitro-refusals")
	installAWSNitroFake(t, fh)
	nonce := Nonce("a thirty-two byte challenger nonce!")

	t.Run("producer construction", func(t *testing.T) {
		describe := nsmDescribePCR
		nsmDescribePCR = func(*os.File, int) ([]byte, error) { return nil, errors.New("pcr unavailable") }
		_, err := NewAWSNitroProducer(AWSNitroProducerConfig{})
		require.ErrorContains(t, err, "read PCR0")
		nsmDescribePCR = func(*os.File, int) ([]byte, error) { return make([]byte, 16), nil }
		_, err = NewAWSNitroProducer(AWSNitroProducerConfig{})
		requireIntegrityErr(t, err, "PCR0 shorter than 32 bytes")
		nsmDescribePCR = describe
	})

	p, err := NewAWSNitroProducer(AWSNitroProducerConfig{UserData: []byte("sagvd")})
	require.NoError(t, err)
	require.True(t, p.Measurement().Equal(fh.measure))
	_, err = p.Quote(Nonce("short"))
	requireStructuralErr(t, err, "nonce")
	getDoc := nsmGetAttestationDoc
	nsmGetAttestationDoc = func(*os.File, nsmAttestationRequest) ([]byte, error) { return nil, errors.New("nsm busy") }
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "NSM_GET_ATTESTATION_DOC")
	nsmGetAttestationDoc = getDoc
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	require.NoError(t, p.Close())
	require.NoError(t, p.Close(), "closing twice is harmless")
	_, err = p.Quote(nonce)
	requireStructuralErr(t, err, "closed")

	v, err := NewAWSNitroVerifier(nil, fh.measure, AWSNitroVerifierConfig{})
	require.NoError(t, err)
	m, err := v.Verify(ev, nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(fh.measure))

	t.Run("verifier", func(t *testing.T) {
		_, err := v.Verify(ev, Nonce("short"))
		requireStructuralErr(t, err, "nonce")
		_, err = v.Verify(ev[:10], nonce)
		requireIntegrityErr(t, err, "too short")
		_, err = v.Verify(bytes.Repeat([]byte{7}, 100), nonce)
		requireIntegrityErr(t, err, "parse COSE_Sign1")
		_, err = v.Verify(ev, Nonce("another thirty-two byte challenge!!"))
		requireIntegrityErr(t, err, "nonce")

		decode := decodeNitroAttestationDoc
		t.Cleanup(func() { decodeNitroAttestationDoc = decode })
		decodeNitroAttestationDoc = func([]byte) (*nitroAttestationDoc, error) { return nil, errors.New("cbor broken") }
		_, err = v.Verify(ev, nonce)
		requireIntegrityErr(t, err, "decode attestation doc")
		edit := func(f func(d *nitroAttestationDoc)) {
			decodeNitroAttestationDoc = func(b []byte) (*nitroAttestationDoc, error) {
				d, err := decode(b)
				if err != nil {
					return nil, err
				}
				f(d)
				return d, nil
			}
		}
		edit(func(d *nitroAttestationDoc) { d.Timestamp = d.Timestamp.Add(-time.Hour) })
		_, err = v.Verify(ev, nonce)
		requireIntegrityErr(t, err, "timestamp skew")
		edit(func(d *nitroAttestationDoc) { d.PCRs = map[int][]byte{0: make([]byte, 32)} })
		_, err = v.Verify(ev, nonce)
		requireIntegrityErr(t, err, "debug-mode")
		edit(func(d *nitroAttestationDoc) { d.PCRs = map[int][]byte{0: bytes.Repeat([]byte{1}, 10)} })
		_, err = v.Verify(ev, nonce)
		requireIntegrityErr(t, err, "unexpected PCR0 length")
		decodeNitroAttestationDoc = decode

		chain := verifyNitroCertChain
		verifyNitroCertChain = func([]byte, [][]byte, [][]byte) ([]byte, error) { return nil, errors.New("unknown root") }
		_, err = v.Verify(ev, nonce)
		requireIntegrityErr(t, err, "cert chain")
		verifyNitroCertChain = chain
		cose := verifyCOSESignature
		verifyCOSESignature = func(*coseSign1, []byte) error { return errors.New("bad signature") }
		_, err = v.Verify(ev, nonce)
		requireIntegrityErr(t, err, "COSE signature")
		verifyCOSESignature = cose

		pcr7, err := NewAWSNitroVerifier(nil, fh.measure, AWSNitroVerifierConfig{PCRIndex: 7})
		require.NoError(t, err)
		_, err = pcr7.Verify(ev, nonce)
		requireIntegrityErr(t, err, "missing PCR7")
		other, err := NewAWSNitroVerifier(nil, MeasurementOf([]byte("another workload")), AWSNitroVerifierConfig{})
		require.NoError(t, err)
		_, err = other.Verify(ev, nonce)
		requireIntegrityErr(t, err, "not in acceptable set")
	})

	t.Run("sealer", func(t *testing.T) {
		unconfigured := NewAWSNitroSealer("", "us-east-1", fh.measure)
		_, err := unconfigured.Seal([]byte("k"), nil)
		requireStructuralErr(t, err, "kms_key_arn")
		_, err = unconfigured.Unseal([]byte("k"), nil)
		requireStructuralErr(t, err, "kms_key_arn")

		s := NewAWSNitroSealer("arn:aws:kms:us-east-1:1:key/2", "us-east-1", fh.measure)
		sealed, err := s.Seal([]byte("the key"), []byte("aad"))
		require.NoError(t, err)
		opened, err := s.Unseal(sealed, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, []byte("the key"), opened)
		_, err = s.Unseal(sealed[:3], []byte("aad"))
		requireIntegrityErr(t, err, "KMS denied")

		encrypt, decrypt := awsKMSEncrypt, awsKMSDecrypt
		t.Cleanup(func() { awsKMSEncrypt, awsKMSDecrypt = encrypt, decrypt })
		awsKMSEncrypt = func(string, string, []byte, map[string]string) ([]byte, error) { return nil, errors.New("throttled") }
		_, err = s.Seal([]byte("k"), nil)
		require.ErrorContains(t, err, "KMS Encrypt")
		awsKMSDecrypt = func(string, string, []byte, map[string]string) ([]byte, error) { return nil, errors.New("throttled") }
		_, err = s.Unseal(sealed, []byte("aad"))
		require.ErrorContains(t, err, "KMS Decrypt")
	})

	require.True(t, nonceMatches([]byte("ab"), []byte("ab")))
	require.False(t, nonceMatches([]byte("ab"), []byte("abc")))
	require.True(t, isDebugAttestation(nil))
	require.True(t, isDebugAttestation(&nitroAttestationDoc{}))
	require.True(t, isDebugAttestation(&nitroAttestationDoc{PCRs: map[int][]byte{0: make([]byte, 48)}}))
	require.False(t, isDebugAttestation(&nitroAttestationDoc{PCRs: map[int][]byte{0: {0, 1}}}))
	ec := mergeEncryptionContext(map[string]string{"a": "1"}, []byte{0xAB})
	require.Equal(t, map[string]string{"a": "1", "vault-genome.aad": "ab"}, ec)
	require.Equal(t, map[string]string{"a": "1"}, mergeEncryptionContext(map[string]string{"a": "1"}, nil))
}

func TestAzureSGXProducerVerifierAndSealerRefusals(t *testing.T) {
	fh := newFakeHardware(t, "azure-sgx-refusals")
	installSGXFake(t, fh, "maa")
	nonce := Nonce("a thirty-two byte challenger nonce!")
	expected := Measurement(fh.measure[:])

	t.Run("producer construction", func(t *testing.T) {
		create, mre := sgxCreateEnclave, sgxGetMREnclave
		t.Cleanup(func() { sgxCreateEnclave, sgxGetMREnclave = create, mre })
		sgxCreateEnclave = func(string) (uint64, error) { return 0, errors.New("no device") }
		_, err := NewAzureSGXProducer(AzureSGXProducerConfig{EnclaveSOPath: "enclave.so"})
		requireStructuralErr(t, err, "load enclave")
		sgxCreateEnclave = create
		sgxGetMREnclave = func(uint64) ([]byte, error) { return nil, errors.New("ecall failed") }
		_, err = NewAzureSGXProducer(AzureSGXProducerConfig{EnclaveSOPath: "enclave.so"})
		require.ErrorContains(t, err, "read MRENCLAVE")
		sgxGetMREnclave = func(uint64) ([]byte, error) { return make([]byte, 31), nil }
		_, err = NewAzureSGXProducer(AzureSGXProducerConfig{EnclaveSOPath: "enclave.so"})
		requireIntegrityErr(t, err, "MRENCLAVE not 32 bytes")
	})

	p, err := NewAzureSGXProducer(AzureSGXProducerConfig{EnclaveSOPath: "enclave.so"})
	require.NoError(t, err)
	require.Equal(t, uint64(0xC0FFEE_BADD_FACE), p.EnclaveID())
	_, err = p.Quote(Nonce("short"))
	requireStructuralErr(t, err, "nonce")
	report, quote := sgxECallCreateReport, dcapGetQuote
	sgxECallCreateReport = func(uint64, []byte) ([]byte, error) { return nil, errors.New("ecall failed") }
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "create_report")
	sgxECallCreateReport = report
	dcapGetQuote = func([]byte) ([]byte, error) { return nil, errors.New("quoting enclave absent") }
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "dcap_get_quote")
	dcapGetQuote = quote
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
	_, err = p.Quote(nonce)
	requireStructuralErr(t, err, "not initialised")

	maa, err := NewAzureSGXVerifier(nil, expected, AzureSGXVerifierConfig{MAAEndpoint: "https://maa.example"})
	require.NoError(t, err)
	m, err := maa.Verify(ev, nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(expected))
	m, err = maa.Verify(ev, nonce)
	require.NoError(t, err, "the JWKS is served from the verifier's cache the second time")
	require.True(t, m.Equal(expected))

	t.Run("verifier in MAA mode", func(t *testing.T) {
		_, err := maa.Verify(ev, Nonce("short"))
		requireStructuralErr(t, err, "nonce")
		_, err = maa.Verify(ev[:100], nonce)
		requireIntegrityErr(t, err, "too short")
		_, err = maa.Verify(ev, Nonce("another thirty-two byte challenge!!"))
		requireIntegrityErr(t, err, "REPORT_DATA")
		submit, jwt, get := maaSubmitQuote, verifyMAAJWT, httpGetWithCacheBust
		t.Cleanup(func() { maaSubmitQuote, verifyMAAJWT, httpGetWithCacheBust = submit, jwt, get })
		maaSubmitQuote = func(string, Evidence, Nonce) ([]byte, error) { return nil, errors.New("503") }
		_, err = maa.Verify(ev, nonce)
		requireIntegrityErr(t, err, "MAA submit")
		maaSubmitQuote = submit
		verifyMAAJWT = func([]byte, []byte, time.Duration) (sgxClaims, error) {
			return sgxClaims{}, errors.New("bad signature")
		}
		_, err = maa.Verify(ev, nonce)
		requireIntegrityErr(t, err, "JWT verify")
		verifyMAAJWT = jwt
		httpGetWithCacheBust = func(string) ([]byte, error) { return nil, errors.New("offline") }
		fresh, err := NewAzureSGXVerifier(nil, expected, AzureSGXVerifierConfig{MAAEndpoint: "https://maa.example"})
		require.NoError(t, err)
		_, err = fresh.Verify(ev, nonce)
		require.ErrorContains(t, err, "fetch JWKS")
		httpGetWithCacheBust = get

		svn, err := NewAzureSGXVerifier(nil, expected, AzureSGXVerifierConfig{MAAEndpoint: "https://maa.example", MinISVSVN: 9})
		require.NoError(t, err)
		_, err = svn.Verify(ev, nonce)
		requireIntegrityErr(t, err, "ISVSVN")
		other, err := NewAzureSGXVerifier(nil, MeasurementOf([]byte("another enclave")), AzureSGXVerifierConfig{MAAEndpoint: "https://maa.example"})
		require.NoError(t, err)
		_, err = other.Verify(ev, nonce)
		requireIntegrityErr(t, err, "MRENCLAVE")
		signer, err := NewAzureSGXVerifier(nil, expected, AzureSGXVerifierConfig{MAAEndpoint: "https://maa.example", AcceptableMRSIGNERS: [][32]byte{{1}}})
		require.NoError(t, err)
		_, err = signer.Verify(ev, nonce)
		requireIntegrityErr(t, err, "MRSIGNER")
	})

	t.Run("verifier in DCAP mode", func(t *testing.T) {
		dcap, err := NewAzureSGXVerifier(nil, expected, AzureSGXVerifierConfig{Mode: AzureSGXModeDCAP, PCCSURL: "https://pccs.example"})
		require.NoError(t, err)
		m, err := dcap.Verify(ev, nonce)
		require.NoError(t, err)
		require.True(t, m.Equal(expected))
		_, err = dcap.Verify(bytes.Repeat([]byte{7}, 500), nonce)
		requireIntegrityErr(t, err, "dcap verdict")
		collateral, verify := pccsFetchCollateral, dcapVerifyQuote
		t.Cleanup(func() { pccsFetchCollateral, dcapVerifyQuote = collateral, verify })
		pccsFetchCollateral = func(string, Evidence) ([]byte, error) { return nil, errors.New("pccs down") }
		_, err = dcap.Verify(ev, nonce)
		requireIntegrityErr(t, err, "fetch collateral")
		pccsFetchCollateral = collateral
		dcapVerifyQuote = func([]byte, []byte) (*dcapVerdict, error) { return nil, errors.New("library error") }
		_, err = dcap.Verify(ev, nonce)
		requireIntegrityErr(t, err, "dcap verify")
		unknown := &AzureSGXVerifier{cfg: AzureSGXVerifierConfig{Mode: "other"}}
		_, err = unknown.Verify(ev, nonce)
		requireStructuralErr(t, err, "unknown verifier mode")
	})

	t.Run("sealer", func(t *testing.T) {
		_, err := NewAzureSGXSealer(1, SGXSealPolicy(9), "k")
		requireStructuralErr(t, err, "SGXSealPolicy")
		s, err := NewAzureSGXSealer(p.EnclaveID(), SGXSealMRENCLAVE, "k")
		require.NoError(t, err)
		sealed, err := s.Seal([]byte("the key"), []byte("aad"))
		require.NoError(t, err)
		opened, err := s.Unseal(sealed, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, []byte("the key"), opened)
		_, err = s.Unseal(sealed, []byte("other aad"))
		requireIntegrityErr(t, err, "unseal")
		seal := sgxECallSealData
		t.Cleanup(func() { sgxECallSealData = seal })
		sgxECallSealData = func(uint64, []byte, []byte, SGXSealPolicy) ([]byte, error) { return nil, errors.New("ecall failed") }
		_, err = s.Seal([]byte("k"), nil)
		require.ErrorContains(t, err, "seal")
	})
}

func TestIntelSGXProducerVerifierAndSealerRefusals(t *testing.T) {
	fh := newFakeHardware(t, "intel-sgx-refusals")
	installSGXFake(t, fh, "dcap")
	nonce := Nonce("a thirty-two byte challenger nonce!")
	expected := Measurement(fh.measure[:])

	t.Run("producer construction", func(t *testing.T) {
		create, mre := sgxCreateEnclave, sgxGetMREnclave
		t.Cleanup(func() { sgxCreateEnclave, sgxGetMREnclave = create, mre })
		sgxCreateEnclave = func(string) (uint64, error) { return 0, errors.New("no device") }
		_, err := NewIntelSGXProducer(IntelSGXProducerConfig{EnclaveSOPath: "enclave.so"})
		requireStructuralErr(t, err, "load enclave")
		sgxCreateEnclave = create
		sgxGetMREnclave = func(uint64) ([]byte, error) { return nil, errors.New("ecall failed") }
		_, err = NewIntelSGXProducer(IntelSGXProducerConfig{EnclaveSOPath: "enclave.so"})
		require.ErrorContains(t, err, "read MRENCLAVE")
		sgxGetMREnclave = func(uint64) ([]byte, error) { return make([]byte, 31), nil }
		_, err = NewIntelSGXProducer(IntelSGXProducerConfig{EnclaveSOPath: "enclave.so"})
		requireIntegrityErr(t, err, "MRENCLAVE not 32 bytes")
	})

	p, err := NewIntelSGXProducer(IntelSGXProducerConfig{EnclaveSOPath: "enclave.so"})
	require.NoError(t, err)
	require.Equal(t, uint64(0xC0FFEE_BADD_FACE), p.EnclaveID())
	require.True(t, p.Measurement().Equal(expected))
	_, err = p.Quote(Nonce("short"))
	requireStructuralErr(t, err, "nonce")
	report, quote := sgxECallCreateReport, dcapGetQuote
	sgxECallCreateReport = func(uint64, []byte) ([]byte, error) { return nil, errors.New("ecall failed") }
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "create_report")
	sgxECallCreateReport = report
	dcapGetQuote = func([]byte) ([]byte, error) { return nil, errors.New("quoting enclave absent") }
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "dcap_get_quote")
	dcapGetQuote = quote
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
	_, err = p.Quote(nonce)
	requireStructuralErr(t, err, "not loaded")

	v, err := NewIntelSGXVerifier(nil, expected, IntelSGXVerifierConfig{PCCSURL: "https://pccs.example"})
	require.NoError(t, err)
	m, err := v.Verify(ev, nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(expected))

	t.Run("verifier", func(t *testing.T) {
		_, err := v.Verify(ev, Nonce("short"))
		requireStructuralErr(t, err, "nonce")
		_, err = v.Verify(ev[:100], nonce)
		requireIntegrityErr(t, err, "too short")
		_, err = v.Verify(bytes.Repeat([]byte{7}, 500), nonce)
		requireIntegrityErr(t, err, "dcap verdict")
		_, err = v.Verify(ev, Nonce("another thirty-two byte challenge!!"))
		requireIntegrityErr(t, err, "REPORT_DATA")
		collateral, verify := pccsFetchCollateral, dcapVerifyQuote
		t.Cleanup(func() { pccsFetchCollateral, dcapVerifyQuote = collateral, verify })
		pccsFetchCollateral = func(string, Evidence) ([]byte, error) { return nil, errors.New("pccs down") }
		_, err = v.Verify(ev, nonce)
		requireIntegrityErr(t, err, "collateral")
		pccsFetchCollateral = collateral
		dcapVerifyQuote = func([]byte, []byte) (*dcapVerdict, error) { return nil, errors.New("library error") }
		_, err = v.Verify(ev, nonce)
		requireIntegrityErr(t, err, "dcap verify")
		dcapVerifyQuote = verify
		svn, err := NewIntelSGXVerifier(nil, expected, IntelSGXVerifierConfig{PCCSURL: "https://pccs.example", MinISVSVN: 9})
		require.NoError(t, err)
		_, err = svn.Verify(ev, nonce)
		requireIntegrityErr(t, err, "ISVSVN")
		other, err := NewIntelSGXVerifier(nil, MeasurementOf([]byte("another enclave")), IntelSGXVerifierConfig{PCCSURL: "https://pccs.example"})
		require.NoError(t, err)
		_, err = other.Verify(ev, nonce)
		requireIntegrityErr(t, err, "MRENCLAVE")
		signer, err := NewIntelSGXVerifier(nil, expected, IntelSGXVerifierConfig{PCCSURL: "https://pccs.example", AcceptableMRSIGNERS: [][32]byte{{1}}})
		require.NoError(t, err)
		_, err = signer.Verify(ev, nonce)
		requireIntegrityErr(t, err, "MRSIGNER")
	})

	t.Run("sealer with and without an HSM", func(t *testing.T) {
		_, err := NewIntelSGXSealer(1, SGXSealPolicy(9), "")
		requireStructuralErr(t, err, "SGXSealPolicy")
		plain, err := NewIntelSGXSealer(p.EnclaveID(), SGXSealMRSIGNER, "")
		require.NoError(t, err)
		sealed, err := plain.Seal([]byte("the key"), []byte("aad"))
		require.NoError(t, err)
		opened, err := plain.Unseal(sealed, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, []byte("the key"), opened)
		_, err = plain.Unseal(sealed, []byte("other"))
		requireIntegrityErr(t, err, "unseal")

		hsm, err := NewIntelSGXSealer(p.EnclaveID(), SGXSealMRSIGNER, "slot-0")
		require.NoError(t, err)
		wrapped, err := hsm.Seal([]byte("the key"), []byte("aad"))
		require.NoError(t, err)
		require.NotEqual(t, sealed, wrapped)
		opened, err = hsm.Unseal(wrapped, []byte("aad"))
		require.NoError(t, err)
		require.Equal(t, []byte("the key"), opened)
		_, err = hsm.Unseal(wrapped[:3], []byte("aad"))
		requireIntegrityErr(t, err, "HSM unwrap")

		seal, wrap := sgxECallSealData, hsmWrap
		t.Cleanup(func() { sgxECallSealData, hsmWrap = seal, wrap })
		hsmWrap = func(string, []byte) ([]byte, error) { return nil, errors.New("token absent") }
		_, err = hsm.Seal([]byte("k"), nil)
		require.ErrorContains(t, err, "HSM wrap")
		sgxECallSealData = func(uint64, []byte, []byte, SGXSealPolicy) ([]byte, error) { return nil, errors.New("ecall failed") }
		_, err = plain.Seal([]byte("k"), nil)
		require.ErrorContains(t, err, "seal")
	})
}

// sevReport builds a 1184-byte SEV-SNP report with the fields the verifier
// reads; its signature is not real, so tests that use it stub the chain and
// signature seams and exercise what comes after them.
func sevReport(nonce []byte, measurement []byte) []byte {
	raw := make([]byte, sevReportLen)
	binary.LittleEndian.PutUint32(raw[0:], 3)
	binary.LittleEndian.PutUint64(raw[sevOffPolicy:], 0x30000)
	binary.LittleEndian.PutUint32(raw[sevOffSigAlgo:], 1)
	prefix := computeReportDataPrefix(nonce)
	copy(raw[sevOffReportData:], prefix[:])
	copy(raw[sevOffMeasurement:], measurement)
	for i := range 32 {
		raw[sevOffHostData+i] = 0x11
	}
	for i := range 64 {
		raw[sevOffChipID+i] = byte(i)
	}
	binary.LittleEndian.PutUint64(raw[sevOffReportedTCB:], 0x0B000000000000C0)
	return raw
}

func TestGCPSEVVerifierRefusesEachDefectAfterTheSignature(t *testing.T) {
	teeFakeMu.Lock()
	t.Cleanup(teeFakeMu.Unlock)
	fetch, chain, sig := amdKDSGetVCEK, verifyAMDChain, verifySEVReportSignature
	t.Cleanup(func() { amdKDSGetVCEK, verifyAMDChain, verifySEVReportSignature = fetch, chain, sig })
	fetches := 0
	amdKDSGetVCEK = func(string, [64]byte, uint64) ([]byte, error) { fetches++; return []byte("vcek"), nil }
	verifyAMDChain = func([]byte, []byte) error { return nil }
	verifySEVReportSignature = func(*sevSNPReport, []byte) error { return nil }

	nonce := Nonce("a thirty-two byte challenger nonce!")
	measurement := bytes.Repeat([]byte{0xA5}, 48)
	good := sevReport(nonce, measurement)
	cache := t.TempDir()
	v, err := NewGCPSEVVerifier(nil, Measurement(measurement), GCPSEVVerifierConfig{VCEKCacheDir: cache, MinReportedTCB: 1})
	require.NoError(t, err)
	m, err := v.Verify(good, nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(Measurement(measurement)))
	_, err = v.Verify(good, nonce)
	require.NoError(t, err)
	require.Equal(t, 1, fetches, "the VCEK is fetched once and then served from memory")
	again, err := NewGCPSEVVerifier(nil, Measurement(measurement), GCPSEVVerifierConfig{VCEKCacheDir: cache})
	require.NoError(t, err)
	_, err = again.Verify(good, nonce)
	require.NoError(t, err)
	require.Equal(t, 1, fetches, "a new verifier reads the VCEK from the cache directory")

	_, err = v.Verify(good, Nonce("short"))
	requireStructuralErr(t, err, "nonce")
	_, err = v.Verify(good[:100], nonce)
	requireIntegrityErr(t, err, "shorter than")
	_, err = v.Verify(good, Nonce("another thirty-two byte challenge!!"))
	requireIntegrityErr(t, err, "REPORT_DATA")

	edits := []struct {
		name     string
		edit     func(raw []byte)
		fragment string
	}{
		{"another signature algorithm", func(raw []byte) { binary.LittleEndian.PutUint32(raw[sevOffSigAlgo:], 2) }, "algorithm 2"},
		{"signed by a VLEK", func(raw []byte) { binary.LittleEndian.PutUint32(raw[sevOffFlags:], 1<<2) }, "key kind 1"},
		{"debuggable guest", func(raw []byte) { binary.LittleEndian.PutUint64(raw[sevOffPolicy:], 0x30000|sevPolicyDebug) }, "DEBUG"},
		{"requested at VMPL 2", func(raw []byte) { binary.LittleEndian.PutUint32(raw[sevOffVMPL:], 2) }, "VMPL 2"},
		{"TCB below the minimum", func(raw []byte) { binary.LittleEndian.PutUint64(raw[sevOffReportedTCB:], 0) }, "ReportedTCB"},
	}
	for _, e := range edits {
		raw := append([]byte(nil), good...)
		e.edit(raw)
		_, err := v.Verify(raw, nonce)
		requireIntegrityErr(t, err, e.fragment)
		t.Log(e.name)
	}

	hostData, err := NewGCPSEVVerifier(nil, Measurement(measurement), GCPSEVVerifierConfig{AcceptableHostData: [][32]byte{{0x22}}})
	require.NoError(t, err)
	_, err = hostData.Verify(good, nonce)
	requireIntegrityErr(t, err, "HOST_DATA")
	var pinned [32]byte
	for i := range pinned {
		pinned[i] = 0x11
	}
	hostData, err = NewGCPSEVVerifier(nil, Measurement(measurement), GCPSEVVerifierConfig{AcceptableHostData: [][32]byte{pinned}})
	require.NoError(t, err)
	_, err = hostData.Verify(good, nonce)
	require.NoError(t, err)
	other, err := NewGCPSEVVerifier(nil, Measurement(bytes.Repeat([]byte{0x5A}, 48)), GCPSEVVerifierConfig{})
	require.NoError(t, err)
	_, err = other.Verify(good, nonce)
	requireIntegrityErr(t, err, "not in acceptable set")

	amdKDSGetVCEK = func(string, [64]byte, uint64) ([]byte, error) { return nil, errors.New("kds unreachable") }
	fresh, err := NewGCPSEVVerifier(nil, Measurement(measurement), GCPSEVVerifierConfig{})
	require.NoError(t, err)
	_, err = fresh.Verify(good, nonce)
	requireIntegrityErr(t, err, "fetch VCEK")
	amdKDSGetVCEK = func(string, [64]byte, uint64) ([]byte, error) { return []byte("vcek"), nil }
	verifyAMDChain = func([]byte, []byte) error { return errors.New("not AMD's") }
	_, err = fresh.Verify(good, nonce)
	requireIntegrityErr(t, err, "AMD chain")
	verifyAMDChain = func([]byte, []byte) error { return nil }
	verifySEVReportSignature = func(*sevSNPReport, []byte) error { return errors.New("forged") }
	_, err = fresh.Verify(good, nonce)
	requireIntegrityErr(t, err, "report signature")
}

// scriptedTSM answers report requests from a script, so the producer can be
// started on a fixed launch measurement and then fed a report that lies.
type scriptedTSM struct {
	reports [][]byte
	errs    []error
	calls   int
}

func (s *scriptedTSM) report(reportData [64]byte, _ uint32) ([]byte, error) {
	i := s.calls
	s.calls++
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	raw := append([]byte(nil), s.reports[i]...)
	if len(raw) >= sevReportLen && raw[0] != 0xFF {
		copy(raw[sevOffReportData:], reportData[:])
	}
	return raw, nil
}

func TestGCPSEVProducerRefusesReportsThatDoNotMatchItsLaunch(t *testing.T) {
	nonce := Nonce("a thirty-two byte challenger nonce!")
	launch := sevReport(nonce, bytes.Repeat([]byte{0xA5}, 48))
	elsewhere := sevReport(nonce, bytes.Repeat([]byte{0x5A}, 48))
	stale := sevReport(Nonce("some other challenge of thirty-two"), bytes.Repeat([]byte{0xA5}, 48))
	stale[0] = 0xFF // the scripted TSM leaves REPORT_DATA untouched for this one

	_, err := newGCPSEVProducer(GCPSEVProducerConfig{}, &scriptedTSM{errs: []error{errors.New("tsm busy")}})
	require.ErrorContains(t, err, "initial report")
	_, err = newGCPSEVProducer(GCPSEVProducerConfig{}, &scriptedTSM{reports: [][]byte{launch[:100]}})
	require.ErrorContains(t, err, "parse report")

	tsm := &scriptedTSM{reports: [][]byte{launch, launch, elsewhere, stale, launch}, errs: []error{nil, nil, nil, nil, errors.New("tsm busy")}}
	p, err := newGCPSEVProducer(GCPSEVProducerConfig{}, tsm)
	require.NoError(t, err)
	require.Equal(t, uint64(0x30000), p.Policy())
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	require.Len(t, ev, sevReportLen)
	_, err = p.Quote(nonce)
	requireIntegrityErr(t, err, "different launch measurement")
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "requested REPORT_DATA")
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "request report")
	_, err = p.Quote(Nonce("short"))
	requireStructuralErr(t, err, "nonce")
	require.NoError(t, p.Close())
	_, err = p.Quote(nonce)
	requireStructuralErr(t, err, "closed")
}

// selfSignedP384 returns a certificate whose subject and issuer are the same
// name; signed by signer, which is the certificate's own key unless another
// is given.
func selfSignedP384(t *testing.T, name string, signer *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	if signer == nil {
		signer = key
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	parent := tmpl
	if signer != key {
		// The issuer name stays the certificate's own; only the signature
		// comes from elsewhere.
		parent = &x509.Certificate{SerialNumber: big.NewInt(1), Subject: tmpl.Subject, PublicKey: &signer.PublicKey}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	require.NoError(t, err)
	return key, der
}

func issuedP384(t *testing.T, name string, issuerDER []byte, issuerKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	issuer, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)
	return key, der
}

func certPEM(der ...[]byte) []byte {
	var out []byte
	for _, d := range der {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return out
}

func TestAMDChainAndReportSignatureRefusals(t *testing.T) {
	arkKey, ark := selfSignedP384(t, "ARK", nil)
	askKey, ask := issuedP384(t, "ASK", ark, arkKey)
	_, vcek := issuedP384(t, "VCEK", ask, askKey)
	require.NoError(t, realVerifyAMDChain(vcek, certPEM(ask, ark)))
	require.NoError(t, realVerifyAMDChain(certPEM(vcek), certPEM(ark, ask)), "PEM input and either order")

	_, err := parseCert([]byte("-----BEGIN JUNK"))
	require.ErrorContains(t, err, "no PEM block")
	_, err = parseCert([]byte{1, 2, 3})
	require.Error(t, err)
	_, _, err = parseASKARK(certPEM(ark))
	require.ErrorContains(t, err, "expected 2 certs")
	_, _, err = parseASKARK(certPEM(ark, ark))
	require.ErrorContains(t, err, "could not identify")
	_, _, err = parseASKARK(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
	require.ErrorContains(t, err, "parse chain cert")

	require.ErrorContains(t, realVerifyAMDChain([]byte{1}, certPEM(ask, ark)), "parse VCEK")
	require.ErrorContains(t, realVerifyAMDChain(vcek, certPEM(ark)), "expected 2 certs")
	otherKey, otherASK := issuedP384(t, "ASK", ark, arkKey)
	require.ErrorContains(t, realVerifyAMDChain(vcek, certPEM(otherASK, ark)), "VCEK not signed by ASK")
	_, otherARK := selfSignedP384(t, "ARK", nil)
	require.ErrorContains(t, realVerifyAMDChain(vcek, certPEM(ask, otherARK)), "ASK not signed by ARK")
	forgedKey, forgedARK := selfSignedP384(t, "ARK", otherKey)
	askKey2, askUnderForged := issuedP384(t, "ASK", forgedARK, forgedKey)
	_, vcekUnderForged := issuedP384(t, "VCEK", askUnderForged, askKey2)
	require.ErrorContains(t, realVerifyAMDChain(vcekUnderForged, certPEM(askUnderForged, forgedARK)), "ARK not self-signed")

	_, err = realParseSEVSNPReport(make([]byte, 100))
	require.ErrorContains(t, err, "too short")
	report, err := realParseSEVSNPReport(sevReport([]byte("n"), make([]byte, 48)))
	require.NoError(t, err)
	require.ErrorContains(t, realVerifySEVReportSignature(report, []byte{1}), "parse VCEK")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "RSA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	rsaDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	require.ErrorContains(t, realVerifySEVReportSignature(report, rsaDER), "not ECDSA")
	short := *report
	short.Raw = short.Raw[:100]
	require.ErrorContains(t, realVerifySEVReportSignature(&short, vcek), "too short")
	require.ErrorContains(t, realVerifySEVReportSignature(report, vcek), "signature verification failed")
}

func TestAMDKDSClientAgainstALocalServer(t *testing.T) {
	var chipID [64]byte
	for i := range chipID {
		chipID[i] = byte(i)
	}
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.String())
		switch {
		case strings.HasSuffix(r.URL.Path, "/cert_chain"):
			_, _ = w.Write([]byte("chain"))
		case strings.Contains(r.URL.Path, "/vcek/v1/"):
			_, _ = w.Write([]byte("vcek"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	tcb := uint64(0x0B000000000000C0) | 2<<8 | 3<<48
	body, err := realAMDKDSGetVCEK(srv.URL, chipID, tcb)
	require.NoError(t, err)
	require.Equal(t, []byte("vcek"), body)
	body, err = realAMDKDSGetVCEKFor(srv.URL, "Genoa", chipID, tcb)
	require.NoError(t, err)
	require.Equal(t, []byte("vcek"), body)
	body, err = realAMDKDSGetCertChain(srv.URL)
	require.NoError(t, err)
	require.Equal(t, []byte("chain"), body)
	require.Len(t, paths, 3)
	require.Contains(t, paths[0], "/vcek/v1/Milan/000102")
	require.Contains(t, paths[0], "blSPL=192")
	require.Contains(t, paths[0], "teeSPL=2")
	require.Contains(t, paths[0], "snpSPL=3")
	require.Contains(t, paths[0], "ucodeSPL=11")
	require.Contains(t, paths[1], "/vcek/v1/Genoa/")
	require.Equal(t, "/vcek/v1/Milan/cert_chain", paths[2])
	_, err = httpGet(srv.URL + "/nothing")
	require.ErrorContains(t, err, "HTTP 404")
}

func TestAMDKDSRetriesWhenThrottled(t *testing.T) {
	var slept []time.Duration
	sleep := kdsSleep
	t.Cleanup(func() { kdsSleep = sleep })
	kdsSleep = func(d time.Duration) { slept = append(slept, d) }
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 3 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	body, err := httpGet(srv.URL)
	require.NoError(t, err)
	require.Equal(t, []byte("ok"), body)
	require.Equal(t, []time.Duration{7 * time.Second, 7 * time.Second}, slept)

	hits = 0
	always := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(http.StatusServiceUnavailable) }))
	t.Cleanup(always.Close)
	_, err = httpGet(always.URL)
	require.ErrorContains(t, err, "HTTP 503")
	require.Equal(t, kdsAttempts, hits, "a throttled server is asked a bounded number of times")

	require.Equal(t, 2*time.Second, kdsBackoff(1, ""))
	require.Equal(t, 16*time.Second, kdsBackoff(4, ""))
	require.Equal(t, kdsMaxWait, kdsBackoff(1, "3600"))
	require.Equal(t, 5*time.Second, kdsBackoff(1, " 5 "))
	require.Equal(t, 2*time.Second, kdsBackoff(1, "-1"))
}

func TestWriteFileAtomicCreatesParentsAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache", "vcek.der")
	require.NoError(t, writeFileAtomic(path, []byte("one")))
	require.NoError(t, writeFileAtomic(path, []byte("two")))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("two"), got)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file is left behind")
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	require.Error(t, writeFileAtomic(filepath.Join(file, "under", "a-file"), []byte("x")))
}

func TestSealedSecretRefusals(t *testing.T) {
	sim, err := NewSimulated([]byte("workload"), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	m := sim.Measurement()
	_, err = SealSecret(nil, sim, ProviderSimulated, m, "k")
	require.ErrorContains(t, err, "required")
	_, err = SealSecret([]byte("s"), nil, ProviderSimulated, m, "k")
	require.ErrorContains(t, err, "required")
	raw, err := SealSecret([]byte("s"), sim, ProviderSimulated, m, "k")
	require.NoError(t, err)
	require.True(t, IsSealedSecret(raw))
	opened, err := OpenSecret(raw, sim, ProviderSimulated, "k")
	require.NoError(t, err)
	require.Equal(t, []byte("s"), opened)
	_, err = OpenSecret(raw, sim, ProviderSimulated, "other")
	requireStructuralErr(t, err, `read as "other"`)
	_, err = OpenSecret(raw, sim, ProviderAWSNitro, "k")
	requireStructuralErr(t, err, "this host is")
	_, err = OpenSecret(raw, nil, ProviderSimulated, "k")
	require.ErrorContains(t, err, "no sealer")
	other, err := NewSimulated([]byte("another workload"), bytes.Repeat([]byte{2}, 32))
	require.NoError(t, err)
	_, err = OpenSecret(raw, other, ProviderSimulated, "k")
	requireIntegrityErr(t, err, "") // the sealing key follows the measurement: another workload cannot open the file
	_, err = ParseSealedSecret([]byte("{"))
	requireStructuralErr(t, err, "not a sealed key file")
	_, err = ParseSealedSecret([]byte(`{"schema":"x"}`))
	requireStructuralErr(t, err, "schema")
	_, err = ParseSealedSecret([]byte(`{"schema":"` + SealedSecretSchema + `"}`))
	requireStructuralErr(t, err, "incomplete")
	require.False(t, IsSealedSecret([]byte("plain key bytes")))

	failing := &failingSealer{}
	_, err = SealSecret([]byte("s"), failing, ProviderSimulated, m, "k")
	require.ErrorContains(t, err, "seal to simulated")
}

type failingSealer struct{}

func (failingSealer) Seal([]byte, []byte) ([]byte, error)   { return nil, errors.New("hsm offline") }
func (failingSealer) Unseal([]byte, []byte) ([]byte, error) { return nil, errors.New("hsm offline") }

func TestSimulatedRefusals(t *testing.T) {
	_, err := NewSimulated([]byte("w"), []byte("short seed"))
	requireStructuralErr(t, err, "seed must be 32 bytes")
	sim, err := NewSimulated([]byte("w"), nil)
	require.NoError(t, err)
	_, err = sim.Unseal([]byte("short"), nil)
	requireIntegrityErr(t, err, "too short")
	v := NewSimulatedVerifier(sim.PublicKey(), sim.Measurement())
	nonce := Nonce("a thirty-two byte challenger nonce!")
	_, err = v.Verify(Evidence("x"), nonce)
	requireIntegrityErr(t, err, "too short")
	_, err = v.Verify(Evidence(bytes.Repeat([]byte("Z"), 40)), nonce)
	requireIntegrityErr(t, err, "magic mismatch")
	sealed, err := sim.Seal([]byte("p"), []byte("aad"))
	require.NoError(t, err)
	opened, err := sim.Unseal(sealed, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("p"), opened)
}

func TestTSMConfigfsOnARealDirectoryAndWithFailingFiles(t *testing.T) {
	dir := t.TempDir()
	var fs osTSMFS
	entry := filepath.Join(dir, "entry")
	require.NoError(t, fs.Mkdir(entry))
	info, err := os.Stat(entry)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Error(t, fs.WriteFile(filepath.Join(entry, "absent"), []byte("x")), "configfs attributes are never created, only written")
	file := filepath.Join(entry, "inblob")
	require.NoError(t, os.WriteFile(file, []byte("old-longer"), 0o600))
	require.NoError(t, fs.WriteFile(file, []byte("new")))
	got, err := fs.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, []byte("new"), got)
	require.NoError(t, os.Remove(file))
	require.NoError(t, fs.Remove(entry))
	_, err = os.Stat(entry)
	require.True(t, os.IsNotExist(err))

	var reportData [64]byte
	run := func(fs tsmFS, privlevel uint32) error {
		_, err := configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs}.report(reportData, privlevel)
		return err
	}
	base := func() *scriptedTSMFS {
		return &scriptedTSMFS{files: map[string][]byte{"provider": []byte("sev_guest\n"), "generation": []byte("1\n"), "outblob": []byte("report")}}
	}
	require.NoError(t, run(base(), 0))
	fs1 := base()
	fs1.mkdirErr = errors.New("eperm")
	require.ErrorContains(t, run(fs1, 0), "create report entry")
	fs2 := base()
	delete(fs2.files, "provider")
	require.ErrorContains(t, run(fs2, 0), "read provider")
	fs3 := base()
	fs3.files["provider"] = []byte("tdx_guest")
	require.ErrorContains(t, run(fs3, 0), `provider is "tdx_guest"`)
	fs4 := base()
	fs4.writeErr = map[string]error{"privlevel": errors.New("eacces")}
	require.ErrorContains(t, run(fs4, 2), "set privlevel 2")
	fs5 := base()
	delete(fs5.files, "generation")
	require.ErrorContains(t, run(fs5, 0), "read generation")
	fs6 := base()
	fs6.files["generation"] = []byte("many")
	require.ErrorContains(t, run(fs6, 0), `generation "many"`)
	fs7 := base()
	fs7.writeErr = map[string]error{"inblob": errors.New("eio")}
	require.ErrorContains(t, run(fs7, 0), "write inblob")
	fs8 := base()
	delete(fs8.files, "outblob")
	require.ErrorContains(t, run(fs8, 0), "read outblob")
	fs9 := base()
	fs9.files["outblob"] = nil
	require.ErrorContains(t, run(fs9, 0), "empty outblob")
	fs10 := base()
	fs10.bumpOnWrite = 2
	err = run(fs10, 0)
	require.ErrorContains(t, err, "gave up after 3 attempts")
	require.ErrorContains(t, err, "generation moved")
	require.Equal(t, 3, fs10.mkdirs, "a raced entry is retried, then given up")
	require.Equal(t, fs10.mkdirs, fs10.removes, "every entry is removed again")
}

// scriptedTSMFS is a configfs-tsm directory in memory with error hooks.
type scriptedTSMFS struct {
	files       map[string][]byte
	mkdirErr    error
	writeErr    map[string]error
	bumpOnWrite uint64 // how far the generation moves on each inblob write (1 is the kernel's behaviour)
	generation  uint64
	mkdirs      int
	removes     int
}

func (f *scriptedTSMFS) Mkdir(string) error {
	f.mkdirs++
	return f.mkdirErr
}

func (f *scriptedTSMFS) Remove(string) error {
	f.removes++
	return nil
}

func (f *scriptedTSMFS) ReadFile(path string) ([]byte, error) {
	name := filepath.Base(path)
	if name == "generation" {
		if _, ok := f.files["generation"]; !ok {
			return nil, os.ErrNotExist
		}
		if string(f.files["generation"]) == "many" {
			return []byte("many"), nil
		}
		return []byte(fmt.Sprintf("%d\n", f.generation)), nil
	}
	b, ok := f.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func (f *scriptedTSMFS) WriteFile(path string, _ []byte) error {
	name := filepath.Base(path)
	if err := f.writeErr[name]; err != nil {
		return err
	}
	if name == "inblob" {
		if f.bumpOnWrite == 0 {
			f.generation++
		} else {
			f.generation += f.bumpOnWrite
		}
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := acceptedList(m)
	sort.Strings(out)
	return out
}

func TestTDXHelpers(t *testing.T) {
	require.Equal(t, []string{"a", "b"}, sortedKeys(map[string]bool{"b": true, "a": true}))
	require.Equal(t, TCBRevoked, worseTCBStatus(TCBUpToDate, TCBRevoked))
	require.Equal(t, TCBOutOfDate, worseTCBStatus(TCBOutOfDate, TCBSWHardeningNeeded))
	require.Equal(t, "Strange", worseTCBStatus("Strange", TCBUpToDate), "an unknown status is never rated better")
	require.Equal(t, "Strange", worseTCBStatus(TCBUpToDate, "Strange"))

	_, err := NewGCPTDXProducer(GCPTDXProducerConfig{TSMReportDir: filepath.Join(t.TempDir(), "absent")})
	requireStructuralErr(t, err, "configfs-tsm")
	_, err = newGCPTDXProducer(GCPTDXProducerConfig{}, &scriptedTSM{errs: []error{errors.New("tsm busy")}})
	require.ErrorContains(t, err, "initial quote")

	_, err = parsePEMCertificates(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
	require.Error(t, err)
	_, err = parsePEMCertificates([]byte("no pem here"))
	require.ErrorContains(t, err, "no certificate")
	_, err = intelRootPool([]byte("junk"))
	require.ErrorContains(t, err, "no certificate")
	_, p384 := selfSignedP384(t, "P384", nil)
	cert, err := x509.ParseCertificate(p384)
	require.NoError(t, err)
	_, err = p256FromCert(cert)
	require.ErrorContains(t, err, "not ECDSA P-256")
	_, err = parsePCKExtension(cert)
	require.ErrorContains(t, err, "no SGX extension")

	var cache pcsCache
	_, ok := cache.load("x")
	require.False(t, ok, "no directory, no cache")
	cache.store("x", pcsDocument{})
	cache = pcsCache{dir: t.TempDir()}
	_, ok = cache.load("x")
	require.False(t, ok)
	require.NoError(t, os.WriteFile(filepath.Join(cache.dir, "x.json"), []byte("{}"), 0o600))
	_, ok = cache.load("x")
	require.False(t, ok, "a body without its issuer chain is not a document")
	cache.store("y", pcsDocument{Body: []byte("{}"), IssuerChain: []byte("pem")})
	d, ok := cache.load("y")
	require.True(t, ok)
	require.Equal(t, []byte("pem"), d.IssuerChain)
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	pcsCache{dir: filepath.Join(file, "under")}.store("z", pcsDocument{Body: []byte("{}")})

	require.False(t, documentCurrent([]byte("not json"), time.Now()))
}

func TestIntelPCSClientReadsTheIssuerChainHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("TCB-Info-Issuer-Chain", "-----BEGIN%20CERTIFICATE-----%0Aabc")
			_, _ = w.Write([]byte(`{"tcbInfo":{}}`))
		case "/no-chain":
			_, _ = w.Write([]byte(`{}`))
		case "/bad-escape":
			w.Header().Set("SGX-Enclave-Identity-Issuer-Chain", "%zz")
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	d, err := realPCSGet(srv.URL + "/ok")
	require.NoError(t, err)
	require.Equal(t, []byte(`{"tcbInfo":{}}`), d.Body)
	require.Equal(t, "-----BEGIN CERTIFICATE-----\nabc", string(d.IssuerChain))
	_, err = realPCSGet(srv.URL + "/no-chain")
	require.ErrorContains(t, err, "no issuer chain header")
	_, err = realPCSGet(srv.URL + "/bad-escape")
	require.ErrorContains(t, err, "issuer chain header")
	_, err = realPCSGet(srv.URL + "/missing")
	require.ErrorContains(t, err, "HTTP 404")
	_, err = realPCSGet("http://127.0.0.1:1/unreachable")
	require.Error(t, err)
	_, err = realPCSGet(":bad url")
	require.Error(t, err)
}

func TestTDXQuoteParserRefusesEachMalformedLayout(t *testing.T) {
	raw := tdxEvidence(t, "q1.quote.bin")
	good, err := parseTDXQuote(raw)
	require.NoError(t, err)
	require.NotEmpty(t, good.PCKChainPEM)
	sd := tdxMinQuoteLen
	certSize := int(binary.LittleEndian.Uint32(raw[sd+130:]))
	cd := sd + 134
	authLen := int(binary.LittleEndian.Uint16(raw[cd+448:]))
	inner := cd + 450 + authLen

	_, err = parseTDXQuote(raw[:100])
	require.ErrorContains(t, err, "shorter than a header")
	edits := []struct {
		name     string
		edit     func(b []byte) []byte
		fragment string
	}{
		{"version", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[0:], 5); return b }, "quote version 5"},
		{"attestation key type", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[2:], 3); return b }, "attestation key type 3"},
		{"TEE type", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], 0); return b }, "TEE type"},
		{"signature data length", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[tdxSignedLen:], uint32(len(b))); return b }, "exceeds"},
		{"signature data too short", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[tdxSignedLen:], 10); return b }, "too short for a signature"},
		{"certification data type", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[sd+128:], 7); return b }, "certification data type 7"},
		{"certification data size", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[sd+130:], uint32(certSize+1000)); return b }, "certification data size"},
		{"QE certification data short", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[tdxSignedLen:], 134+10)
			binary.LittleEndian.PutUint32(b[sd+130:], 10)
			return b
		}, "QE report certification data too short"},
		{"QE authentication data overflow", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[cd+448:], 60000); return b }, "runs past"},
		{"inner certification type", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[inner:], 9); return b }, "QE certification data type 9"},
		{"inner certification size", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[inner+2:], 1<<30); return b }, "PCK chain size"},
	}
	for _, e := range edits {
		b := e.edit(append([]byte(nil), raw...))
		_, err := parseTDXQuote(b)
		require.Error(t, err, e.name)
		require.ErrorContains(t, err, e.fragment, e.name)
	}
	_, err = parseSGXReport(make([]byte, 10))
	require.ErrorContains(t, err, "SGX report body is 10 bytes")
}
