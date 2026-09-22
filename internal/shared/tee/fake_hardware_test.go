// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — fake hardware harness for Phase-1 integration tests.
//
// What this file provides:
//
//   The 4 real-hardware TEE adapters (AWS Nitro, Azure SGX, GCP SEV-SNP,
//   Intel SGX bare metal) call out to a small set of platform-specific
//   helpers that touch /dev/nsm, /dev/sev-guest, the SGX SDK, AWS KMS,
//   AMD KDS, MAA, PCCS, etc. Those helpers are stubbed in production
//   builds (Phase 2 wiring) — they return "not yet wired" errors. So the
//   adapter's *call path* is currently not exercised by any test.
//
//   This harness flips that. Every Phase-2 stub is now an injectable
//   `var = func(...)`. In `installXxxFake(t, fh)` the test swaps the
//   stubs for in-process implementations that round-trip a self-consistent
//   synthetic format (Ed25519-signed JSON envelope), exercising every line
//   of the adapter Quote/Verify/Seal/Unseal path including:
//
//     - Nonce floor enforcement (R-10)
//     - Cert chain / signature verification ordering
//     - Measurement / MRENCLAVE / PCR / launch-measurement extraction
//     - Acceptable-set policy (MRSIGNER, AcceptableMeasurements, …)
//     - Sealing AAD binding & unseal-on-mismatch behaviour
//     - Threading (each Quote takes the producer mutex)
//     - Capability + Close idempotency
//
//   The AWS Nitro fake is different since the verifier's codec became
//   real (aws_nitro_cose.go): its fake NSM writes a genuine CBOR
//   attestation document in a genuine COSE_Sign1 envelope, signed by a
//   synthetic five-certificate P-384 chain (aws_nitro_fixture_test.go),
//   and the verifier under test pins that chain's root. Every byte of
//   the production parsing, chain and signature code runs; only the NSM
//   device and KMS are faked. The SGX and SEV-SNP fakes still swap the
//   on-the-wire sgx_quote3_t / SEV-SNP-1184B formats for Ed25519-signed
//   JSON — go.mod has no codec for those, and the docs/dependencies/
//   process governs adding one.

package tee

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// teeFakeMu serializes installXxxFake calls. The hardware stubs are
// package-level vars, so concurrent fake installation would race.
// Top-level integration tests therefore do NOT call t.Parallel(); they
// run sequentially under this mutex.
var teeFakeMu sync.Mutex

// fakeMagic prefixes every fake-hardware envelope so accidentally hitting
// a real (non-fake) parser path fails fast and audibly.
const fakeMagic = "VG-FAKE-TEE-v1\x00"

// fakeAttestation is the synthetic doc the fake hardware emits across
// all 4 platform adapters. Logical fields parallel real attestations
// (PCRs, MRENCLAVE, launch MEASUREMENT, REPORT_DATA, CHIP_ID, HOST_DATA)
// but the wire format is JSON + Ed25519 — sufficient to exercise every
// adapter call path without external crypto libraries.
type fakeAttestation struct {
	Format      string         `json:"format"`
	Nonce       []byte         `json:"nonce"`
	Measurement [32]byte       `json:"measurement"`
	Timestamp   int64          `json:"timestamp"`
	UserData    []byte         `json:"user_data,omitempty"`
	PCRs        map[int][]byte `json:"pcrs,omitempty"`
	MRSigner    [32]byte       `json:"mr_signer"`
	ISVSVN      uint16         `json:"isv_svn"`
	ISVPRODID   uint16         `json:"isv_prodid"`
	ChipID      [64]byte       `json:"chip_id"`
	HostData    [32]byte       `json:"host_data"`
	ReportData  [64]byte       `json:"report_data"`
	ReportedTCB uint64         `json:"reported_tcb"`
	Debug       bool           `json:"debug"`
}

// fakeHardware is the test-only "hardware" — owns an Ed25519 attestation
// key plus a deterministic per-label set of PCR / MRENCLAVE / etc. values.
type fakeHardware struct {
	label       string
	pub         shared_crypto.PublicKey
	priv        shared_crypto.PrivateKey
	measure     Measurement
	pcrs        map[int][]byte
	nitro       *nitroTestChain // set by installAWSNitroFake
	mrSigner    [32]byte
	chipID      [64]byte
	hostData    [32]byte
	isvSVN      uint16
	isvPID      uint16
	reportedTCB uint64
}

func newFakeHardware(t testing.TB, label string) *fakeHardware {
	t.Helper()
	seed := shared_crypto.SHA256Slice([]byte("vg-fake-tee-seed-" + label))
	pub, priv, err := shared_crypto.Ed25519FromSeed(seed)
	if err != nil {
		t.Fatalf("fake hardware: ed25519 seed: %v", err)
	}
	measure := MeasurementOf([]byte("vg-fake-workload-" + label))

	fh := &fakeHardware{
		label:       label,
		pub:         pub,
		priv:        priv,
		measure:     measure,
		pcrs:        map[int][]byte{0: measure[:], 1: measure[:], 2: measure[:]},
		mrSigner:    shared_crypto.SHA256([]byte("vg-fake-mrsigner-" + label)),
		hostData:    shared_crypto.SHA256([]byte("vg-fake-hostdata-" + label)),
		isvSVN:      5,
		isvPID:      1,
		reportedTCB: 100,
	}
	chipFront := shared_crypto.SHA256Slice([]byte("vg-fake-chipid-" + label))
	chipBack := shared_crypto.SHA256Slice([]byte("vg-fake-chipid-extra-" + label))
	copy(fh.chipID[:32], chipFront)
	copy(fh.chipID[32:], chipBack)
	return fh
}

// signAttestation produces a fake-magic-prefixed Ed25519-signed JSON
// envelope binding the given (format, nonce, userData). REPORT_DATA[:32]
// = SHA-256(nonce) so SGX/SEV-SNP nonce-binding paths work.
func (fh *fakeHardware) signAttestation(format string, nonce []byte, userData []byte) []byte {
	att := fakeAttestation{
		Format:      format,
		Nonce:       append([]byte(nil), nonce...),
		Measurement: [32]byte(fh.measure),
		Timestamp:   time.Now().UnixNano(),
		UserData:    append([]byte(nil), userData...),
		PCRs:        fh.pcrs,
		MRSigner:    fh.mrSigner,
		ISVSVN:      fh.isvSVN,
		ISVPRODID:   fh.isvPID,
		ChipID:      fh.chipID,
		HostData:    fh.hostData,
		ReportedTCB: fh.reportedTCB,
	}
	rd := shared_crypto.SHA256(nonce)
	copy(att.ReportData[:], rd[:])

	body, err := json.Marshal(att)
	if err != nil {
		panic(fmt.Sprintf("fake: json marshal: %v", err))
	}
	sig, err := shared_crypto.Sign(fh.priv, body)
	if err != nil {
		panic(fmt.Sprintf("fake: sign: %v", err))
	}

	var buf bytes.Buffer
	buf.WriteString(fakeMagic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	buf.Write(lenBuf[:])
	buf.Write(body)
	buf.Write(sig)
	return buf.Bytes()
}

// parseAttestation reverses signAttestation, verifying the Ed25519 sig.
// Used by all fake parser/verifier overrides.
func (fh *fakeHardware) parseAttestation(blob []byte) (*fakeAttestation, error) {
	if len(blob) < len(fakeMagic)+4+shared_crypto.Ed25519SignatureSize {
		return nil, fmt.Errorf("fake: blob too short (%d)", len(blob))
	}
	if string(blob[:len(fakeMagic)]) != fakeMagic {
		return nil, fmt.Errorf("fake: magic mismatch")
	}
	off := len(fakeMagic)
	bodyLen := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	// uint64 arithmetic so a crafted bodyLen near 2^32-1 cannot wrap
	// the truncation check (same pattern as simulated.go's Verify).
	if uint64(len(blob)-off) < uint64(bodyLen)+uint64(shared_crypto.Ed25519SignatureSize) {
		return nil, fmt.Errorf("fake: truncated")
	}
	body := blob[off : off+int(bodyLen)]
	sig := blob[off+int(bodyLen):]
	if err := shared_crypto.Verify(fh.pub, body, sig); err != nil {
		return nil, fmt.Errorf("fake: signature invalid: %w", err)
	}
	var att fakeAttestation
	if err := json.Unmarshal(body, &att); err != nil {
		return nil, fmt.Errorf("fake: json unmarshal: %w", err)
	}
	return &att, nil
}

// canonicalEC produces deterministic AAD bytes from the EncryptionContext
// map so encrypt/decrypt match across calls. KMS uses lex-sorted keys.
func canonicalEC(ec map[string]string) []byte {
	keys := make([]string, 0, len(ec))
	for k := range ec {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(ec[k])
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// =============================================================================
// AWS Nitro fake harness
// =============================================================================

// installAWSNitroFake wires a fake NSM + fake KMS for a single test. Must
// be called BEFORE constructing AWSNitroProducer/Verifier/Sealer. Restores
// originals via t.Cleanup. Acquires teeFakeMu so concurrent platform tests
// don't race on the package-level vars.
//
// The fake NSM signs real attestation documents with a synthetic chain
// (fh.nitro); the hardware's PCRs become 48-byte SHA-384 values, as on a
// Nitro Enclave, and fh.measure becomes PCR0. A verifier for this fake
// pins fh.nitro.rootDER.
func installAWSNitroFake(t testing.TB, fh *fakeHardware) {
	t.Helper()
	teeFakeMu.Lock()

	fh.nitro = newNitroTestChain(t, time.Now())
	fh.pcrs = map[int][]byte{0: nitroPCR(fh.label, 0), 1: nitroPCR(fh.label, 1), 2: nitroPCR(fh.label, 2)}
	fh.measure = Measurement(fh.pcrs[0])

	// Save originals.
	origOpenNSM := openNSMDevice
	origNsmDescribePCR := nsmDescribePCR
	origNsmGetAttestationDoc := nsmGetAttestationDoc
	origAwsKMSEncrypt := awsKMSEncrypt
	origAwsKMSDecrypt := awsKMSDecrypt
	origIsKMSAccessDenied := isKMSAccessDenied

	// Fake /dev/nsm — adapter just needs a non-nil *os.File handle.
	openNSMDevice = func(_ string) (*os.File, error) {
		f, err := os.CreateTemp("", "vg-fake-nsm-*")
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = os.Remove(f.Name()) })
		return f, nil
	}
	nsmDescribePCR = func(_ *os.File, idx int) ([]byte, error) {
		if pcr, ok := fh.pcrs[idx]; ok {
			return pcr, nil
		}
		return nil, fmt.Errorf("fake-nsm: PCR%d not set", idx)
	}
	nsmGetAttestationDoc = func(_ *os.File, req nsmAttestationRequest) ([]byte, error) {
		return fh.nitro.sign(t, nitroTestDoc{
			ModuleID:  "i-fake-" + fh.label,
			Timestamp: time.Now(),
			PCRs:      fh.pcrs,
			Nonce:     req.Nonce,
			UserData:  req.UserData,
		}), nil
	}

	// Fake KMS: AES-GCM with a key derived from the workload measurement;
	// EncryptionContext is the AAD so PCR-conditional access is enforced.
	fakeKMSKey := shared_crypto.SHA256Slice(append([]byte("fake-kms-key-"), fh.measure[:]...))
	awsKMSEncrypt = func(_, keyARN string, pt []byte, ec map[string]string) ([]byte, error) {
		if keyARN == "" {
			return nil, fmt.Errorf("fake-kms: empty keyARN")
		}
		aad := canonicalEC(ec)
		nonce, ct, err := shared_crypto.Seal(fakeKMSKey, pt, aad, nil)
		if err != nil {
			return nil, err
		}
		return append(nonce, ct...), nil
	}
	awsKMSDecrypt = func(_, keyARN string, blob []byte, ec map[string]string) ([]byte, error) {
		if keyARN == "" {
			return nil, fmt.Errorf("fake-kms: empty keyARN")
		}
		if len(blob) < shared_crypto.GCMNonceSize {
			return nil, fmt.Errorf("fake-kms: AccessDeniedException — truncated")
		}
		aad := canonicalEC(ec)
		nonce := blob[:shared_crypto.GCMNonceSize]
		ct := blob[shared_crypto.GCMNonceSize:]
		pt, err := shared_crypto.Open(fakeKMSKey, nonce, ct, aad)
		if err != nil {
			return nil, fmt.Errorf("fake-kms: AccessDeniedException — %v", err)
		}
		return pt, nil
	}
	isKMSAccessDenied = func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "AccessDeniedException")
	}

	t.Cleanup(func() {
		openNSMDevice = origOpenNSM
		nsmDescribePCR = origNsmDescribePCR
		nsmGetAttestationDoc = origNsmGetAttestationDoc
		awsKMSEncrypt = origAwsKMSEncrypt
		awsKMSDecrypt = origAwsKMSDecrypt
		isKMSAccessDenied = origIsKMSAccessDenied
		teeFakeMu.Unlock()
	})
}

// =============================================================================
// Azure SGX / Intel SGX shared fake harness
// =============================================================================

// installSGXFake wires fake SGX runtime for both Azure and Intel adapters
// (they share sgxCreateEnclave / dcapGetQuote / sgxECallSealData etc.).
// `mode` is either "maa" or "dcap" — switches which verifier-side helpers
// the fake populates.
func installSGXFake(t testing.TB, fh *fakeHardware, mode string) {
	t.Helper()
	teeFakeMu.Lock()

	// Save originals.
	origCreate := sgxCreateEnclave
	origDestroy := sgxDestroyEnclave
	origGetMRE := sgxGetMREnclave
	origCreateReport := sgxECallCreateReport
	origDcapGetQuote := dcapGetQuote
	origDcapVerify := dcapVerifyQuote
	origPccs := pccsFetchCollateral
	origSeal := sgxECallSealData
	origUnseal := sgxECallUnsealData
	origMaaSubmit := maaSubmitQuote
	origMaaJWT := verifyMAAJWT
	origHTTP := httpGetWithCacheBust
	origHsmWrap := hsmWrap
	origHsmUnwrap := hsmUnwrap

	// Sealing key derived from measurement (mimics MRENCLAVE-bound key).
	sealKey := shared_crypto.SHA256Slice(append([]byte("fake-sgx-seal-"), fh.measure[:]...))

	// Fake enclave handle — any non-zero uint64 the adapter can pass back.
	const fakeEnclaveID uint64 = 0xC0FFEE_BADD_FACE

	sgxCreateEnclave = func(_ string) (uint64, error) { return fakeEnclaveID, nil }
	sgxDestroyEnclave = func(_ uint64) error { return nil }
	sgxGetMREnclave = func(_ uint64) ([]byte, error) {
		out := make([]byte, 32)
		copy(out, fh.measure[:])
		return out, nil
	}
	sgxECallCreateReport = func(_ uint64, nonce []byte) ([]byte, error) {
		// Real path returns sgx_report_t (432 bytes); fake returns the
		// envelope body, dcapGetQuote then wraps it.
		return fh.signAttestation("sgx-report", nonce, nil), nil
	}
	dcapGetQuote = func(report []byte) ([]byte, error) {
		// Real path wraps sgx_report_t into sgx_quote3_t; fake passes the
		// envelope through verbatim. The Quote evidence MUST be ≥432 bytes
		// (adapter pre-check); our envelope is much larger.
		return report, nil
	}
	dcapVerifyQuote = func(quote, _ []byte) (*dcapVerdict, error) {
		att, err := fh.parseAttestation(quote)
		if err != nil {
			return &dcapVerdict{OK: false, Reason: err.Error()}, nil
		}
		return &dcapVerdict{
			OK: true,
			Claims: sgxClaims{
				MRENCLAVE:  att.Measurement,
				MRSIGNER:   att.MRSigner,
				ISVPRODID:  att.ISVPRODID,
				ISVSVN:     att.ISVSVN,
				ReportData: att.ReportData,
				Debug:      att.Debug,
			},
		}, nil
	}
	pccsFetchCollateral = func(_ string, _ Evidence) ([]byte, error) {
		// Fake collateral is a sentinel — dcapVerifyQuote ignores it.
		return []byte("fake-pccs-collateral"), nil
	}
	sgxECallSealData = func(_ uint64, plaintext, aad []byte, _ SGXSealPolicy) ([]byte, error) {
		nonce, ct, err := shared_crypto.Seal(sealKey, plaintext, aad, nil)
		if err != nil {
			return nil, err
		}
		return append(nonce, ct...), nil
	}
	sgxECallUnsealData = func(_ uint64, sealed, aad []byte) ([]byte, error) {
		if len(sealed) < shared_crypto.GCMNonceSize {
			return nil, fmt.Errorf("fake-sgx: sealed truncated")
		}
		return shared_crypto.Open(sealKey, sealed[:shared_crypto.GCMNonceSize], sealed[shared_crypto.GCMNonceSize:], aad)
	}

	if mode == "maa" {
		maaSubmitQuote = func(_ string, ev Evidence, _ Nonce) ([]byte, error) {
			// Fake JWT = the envelope; verifyMAAJWT below knows the format.
			return ev, nil
		}
		verifyMAAJWT = func(jwt []byte, _ []byte, _ time.Duration) (sgxClaims, error) {
			att, err := fh.parseAttestation(jwt)
			if err != nil {
				return sgxClaims{}, err
			}
			return sgxClaims{
				MRENCLAVE:  att.Measurement,
				MRSIGNER:   att.MRSigner,
				ISVPRODID:  att.ISVPRODID,
				ISVSVN:     att.ISVSVN,
				ReportData: att.ReportData,
				Debug:      att.Debug,
			}, nil
		}
		httpGetWithCacheBust = func(_ string) ([]byte, error) {
			// Fake JWKS — verifier just needs non-error.
			return []byte(`{"keys":[]}`), nil
		}
	}

	// HSM wrap layer (Intel bare-metal optional defense in depth).
	hsmKey := shared_crypto.SHA256Slice([]byte("fake-hsm-wrapping-key"))
	hsmWrap = func(_ string, sealed []byte) ([]byte, error) {
		nonce, ct, err := shared_crypto.Seal(hsmKey, sealed, []byte("hsm-aad"), nil)
		if err != nil {
			return nil, err
		}
		return append(nonce, ct...), nil
	}
	hsmUnwrap = func(_ string, wrapped []byte) ([]byte, error) {
		if len(wrapped) < shared_crypto.GCMNonceSize {
			return nil, fmt.Errorf("fake-hsm: truncated")
		}
		return shared_crypto.Open(hsmKey, wrapped[:shared_crypto.GCMNonceSize], wrapped[shared_crypto.GCMNonceSize:], []byte("hsm-aad"))
	}

	t.Cleanup(func() {
		sgxCreateEnclave = origCreate
		sgxDestroyEnclave = origDestroy
		sgxGetMREnclave = origGetMRE
		sgxECallCreateReport = origCreateReport
		dcapGetQuote = origDcapGetQuote
		dcapVerifyQuote = origDcapVerify
		pccsFetchCollateral = origPccs
		sgxECallSealData = origSeal
		sgxECallUnsealData = origUnseal
		maaSubmitQuote = origMaaSubmit
		verifyMAAJWT = origMaaJWT
		httpGetWithCacheBust = origHTTP
		hsmWrap = origHsmWrap
		hsmUnwrap = origHsmUnwrap
		teeFakeMu.Unlock()
	})
}

// =============================================================================
// GCP SEV-SNP fake harness
// =============================================================================

func installSEVSNPFake(t testing.TB, fh *fakeHardware) {
	t.Helper()
	teeFakeMu.Lock()

	origGuest := sevSNPGuestReport
	origParse := parseSEVSNPReport
	origAMD := amdKDSGetVCEK
	origChain := verifyAMDChain
	origReportSig := verifySEVReportSignature
	origDerivedKey := sevSNPDerivedKey
	origAEADSeal := sevAEADSeal
	origAEADOpen := sevAEADOpen

	// Track the last-emitted envelope so parseSEVSNPReport (called by
	// verifier on the raw evidence bytes) can recover the same struct
	// the producer emitted.
	sevSNPGuestReport = func(_ tsmReporter, nonce []byte, _ uint32) (*sevSNPReport, error) {
		raw := fh.signAttestation("sev-snp", nonce, nil)
		// Synthesize the *sevSNPReport struct fields from the fake
		// envelope. The verifier will call parseSEVSNPReport(raw) and get
		// an equivalent struct back.
		var meas [48]byte
		copy(meas[:32], fh.measure[:])
		var rd [64]byte
		rdHash := shared_crypto.SHA256(nonce)
		copy(rd[:], rdHash[:])
		return &sevSNPReport{
			Raw:         raw,
			Measurement: meas,
			HostData:    fh.hostData,
			ChipID:      fh.chipID,
			ReportedTCB: fh.reportedTCB,
			ReportData:  rd,
		}, nil
	}
	parseSEVSNPReport = func(raw []byte) (*sevSNPReport, error) {
		att, err := fh.parseAttestation(raw)
		if err != nil {
			return nil, err
		}
		var meas [48]byte
		copy(meas[:32], att.Measurement[:])
		return &sevSNPReport{
			Raw:           raw,
			Measurement:   meas,
			HostData:      att.HostData,
			ChipID:        att.ChipID,
			ReportedTCB:   att.ReportedTCB,
			ReportData:    att.ReportData,
			SignatureAlgo: 1, // ECDSA P-384, signed by the (fake) VCEK
		}, nil
	}
	amdKDSGetVCEK = func(_ string, _ [64]byte, _ uint64) ([]byte, error) {
		return []byte("-----BEGIN FAKE VCEK-----\nVG-FAKE-VCEK\n-----END FAKE VCEK-----"), nil
	}
	verifyAMDChain = func(_ []byte, _ []byte) error { return nil }
	verifySEVReportSignature = func(report *sevSNPReport, _ []byte) error {
		// The signature has already been verified inside parseSEVSNPReport
		// (which calls fh.parseAttestation). This helper exists in the
		// real adapter to verify the ECDSA-P384 over the report fields;
		// the fake leaves it as a no-op since round-trip integrity is
		// already guaranteed by the envelope's Ed25519 sig.
		if report == nil || len(report.Raw) == 0 {
			return fmt.Errorf("fake-sev: missing raw report")
		}
		return nil
	}

	derivedKey := shared_crypto.SHA256Slice(append([]byte("fake-sev-derived-"), fh.measure[:]...))
	sevSNPDerivedKey = func(_ *os.File, _ Measurement, _ uint64) ([]byte, error) {
		out := make([]byte, len(derivedKey))
		copy(out, derivedKey)
		return out, nil
	}
	sevAEADSeal = func(key, plaintext, aad []byte) ([]byte, error) {
		nonce, ct, err := shared_crypto.Seal(key, plaintext, aad, nil)
		if err != nil {
			return nil, err
		}
		return append(nonce, ct...), nil
	}
	sevAEADOpen = func(key, sealed, aad []byte) ([]byte, error) {
		if len(sealed) < shared_crypto.GCMNonceSize {
			return nil, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				"fake-sev: truncated sealed",
				nil,
			)
		}
		return shared_crypto.Open(key, sealed[:shared_crypto.GCMNonceSize], sealed[shared_crypto.GCMNonceSize:], aad)
	}

	t.Cleanup(func() {
		sevSNPGuestReport = origGuest
		parseSEVSNPReport = origParse
		amdKDSGetVCEK = origAMD
		verifyAMDChain = origChain
		verifySEVReportSignature = origReportSig
		sevSNPDerivedKey = origDerivedKey
		sevAEADSeal = origAEADSeal
		sevAEADOpen = origAEADOpen
		teeFakeMu.Unlock()
	})
}

// =============================================================================
// fakeFileForSEV — opens a temp file the SEV adapter can keep as device handle
// =============================================================================

func fakeFileForSEV(t testing.TB) *os.File {
	t.Helper()
	f, err := os.CreateTemp("", "vg-fake-sev-guest-*")
	if err != nil {
		t.Fatalf("fake sev device: %v", err)
	}
	t.Cleanup(func() { _ = f.Close(); _ = os.Remove(f.Name()) })
	return f
}
