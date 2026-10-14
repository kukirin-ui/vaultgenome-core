// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — Azure Confidential Computing (Intel SGX via MAA) adapter.
//
// Azure exposes SGX-capable VMs in the DCsv2 / DCsv3 / DCdsv3 SKU series.
// Inside an SGX enclave running on these VMs the producer:
//
//  1. Generates an SGX Quote using libsgx_dcap_ql + libsgx_quote_3
//     (DCAP SDK). The Quote includes:
//        - SGX Report (REPORT_BODY): MRENCLAVE (32B) + MRSIGNER (32B) +
//          ISVPRODID (2B) + ISVSVN (2B) + REPORT_DATA (64B, holds nonce
//          + bound public key)
//        - QE (Quoting Enclave) report
//        - QE auth data
//        - ECDSA-P256 signature by the platform's attestation key (PCK)
//        - PCK certificate (root: Intel SGX Root CA)
//
//  2. Submits the Quote to Microsoft Azure Attestation (MAA) at
//     https://<region>.attest.azure.net for verification + JWT issuance.
//     MAA returns a signed JWT with claims like x-ms-sgx-mrenclave,
//     x-ms-sgx-mrsigner, x-ms-sgx-product-id, x-ms-sgx-svn, x-ms-attestation-type.
//
// Verification can use either:
//   - MAA JWT (online, depends on Microsoft availability) — convenient
//     for cloud-native deployments.
//   - DCAP local verification (offline, deterministic) — preferred for
//     air-gapped or sovereign deployments. Uses libsgx_dcap_quoteverify
//     + Intel collateral served from a local PCCS.
//
// Both modes are supported; choose via AzureSGXVerifierConfig.Mode.
//
// Sealing on Azure SGX uses the SGX Sealing Key API
// (sgx_seal_data / sgx_unseal_data) with MRENCLAVE binding. Sealed data
// can only be unsealed by the SAME enclave on the SAME platform.

package tee

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// AzureSGXVerifierMode chooses online (MAA) vs offline (DCAP) verification.
type AzureSGXVerifierMode string

const (
	// AzureSGXModeMAA verifies the SGX quote by submitting it to
	// Microsoft Azure Attestation and validating the returned JWT
	// signature against MAA's published JWKS.
	AzureSGXModeMAA AzureSGXVerifierMode = "maa"

	// AzureSGXModeDCAP verifies the quote locally using libsgx_dcap_quoteverify
	// and Intel-published collateral (TCB info, QE identity, PCK CRL)
	// served from a local PCCS at Cfg.PCCSURL.
	AzureSGXModeDCAP AzureSGXVerifierMode = "dcap"
)

// AzureSGXProducerConfig configures an Intel SGX enclave producer.
type AzureSGXProducerConfig struct {
	// EnclaveSOPath is the path to the .signed.so SGX enclave shared
	// object loaded into this process (the Vault Genome enclave image).
	EnclaveSOPath string

	// QPLPath overrides the default Quote Provider Library path
	// ("/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so" on Ubuntu).
	QPLPath string

	// AttestKeyType is "ecdsa" (default) or "epid". ECDSA is the only
	// option for DCAP attestation flows; EPID is legacy (deprecated by
	// Intel as of 2024 for new deployments).
	AttestKeyType string
}

// AzureSGXVerifierConfig configures the SGX quote verifier.
type AzureSGXVerifierConfig struct {
	Mode AzureSGXVerifierMode

	// MAA settings (used if Mode == MAA).
	MAAEndpoint string // e.g. https://sharedeus.eus.attest.azure.net
	MAAJWKSURL  string // optional override; default derived from endpoint

	// DCAP settings (used if Mode == DCAP).
	PCCSURL                   string // local PCCS, e.g. https://localhost:8081/sgx/certification/v4
	CollateralRefreshInterval time.Duration

	// Acceptable enclave identity components. ALL non-empty fields must
	// match the quote's REPORT_BODY for verification to succeed.
	AcceptableMRENCLAVES []Measurement
	AcceptableMRSIGNERS  [][32]byte
	MinISVSVN            uint16

	// MaxClockSkew is enforced when Mode == MAA (JWT timestamps).
	MaxClockSkew time.Duration
}

// AzureSGXProducer implements Producer using SGX DCAP quote generation.
type AzureSGXProducer struct {
	cfg         AzureSGXProducerConfig
	measurement Measurement // MRENCLAVE of the loaded enclave

	mu          sync.Mutex
	enclaveID   uint64 // SGX enclave handle (sgx_enclave_id_t)
	initialized bool
}

// AzureSGXVerifier implements Verifier for SGX quotes using either MAA
// or local DCAP verification.
type AzureSGXVerifier struct {
	cfg          AzureSGXVerifierConfig
	expected     Measurement
	mrSigners    [][32]byte
	mrEnclaves   []Measurement
	minISVSVN    uint16
	maxClockSkew time.Duration

	mu        sync.Mutex
	jwksCache []byte
	jwksAt    time.Time
}

// AzureSGXSealer implements Sealer using the SGX Sealing Key API.
type AzureSGXSealer struct {
	enclaveID    uint64
	policy       SGXSealPolicy
	keyPolicyKID string // human-readable identifier for diagnostics
}

// SGXSealPolicy chooses MRENCLAVE-only vs MRSIGNER-flexible sealing.
type SGXSealPolicy int

const (
	// SGXSealMRENCLAVE binds sealed data to this exact enclave image.
	// Rebuilding the enclave invalidates all previously sealed data.
	// Most secure; required for keys that must never survive an upgrade.
	SGXSealMRENCLAVE SGXSealPolicy = 1

	// SGXSealMRSIGNER binds to the enclave's signing identity (the
	// developer's signing key). Allows enclave updates to unseal old
	// data, supporting graceful upgrade.
	SGXSealMRSIGNER SGXSealPolicy = 2
)

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

// NewAzureSGXProducer loads the SGX enclave and prepares the DCAP
// quoting infrastructure. Returns Structural error if SGX is not
// available on this CPU/OS, or the enclave .so cannot be loaded.
func NewAzureSGXProducer(cfg AzureSGXProducerConfig) (*AzureSGXProducer, error) {
	if cfg.EnclaveSOPath == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"azure-sgx: enclave_so_path is required",
			nil,
		)
	}
	if cfg.AttestKeyType == "" {
		cfg.AttestKeyType = "ecdsa"
	}

	p := &AzureSGXProducer{cfg: cfg}

	// Load the enclave from disk; sgx_create_enclave returns a handle
	// (sgx_enclave_id_t) we use for all subsequent ECALLs.
	eid, err := sgxCreateEnclave(cfg.EnclaveSOPath)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("azure-sgx: load enclave %s: %v", cfg.EnclaveSOPath, err),
			err,
		)
	}
	p.enclaveID = eid

	// Read MRENCLAVE for caching as our Measurement. This is the
	// SHA-256 of the enclave page contents at load time and is
	// deterministic across rebuilds with the same source + Intel SDK
	// version.
	mre, err := sgxGetMREnclave(eid)
	if err != nil {
		_ = sgxDestroyEnclave(eid)
		return nil, fmt.Errorf("azure-sgx: read MRENCLAVE: %w", err)
	}
	if len(mre) != 32 {
		_ = sgxDestroyEnclave(eid)
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"azure-sgx: MRENCLAVE not 32 bytes",
			nil,
		)
	}
	p.measurement = append(Measurement(nil), mre...)
	p.initialized = true
	return p, nil
}

// NewAzureSGXVerifier constructs a verifier for SGX quotes.
func NewAzureSGXVerifier(_ crypto.PublicKey, expected Measurement, cfg AzureSGXVerifierConfig) (*AzureSGXVerifier, error) {
	if cfg.Mode == "" {
		cfg.Mode = AzureSGXModeMAA
	}
	if cfg.Mode == AzureSGXModeMAA && cfg.MAAEndpoint == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"azure-sgx: MAA mode requires maa_endpoint",
			nil,
		)
	}
	if cfg.Mode == AzureSGXModeDCAP && cfg.PCCSURL == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"azure-sgx: DCAP mode requires pccs_url",
			nil,
		)
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}
	if cfg.CollateralRefreshInterval == 0 {
		cfg.CollateralRefreshInterval = 24 * time.Hour
	}

	mre := cfg.AcceptableMRENCLAVES
	if len(mre) == 0 {
		mre = []Measurement{expected}
	}
	return &AzureSGXVerifier{
		cfg:          cfg,
		expected:     expected,
		mrSigners:    cfg.AcceptableMRSIGNERS,
		mrEnclaves:   mre,
		minISVSVN:    cfg.MinISVSVN,
		maxClockSkew: cfg.MaxClockSkew,
	}, nil
}

// NewAzureSGXSealer constructs a sealer bound to this enclave's
// MRENCLAVE or MRSIGNER (per policy).
func NewAzureSGXSealer(enclaveID uint64, policy SGXSealPolicy, kidLabel string) (*AzureSGXSealer, error) {
	if policy != SGXSealMRENCLAVE && policy != SGXSealMRSIGNER {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"azure-sgx: unknown SGXSealPolicy",
			nil,
		)
	}
	return &AzureSGXSealer{
		enclaveID:    enclaveID,
		policy:       policy,
		keyPolicyKID: kidLabel,
	}, nil
}

// ----------------------------------------------------------------------------
// Producer / Verifier / Sealer
// ----------------------------------------------------------------------------

// Quote implements Producer. Generates an SGX Quote bound to the
// challenger nonce + (optional) caller-supplied REPORT_DATA. The Quote
// is returned as Evidence; the verifier parses it.
//
// REPORT_DATA layout (64 bytes):
//
//	[0:32]    SHA-256(nonce) — binds the quote to challenger freshness
//	[32:64]   reserved (zero in V1)
func (p *AzureSGXProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"azure-sgx: nonce must be at least NonceMinBytes",
			nil,
		)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.initialized {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"azure-sgx: enclave not initialised",
			nil,
		)
	}

	// Step 1: ECALL into enclave to produce an sgx_report_t with
	// REPORT_DATA = SHA-256(nonce) || 0×32. The enclave uses sgx_create_report.
	report, err := sgxECallCreateReport(p.enclaveID, nonce)
	if err != nil {
		return nil, fmt.Errorf("azure-sgx: enclave create_report: %w", err)
	}

	// Step 2: Untrusted-side calls libsgx_dcap_ql to convert the
	// sgx_report_t into a full sgx_quote3_t, which includes the
	// platform attestation key signature and PCK certificate.
	quote, err := dcapGetQuote(report)
	if err != nil {
		return nil, fmt.Errorf("azure-sgx: dcap_get_quote: %w", err)
	}
	return Evidence(quote), nil
}

// Measurement returns the cached MRENCLAVE.
func (p *AzureSGXProducer) Measurement() Measurement {
	return p.measurement
}

// EnclaveID returns the loaded enclave's sgx_enclave_id_t handle. Used
// by acpctl recover to wire a Sealer that shares the producer's loaded
// enclave instead of re-loading the .signed.so a second time.
func (p *AzureSGXProducer) EnclaveID() uint64 {
	return p.enclaveID
}

// Close destroys the SGX enclave handle.
func (p *AzureSGXProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.initialized {
		return nil
	}
	err := sgxDestroyEnclave(p.enclaveID)
	p.initialized = false
	return err
}

// Verify implements Verifier. Dispatches to the configured mode.
func (v *AzureSGXVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	var zero Measurement
	if len(nonce) < NonceMinBytes {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"azure-sgx: challenger nonce too short",
			nil,
		)
	}
	if len(ev) < 432 {
		// sgx_quote3_t minimum size (header + report body + sig data length)
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"azure-sgx: evidence too short for SGX quote",
			nil,
		)
	}

	switch v.cfg.Mode {
	case AzureSGXModeMAA:
		return v.verifyMAA(ev, nonce)
	case AzureSGXModeDCAP:
		return v.verifyDCAP(ev, nonce)
	default:
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("azure-sgx: unknown verifier mode %q", v.cfg.Mode),
			nil,
		)
	}
}

// verifyMAA submits the quote to Microsoft Azure Attestation, parses
// the returned JWT, and verifies its signature against MAA's JWKS.
func (v *AzureSGXVerifier) verifyMAA(quote Evidence, nonce Nonce) (Measurement, error) {
	var zero Measurement

	jwt, err := maaSubmitQuote(v.cfg.MAAEndpoint, quote, nonce)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("azure-sgx: MAA submit: %v", err),
			err,
		)
	}

	jwks, err := v.fetchJWKS()
	if err != nil {
		return zero, fmt.Errorf("azure-sgx: fetch JWKS: %w", err)
	}

	claims, err := verifyMAAJWT(jwt, jwks, v.maxClockSkew)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("azure-sgx: JWT verify: %v", err),
			err,
		)
	}

	return v.applyPolicy(claims, nonce)
}

// verifyDCAP verifies the quote locally using libsgx_dcap_quoteverify
// + Intel collateral served by a local PCCS.
func (v *AzureSGXVerifier) verifyDCAP(quote Evidence, nonce Nonce) (Measurement, error) {
	var zero Measurement

	collateral, err := pccsFetchCollateral(v.cfg.PCCSURL, quote)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("azure-sgx: fetch collateral: %v", err),
			err,
		)
	}

	verdict, err := dcapVerifyQuote(quote, collateral)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("azure-sgx: dcap verify: %v", err),
			err,
		)
	}
	if !verdict.OK {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("azure-sgx: dcap verdict: %s", verdict.Reason),
			nil,
		)
	}

	return v.applyPolicy(verdict.Claims, nonce)
}

// applyPolicy compares attestation claims against the verifier's
// acceptable identity set. Returns the matched MRENCLAVE on success.
func (v *AzureSGXVerifier) applyPolicy(claims sgxClaims, nonce Nonce) (Measurement, error) {
	var zero Measurement

	if !nonceMatchesReportData(claims.ReportData, nonce) {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"azure-sgx: REPORT_DATA does not bind challenger nonce (replay?)",
			nil,
		)
	}

	if claims.ISVSVN < v.minISVSVN {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("azure-sgx: ISVSVN %d below minimum %d (revoked enclave version)", claims.ISVSVN, v.minISVSVN),
			nil,
		)
	}

	matchedMRE := false
	for _, m := range v.mrEnclaves {
		if m.Equal(claims.MRENCLAVE[:]) {
			matchedMRE = true
			break
		}
	}
	if !matchedMRE {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("azure-sgx: MRENCLAVE %x not in acceptable set", claims.MRENCLAVE),
			nil,
		)
	}

	if len(v.mrSigners) > 0 {
		matchedSigner := false
		for _, m := range v.mrSigners {
			if m == claims.MRSIGNER {
				matchedSigner = true
				break
			}
		}
		if !matchedSigner {
			return zero, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("azure-sgx: MRSIGNER %x not in acceptable set", claims.MRSIGNER),
				nil,
			)
		}
	}

	return Measurement(claims.MRENCLAVE[:]), nil
}

// fetchJWKS retrieves Microsoft Azure Attestation's JSON Web Key Set
// for JWT signature verification, with simple in-memory caching.
func (v *AzureSGXVerifier) fetchJWKS() ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.jwksCache != nil && time.Since(v.jwksAt) < v.cfg.CollateralRefreshInterval {
		return v.jwksCache, nil
	}
	url := v.cfg.MAAJWKSURL
	if url == "" {
		url = v.cfg.MAAEndpoint + "/certs"
	}
	jwks, err := httpGetWithCacheBust(url)
	if err != nil {
		return nil, err
	}
	v.jwksCache = jwks
	v.jwksAt = time.Now()
	return jwks, nil
}

// Seal implements Sealer using SGX sealing key (MRENCLAVE or MRSIGNER bound).
func (s *AzureSGXSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	sealed, err := sgxECallSealData(s.enclaveID, plaintext, aad, s.policy)
	if err != nil {
		return nil, fmt.Errorf("azure-sgx-sealer: seal: %w", err)
	}
	return sealed, nil
}

// Unseal implements Sealer.
func (s *AzureSGXSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	plaintext, err := sgxECallUnsealData(s.enclaveID, sealed, aad)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("azure-sgx-sealer: unseal: %v (sealing key mismatch?)", err),
			err,
		)
	}
	return plaintext, nil
}

// ----------------------------------------------------------------------------
// Capability
// ----------------------------------------------------------------------------

func azureSGXCapability() (bool, string) {
	// Real check: cpuid leaf 0x07 sub 0 EBX bit 2 (SGX1), plus the
	// presence of /dev/sgx_enclave (mainline kernel ≥ 5.11) or
	// /dev/isgx (legacy DCAP driver).
	if _, err := os.Stat("/dev/sgx_enclave"); err == nil {
		return true, "Azure SGX: /dev/sgx_enclave present (in-kernel driver)"
	}
	if _, err := os.Stat("/dev/isgx"); err == nil {
		return true, "Azure SGX: /dev/isgx present (DCAP out-of-tree driver)"
	}
	return false, "Azure SGX: no /dev/sgx_enclave or /dev/isgx — host lacks SGX support"
}

// ----------------------------------------------------------------------------
// SGX SDK + MAA stubs (Phase 2 wiring)
// ----------------------------------------------------------------------------

type sgxClaims struct {
	MRENCLAVE  [32]byte
	MRSIGNER   [32]byte
	ISVPRODID  uint16
	ISVSVN     uint16
	ReportData [64]byte
	Debug      bool
}

type dcapVerdict struct {
	OK     bool
	Reason string
	Claims sgxClaims
}

// sgxCreateEnclave wraps sgx_create_enclave (Intel SGX SDK).
//
// Phase 2 wiring: cgo binding to libsgx_urts. The Go side passes the
// path to the .signed.so enclave file; libsgx_urts loads it into
// protected memory and returns sgx_enclave_id_t (uint64).
//
// Stored as a var so integration tests can substitute a fake SGX runtime.
var sgxCreateEnclave = func(_ string) (uint64, error) {
	return 0, errors.New("sgxCreateEnclave: not yet wired to Intel SGX SDK (Phase 2 — cgo bind libsgx_urts)")
}

// sgxDestroyEnclave wraps sgx_destroy_enclave.
var sgxDestroyEnclave = func(_ uint64) error {
	return errors.New("sgxDestroyEnclave: not yet wired (Phase 2)")
}

// sgxGetMREnclave reads MRENCLAVE from the loaded enclave's measurement.
var sgxGetMREnclave = func(_ uint64) ([]byte, error) {
	return nil, errors.New("sgxGetMREnclave: not yet wired (Phase 2 — sgx_get_measurement_t via custom ECALL)")
}

// sgxECallCreateReport invokes an enclave ECALL that produces an
// sgx_report_t with REPORT_DATA = SHA-256(nonce) || zeros(32).
var sgxECallCreateReport = func(_ uint64, _ []byte) ([]byte, error) {
	return nil, errors.New("sgxECallCreateReport: not yet wired (Phase 2 — define ECALL in enclave EDL)")
}

// dcapGetQuote calls libsgx_dcap_ql sgx_qe_get_quote().
var dcapGetQuote = func(_ []byte) ([]byte, error) {
	return nil, errors.New("dcapGetQuote: not yet wired (Phase 2 — cgo bind libsgx_dcap_ql)")
}

var dcapVerifyQuote = func(_ []byte, _ []byte) (*dcapVerdict, error) {
	return nil, errors.New("dcapVerifyQuote: not yet wired (Phase 2 — cgo bind libsgx_dcap_quoteverify)")
}

var pccsFetchCollateral = func(_ string, _ Evidence) ([]byte, error) {
	return nil, errors.New("pccsFetchCollateral: not yet wired (Phase 2 — HTTP GET to PCCS endpoint)")
}

var sgxECallSealData = func(_ uint64, _, _ []byte, _ SGXSealPolicy) ([]byte, error) {
	return nil, errors.New("sgxECallSealData: not yet wired (Phase 2 — ECALL wrapping sgx_seal_data)")
}

var sgxECallUnsealData = func(_ uint64, _, _ []byte) ([]byte, error) {
	return nil, errors.New("sgxECallUnsealData: not yet wired (Phase 2)")
}

var maaSubmitQuote = func(_ string, _ Evidence, _ Nonce) ([]byte, error) {
	return nil, errors.New("maaSubmitQuote: not yet wired (Phase 2 — POST to MAA REST API)")
}

var verifyMAAJWT = func(_ []byte, _ []byte, _ time.Duration) (sgxClaims, error) {
	return sgxClaims{}, errors.New("verifyMAAJWT: not yet wired (Phase 2 — github.com/golang-jwt/jwt/v5 + RS256/ES256)")
}

var httpGetWithCacheBust = func(_ string) ([]byte, error) {
	return nil, errors.New("httpGetWithCacheBust: not yet wired (Phase 2 — net/http with no-cache headers)")
}

func nonceMatchesReportData(reportData [64]byte, nonce []byte) bool {
	// The producer should put SHA-256(nonce) in the first 32 bytes of
	// REPORT_DATA. Compare that here.
	expected := computeReportDataPrefix(nonce)
	for i := 0; i < 32; i++ {
		if reportData[i] != expected[i] {
			return false
		}
	}
	return true
}

func computeReportDataPrefix(nonce []byte) [32]byte {
	// REPORT_DATA[0:32] = SHA-256(nonce). The producer enclave computes
	// this inside an ECALL via sgx_create_report; the verifier recomputes
	// it here to confirm the quote is bound to the challenger's nonce.
	return shared_crypto.SHA256(nonce)
}

// Compile-time interface conformance.
var (
	_ Producer = (*AzureSGXProducer)(nil)
	_ Verifier = (*AzureSGXVerifier)(nil)
	_ Sealer   = (*AzureSGXSealer)(nil)
)
