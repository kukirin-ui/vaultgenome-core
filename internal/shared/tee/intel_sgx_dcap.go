// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — Intel SGX bare-metal adapter (DCAP attestation).
//
// This adapter targets on-premise SGX deployments — banks, sovereign
// installations, regulated medical AI vendors that want SGX without
// going through a hyperscaler. The flow is identical to azure_sgx.go's
// DCAP mode, but the verifier ships with its own PCCS pointer (no MAA
// option) and the producer assumes a directly-managed SGX driver.
//
// Why a separate adapter from Azure SGX:
//   - Azure SGX implies Microsoft Azure Attestation as a verification
//     path; bare-metal customers explicitly do not want a Microsoft
//     dependency.
//   - Bare-metal operators run their own PCCS (Provisioning Certificate
//     Caching Service) — they are responsible for keeping Intel
//     collateral fresh.
//   - Sealing policy on bare metal often combines SGX local sealing
//     with HSM-backed key wrapping, since the bare-metal operator
//     typically already has an HSM (Thales, Entrust, etc.).
//
// Key rotation + revocation:
//   - Intel publishes TCB recovery events when SGX vulnerabilities are
//     disclosed. Operators must update PCCS collateral + bump the
//     verifier's MinISVSVN when affected.
//   - The producer tracks its enclave's ISVSVN; when Intel revokes the
//     prior version, the producer enclave must be rebuilt + re-signed.

package tee

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// IntelSGXProducerConfig configures a bare-metal SGX producer.
type IntelSGXProducerConfig struct {
	EnclaveSOPath string
	QPLPath       string

	// HSMSlot, if non-empty, names a PKCS#11 slot used to wrap the
	// enclave's sealing key (defense-in-depth for sovereign deployments).
	HSMSlot string
}

// IntelSGXVerifierConfig configures the bare-metal verifier.
type IntelSGXVerifierConfig struct {
	// PCCSURL is required (no MAA fallback in bare-metal mode).
	PCCSURL string

	// AcceptableMRENCLAVES + AcceptableMRSIGNERS define the policy.
	AcceptableMRENCLAVES []Measurement
	AcceptableMRSIGNERS  [][32]byte
	MinISVSVN            uint16

	// IntelRootPEM overrides the embedded Intel SGX Root CA.
	IntelRootPEM []byte

	// CollateralRefreshInterval. Default 24h.
	CollateralRefreshInterval time.Duration

	MaxClockSkew time.Duration
}

// IntelSGXProducer implements Producer for SGX on bare metal.
type IntelSGXProducer struct {
	cfg         IntelSGXProducerConfig
	measurement Measurement

	mu        sync.Mutex
	enclaveID uint64
	loaded    bool
}

// IntelSGXVerifier implements Verifier for DCAP-only quote verification.
type IntelSGXVerifier struct {
	cfg          IntelSGXVerifierConfig
	expected     Measurement
	mrSigners    [][32]byte
	mrEnclaves   []Measurement
	minISVSVN    uint16
	maxClockSkew time.Duration
}

// IntelSGXSealer implements Sealer using SGX local sealing + optional
// HSM wrap.
type IntelSGXSealer struct {
	enclaveID uint64
	policy    SGXSealPolicy
	hsmSlot   string
}

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

func NewIntelSGXProducer(cfg IntelSGXProducerConfig) (*IntelSGXProducer, error) {
	if cfg.EnclaveSOPath == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"intel-sgx: enclave_so_path is required",
			nil,
		)
	}
	p := &IntelSGXProducer{cfg: cfg}

	eid, err := sgxCreateEnclave(cfg.EnclaveSOPath)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("intel-sgx: load enclave: %v", err),
			err,
		)
	}
	p.enclaveID = eid

	mre, err := sgxGetMREnclave(eid)
	if err != nil {
		_ = sgxDestroyEnclave(eid)
		return nil, fmt.Errorf("intel-sgx: read MRENCLAVE: %w", err)
	}
	if len(mre) != 32 {
		_ = sgxDestroyEnclave(eid)
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"intel-sgx: MRENCLAVE not 32 bytes",
			nil,
		)
	}
	p.measurement = append(Measurement(nil), mre...)
	p.loaded = true
	return p, nil
}

func NewIntelSGXVerifier(_ crypto.PublicKey, expected Measurement, cfg IntelSGXVerifierConfig) (*IntelSGXVerifier, error) {
	if cfg.PCCSURL == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"intel-sgx: pccs_url is required (bare-metal mode does not support MAA fallback)",
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
	return &IntelSGXVerifier{
		cfg:          cfg,
		expected:     expected,
		mrEnclaves:   mre,
		mrSigners:    cfg.AcceptableMRSIGNERS,
		minISVSVN:    cfg.MinISVSVN,
		maxClockSkew: cfg.MaxClockSkew,
	}, nil
}

func NewIntelSGXSealer(enclaveID uint64, policy SGXSealPolicy, hsmSlot string) (*IntelSGXSealer, error) {
	if policy != SGXSealMRENCLAVE && policy != SGXSealMRSIGNER {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"intel-sgx: unknown SGXSealPolicy",
			nil,
		)
	}
	return &IntelSGXSealer{enclaveID: enclaveID, policy: policy, hsmSlot: hsmSlot}, nil
}

// ----------------------------------------------------------------------------
// Producer / Verifier / Sealer
// ----------------------------------------------------------------------------

func (p *IntelSGXProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"intel-sgx: nonce too short",
			nil,
		)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.loaded {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"intel-sgx: enclave not loaded",
			nil,
		)
	}
	report, err := sgxECallCreateReport(p.enclaveID, nonce)
	if err != nil {
		return nil, fmt.Errorf("intel-sgx: create_report: %w", err)
	}
	quote, err := dcapGetQuote(report)
	if err != nil {
		return nil, fmt.Errorf("intel-sgx: dcap_get_quote: %w", err)
	}
	return Evidence(quote), nil
}

func (p *IntelSGXProducer) Measurement() Measurement {
	return p.measurement
}

// EnclaveID exposes the enclave handle so acpctl recover can construct a
// Sealer that shares this producer's loaded enclave.
func (p *IntelSGXProducer) EnclaveID() uint64 {
	return p.enclaveID
}

func (p *IntelSGXProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.loaded {
		return nil
	}
	err := sgxDestroyEnclave(p.enclaveID)
	p.loaded = false
	return err
}

func (v *IntelSGXVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	var zero Measurement
	if len(nonce) < NonceMinBytes {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"intel-sgx: challenger nonce too short",
			nil,
		)
	}
	if len(ev) < 432 {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"intel-sgx: evidence too short",
			nil,
		)
	}

	collateral, err := pccsFetchCollateral(v.cfg.PCCSURL, ev)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("intel-sgx: collateral: %v", err),
			err,
		)
	}
	verdict, err := dcapVerifyQuote(ev, collateral)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("intel-sgx: dcap verify: %v", err),
			err,
		)
	}
	if !verdict.OK {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("intel-sgx: dcap verdict: %s", verdict.Reason),
			nil,
		)
	}

	if !nonceMatchesReportData(verdict.Claims.ReportData, nonce) {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"intel-sgx: REPORT_DATA does not bind nonce",
			nil,
		)
	}
	if verdict.Claims.ISVSVN < v.minISVSVN {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("intel-sgx: ISVSVN %d below minimum %d", verdict.Claims.ISVSVN, v.minISVSVN),
			nil,
		)
	}

	matchedMRE := false
	for _, m := range v.mrEnclaves {
		if m.Equal(verdict.Claims.MRENCLAVE[:]) {
			matchedMRE = true
			break
		}
	}
	if !matchedMRE {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("intel-sgx: MRENCLAVE %x not in acceptable set", verdict.Claims.MRENCLAVE),
			nil,
		)
	}

	if len(v.mrSigners) > 0 {
		matchedSigner := false
		for _, m := range v.mrSigners {
			if m == verdict.Claims.MRSIGNER {
				matchedSigner = true
				break
			}
		}
		if !matchedSigner {
			return zero, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("intel-sgx: MRSIGNER %x not in acceptable set", verdict.Claims.MRSIGNER),
				nil,
			)
		}
	}

	return Measurement(verdict.Claims.MRENCLAVE[:]), nil
}

func (s *IntelSGXSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	sealed, err := sgxECallSealData(s.enclaveID, plaintext, aad, s.policy)
	if err != nil {
		return nil, fmt.Errorf("intel-sgx-sealer: seal: %w", err)
	}
	if s.hsmSlot != "" {
		// Defense-in-depth: wrap the SGX-sealed blob with an HSM key.
		// Phase 2 wiring: github.com/miekg/pkcs11 to Thales / Entrust /
		// SoftHSM. The HSM wrapping protects against an attacker who has
		// physical access + can extract the SGX sealing key (a weak but
		// theoretical attack against bare-metal SGX).
		wrapped, err := hsmWrap(s.hsmSlot, sealed)
		if err != nil {
			return nil, fmt.Errorf("intel-sgx-sealer: HSM wrap: %w", err)
		}
		return wrapped, nil
	}
	return sealed, nil
}

func (s *IntelSGXSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	if s.hsmSlot != "" {
		unwrapped, err := hsmUnwrap(s.hsmSlot, sealed)
		if err != nil {
			return nil, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("intel-sgx-sealer: HSM unwrap: %v", err),
				err,
			)
		}
		sealed = unwrapped
	}
	plaintext, err := sgxECallUnsealData(s.enclaveID, sealed, aad)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("intel-sgx-sealer: unseal: %v", err),
			err,
		)
	}
	return plaintext, nil
}

// ----------------------------------------------------------------------------
// Capability
// ----------------------------------------------------------------------------

func intelSGXCapability() (bool, string) {
	if _, err := os.Stat("/dev/sgx_enclave"); err == nil {
		return true, "Intel SGX (bare metal): /dev/sgx_enclave present"
	}
	if _, err := os.Stat("/dev/isgx"); err == nil {
		return true, "Intel SGX (bare metal): /dev/isgx present"
	}
	return false, "Intel SGX (bare metal): no SGX device — install intel-sgx-dcap-driver or upgrade to kernel ≥ 5.11"
}

// ----------------------------------------------------------------------------
// PKCS#11 / HSM stubs (Phase 2 wiring)
// ----------------------------------------------------------------------------

var hsmWrap = func(_ string, _ []byte) ([]byte, error) {
	return nil, errors.New("hsmWrap: not yet wired (Phase 2 — github.com/miekg/pkcs11)")
}

var hsmUnwrap = func(_ string, _ []byte) ([]byte, error) {
	return nil, errors.New("hsmUnwrap: not yet wired (Phase 2)")
}

// Compile-time interface conformance.
var (
	_ Producer = (*IntelSGXProducer)(nil)
	_ Verifier = (*IntelSGXVerifier)(nil)
	_ Sealer   = (*IntelSGXSealer)(nil)
)
