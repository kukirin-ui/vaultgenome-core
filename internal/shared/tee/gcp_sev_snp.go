// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — Google Cloud Confidential VMs (AMD SEV-SNP) adapter.
//
// GCP Confidential VMs (N2D-confidential, C3D-confidential) run on AMD
// EPYC processors with SEV-SNP (Secure Encrypted Virtualization with
// Secure Nested Paging) enabled. The producer requests attestation
// reports (1184 bytes) through the kernel's configfs-tsm interface
// (tsm_configfs.go; Linux ≥ 6.7), which fronts the sev-guest driver
// with plain file I/O. The sealer asks the firmware for a derived key
// through /dev/sev-guest (SNP_GET_DERIVED_KEY; gcp_sev_snp_seal.go).
//
// The attestation report contains:
//
//   - VERSION (1B)
//   - GUEST_SVN, POLICY (8B): firmware version + guest policy bits
//   - FAMILY_ID, IMAGE_ID (32B): caller-defined VM identity
//   - VMPL (4B): Virtual Machine Privilege Level (0 = full)
//   - SIGNATURE_ALGO (4B): typically 1 = ECDSA-P384-SHA384
//   - PLATFORM_INFO (8B), PLATFORM_VERSION (8B)
//   - REPORT_DATA (64B): caller-supplied — we put SHA-256(nonce) here
//   - MEASUREMENT (48B): the launch measurement (SHA-384 of guest
//     pages at launch — carried whole as our Measurement, ADR 0007)
//   - HOST_DATA (32B), ID_KEY_DIGEST (48B), AUTHOR_KEY_DIGEST (48B)
//   - REPORT_ID (32B), REPORT_ID_MA (32B)
//   - REPORTED_TCB (8B), CPUID (24B)
//   - CHIP_ID (64B), COMMITTED_TCB / CURRENT_TCB
//   - SIGNATURE (512B): ECDSA-P384 by VCEK (Versioned Chip Endorsement Key)
//
// The VCEK is unique per CPU; AMD signs it with their AMD SEV-SNP
// signing key, which chains to the AMD Root CA. Verification:
//
//   1. Fetch VCEK certificate from AMD KDS using CHIP_ID + reported TCB
//      (URL: https://kdsintf.amd.com/vcek/v1/Milan/<CHIP_ID>?...)
//   2. Validate VCEK chain: VCEK ← ASK (Milan/Genoa) ← ARK (AMD Root)
//   3. Verify ECDSA-P384 signature over the report (excluding signature)
//   4. Check freshness via REPORT_DATA nonce binding
//   5. Check launch MEASUREMENT against expected
//
// Sealing on SEV-SNP uses derived keys from the platform sealing root.
// Unlike SGX, SEV-SNP sealing is not transparent — the guest must
// derive its own AES key from the SEV_SNP_GUEST_MSG_DERIVED_KEY
// response, then use it for AEAD. The derivation can be bound to the
// guest policy + measurement so that a different VM image cannot
// reproduce the key.

package tee

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// GCPSEVProducerConfig configures the SEV-SNP producer.
type GCPSEVProducerConfig struct {
	// TSMReportDir is the configfs-tsm report directory. Default
	// DefaultTSMReportDir ("/sys/kernel/config/tsm/report").
	TSMReportDir string

	// VMPL is the Virtual Machine Privilege Level requested in the
	// attestation report (0–3). Default 0 = full guest privilege.
	VMPL uint32
}

// GCPSEVVerifierConfig configures the SEV-SNP verifier.
type GCPSEVVerifierConfig struct {
	// AMDKDSURL overrides the default https://kdsintf.amd.com base URL.
	// Useful for air-gapped / mirrored deployments that cache VCEK
	// responses locally (Google publishes a mirror at
	// https://confidentialcomputing.googleapis.com/v1/...).
	AMDKDSURL string

	// AMDRootPEM overrides the pinned AMD ARK certificate (for sovereign
	// installations using their own pinned trust anchor). Default uses
	// the AMD-published Milan / Genoa / Turin roots embedded at build.
	AMDRootPEM []byte

	// AcceptableMeasurements lists every launch measurement the verifier
	// will accept. When empty, falls back to VerifierSpec.ExpectedMeasurement.
	AcceptableMeasurements []Measurement

	// MinReportedTCB enforces minimum AMD secure firmware version. Set
	// to the current TCB at deployment time and bump on AMD security
	// advisories.
	MinReportedTCB uint64

	// MaxClockSkew bounds REPORT freshness using either REPORT_ID or
	// an external timestamp service. Default 5 minutes.
	MaxClockSkew time.Duration

	// VMPL is the privilege level the attested workload runs at; a
	// report requested from any other level is refused. Default 0.
	VMPL uint32

	// VCEKCacheDir, when set, keeps every VCEK fetched from AMD KDS on
	// disk (one DER file per CHIP_ID and TCB) and reads it back instead
	// of asking KDS again — KDS rate-limits (HTTP 429) quickly, and a
	// one-shot verifier such as `sagvd crosscloud-restore` would
	// otherwise ask on every run. A cached certificate is checked
	// against the pinned AMD chain on every use, exactly like a fresh
	// one, so the cache is never trusted on its own. Operators may
	// pre-fill it for verifiers that cannot reach KDS.
	VCEKCacheDir string

	// AcceptableHostData, if non-empty, restricts which host
	// configurations (HOST_DATA field, set by the hypervisor) are
	// acceptable. GCP populates HOST_DATA with deployment-specific
	// metadata — operators can pin specific values.
	AcceptableHostData [][32]byte
}

// GCPSEVProducer implements Producer using configfs-tsm reports.
type GCPSEVProducer struct {
	cfg         GCPSEVProducerConfig
	measurement Measurement // launch MEASUREMENT (full 48-byte SHA-384)
	policy      uint64      // guest POLICY, as the launch report carries it

	mu  sync.Mutex
	tsm tsmReporter // nil once closed
}

// GCPSEVVerifier implements Verifier for SEV-SNP attestation reports.
type GCPSEVVerifier struct {
	cfg            GCPSEVVerifierConfig
	expected       Measurement
	acceptable     []Measurement
	minReportedTCB uint64
	maxClockSkew   time.Duration

	mu        sync.Mutex
	vcekCache map[string][]byte // CHIP_ID+TCB → VCEK PEM
}

// GCPSEVSealer implements Sealer with a key the firmware derives for
// this guest (SNP_GET_DERIVED_KEY on /dev/sev-guest): bound to the chip,
// the launch measurement and the guest policy, derived for every call
// and never stored. See gcp_sev_snp_seal.go.
type GCPSEVSealer struct {
	device  *os.File
	measure Measurement
	policy  uint64 // guest policy, as the launch report carries it
}

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

// NewGCPSEVProducer checks that this guest can request SEV-SNP reports
// through configfs-tsm and reads its launch measurement from a first
// report.
func NewGCPSEVProducer(cfg GCPSEVProducerConfig) (*GCPSEVProducer, error) {
	if cfg.TSMReportDir == "" {
		cfg.TSMReportDir = DefaultTSMReportDir
	}
	if cfg.VMPL > 3 {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"gcp-sev: vmpl must be 0..3",
			nil,
		)
	}
	if st, err := os.Stat(cfg.TSMReportDir); err != nil || !st.IsDir() {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("gcp-sev: no configfs-tsm report directory at %s (this binary must run inside a Confidential VM on Linux 6.7 or later)", cfg.TSMReportDir),
			err,
		)
	}
	return newGCPSEVProducer(cfg, configfsTSM{dir: cfg.TSMReportDir, provider: "sev_guest", fs: osTSMFS{}})
}

func newGCPSEVProducer(cfg GCPSEVProducerConfig, tsm tsmReporter) (*GCPSEVProducer, error) {
	p := &GCPSEVProducer{cfg: cfg, tsm: tsm}

	// Read a one-time report with a synthetic nonce just to extract the
	// launch MEASUREMENT field. After this, every Quote() call gets a
	// fresh report with the challenger's actual nonce.
	dummyNonce := make([]byte, NonceMinBytes)
	for i := range dummyNonce {
		dummyNonce[i] = byte(i)
	}
	report, err := sevSNPGuestReport(tsm, dummyNonce, cfg.VMPL)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev: initial report: %w", err)
	}
	// SEV-SNP MEASUREMENT is a fixed 48-byte SHA-384 field; carry it at full
	// length (no truncation to 32 — ADR-0007).
	p.measurement = append(Measurement(nil), report.Measurement[:]...)
	p.policy = report.Policy
	return p, nil
}

// NewGCPSEVVerifier constructs a verifier for SEV-SNP reports.
func NewGCPSEVVerifier(_ crypto.PublicKey, expected Measurement, cfg GCPSEVVerifierConfig) (*GCPSEVVerifier, error) {
	if cfg.AMDKDSURL == "" {
		cfg.AMDKDSURL = "https://kdsintf.amd.com"
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}
	acc := cfg.AcceptableMeasurements
	if len(acc) == 0 {
		acc = []Measurement{expected}
	}
	return &GCPSEVVerifier{
		cfg:            cfg,
		expected:       expected,
		acceptable:     acc,
		minReportedTCB: cfg.MinReportedTCB,
		maxClockSkew:   cfg.MaxClockSkew,
		vcekCache:      map[string][]byte{},
	}, nil
}

// NewGCPSEVSealer constructs a sealer over an open /dev/sev-guest: its
// AEAD key is derived by the firmware for this chip, launch measurement
// and guest policy (the producer's Measurement and Policy).
func NewGCPSEVSealer(device *os.File, measure Measurement, policy uint64) *GCPSEVSealer {
	return &GCPSEVSealer{device: device, measure: measure, policy: policy}
}

// ----------------------------------------------------------------------------
// Producer / Verifier / Sealer
// ----------------------------------------------------------------------------

// Quote implements Producer. Requests a report with
// REPORT_DATA = SHA-256(nonce) || zeros(32) and returns the raw report
// bytes (1184 bytes) as Evidence. A report whose launch measurement
// differs from the one read at construction is refused: the workload
// this producer speaks for cannot change underneath it.
func (p *GCPSEVProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"gcp-sev: nonce must be at least NonceMinBytes",
			nil,
		)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tsm == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"gcp-sev: producer closed",
			nil,
		)
	}
	report, err := sevSNPGuestReport(p.tsm, nonce, p.cfg.VMPL)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev: request report: %w", err)
	}
	if !Measurement(report.Measurement[:]).Equal(p.measurement) {
		return nil, shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			"gcp-sev: report carries a different launch measurement than this producer was started with",
			nil,
		)
	}
	return Evidence(report.Raw), nil
}

// Measurement returns the cached launch MEASUREMENT.
func (p *GCPSEVProducer) Measurement() Measurement {
	return p.measurement
}

// Policy returns the guest POLICY the launch report carries: what the
// sealer binds its key to, with the measurement.
func (p *GCPSEVProducer) Policy() uint64 {
	return p.policy
}

// Close stops the producer; later Quote calls fail.
func (p *GCPSEVProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tsm = nil
	return nil
}

// Verify implements Verifier. Parses the SEV-SNP report, fetches and
// validates the VCEK + AMD chain, verifies the ECDSA signature, and
// checks REPORT_DATA + MEASUREMENT against expected values.
func (v *GCPSEVVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	var zero Measurement
	if len(nonce) < NonceMinBytes {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"gcp-sev: challenger nonce too short",
			nil,
		)
	}
	if len(ev) < 1184 {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"gcp-sev: evidence shorter than SEV-SNP report (1184 bytes)",
			nil,
		)
	}

	report, err := parseSEVSNPReport(ev)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: parse report: %v", err),
			err,
		)
	}

	// Fetch + verify VCEK certificate chain (cached per CHIP_ID + TCB).
	vcekPEM, err := v.fetchVCEK(report.ChipID, report.ReportedTCB)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: fetch VCEK: %v", err),
			err,
		)
	}
	if err := verifyAMDChain(vcekPEM, v.cfg.AMDRootPEM); err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: AMD chain: %v", err),
			err,
		)
	}

	// Verify ECDSA-P384 signature over the report (excluding the
	// signature field).
	if err := verifySEVReportSignature(report, vcekPEM); err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: report signature: %v", err),
			err,
		)
	}

	// Guest policy and report provenance, read from the now-verified
	// report: signed by the VCEK this verifier fetched, with the
	// algorithm it checked, for a non-debug guest at the expected VMPL.
	if report.SignatureAlgo != 1 || report.SigningKey != 0 {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: report signed with algorithm %d by key kind %d; this verifier accepts ECDSA P-384 (1) by the VCEK (0)", report.SignatureAlgo, report.SigningKey),
			nil,
		)
	}
	if report.Policy&sevPolicyDebug != 0 {
		return zero, shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			"gcp-sev: guest policy allows DEBUG — the hypervisor can read this guest's memory",
			nil,
		)
	}
	if report.VMPL != v.cfg.VMPL {
		return zero, shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			fmt.Sprintf("gcp-sev: report requested at VMPL %d, expected %d", report.VMPL, v.cfg.VMPL),
			nil,
		)
	}

	// Reported TCB must be ≥ minimum (no rollback to vulnerable firmware).
	if report.ReportedTCB < v.minReportedTCB {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: ReportedTCB %d below minimum %d", report.ReportedTCB, v.minReportedTCB),
			nil,
		)
	}

	// Bind nonce.
	if !nonceMatchesReportDataSEV(report.ReportData, nonce) {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"gcp-sev: REPORT_DATA does not bind challenger nonce (replay?)",
			nil,
		)
	}

	// HOST_DATA policy (optional).
	if len(v.cfg.AcceptableHostData) > 0 {
		ok := false
		for _, hd := range v.cfg.AcceptableHostData {
			if hd == report.HostData {
				ok = true
				break
			}
		}
		if !ok {
			return zero, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("gcp-sev: HOST_DATA %x not in acceptable set", report.HostData),
				nil,
			)
		}
	}

	// Launch MEASUREMENT must match an acceptable value, compared at full
	// length (48-byte SHA-384) — no truncation (ADR-0007).
	reported, mErr := MeasurementFromBytes(report.Measurement[:])
	if mErr != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: unexpected MEASUREMENT length: %v", mErr),
			nil,
		)
	}
	matched := false
	for _, m := range v.acceptable {
		if m.Equal(reported) {
			matched = true
			break
		}
	}
	if !matched {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev: MEASUREMENT %x not in acceptable set", reported),
			nil,
		)
	}

	return reported, nil
}

// fetchVCEK returns the VCEK certificate for a CHIP_ID + TCB: from memory,
// then from VCEKCacheDir, then from AMD KDS (stored back to both). The
// caller verifies whatever comes back against the pinned AMD chain.
func (v *GCPSEVVerifier) fetchVCEK(chipID [64]byte, tcb uint64) ([]byte, error) {
	key := fmt.Sprintf("%x-%d", chipID, tcb)
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok := v.vcekCache[key]; ok {
		return c, nil
	}
	var file string
	if v.cfg.VCEKCacheDir != "" {
		file = filepath.Join(v.cfg.VCEKCacheDir, key+".der")
		if c, err := os.ReadFile(file); err == nil && len(c) > 0 {
			v.vcekCache[key] = c
			return c, nil
		}
	}
	cert, err := amdKDSGetVCEK(v.cfg.AMDKDSURL, chipID, tcb)
	if err != nil {
		return nil, err
	}
	v.vcekCache[key] = cert
	if file != "" {
		// Best effort: a cache that cannot be written only costs a
		// KDS round trip next time.
		_ = writeFileAtomic(file, cert)
	}
	return cert, nil
}

// writeFileAtomic writes data to path via a temporary file and rename,
// so a concurrent reader never sees a partial certificate.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vcek-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Seal implements Sealer: AES-256-GCM under the key the firmware derives
// for this chip, measurement and policy, with aad bound in.
func (s *GCPSEVSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	key, err := sevSNPDerivedKey(s.device, s.measure, s.policy)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-sealer: derive key: %w", err)
	}
	ciphertext, err := sevAEADSeal(key, plaintext, aad)
	zeroize(key)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-sealer: AEAD seal: %w", err)
	}
	return ciphertext, nil
}

// Unseal implements Sealer.
func (s *GCPSEVSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	key, err := sevSNPDerivedKey(s.device, s.measure, s.policy)
	if err != nil {
		return nil, fmt.Errorf("gcp-sev-sealer: derive key: %w", err)
	}
	plaintext, err := sevAEADOpen(key, sealed, aad)
	zeroize(key)
	if err != nil {
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("gcp-sev-sealer: AEAD open: %v (different VM image / policy?)", err),
			err,
		)
	}
	return plaintext, nil
}

// ----------------------------------------------------------------------------
// Capability
// ----------------------------------------------------------------------------

func gcpSEVCapability() (bool, string) {
	if st, err := os.Stat(DefaultTSMReportDir); err == nil && st.IsDir() {
		return true, "GCP SEV-SNP: configfs-tsm reports available at " + DefaultTSMReportDir
	}
	return false, "GCP SEV-SNP: no configfs-tsm reports at " + DefaultTSMReportDir + " (not a Confidential VM, or kernel < 6.7)"
}

// ----------------------------------------------------------------------------
// Stubs (Phase 2 wiring)
// ----------------------------------------------------------------------------

type sevSNPReport struct {
	Raw         []byte
	Measurement [48]byte
	HostData    [32]byte
	ChipID      [64]byte
	ReportedTCB uint64
	ReportData  [64]byte

	Policy        uint64 // guest policy; bit 19 = DEBUG
	VMPL          uint32 // privilege level the report was requested at
	SignatureAlgo uint32 // 1 = ECDSA P-384 with SHA-384
	SigningKey    uint8  // 0 = VCEK, 1 = VLEK, 7 = none
}

// sevPolicyDebug is the guest-policy bit that lets the hypervisor read
// and modify guest memory. A debuggable guest's attestation says nothing
// about confidentiality, so the verifier refuses it.
const sevPolicyDebug = 1 << 19

// sevSNPGuestReport requests a report whose REPORT_DATA is
// SHA-256(nonce) || zeros(32) — the binding the verifier checks — and
// parses it. A report that does not echo the requested REPORT_DATA is
// refused: it does not answer this challenge.
//
// Stored as a var so integration tests can substitute a fake SEV guest.
var sevSNPGuestReport = func(tsm tsmReporter, nonce []byte, vmpl uint32) (*sevSNPReport, error) {
	var reportData [64]byte
	prefix := computeReportDataPrefix(nonce)
	copy(reportData[:], prefix[:])
	raw, err := tsm.report(reportData, vmpl)
	if err != nil {
		return nil, err
	}
	report, err := parseSEVSNPReport(raw)
	if err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}
	if report.ReportData != reportData {
		return nil, errors.New("report does not carry the requested REPORT_DATA")
	}
	return report, nil
}

var parseSEVSNPReport = func(_ []byte) (*sevSNPReport, error) {
	return nil, errors.New("parseSEVSNPReport: not yet wired (Phase 2 — fixed-offset binary parse)")
}

// amdKDSGetVCEK GET https://kdsintf.amd.com/vcek/v1/Milan/<CHIP_ID>?...
var amdKDSGetVCEK = func(_ string, _ [64]byte, _ uint64) ([]byte, error) {
	return nil, errors.New("amdKDSGetVCEK: not yet wired (Phase 2 — net/http GET to AMD KDS)")
}

var verifyAMDChain = func(_ []byte, _ []byte) error {
	return errors.New("verifyAMDChain: not yet wired (Phase 2 — crypto/x509 chain validate against AMD ARK)")
}

var verifySEVReportSignature = func(_ *sevSNPReport, _ []byte) error {
	return errors.New("verifySEVReportSignature: not yet wired (Phase 2 — ECDSA-P384 over report excluding signature)")
}

// The sealer's primitives, wired to gcp_sev_snp_seal.go by its init;
// vars so tests can substitute them.
var (
	sevSNPDerivedKey func(device *os.File, measure Measurement, policy uint64) ([]byte, error)
	sevAEADSeal      func(key, plaintext, aad []byte) ([]byte, error)
	sevAEADOpen      func(key, sealed, aad []byte) ([]byte, error)
)

func nonceMatchesReportDataSEV(reportData [64]byte, nonce []byte) bool {
	expected := computeReportDataPrefix(nonce)
	for i := 0; i < 32; i++ {
		if reportData[i] != expected[i] {
			return false
		}
	}
	return true
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Compile-time interface conformance.
var (
	_ Producer = (*GCPSEVProducer)(nil)
	_ Verifier = (*GCPSEVVerifier)(nil)
	_ Sealer   = (*GCPSEVSealer)(nil)
)
