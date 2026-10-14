// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — Google Cloud Confidential VMs with Intel TDX adapter.
//
// A c3 or a3 Confidential VM with Intel TDX runs as a Trust Domain: its
// memory is encrypted with a key the host never holds, and the TDX module
// measures what was loaded into it — MRTD, the initial contents (the
// virtual firmware), and RTMR0..3, extended at boot with the firmware's
// configuration, the kernel, the initrd and the command line. The guest
// asks for a quote through configfs-tsm (provider "tdx_guest"); the host's
// Quote Generation Service signs it with a Quoting Enclave whose key the
// platform's PCK certificate certifies, chained to the Intel SGX Root CA.
//
// The producer here puts SHA-256(nonce) in REPORTDATA and reports as its
// measurement the SHA-384 of MRTD and the four RTMRs together: one pin
// that names the firmware and the boot chain. The verifier walks the
// quote's signatures to the pinned Intel root, evaluates the platform's
// TCB against Intel PCS (gcp_tdx_pcs.go), refuses a debuggable TD and a
// TCB below the accepted statuses, binds the nonce, and compares the
// measurement. There is no sealer: TDX gives a guest no sealing key
// (the vTPM is the way, not wired yet), so an escrow key cannot be sealed
// to a TDX host.
package tee

import (
	"crypto"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// GCPTDXProducerConfig configures the TDX producer.
type GCPTDXProducerConfig struct {
	// TSMReportDir is the configfs-tsm report directory. Default
	// DefaultTSMReportDir.
	TSMReportDir string
}

// GCPTDXVerifierConfig configures the TDX verifier.
type GCPTDXVerifierConfig struct {
	// PCSURL overrides the Intel PCS base URL (a mirror, a PCCS).
	PCSURL string
	// PCSCacheDir keeps the TCB info and QE identity documents between
	// runs; each is checked like a fresh one on every use.
	PCSCacheDir string
	// IntelRootPEM overrides the pinned Intel SGX Root CA.
	IntelRootPEM []byte
	// AcceptableTCBStatuses lists the TCB statuses accepted for the
	// platform, the TDX module and the QE. Default: UpToDate only.
	// OutOfDate and Revoked are never accepted.
	AcceptableTCBStatuses []string
	// AcceptableMeasurements lists every measurement the verifier will
	// accept. When empty, falls back to VerifierSpec.ExpectedMeasurement.
	AcceptableMeasurements []Measurement
	// Now overrides the clock (tests).
	Now func() time.Time
}

// GCPTDXProducer implements Producer using configfs-tsm quotes.
type GCPTDXProducer struct {
	cfg         GCPTDXProducerConfig
	measurement Measurement
	mrtd        [48]byte
	rtmr        [4][48]byte

	mu  sync.Mutex
	tsm tsmReporter // nil once closed
}

// GCPTDXVerifier implements Verifier for TDX quotes.
type GCPTDXVerifier struct {
	cfg        GCPTDXVerifierConfig
	acceptable []Measurement
	statuses   map[string]bool
	pcs        pcsClient
}

// tdxMeasurement is the pin: SHA-384 over MRTD and RTMR0..3.
func tdxMeasurement(mrtd [48]byte, rtmr [4][48]byte) Measurement {
	h := sha512.New384()
	h.Write(mrtd[:])
	for i := range rtmr {
		h.Write(rtmr[i][:])
	}
	return Measurement(h.Sum(nil))
}

// tdxGuestQuote requests a quote whose REPORTDATA is SHA-256(nonce) ||
// zeros(32) and parses it. A var so tests can substitute a fake guest.
var tdxGuestQuote = func(tsm tsmReporter, nonce []byte) (*tdxQuote, error) {
	var reportData [64]byte
	prefix := computeReportDataPrefix(nonce)
	copy(reportData[:], prefix[:])
	raw, err := tsm.report(reportData, 0)
	if err != nil {
		return nil, err
	}
	q, err := parseTDXQuote(raw)
	if err != nil {
		return nil, fmt.Errorf("parse quote: %w", err)
	}
	if q.ReportData != reportData {
		return nil, errors.New("quote does not carry the requested REPORTDATA")
	}
	return q, nil
}

// NewGCPTDXProducer checks that this guest can request TDX quotes through
// configfs-tsm and reads its measurement from a first one.
func NewGCPTDXProducer(cfg GCPTDXProducerConfig) (*GCPTDXProducer, error) {
	if cfg.TSMReportDir == "" {
		cfg.TSMReportDir = DefaultTSMReportDir
	}
	if st, err := os.Stat(cfg.TSMReportDir); err != nil || !st.IsDir() {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("gcp-tdx: no configfs-tsm report directory at %s (this binary must run inside a TDX Confidential VM on Linux 6.7 or later)", cfg.TSMReportDir),
			err,
		)
	}
	return newGCPTDXProducer(cfg, configfsTSM{dir: cfg.TSMReportDir, provider: "tdx_guest", fs: osTSMFS{}})
}

func newGCPTDXProducer(cfg GCPTDXProducerConfig, tsm tsmReporter) (*GCPTDXProducer, error) {
	p := &GCPTDXProducer{cfg: cfg, tsm: tsm}
	dummyNonce := make([]byte, NonceMinBytes)
	for i := range dummyNonce {
		dummyNonce[i] = byte(i)
	}
	q, err := tdxGuestQuote(tsm, dummyNonce)
	if err != nil {
		return nil, fmt.Errorf("gcp-tdx: initial quote: %w", err)
	}
	p.mrtd, p.rtmr = q.MRTD, q.RTMR
	p.measurement = tdxMeasurement(q.MRTD, q.RTMR)
	return p, nil
}

// Quote implements Producer. A quote whose MRTD or RTMRs differ from the
// ones read at construction is refused: the workload this producer
// speaks for cannot change underneath it.
func (p *GCPTDXProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gcp-tdx: nonce must be at least NonceMinBytes", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tsm == nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gcp-tdx: producer closed", nil)
	}
	q, err := tdxGuestQuote(p.tsm, nonce)
	if err != nil {
		return nil, fmt.Errorf("gcp-tdx: request quote: %w", err)
	}
	if q.MRTD != p.mrtd || q.RTMR != p.rtmr {
		return nil, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			"gcp-tdx: quote carries a different MRTD or RTMRs than this producer was started with", nil)
	}
	return Evidence(q.Raw), nil
}

// Measurement returns the pin: SHA-384 over MRTD and RTMR0..3.
func (p *GCPTDXProducer) Measurement() Measurement { return p.measurement }

// MRTD returns the TD's initial measurement.
func (p *GCPTDXProducer) MRTD() [48]byte { return p.mrtd }

// RTMRs returns the four runtime measurement registers.
func (p *GCPTDXProducer) RTMRs() [4][48]byte { return p.rtmr }

// Close stops the producer; later Quote calls fail.
func (p *GCPTDXProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tsm = nil
	return nil
}

// NewGCPTDXVerifier constructs a verifier for TDX quotes.
func NewGCPTDXVerifier(_ crypto.PublicKey, expected Measurement, cfg GCPTDXVerifierConfig) (*GCPTDXVerifier, error) {
	if cfg.PCSURL == "" {
		cfg.PCSURL = DefaultIntelPCSURL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	acc := cfg.AcceptableMeasurements
	if len(acc) == 0 {
		acc = []Measurement{expected}
	}
	statuses := map[string]bool{TCBUpToDate: true}
	if len(cfg.AcceptableTCBStatuses) > 0 {
		statuses = map[string]bool{}
		for _, s := range cfg.AcceptableTCBStatuses {
			rank, ok := tcbStatusRank[s]
			if !ok {
				return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("gcp-tdx: unknown TCB status %q", s), nil)
			}
			if rank >= tcbStatusRank[TCBOutOfDate] {
				return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("gcp-tdx: TCB status %q is never accepted", s), nil)
			}
			statuses[s] = true
		}
	}
	if _, err := intelRootPool(cfg.IntelRootPEM); err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gcp-tdx: Intel root PEM: "+err.Error(), err)
	}
	return &GCPTDXVerifier{
		cfg:        cfg,
		acceptable: acc,
		statuses:   statuses,
		pcs:        pcsClient{baseURL: cfg.PCSURL, cache: pcsCache{dir: cfg.PCSCacheDir}, rootOverride: cfg.IntelRootPEM, now: cfg.Now},
	}, nil
}

// TDXVerdict is what a verified quote said, for callers that record it.
type TDXVerdict struct {
	Measurement Measurement
	MRTD        [48]byte
	RTMR        [4][48]byte
	TCBStatus   string
	TCBDate     time.Time
	QEStatus    string
	AdvisoryIDs []string
}

// Verify implements Verifier.
func (v *GCPTDXVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	verdict, err := v.VerifyQuote(ev, nonce)
	if err != nil {
		return nil, err
	}
	return verdict.Measurement, nil
}

// VerifyQuote is Verify with the verdict's detail.
func (v *GCPTDXVerifier) VerifyQuote(ev Evidence, nonce Nonce) (*TDXVerdict, error) {
	integrity := func(code, msg string, err error) error {
		return shared_errors.Integrity(code, "gcp-tdx: "+msg, err)
	}
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gcp-tdx: challenger nonce too short", nil)
	}
	q, err := parseTDXQuote(ev)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "parse quote: "+err.Error(), err)
	}
	now := v.cfg.Now()
	chain, err := parsePEMCertificates(q.PCKChainPEM)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "PCK chain: "+err.Error(), err)
	}
	if err := verifyChainToIntelRoot(chain, v.cfg.IntelRootPEM, now); err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "PCK chain does not chain to the Intel root: "+err.Error(), err)
	}
	if err := verifyQuoteSignatures(q, chain[0]); err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, err.Error(), err)
	}
	platform, err := parsePCKExtension(chain[0])
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "PCK certificate: "+err.Error(), err)
	}
	// Intel's word on the platform and the QE, verified before it is read.
	info, err := v.pcs.tcbInfo(platform.FMSPC)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "TCB info: "+err.Error(), err)
	}
	tcb, err := evaluateTCB(info, platform, q)
	if err != nil {
		return nil, integrity(shared_errors.CodeAttestationDenied, "TCB: "+err.Error(), err)
	}
	qeID, err := v.pcs.qeIdentity()
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "QE identity: "+err.Error(), err)
	}
	qeStatus, err := evaluateQE(qeID, q.QEReport)
	if err != nil {
		return nil, integrity(shared_errors.CodeAttestationDenied, "QE: "+err.Error(), err)
	}
	for what, status := range map[string]string{"platform TCB": tcb.PlatformStatus, "TDX module TCB": tcb.ModuleStatus, "QE TCB": qeStatus} {
		if !v.statuses[status] {
			return nil, integrity(shared_errors.CodeAttestationDenied,
				fmt.Sprintf("%s status %s is not accepted (accepted: %v)", what, status, acceptedList(v.statuses)), nil)
		}
	}
	// The TD itself: not debuggable, answering this challenge, the pinned code.
	if q.TDAttrs&tdxAttrDebug != 0 {
		return nil, integrity(shared_errors.CodeAttestationDenied, "TD attributes allow DEBUG — the host can read this guest's memory", nil)
	}
	if !nonceMatchesReportDataSEV(q.ReportData, nonce) {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "REPORTDATA does not bind challenger nonce (replay?)", nil)
	}
	m := tdxMeasurement(q.MRTD, q.RTMR)
	matched := false
	for _, a := range v.acceptable {
		if a.Equal(m) {
			matched = true
		}
	}
	if !matched {
		return nil, integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("measurement %x (SHA-384 of MRTD %x… and RTMR0..3) not in acceptable set", m, q.MRTD[:6]), nil)
	}
	return &TDXVerdict{Measurement: m, MRTD: q.MRTD, RTMR: q.RTMR, TCBStatus: tcb.Status, TCBDate: tcb.PlatformDate, QEStatus: qeStatus, AdvisoryIDs: tcb.AdvisoryIDs}, nil
}

func acceptedList(m map[string]bool) []string {
	var out []string
	for s := range m {
		out = append(out, s)
	}
	return out
}

func gcpTDXCapability() (bool, string) {
	if st, err := os.Stat(DefaultTSMReportDir); err == nil && st.IsDir() {
		return true, "GCP TDX: configfs-tsm reports available at " + DefaultTSMReportDir
	}
	return false, "GCP TDX: no configfs-tsm reports at " + DefaultTSMReportDir + " (not a Confidential VM, or kernel < 6.7)"
}

// Compile-time interface conformance.
var (
	_ Producer = (*GCPTDXProducer)(nil)
	_ Verifier = (*GCPTDXVerifier)(nil)
)
