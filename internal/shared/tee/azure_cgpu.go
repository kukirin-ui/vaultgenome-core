// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — Azure Confidential VMs with NVIDIA H100 (NCC H100 v5) adapter.
//
// An Azure confidential GPU VM is an AMD SEV-SNP guest under the paravisor
// with an H100 in confidential-computing mode. Two roots of trust vouch
// for it and this adapter carries both in one Evidence:
//
//   - the chip: the SEV-SNP report Azure keeps in the vTPM (the HCL
//     report, azure_cgpu_hcl.go), whose REPORT_DATA names the vTPM's
//     attestation key, and a TPM quote by that key over the PCRs with the
//     challenge in extraData (azure_cgpu_tpm.go) — the binding of a
//     caller's nonce to a report that was issued at boot;
//   - the GPU: NVIDIA's signed attestation tokens for the same challenge
//     (nvidia_eat.go), obtained on the guest through NVIDIA's own tools.
//
// The measurement is the SNP launch measurement (48 bytes, the paravisor
// and firmware Azure measures). What NVIDIA vouched for — the GPU's model,
// driver and VBIOS with their reference manifests — is in the verdict, and
// an operator may pin it. There is no sealer: the guest has no derived-key
// interface, and sealing through the vTPM is not wired.
package tee

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// AzureCGPUEvidenceSchema names the Evidence envelope.
const AzureCGPUEvidenceSchema = "vault-genome/azure-cgpu-evidence/v1"

// DefaultTPMQuotePCRs are the PCRs the producer quotes: the measured boot
// (0–7), the kernel's IMA and the OS (8–14).
const DefaultTPMQuotePCRs = "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14"

// AzureCGPUProducerConfig configures the producer on the guest.
type AzureCGPUProducerConfig struct {
	// GPUAttestCommand collects the GPU's evidence for a nonce through
	// NVIDIA's tools and prints NRAS's response on stdout; the nonce (64
	// hex characters) is appended as the last argument. Required.
	GPUAttestCommand []string
	// TPM2ToolsDir is where tpm2_nvread, tpm2_quote, tpm2_getcap and
	// tpm2_readpublic live; empty means PATH.
	TPM2ToolsDir string
	// AKHandle is the persistent handle of the HCL attestation key; empty
	// means: find the persistent key whose public part is HCLAkPub.
	AKHandle string
	// PCRs is the tpm2_quote PCR selection. Default DefaultTPMQuotePCRs.
	PCRs string
	// Timeout bounds each command. Default 2 minutes.
	Timeout time.Duration
}

// AzureCGPUVerifierConfig configures the verifier, anywhere.
type AzureCGPUVerifierConfig struct {
	// AMDKDSURL overrides AMD KDS; AMDRootPEM is the ASK+ARK chain (PEM)
	// of the chip's product (Genoa for NCC H100 v5), required; VCEKCacheDir
	// keeps fetched VCEKs; MinReportedTCB is the TCB floor.
	AMDKDSURL      string
	AMDRootPEM     []byte
	VCEKCacheDir   string
	MinReportedTCB uint64
	// NRASJWKSURL overrides NVIDIA's key set URL; NRASCacheDir keeps it.
	NRASJWKSURL  string
	NRASCacheDir string
	// GPU is the per-GPU claims policy.
	GPU GPUClaimsPolicy
	// GPUEvaluation says whose evaluation of the GPU's report the verdict
	// rests on: GPUEvaluationNRAS (the default) takes NVIDIA's signed
	// tokens; GPUEvaluationBoth requires them and this verifier's own
	// evaluation of the report and certificate chain the evidence carries
	// (nvidia_gpu_report.go, nvidia_rim.go); GPUEvaluationOwn would rest
	// on the own evaluation alone and is refused by this build, which does
	// not verify the manifests' XML signatures.
	GPUEvaluation string
	// GPURevocation says whether the verifier's evaluation asks NVIDIA's
	// OCSP responder about the GPU's certificate chain: GPURevocationOCSP
	// (the default under both and own) or GPURevocationOff, which leaves
	// revocation unchecked, on the record. OCSPURL overrides the responder
	// for certificates that carry no URL of their own (default
	// NVIDIAOCSPURL); answers are cached under RIMCacheDir.
	GPURevocation string
	OCSPURL       string
	// NVIDIADeviceRootPEM and NVIDIARIMRootPEM override the pinned NVIDIA
	// roots (nvidia_roots.go); RIMServiceURL overrides NVIDIA's RIM
	// service and RIMCacheDir keeps the manifests fetched.
	NVIDIADeviceRootPEM []byte
	NVIDIARIMRootPEM    []byte
	RIMServiceURL       string
	RIMCacheDir         string
	// AcceptablePCRDigests, when set, pins the quote's PCR digest — the
	// SHA-256 over the selected PCRs' values, as TPM2_Quote computes it —
	// to one of these, so the OS and driver measured into the vTPM are
	// policed and not only recorded. Empty: recorded only.
	AcceptablePCRDigests [][]byte
	// AcceptableMeasurements lists every SNP measurement accepted. When
	// empty, falls back to VerifierSpec.ExpectedMeasurement.
	AcceptableMeasurements []Measurement
	// MaxClockSkew bounds token validity checks. Default 5 minutes.
	MaxClockSkew time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
}

// The evaluations a verifier may be configured for.
const (
	GPUEvaluationNRAS = "nras"
	GPUEvaluationBoth = "both"
	GPUEvaluationOwn  = "own"

	GPURevocationOCSP = "ocsp"
	GPURevocationOff  = "off"
)

// azureCGPUEvidence is the Evidence envelope.
type azureCGPUEvidence struct {
	Schema         string          `json:"schema"`
	HCLReport      []byte          `json:"hcl_report"`
	QuoteMessage   []byte          `json:"quote_message"`
	QuoteSignature []byte          `json:"quote_signature"`
	GPUToken       json.RawMessage `json:"gpu_token"`
	// GPUEvidence is what NVIDIA's service evaluated, one entry per GPU:
	// the attestation report and the certificate chain, so a verifier can
	// evaluate them itself. Absent from evidence made by an older producer.
	GPUEvidence []gpuEvidenceItem `json:"gpu_evidence,omitempty"`
}

// gpuEvidenceItem is one GPU's raw evidence as NVIDIA's collector hands
// it out: the SPDM attestation report and the PEM certificate chain,
// both base64 on the wire.
type gpuEvidenceItem struct {
	Report    []byte `json:"evidence"`
	CertChain []byte `json:"certificate"`
}

// gpuAttestOutput is the GPU attestation command's output in its full
// form: NVIDIA's response and the raw evidence it was given. A command
// that prints NVIDIA's response alone (the older contract) still works;
// the evidence then carries no gpu_evidence.
type gpuAttestOutput struct {
	NRAS        json.RawMessage   `json:"nras"`
	GPUEvidence []gpuEvidenceItem `json:"gpu_evidence"`
}

// parseGPUAttestOutput reads the command's output in either form.
func parseGPUAttestOutput(out []byte) (token json.RawMessage, items []gpuEvidenceItem, err error) {
	var full gpuAttestOutput
	if json.Unmarshal(out, &full) == nil && len(full.NRAS) > 0 {
		token, items = full.NRAS, full.GPUEvidence
	} else {
		token = out
	}
	if _, err := parseNRASResponse(token); err != nil {
		return nil, nil, err
	}
	for i, it := range items {
		if len(it.Report) == 0 || len(it.CertChain) == 0 {
			return nil, nil, fmt.Errorf("gpu_evidence[%d] lacks the report or the certificate chain", i)
		}
	}
	return token, items, nil
}

// AzureCGPUProducer implements Producer on the guest.
type AzureCGPUProducer struct {
	cfg         AzureCGPUProducerConfig
	hcl         *hclReport
	akHandle    string
	measurement Measurement
	boot        *tpmQuote // a quote taken at construction: what the vTPM measured of this boot

	mu     sync.Mutex
	closed bool
}

// AzureCGPUVerifier implements Verifier for the composite evidence.
type AzureCGPUVerifier struct {
	cfg        AzureCGPUVerifierConfig
	acceptable []Measurement
	jwks       *nrasJWKS
	gpuEval    *GPUEvaluator // nil unless the policy asks for the own evaluation
	ownOnly    bool          // GPUEvaluationOwn: the verdict rests on the evaluation alone

	mu        sync.Mutex
	vcekCache map[string][]byte
}

// AzureCGPUVerdict is what a verified evidence said.
type AzureCGPUVerdict struct {
	Measurement   Measurement
	Product       string
	ChipID        [64]byte
	ReportedTCB   uint64
	PCRSelections []tpmPCRSelection
	PCRDigest     []byte
	GPUs          []GPUVerdict
	// Evaluations are this verifier's own evaluations of the GPUs'
	// reports, one per gpu_evidence entry, when the policy asked for them.
	Evaluations []GPUEvaluation
}

// runCommand runs argv with a timeout and returns stdout; stderr goes
// into the error.
var runCommand = func(timeout time.Duration, argv ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is the operator's configuration
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(argv[0]), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (cfg AzureCGPUProducerConfig) tool(name string) string {
	if cfg.TPM2ToolsDir == "" {
		return name
	}
	return filepath.Join(cfg.TPM2ToolsDir, name)
}

// NewAzureCGPUProducer reads the HCL report from the vTPM, finds the
// attestation key the chip vouched for among the persistent keys, and
// fixes the measurement.
func NewAzureCGPUProducer(cfg AzureCGPUProducerConfig) (*AzureCGPUProducer, error) {
	if len(cfg.GPUAttestCommand) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: GPUAttestCommand required", nil)
	}
	if cfg.PCRs == "" {
		cfg.PCRs = DefaultTPMQuotePCRs
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Minute
	}
	raw, err := runCommand(cfg.Timeout, cfg.tool("tpm2_nvread"), "-C", "o", hclNVIndex)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: read the HCL report from the vTPM: %w", err)
	}
	h, err := parseHCLReport(raw)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: HCL report: %w", err)
	}
	ak, err := h.attestationKey()
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: %w", err)
	}
	handle := cfg.AKHandle
	if handle == "" {
		handle, err = findAKHandle(cfg, ak)
		if err != nil {
			return nil, fmt.Errorf("azure-cgpu: %w", err)
		}
	}
	m, err := MeasurementFromBytes(h.SNP.Measurement[:])
	if err != nil {
		return nil, err
	}
	p := &AzureCGPUProducer{cfg: cfg, hcl: h, akHandle: handle, measurement: m}
	// One quote now, under a fixed challenge, records what this boot
	// measured into the vTPM — the PCR digest an operator may pin.
	msg, sig, err := p.tpmQuote(tpmQuoteExtraDataFor([]byte("vault-genome azure-cgpu boot identity")))
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: initial TPM quote: %w", err)
	}
	q, err := parseTPMQuote(msg)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: initial TPM quote: %w", err)
	}
	if err := verifyTPMQuoteSignature(ak, msg, sig); err != nil {
		return nil, fmt.Errorf("azure-cgpu: initial TPM quote: %w", err)
	}
	p.boot = q
	return p, nil
}

// tpmQuote runs tpm2_quote for a challenge and returns the message and
// the raw signature.
func (p *AzureCGPUProducer) tpmQuote(challenge [32]byte) (msg, sig []byte, err error) {
	dir, err := os.MkdirTemp("", "vg-quote-*")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	msgPath, sigPath := filepath.Join(dir, "quote.msg"), filepath.Join(dir, "quote.sig")
	if _, err := runCommand(p.cfg.Timeout, p.cfg.tool("tpm2_quote"), "-c", p.akHandle, "-l", p.cfg.PCRs, "-q", hex.EncodeToString(challenge[:]),
		"-g", "sha256", "-m", msgPath, "-s", sigPath, "-f", "plain"); err != nil {
		return nil, nil, fmt.Errorf("TPM quote: %w", err)
	}
	if msg, err = os.ReadFile(msgPath); err != nil {
		return nil, nil, err
	}
	if sig, err = os.ReadFile(sigPath); err != nil {
		return nil, nil, err
	}
	return msg, sig, nil
}

// VTPMBoot is what the vTPM measured of this boot: the PCRs quoted and
// their digest, which a peer may pin (AcceptablePCRDigests).
func (p *AzureCGPUProducer) VTPMBoot() (selections []tpmPCRSelection, digest []byte) {
	return p.boot.PCRSelections, append([]byte(nil), p.boot.PCRDigest...)
}

// findAKHandle lists the vTPM's persistent handles and returns the one
// whose public key is the HCL attestation key.
func findAKHandle(cfg AzureCGPUProducerConfig, ak *rsa.PublicKey) (string, error) {
	out, err := runCommand(cfg.Timeout, cfg.tool("tpm2_getcap"), "handles-persistent")
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "vg-ak-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	for _, field := range strings.Fields(string(out)) {
		if !strings.HasPrefix(field, "0x") {
			continue
		}
		pem := filepath.Join(dir, field+".pem")
		if _, err := runCommand(cfg.Timeout, cfg.tool("tpm2_readpublic"), "-c", field, "-f", "pem", "-o", pem); err != nil {
			continue
		}
		raw, err := os.ReadFile(pem)
		if err != nil {
			continue
		}
		pub, err := parsePEMRSAPublicKey(raw)
		if err != nil {
			continue
		}
		if pub.Equal(ak) {
			return field, nil
		}
	}
	return "", errors.New("no persistent vTPM key is the HCL attestation key")
}

// Quote implements Producer: a TPM quote with SHA-256(nonce) in extraData,
// NVIDIA's tokens for the same value, and the HCL report, in one envelope.
func (p *AzureCGPUProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: nonce must be at least NonceMinBytes", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: producer closed", nil)
	}
	challenge := tpmQuoteExtraDataFor(nonce)
	challengeHex := hex.EncodeToString(challenge[:])
	quoteMsg, quoteSig, err := p.tpmQuote(challenge)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: %w", err)
	}
	argv := append(append([]string(nil), p.cfg.GPUAttestCommand...), challengeHex)
	out, err := runCommand(p.cfg.Timeout, argv...)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: GPU attestation: %w", err)
	}
	token, items, err := parseGPUAttestOutput(out)
	if err != nil {
		return nil, fmt.Errorf("azure-cgpu: GPU attestation command output: %w", err)
	}
	ev, err := json.Marshal(azureCGPUEvidence{Schema: AzureCGPUEvidenceSchema, HCLReport: p.hcl.Raw, QuoteMessage: quoteMsg, QuoteSignature: quoteSig, GPUToken: token, GPUEvidence: items})
	if err != nil {
		return nil, err
	}
	return Evidence(ev), nil
}

// Measurement implements Producer: the SNP launch measurement.
func (p *AzureCGPUProducer) Measurement() Measurement {
	return append(Measurement(nil), p.measurement...)
}

// Close implements Producer.
func (p *AzureCGPUProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// NewAzureCGPUVerifier constructs the composite verifier.
func NewAzureCGPUVerifier(_ crypto.PublicKey, expected Measurement, cfg AzureCGPUVerifierConfig) (*AzureCGPUVerifier, error) {
	if len(cfg.AMDRootPEM) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: AMDRootPEM (the product's ASK+ARK chain) required", nil)
	}
	if _, _, err := parseASKARK(cfg.AMDRootPEM); err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: AMDRootPEM: "+err.Error(), err)
	}
	if cfg.AMDKDSURL == "" {
		cfg.AMDKDSURL = "https://kdsintf.amd.com"
	}
	if cfg.NRASJWKSURL == "" {
		cfg.NRASJWKSURL = DefaultNRASJWKSURL
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	acc := cfg.AcceptableMeasurements
	if len(acc) == 0 {
		acc = []Measurement{expected}
	}
	v := &AzureCGPUVerifier{
		cfg:        cfg,
		acceptable: acc,
		jwks:       &nrasJWKS{url: cfg.NRASJWKSURL, dir: cfg.NRASCacheDir, get: nrasHTTPGet},
		vcekCache:  map[string][]byte{},
	}
	switch cfg.GPUEvaluation {
	case "", GPUEvaluationNRAS:
	case GPUEvaluationOwn, GPUEvaluationBoth:
		v.ownOnly = cfg.GPUEvaluation == GPUEvaluationOwn
		device, err := parseNVIDIARoot(cfg.NVIDIADeviceRootPEM, NVIDIADeviceRootPEM)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: NVIDIA device root: "+err.Error(), err)
		}
		rimRoot, err := parseNVIDIARoot(cfg.NVIDIARIMRootPEM, NVIDIARIMRootPEM)
		if err != nil {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: NVIDIA RIM root: "+err.Error(), err)
		}
		v.gpuEval = &GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: cfg.Now,
			RIMs: &RIMFetcher{BaseURL: cfg.RIMServiceURL, CacheDir: cfg.RIMCacheDir}}
		switch cfg.GPURevocation {
		case "", GPURevocationOCSP:
			v.gpuEval.OCSP = &OCSPChecker{URL: cfg.OCSPURL, CacheDir: cfg.RIMCacheDir, Now: cfg.Now}
		case GPURevocationOff:
		default:
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("azure-cgpu: GPURevocation %q (one of ocsp, off)", cfg.GPURevocation), nil)
		}
	default:
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("azure-cgpu: GPUEvaluation %q (one of nras, both, own)", cfg.GPUEvaluation), nil)
	}
	return v, nil
}

// nrasHTTPGet fetches NVIDIA's key set; a var so tests run without network.
var nrasHTTPGet = func(url string) ([]byte, error) { return httpGet(url) }

// Verify implements Verifier.
func (v *AzureCGPUVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, err
	}
	return verdict.Measurement, nil
}

// VerifyDetailed implements DetailedVerifier: the verdict's platform and
// GPU facts go with the measurement.
func (v *AzureCGPUVerifier) VerifyDetailed(ev Evidence, nonce Nonce) (Measurement, *AttestationDetail, error) {
	verdict, err := v.VerifyEvidence(ev, nonce)
	if err != nil {
		return nil, nil, err
	}
	return verdict.Measurement, verdict.Detail(), nil
}

// Detail is the verdict as an AttestationDetail for the audit record.
func (d *AzureCGPUVerdict) Detail() *AttestationDetail {
	sel := make([]string, 0, len(d.PCRSelections))
	for _, s := range d.PCRSelections {
		sel = append(sel, s.String())
	}
	return &AttestationDetail{Provider: ProviderAzureCGPU, Product: d.Product, ChipIDHex: hex.EncodeToString(d.ChipID[:]),
		ReportedTCB: d.ReportedTCB, PCRSelection: strings.Join(sel, "+"), PCRDigestHex: hex.EncodeToString(d.PCRDigest),
		GPUs: d.GPUs, Evaluations: d.Evaluations}
}

// VerifyEvidence verifies and says what the evidence said.
func (v *AzureCGPUVerifier) VerifyEvidence(ev Evidence, nonce Nonce) (*AzureCGPUVerdict, error) {
	integrity := func(code, msg string, err error) error {
		return shared_errors.Integrity(code, "azure-cgpu: "+msg, err)
	}
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "azure-cgpu: challenger nonce too short", nil)
	}
	var env azureCGPUEvidence
	if err := json.Unmarshal(ev, &env); err != nil || env.Schema != AzureCGPUEvidenceSchema {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "evidence is not a "+AzureCGPUEvidenceSchema+" envelope", err)
	}

	// The chip: the SNP report inside the HCL report, verified to AMD.
	h, err := parseHCLReport(env.HCLReport)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "HCL report: "+err.Error(), err)
	}
	report := h.SNP
	product := sevProductName(report)
	vcek, err := v.fetchVCEK(product, report.ChipID, report.ReportedTCB)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "fetch VCEK: "+err.Error(), err)
	}
	if err := verifyAMDChain(vcek, v.cfg.AMDRootPEM); err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "AMD chain ("+product+"): "+err.Error(), err)
	}
	if err := verifySEVReportSignature(report, vcek); err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "report signature: "+err.Error(), err)
	}
	if report.SignatureAlgo != 1 || report.SigningKey != 0 {
		return nil, integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("report signed with algorithm %d by key kind %d; this verifier accepts ECDSA P-384 (1) by the VCEK (0)", report.SignatureAlgo, report.SigningKey), nil)
	}
	if report.Policy&sevPolicyDebug != 0 {
		return nil, integrity(shared_errors.CodeAttestationDenied, "guest policy allows DEBUG — the hypervisor can read this guest's memory", nil)
	}
	if report.VMPL != 0 {
		return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("report requested at VMPL %d, expected 0", report.VMPL), nil)
	}
	if report.ReportedTCB < v.cfg.MinReportedTCB {
		return nil, integrity(shared_errors.CodeSignatureInvalid, fmt.Sprintf("ReportedTCB %d below minimum %d", report.ReportedTCB, v.cfg.MinReportedTCB), nil)
	}

	// The vTPM: the attestation key the chip named signs the challenge.
	ak, err := h.attestationKey()
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, err.Error(), err)
	}
	quote, err := parseTPMQuote(env.QuoteMessage)
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote: "+err.Error(), err)
	}
	if err := verifyTPMQuoteSignature(ak, env.QuoteMessage, env.QuoteSignature); err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote: "+err.Error(), err)
	}
	challenge := tpmQuoteExtraDataFor(nonce)
	if !bytes.Equal(quote.ExtraData, challenge[:]) {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "TPM quote does not bind challenger nonce (replay?)", nil)
	}
	if len(v.cfg.AcceptablePCRDigests) > 0 {
		pinned := false
		for _, d := range v.cfg.AcceptablePCRDigests {
			if bytes.Equal(d, quote.PCRDigest) {
				pinned = true
				break
			}
		}
		if !pinned {
			return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("PCR digest %x is not in the acceptable set: the boot measured into the vTPM is not one the policy names", quote.PCRDigest), nil)
		}
	}

	// The GPU: NVIDIA's tokens for the same challenge — unless the policy
	// rests the verdict on this verifier's own evaluation alone.
	var gpus []GPUVerdict
	if !v.ownOnly {
		token, err := parseNRASResponse(env.GPUToken)
		if err != nil {
			return nil, integrity(shared_errors.CodeSignatureInvalid, "GPU token: "+err.Error(), err)
		}
		now := v.cfg.Now()
		overall, err := v.jwks.verify(token.Overall, now, v.cfg.MaxClockSkew)
		if err != nil {
			return nil, integrity(shared_errors.CodeSignatureInvalid, "GPU overall token: "+err.Error(), err)
		}
		detached := map[string]map[string]any{}
		for key, t := range token.Detached {
			c, err := v.jwks.verify(t, now, v.cfg.MaxClockSkew)
			if err != nil {
				return nil, integrity(shared_errors.CodeSignatureInvalid, "GPU token "+key+": "+err.Error(), err)
			}
			detached[key] = c
		}
		if gpus, err = evaluateGPUClaims(overall, detached, hex.EncodeToString(challenge[:]), v.cfg.GPU); err != nil {
			return nil, integrity(shared_errors.CodeAttestationDenied, "GPU: "+err.Error(), err)
		}
	}

	// The GPU, evaluated here: the report and chain the driver produced,
	// held to NVIDIA's roots and signed manifests by this verifier, for
	// the same challenge. Under "both", every GPU NVIDIA spoke for must be
	// in the evidence and what the report says of it must be what NVIDIA
	// said; under "own", the report is the whole of the GPU's word, and
	// the policy's model and version pins are held against it.
	var evaluations []GPUEvaluation
	if v.gpuEval != nil {
		if len(env.GPUEvidence) == 0 {
			return nil, integrity(shared_errors.CodeAttestationDenied, "GPU: the evidence carries no report to evaluate (gpu_evidence), and the policy requires the verifier's own evaluation", nil)
		}
		if !v.ownOnly && len(env.GPUEvidence) != len(gpus) {
			return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("GPU: %d reports in the evidence, %d GPUs in NVIDIA's tokens", len(env.GPUEvidence), len(gpus)), nil)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for i, item := range env.GPUEvidence {
			e := v.gpuEval.Evaluate(ctx, item.Report, item.CertChain, challenge[:])
			evaluations = append(evaluations, e)
			if !e.Complete() {
				return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("GPU %d, own evaluation: %s", i, strings.Join(e.Errors, "; ")), nil)
			}
			if v.ownOnly {
				g := GPUVerdict{Key: fmt.Sprintf("GPU-%d", i), HWModel: e.HWModel, DriverVersion: e.DriverVersion, VBIOSVersion: e.VBIOSVersion, UEID: e.UEID, Issuer: "own evaluation"}
				if err := v.cfg.GPU.holdsPins(g); err != nil {
					return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("GPU %d: %s", i, err), err)
				}
				gpus = append(gpus, g)
				continue
			}
			if e.DriverVersion != gpus[i].DriverVersion || !strings.EqualFold(e.VBIOSVersion, gpus[i].VBIOSVersion) {
				return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("GPU %d: the report names driver %s and VBIOS %s, NVIDIA's token %s and %s", i, e.DriverVersion, e.VBIOSVersion, gpus[i].DriverVersion, gpus[i].VBIOSVersion), nil)
			}
		}
	}

	// The pin.
	m, err := MeasurementFromBytes(report.Measurement[:])
	if err != nil {
		return nil, integrity(shared_errors.CodeSignatureInvalid, "unexpected MEASUREMENT length: "+err.Error(), err)
	}
	matched := false
	for _, a := range v.acceptable {
		if a.Equal(m) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, integrity(shared_errors.CodeAttestationDenied, fmt.Sprintf("MEASUREMENT %x not in acceptable set", m), nil)
	}
	return &AzureCGPUVerdict{Measurement: m, Product: product, ChipID: report.ChipID, ReportedTCB: report.ReportedTCB,
		PCRSelections: quote.PCRSelections, PCRDigest: quote.PCRDigest, GPUs: gpus, Evaluations: evaluations}, nil
}

// fetchVCEK is the GCP verifier's cache, per product.
func (v *AzureCGPUVerifier) fetchVCEK(product string, chipID [64]byte, tcb uint64) ([]byte, error) {
	key := fmt.Sprintf("%s-%x-%d", strings.ToLower(product), chipID, tcb)
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
	cert, err := amdKDSGetVCEKFor(v.cfg.AMDKDSURL, product, chipID, tcb)
	if err != nil {
		return nil, err
	}
	v.vcekCache[key] = cert
	if file != "" {
		_ = writeFileAtomic(file, cert)
	}
	return cert, nil
}

// amdKDSGetVCEKFor fetches a VCEK from AMD KDS for a product; a var so
// tests run without network.
var amdKDSGetVCEKFor = func(baseURL, product string, chipID [64]byte, reportedTCB uint64) ([]byte, error) {
	return realAMDKDSGetVCEKFor(baseURL, product, chipID, reportedTCB)
}

// azureCGPUCapability: the vTPM, tpm2-tools and an NVIDIA device.
func azureCGPUCapability() (bool, string) {
	if _, err := os.Stat("/dev/tpmrm0"); err != nil {
		return false, "Azure confidential GPU: no /dev/tpmrm0 (not a Confidential VM with a vTPM)"
	}
	if _, err := exec.LookPath("tpm2_quote"); err != nil {
		return false, "Azure confidential GPU: tpm2-tools not installed"
	}
	if _, err := os.Stat("/dev/nvidia0"); err != nil {
		return false, "Azure confidential GPU: no /dev/nvidia0 (no NVIDIA driver, or no GPU)"
	}
	return true, "Azure confidential GPU: vTPM, tpm2-tools and an NVIDIA device present"
}

// Compile-time interface conformance.
var (
	_ Producer = (*AzureCGPUProducer)(nil)
	_ Verifier = (*AzureCGPUVerifier)(nil)
)
