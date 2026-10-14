// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — AWS Nitro Enclaves adapter.
//
// AWS Nitro Enclaves expose a per-enclave Nitro Secure Module (NSM) at
// /dev/nsm. The enclave calls NSM_GET_ATTESTATION_DOC with a user-supplied
// nonce + optional public key, and NSM returns a CBOR-encoded COSE_Sign1
// attestation document signed by the AWS PCA root. The document includes:
//
//   - PCRs (Platform Configuration Registers) — the enclave's measurement
//     equivalent: PCR0 = enclave image (used as Measurement here), PCR1 =
//     kernel + bootstrap, PCR2 = application, PCR3-15 = various optional
//     bindings.
//   - Module ID — opaque enclave identifier
//   - Timestamp — RFC 8949 absolute time
//   - User data + nonce + public key — challenger-bound fields
//   - Signature — COSE_Sign1 over the protected header + payload
//   - Certificate chain — leaf cert (root of trust for this attestation)
//     + intermediate(s) + AWS PCA root
//
// Verification:
//   1. Parse CBOR → COSE_Sign1 envelope
//   2. Validate certificate chain against AWS PCA root (pinned at build)
//   3. Verify ECDSA-P384 signature
//   4. Check timestamp freshness
//   5. Compare PCR0 with expected measurement
//   6. Compare nonce with challenger nonce
//
// Sealing on Nitro is NOT a built-in NSM operation. The recommended
// pattern is:
//   - Generate ephemeral keys inside the enclave
//   - Use AWS KMS with an IAM role that requires the CallerIdentity
//     condition kms:RecipientAttestation:PCR0=<expected_pcr0>
//   - KMS Decrypt() returns plaintext only to enclaves matching the PCR
//
// Production caveats this adapter wires for:
//   - NSM device may be absent (running outside enclave) — Capability()
//     reports it
//   - PCR0 changes whenever the enclave image is rebuilt — measurement
//     stability requires reproducible builds
//   - AWS PCA root certificate rotation — pinned root must be refreshable
//     (see awsNitroPinnedRoots)

package tee

import (
	"crypto"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"crypto/subtle"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// AWSNitroProducerConfig configures a Nitro NSM producer.
type AWSNitroProducerConfig struct {
	// NSMDevicePath is the path to the NSM character device. Default
	// "/dev/nsm". Override only for testing or custom container runtimes.
	NSMDevicePath string

	// IncludePublicKey controls whether NSM_GET_ATTESTATION_DOC includes
	// an enclave-supplied public key in the attestation document. If
	// non-nil, the key is bound into the document so a verifier can use
	// it as the basis of subsequent encrypted communication.
	IncludePublicKey crypto.PublicKey

	// UserData is up to 1024 bytes of caller-controlled context bound
	// into the attestation. Use it to bind the attestation to a specific
	// session or job.
	UserData []byte
}

// AWSNitroVerifierConfig configures a Nitro attestation document verifier.
type AWSNitroVerifierConfig struct {
	// PCRIndex selects which PCR to use as the measurement basis. PCR0
	// (enclave image hash) is the standard choice. Default 0.
	PCRIndex int

	// AcceptablePCRSet, if non-empty, lists every PCR0 value the verifier
	// will accept. This supports rolling deployments where two enclave
	// images are simultaneously valid (current + canary). When empty the
	// VerifierSpec.ExpectedMeasurement is used as a single-element set.
	AcceptablePCRSet []Measurement

	// MaxClockSkew is the largest acceptable difference between the
	// timestamp in the attestation document and the local clock.
	// Default 5 minutes. Tighter values reject delayed quotes.
	MaxClockSkew time.Duration

	// PinnedRoots overrides the built-in AWS PCA root certificate set.
	// Use only for region-specific or government-cloud deployments.
	PinnedRoots [][]byte
}

// AWSNitroProducer implements Producer using the NSM device.
type AWSNitroProducer struct {
	cfg         AWSNitroProducerConfig
	measurement Measurement // cached PCR0 read at construction

	mu        sync.Mutex
	nsmHandle *os.File // the NSM device handle, opened lazily
}

// AWSNitroVerifier implements Verifier for COSE_Sign1 attestation docs.
type AWSNitroVerifier struct {
	expected     Measurement
	acceptable   []Measurement // expanded set including expected
	maxClockSkew time.Duration
	pinnedRoots  [][]byte
	pcrIndex     int
}

// AWSNitroSealer implements Sealer using AWS KMS with PCR-conditional
// access. It is constructed separately from the Producer because sealing
// requires AWS SDK credentials and KMS key ARNs that the daemon resolves
// from environment / IAM role at runtime.
type AWSNitroSealer struct {
	kmsKeyARN         string
	expectedPCR0      Measurement
	awsRegion         string
	encryptionContext map[string]string
}

// ----------------------------------------------------------------------------
// Constructors
// ----------------------------------------------------------------------------

// NewAWSNitroProducer opens the NSM device and reads PCR0 to cache as the
// measurement. Returns Structural error if the device is absent (host is
// not running inside an enclave) or if the daemon lacks permission.
//
// In production the NSM device requires the enclave to be configured with
// `--debug-mode false` for genuine attestation; debug-mode enclaves still
// produce attestation docs but mark them as debug, which the verifier
// will reject by default.
func NewAWSNitroProducer(cfg AWSNitroProducerConfig) (*AWSNitroProducer, error) {
	if cfg.NSMDevicePath == "" {
		cfg.NSMDevicePath = "/dev/nsm"
	}
	if len(cfg.UserData) > 1024 {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"aws-nitro: user_data must be <= 1024 bytes",
			nil,
		)
	}

	p := &AWSNitroProducer{cfg: cfg}

	// Open NSM device. On a host without the device we fail fast at
	// startup with a clear diagnostic; the daemon should fall back or
	// refuse to boot rather than running with a silent dummy backend.
	nsm, err := openNSMDevice(cfg.NSMDevicePath)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("aws-nitro: open NSM device %s: %v (this binary must run inside a Nitro Enclave)", cfg.NSMDevicePath, err),
			err,
		)
	}
	p.nsmHandle = nsm

	// Read PCR0 once and cache it. PCR0 is the enclave image hash and is
	// stable for the life of the enclave.
	pcr0, err := nsmDescribePCR(nsm, 0)
	if err != nil {
		_ = nsm.Close()
		return nil, fmt.Errorf("aws-nitro: read PCR0: %w", err)
	}
	if len(pcr0) < 32 {
		_ = nsm.Close()
		return nil, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"aws-nitro: PCR0 shorter than 32 bytes",
			nil,
		)
	}
	p.measurement = append(Measurement(nil), pcr0...)
	return p, nil
}

// NewAWSNitroVerifier constructs a verifier pinned to a single expected
// measurement (or a set, via cfg.AcceptablePCRSet).
func NewAWSNitroVerifier(_ crypto.PublicKey, expected Measurement, cfg AWSNitroVerifierConfig) (*AWSNitroVerifier, error) {
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}
	if cfg.PinnedRoots == nil {
		cfg.PinnedRoots = awsNitroPinnedRoots()
	}
	acc := cfg.AcceptablePCRSet
	if len(acc) == 0 {
		acc = []Measurement{expected}
	}
	return &AWSNitroVerifier{
		expected:     expected,
		acceptable:   acc,
		maxClockSkew: cfg.MaxClockSkew,
		pinnedRoots:  cfg.PinnedRoots,
		pcrIndex:     cfg.PCRIndex,
	}, nil
}

// NewAWSNitroSealer constructs a Sealer that delegates to AWS KMS with
// PCR-conditional access. The kmsKeyARN must reference a key whose policy
// includes a kms:RecipientAttestation:ImageSha384 condition matching
// expectedPCR0; otherwise Decrypt calls from this enclave will fail.
func NewAWSNitroSealer(kmsKeyARN, awsRegion string, expectedPCR0 Measurement) *AWSNitroSealer {
	return &AWSNitroSealer{
		kmsKeyARN:    kmsKeyARN,
		awsRegion:    awsRegion,
		expectedPCR0: expectedPCR0,
		encryptionContext: map[string]string{
			"vault-genome.tee":      "aws-nitro",
			"vault-genome.workload": "sagvd",
		},
	}
}

// ----------------------------------------------------------------------------
// Producer / Verifier / Sealer implementations
// ----------------------------------------------------------------------------

// Quote implements Producer. It calls NSM_GET_ATTESTATION_DOC with the
// challenger nonce and returns the raw CBOR attestation document as
// Evidence. The document is signed by the per-enclave attestation key
// chained to the AWS PCA root.
func (p *AWSNitroProducer) Quote(nonce Nonce) (Evidence, error) {
	if len(nonce) < NonceMinBytes {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"aws-nitro: nonce must be at least NonceMinBytes",
			nil,
		)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nsmHandle == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"aws-nitro: NSM handle not open (producer was closed)",
			nil,
		)
	}

	doc, err := nsmGetAttestationDoc(p.nsmHandle, nsmAttestationRequest{
		Nonce:     nonce,
		UserData:  p.cfg.UserData,
		PublicKey: p.cfg.IncludePublicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-nitro: NSM_GET_ATTESTATION_DOC: %w", err)
	}
	return Evidence(doc), nil
}

// Measurement returns the cached PCR0 read at construction.
func (p *AWSNitroProducer) Measurement() Measurement {
	return p.measurement
}

// Close releases the NSM device handle. Idempotent.
func (p *AWSNitroProducer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nsmHandle == nil {
		return nil
	}
	err := p.nsmHandle.Close()
	p.nsmHandle = nil
	return err
}

// Verify implements Verifier. It parses the CBOR COSE_Sign1 attestation
// document, validates the certificate chain to a pinned AWS root,
// verifies the COSE signature, checks freshness, and compares PCR + nonce
// against the expected values.
func (v *AWSNitroVerifier) Verify(ev Evidence, nonce Nonce) (Measurement, error) {
	var zero Measurement
	if len(nonce) < NonceMinBytes {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"aws-nitro: challenger nonce too short",
			nil,
		)
	}
	if len(ev) < 64 {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"aws-nitro: evidence too short for COSE_Sign1",
			nil,
		)
	}

	// 1. Parse CBOR → COSE_Sign1 (protected header, unprotected header,
	//    payload, signature).
	cose, err := parseCOSESign1(ev)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("aws-nitro: parse COSE_Sign1: %v", err),
			err,
		)
	}

	// 2. Decode payload as Nitro AttestationDocument.
	doc, err := decodeNitroAttestationDoc(cose.Payload)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("aws-nitro: decode attestation doc: %v", err),
			err,
		)
	}

	// 3. Verify certificate chain to pinned root.
	leaf, err := verifyNitroCertChain(doc.Certificate, doc.CABundle, v.pinnedRoots)
	if err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("aws-nitro: cert chain: %v", err),
			err,
		)
	}

	// 4. Verify ECDSA-P384 signature on the COSE_Sign1 envelope.
	if err := verifyCOSESignature(cose, leaf); err != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("aws-nitro: COSE signature: %v", err),
			err,
		)
	}

	// 5. Check freshness.
	skew := time.Since(doc.Timestamp).Abs()
	if skew > v.maxClockSkew {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("aws-nitro: timestamp skew %v exceeds max %v", skew, v.maxClockSkew),
			nil,
		)
	}

	// 6. Check nonce binding.
	if !nonceMatches(doc.Nonce, nonce) {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"aws-nitro: nonce in attestation doc does not match challenger nonce",
			nil,
		)
	}

	// 7. Reject debug-mode attestations (PCR0 in debug mode is all-zeroes
	//    or a sentinel value depending on enclave config).
	if isDebugAttestation(doc) {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"aws-nitro: debug-mode enclave rejected (production verifier)",
			nil,
		)
	}

	// 8. Extract selected PCR and check against acceptable set.
	pcr, ok := doc.PCRs[v.pcrIndex]
	if !ok {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("aws-nitro: attestation doc missing PCR%d", v.pcrIndex),
			nil,
		)
	}
	reported, mErr := MeasurementFromBytes(pcr)
	if mErr != nil {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("aws-nitro: unexpected PCR%d length: %v", v.pcrIndex, mErr),
			nil,
		)
	}

	matched := false
	for _, ok := range v.acceptable {
		if ok.Equal(reported) {
			matched = true
			break
		}
	}
	if !matched {
		return zero, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("aws-nitro: PCR%d not in acceptable set (got %x)", v.pcrIndex, reported),
			nil,
		)
	}
	return reported, nil
}

// Seal implements Sealer via AWS KMS Encrypt with PCR-conditional access.
//
// The cleartext is sent to KMS using the configured CMK (kmsKeyARN) plus
// an EncryptionContext that binds the ciphertext to this workload. The
// returned blob is the KMS ciphertext blob (opaque, ~200 bytes overhead
// regardless of plaintext size).
func (s *AWSNitroSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	if s.kmsKeyARN == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"aws-nitro-sealer: kms_key_arn not configured",
			nil,
		)
	}
	ec := mergeEncryptionContext(s.encryptionContext, aad)
	ciphertext, err := awsKMSEncrypt(s.awsRegion, s.kmsKeyARN, plaintext, ec)
	if err != nil {
		return nil, fmt.Errorf("aws-nitro-sealer: KMS Encrypt: %w", err)
	}
	return ciphertext, nil
}

// Unseal implements Sealer via AWS KMS Decrypt. KMS will only return
// plaintext if the calling identity (the enclave) satisfies the key
// policy's RecipientAttestation conditions — meaning the enclave must
// produce a fresh attestation that includes the expected PCR0.
func (s *AWSNitroSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	if s.kmsKeyARN == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"aws-nitro-sealer: kms_key_arn not configured",
			nil,
		)
	}
	ec := mergeEncryptionContext(s.encryptionContext, aad)
	plaintext, err := awsKMSDecrypt(s.awsRegion, s.kmsKeyARN, sealed, ec)
	if err != nil {
		// AccessDeniedException from KMS often means PCR0 mismatch — the
		// enclave running now is not the one whose attestation was bound
		// to this ciphertext. Surface as Integrity.
		if isKMSAccessDenied(err) {
			return nil, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				"aws-nitro-sealer: KMS denied (PCR0 mismatch — unauthorized enclave)",
				err,
			)
		}
		return nil, fmt.Errorf("aws-nitro-sealer: KMS Decrypt: %w", err)
	}
	return plaintext, nil
}

// ----------------------------------------------------------------------------
// Capability — startup-time check whether we can actually use this backend
// ----------------------------------------------------------------------------

func awsNitroCapability() (bool, string) {
	if _, err := os.Stat("/dev/nsm"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, "AWS Nitro: /dev/nsm device not present (binary must run inside a Nitro Enclave)"
		}
		return false, fmt.Sprintf("AWS Nitro: /dev/nsm stat failed: %v", err)
	}
	return true, "AWS Nitro: NSM device present"
}

// ----------------------------------------------------------------------------
// NSM device + KMS helper stubs
//
// These are isolated from the main adapter logic so that wiring the real
// SDK in Phase 2 (when we have funded engineering time + an actual Nitro
// instance to test against) is a single-file change. Each helper is
// documented with the exact AWS SDK / NSM ioctl / library it should call.
// ----------------------------------------------------------------------------

type nsmAttestationRequest struct {
	Nonce     []byte
	UserData  []byte
	PublicKey crypto.PublicKey
}

// openNSMDevice opens /dev/nsm. In production this is a simple os.Open —
// the NSM device is exposed inside Nitro Enclaves with character-device
// semantics. The kernel side is at github.com/aws/aws-nitro-enclaves-sdk-c.
//
// Exposed as a var so integration tests can substitute a fake that
// constructs an in-memory file pointer without touching the host.
var openNSMDevice = func(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR, 0)
}

// nsmDescribePCR issues NSM_DESCRIBE_PCR for the requested PCR index.
//
// Phase 2 wiring: replace with calls into github.com/hf/nitrite or
// the nsm-api-rs Rust crate via cgo. The wire format is CBOR over the
// NSM ioctl interface; the response includes the PCR's lock state +
// 32-byte SHA-256 value.
//
// Stored as a var (not func) so integration tests can inject a fake NSM
// that returns synthetic but format-faithful PCR readings.
var nsmDescribePCR = func(_ *os.File, _ int) ([]byte, error) {
	return nil, errors.New("nsmDescribePCR: not yet wired to NSM SDK (Phase 2 — wire github.com/hf/nitrite or nitro-attestation-sdk)")
}

// nsmGetAttestationDoc issues NSM_GET_ATTESTATION_DOC.
//
// Phase 2 wiring: same as nsmDescribePCR. The response is a complete
// COSE_Sign1 CBOR document; we return its raw bytes verbatim as Evidence
// so the verifier sees the exact bytes the enclave's attestation key
// signed.
var nsmGetAttestationDoc = func(_ *os.File, _ nsmAttestationRequest) ([]byte, error) {
	return nil, errors.New("nsmGetAttestationDoc: not yet wired to NSM SDK (Phase 2)")
}

// awsKMSEncrypt wraps aws-sdk-go-v2 kms.Client.Encrypt.
//
// Phase 2 wiring: import "github.com/aws/aws-sdk-go-v2/service/kms",
// build a Client with config.LoadDefaultConfig (uses the Nitro
// enclave's IAM role via the parent EC2 instance's credential proxy),
// then call Encrypt with KeyId + Plaintext + EncryptionContext.
var awsKMSEncrypt = func(_ /*region*/ string, _ /*keyARN*/ string, _ []byte, _ map[string]string) ([]byte, error) {
	return nil, errors.New("awsKMSEncrypt: not yet wired to AWS SDK (Phase 2 — import github.com/aws/aws-sdk-go-v2/service/kms)")
}

// awsKMSDecrypt wraps kms.Client.Decrypt with PCR-conditional access.
var awsKMSDecrypt = func(_ /*region*/ string, _ /*keyARN*/ string, _ []byte, _ map[string]string) ([]byte, error) {
	return nil, errors.New("awsKMSDecrypt: not yet wired to AWS SDK (Phase 2)")
}

var isKMSAccessDenied = func(err error) bool {
	// Phase 2: detect via errors.As on smithy.GenericAPIError with code
	// "AccessDeniedException".
	return false
}

// awsNitroPinnedRoots returns the AWS Nitro Enclaves PCA root certificate(s)
// pinned at build time. AWS publishes one root cert; rotation is rare but
// must be supported by allowing operators to override via
// AWSNitroVerifierConfig.PinnedRoots.
//
// The actual root PEM is published at:
// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
func awsNitroPinnedRoots() [][]byte {
	// Phase 2: embed via go:embed of the published root certificate.
	// For now return empty — verifier construction will fail until wired.
	return nil
}

// ----------------------------------------------------------------------------
// COSE / CBOR / certificate helpers (stubs)
// ----------------------------------------------------------------------------

type coseSign1 struct {
	ProtectedRaw   []byte
	UnprotectedRaw []byte
	Payload        []byte
	Signature      []byte
}

var parseCOSESign1 = func(_ []byte) (*coseSign1, error) {
	return nil, errors.New("parseCOSESign1: not yet wired to CBOR library (Phase 2 — import github.com/fxamacker/cbor/v2)")
}

type nitroAttestationDoc struct {
	ModuleID    string
	Timestamp   time.Time
	Digest      string // "SHA384"
	PCRs        map[int][]byte
	Certificate []byte // leaf cert
	CABundle    [][]byte
	Nonce       []byte
	UserData    []byte
	PublicKey   []byte
}

var decodeNitroAttestationDoc = func(_ []byte) (*nitroAttestationDoc, error) {
	return nil, errors.New("decodeNitroAttestationDoc: not yet wired (Phase 2)")
}

var verifyNitroCertChain = func(_ []byte, _ [][]byte, _ [][]byte) ([]byte, error) {
	return nil, errors.New("verifyNitroCertChain: not yet wired (Phase 2 — use crypto/x509)")
}

var verifyCOSESignature = func(_ *coseSign1, _ []byte) error {
	return errors.New("verifyCOSESignature: not yet wired (Phase 2 — verify ECDSA-P384 over Sig_structure)")
}

func nonceMatches(docNonce, challengerNonce []byte) bool {
	if len(docNonce) != len(challengerNonce) {
		return false
	}
	return subtle.ConstantTimeCompare(docNonce, challengerNonce) == 1
}

func isDebugAttestation(doc *nitroAttestationDoc) bool {
	// Debug-mode enclaves report PCR0 = all zeros. Production-mode PCR0
	// is the enclave image SHA-384.
	if doc == nil {
		return true
	}
	pcr0, ok := doc.PCRs[0]
	if !ok {
		return true
	}
	for _, b := range pcr0 {
		if b != 0 {
			return false
		}
	}
	return true
}

func mergeEncryptionContext(base map[string]string, aad []byte) map[string]string {
	out := make(map[string]string, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	if len(aad) > 0 {
		out["vault-genome.aad"] = fmt.Sprintf("%x", aad)
	}
	return out
}

// Compile-time interface conformance.
var (
	_ Producer = (*AWSNitroProducer)(nil)
	_ Verifier = (*AWSNitroVerifier)(nil)
	_ Sealer   = (*AWSNitroSealer)(nil)
)
