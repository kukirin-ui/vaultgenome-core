// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Real AMD SEV-SNP verification: fixed-offset report parse, ECDSA-P384
// signature check under the VCEK, and VCEK -> ASK -> ARK certificate-chain
// validation. These replace the Phase-2 stubs in gcp_sev_snp.go (wired via
// init below); integration tests still override the package vars with a fake
// SEV guest, and the pure functions here are exercised directly against a
// genuine captured hardware report in gcp_sev_snp_verify_test.go.
//
// Report layout (SEV-SNP ABI, report versions 2–5), byte offsets:
//   0x008 POLICY        (8, little-endian; bit 19 = DEBUG)
//   0x030 VMPL          (4, little-endian)
//   0x034 SIG_ALGO      (4, little-endian; 1 = ECDSA P-384 / SHA-384)
//   0x048 FLAGS         (4; bits 4:2 = SIGNING_KEY, 0 = VCEK, 1 = VLEK)
//   0x050 REPORT_DATA   (64)   caller-supplied freshness field
//   0x090 MEASUREMENT   (48)   launch measurement, SHA-384
//   0x0C0 HOST_DATA     (32)
//   0x180 REPORTED_TCB  (8, little-endian)
//   0x1A0 CHIP_ID       (64)
//   0x2A0 SIGNATURE     ECDSA r (72-byte slot, 48 used, little-endian),
//                       then s at 0x2A0+72 (same shape). Signed body is
//                       report[:0x2A0], hashed with SHA-384.

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	sevOffPolicy      = 0x008
	sevOffVMPL        = 0x030
	sevOffSigAlgo     = 0x034
	sevOffFlags       = 0x048
	sevOffReportData  = 0x050
	sevOffMeasurement = 0x090
	sevOffHostData    = 0x0C0
	sevOffReportedTCB = 0x180
	sevOffChipID      = 0x1A0
	sevOffSignature   = 0x2A0
	sevReportLen      = 1184
	sevSigComponent   = 48 // P-384 r/s length in bytes
	sevSigSlot        = 72 // per-component slot in the signature field
)

func init() {
	// Wire the network-free real implementations into the package vars.
	// (amdKDSGetVCEK / verifyAMDChain do network + X.509 and are wired too;
	// integration tests override all of these with a fake SEV guest.)
	parseSEVSNPReport = realParseSEVSNPReport
	verifySEVReportSignature = realVerifySEVReportSignature
	verifyAMDChain = realVerifyAMDChain
	amdKDSGetVCEK = realAMDKDSGetVCEK
}

// realParseSEVSNPReport reads the fixed-offset fields from a 1184-byte report.
func realParseSEVSNPReport(raw []byte) (*sevSNPReport, error) {
	if len(raw) < sevReportLen {
		return nil, fmt.Errorf("sev report too short: %d < %d", len(raw), sevReportLen)
	}
	r := &sevSNPReport{Raw: append([]byte(nil), raw[:sevReportLen]...)}
	copy(r.ReportData[:], raw[sevOffReportData:sevOffReportData+64])
	copy(r.Measurement[:], raw[sevOffMeasurement:sevOffMeasurement+48])
	copy(r.HostData[:], raw[sevOffHostData:sevOffHostData+32])
	copy(r.ChipID[:], raw[sevOffChipID:sevOffChipID+64])
	r.ReportedTCB = binary.LittleEndian.Uint64(raw[sevOffReportedTCB : sevOffReportedTCB+8])
	r.Policy = binary.LittleEndian.Uint64(raw[sevOffPolicy : sevOffPolicy+8])
	r.VMPL = binary.LittleEndian.Uint32(raw[sevOffVMPL : sevOffVMPL+4])
	r.SignatureAlgo = binary.LittleEndian.Uint32(raw[sevOffSigAlgo : sevOffSigAlgo+4])
	r.SigningKey = uint8(binary.LittleEndian.Uint32(raw[sevOffFlags:sevOffFlags+4])>>2) & 0x7
	return r, nil
}

// realVerifySEVReportSignature checks the ECDSA-P384 signature over
// report[:0x2A0] under the VCEK's public key. r and s are stored
// little-endian in the report and reversed to big-endian here.
func realVerifySEVReportSignature(report *sevSNPReport, vcekCert []byte) error {
	cert, err := parseCert(vcekCert)
	if err != nil {
		return fmt.Errorf("parse VCEK: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("VCEK public key is not ECDSA")
	}
	if len(report.Raw) < sevReportLen {
		return errors.New("report raw too short for signature")
	}
	rBytes := leToBE(report.Raw[sevOffSignature : sevOffSignature+sevSigComponent])
	sBytes := leToBE(report.Raw[sevOffSignature+sevSigSlot : sevOffSignature+sevSigSlot+sevSigComponent])
	rInt := new(big.Int).SetBytes(rBytes)
	sInt := new(big.Int).SetBytes(sBytes)
	digest := sha512.Sum384(report.Raw[:sevOffSignature])
	if !ecdsa.Verify(pub, digest[:], rInt, sInt) {
		return errors.New("ECDSA-P384 signature verification failed")
	}
	return nil
}

// realVerifyAMDChain validates VCEK <- ASK <- ARK (self-signed). chainPEM is
// the AMD KDS cert_chain (ASK then ARK, PEM). Signatures are checked directly
// (RSASSA-PSS) so CA/key-usage policy quirks in AMD certs do not block a
// cryptographically valid chain.
func realVerifyAMDChain(vcekCert []byte, chainPEM []byte) error {
	vcek, err := parseCert(vcekCert)
	if err != nil {
		return fmt.Errorf("parse VCEK: %w", err)
	}
	ask, ark, err := parseASKARK(chainPEM)
	if err != nil {
		return err
	}
	if err := ask.CheckSignature(vcek.SignatureAlgorithm, vcek.RawTBSCertificate, vcek.Signature); err != nil {
		return fmt.Errorf("VCEK not signed by ASK: %w", err)
	}
	if err := ark.CheckSignature(ask.SignatureAlgorithm, ask.RawTBSCertificate, ask.Signature); err != nil {
		return fmt.Errorf("ASK not signed by ARK: %w", err)
	}
	if err := ark.CheckSignature(ark.SignatureAlgorithm, ark.RawTBSCertificate, ark.Signature); err != nil {
		return fmt.Errorf("ARK not self-signed (root mismatch): %w", err)
	}
	return nil
}

// realAMDKDSGetVCEK fetches the VCEK certificate (DER) from the AMD KDS for a
// given CHIP_ID and reported TCB. TCB is decomposed into the four SPL bytes
// AMD's endpoint expects.
func realAMDKDSGetVCEK(baseURL string, chipID [64]byte, reportedTCB uint64) ([]byte, error) {
	if baseURL == "" {
		baseURL = "https://kdsintf.amd.com"
	}
	bl := byte(reportedTCB)
	tee := byte(reportedTCB >> 8)
	snp := byte(reportedTCB >> 48)
	ucode := byte(reportedTCB >> 56)
	q := url.Values{}
	q.Set("blSPL", fmt.Sprintf("%d", bl))
	q.Set("teeSPL", fmt.Sprintf("%d", tee))
	q.Set("snpSPL", fmt.Sprintf("%d", snp))
	q.Set("ucodeSPL", fmt.Sprintf("%d", ucode))
	u := fmt.Sprintf("%s/vcek/v1/Milan/%x?%s", baseURL, chipID[:], q.Encode())
	return httpGet(u)
}

// realAMDKDSGetVCEKFor is realAMDKDSGetVCEK for a named product (Milan,
// Genoa, Turin): AMD KDS serves each product's VCEKs under its own path.
func realAMDKDSGetVCEKFor(baseURL, product string, chipID [64]byte, reportedTCB uint64) ([]byte, error) {
	if baseURL == "" {
		baseURL = "https://kdsintf.amd.com"
	}
	q := url.Values{}
	q.Set("blSPL", fmt.Sprintf("%d", byte(reportedTCB)))
	q.Set("teeSPL", fmt.Sprintf("%d", byte(reportedTCB>>8)))
	q.Set("snpSPL", fmt.Sprintf("%d", byte(reportedTCB>>48)))
	q.Set("ucodeSPL", fmt.Sprintf("%d", byte(reportedTCB>>56)))
	return httpGet(fmt.Sprintf("%s/vcek/v1/%s/%x?%s", baseURL, product, chipID[:], q.Encode()))
}

// realAMDKDSGetCertChain fetches the ASK+ARK PEM bundle from AMD KDS.
func realAMDKDSGetCertChain(baseURL string) ([]byte, error) {
	if baseURL == "" {
		baseURL = "https://kdsintf.amd.com"
	}
	return httpGet(baseURL + "/vcek/v1/Milan/cert_chain")
}

// ---- helpers ---------------------------------------------------------------

func leToBE(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func parseCert(b []byte) (*x509.Certificate, error) {
	if len(b) >= 10 && string(b[:10]) == "-----BEGIN" {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("no PEM block")
		}
		b = blk.Bytes
	}
	return x509.ParseCertificate(b)
}

// parseASKARK returns (ASK, ARK) from a PEM bundle containing both, in either
// order (ASK is the intermediate, ARK is self-signed / the root).
func parseASKARK(chainPEM []byte) (ask, ark *x509.Certificate, err error) {
	var certs []*x509.Certificate
	rest := chainPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, e := x509.ParseCertificate(blk.Bytes)
		if e != nil {
			return nil, nil, fmt.Errorf("parse chain cert: %w", e)
		}
		certs = append(certs, c)
	}
	if len(certs) < 2 {
		return nil, nil, fmt.Errorf("expected 2 certs (ASK, ARK) in chain, got %d", len(certs))
	}
	for _, c := range certs {
		if c.Subject.String() == c.Issuer.String() {
			ark = c
		} else {
			ask = c
		}
	}
	if ask == nil || ark == nil {
		return nil, nil, errors.New("could not identify ASK (intermediate) and ARK (self-signed root)")
	}
	return ask, ark, nil
}

// kdsAttempts and kdsMaxWait bound how long a verifier waits out AMD KDS
// rate limiting (HTTP 429) or unavailability (503) before failing closed.
const (
	kdsAttempts = 4
	kdsMaxWait  = 20 * time.Second
)

// kdsSleep is time.Sleep; tests replace it to avoid real waits.
var kdsSleep = time.Sleep

func httpGet(u string) ([]byte, error) {
	client := &http.Client{Timeout: 40 * time.Second}
	var status int
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "vault-genome (+https://github.com/vault-genome/vaultgenome-core)")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		status = resp.StatusCode
		if status == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return body, err
		}
		retryAfter := resp.Header.Get("Retry-After")
		_ = resp.Body.Close()
		if (status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable) || attempt == kdsAttempts {
			break
		}
		kdsSleep(kdsBackoff(attempt, retryAfter))
	}
	return nil, fmt.Errorf("AMD KDS returned HTTP %d for %s", status, u)
}

// kdsBackoff honours a Retry-After in seconds, else doubles from two
// seconds, never waiting longer than kdsMaxWait.
func kdsBackoff(attempt int, retryAfter string) time.Duration {
	wait := time.Duration(1<<attempt) * time.Second
	if secs, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && secs >= 0 {
		wait = time.Duration(secs) * time.Second
	}
	if wait > kdsMaxWait {
		wait = kdsMaxWait
	}
	return wait
}
