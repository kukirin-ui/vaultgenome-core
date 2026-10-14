// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Azure Confidential VMs (AMD SEV-SNP under the paravisor) do not expose
// /dev/sev-guest. The SEV-SNP report is issued at boot and kept in the
// vTPM at NV index 0x01400001 as the "HCL report": a 32-byte header, the
// 1184-byte SNP report, then the runtime data — a small header and a JSON
// document naming the vTPM's attestation key (HCLAkPub), its endorsement
// key and the VM's configuration. The report's REPORT_DATA is the SHA-256
// of that JSON: the chip's signature over the report vouches for the
// vTPM's attestation key, and a TPM quote signed by that key carries a
// caller's nonce. That is how a challenge is bound on Azure — through the
// attestation key the chip named, not through REPORT_DATA directly.

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

const (
	hclHeaderLen        = 32
	hclRuntimeHeaderLen = 20
	hclRuntimeVersion   = 1
	hclReportTypeSNP    = 2
	hclHashTypeSHA256   = 1
	hclNVIndex          = "0x01400001"
	hclMagic            = "HCLA"
	hclAKKeyID          = "HCLAkPub"
)

// hclReport is the vTPM's HCL report, parsed.
type hclReport struct {
	Raw         []byte
	SNP         *sevSNPReport
	RuntimeData []byte // the JSON REPORT_DATA hashes
	Runtime     hclRuntime
}

// hclRuntime is the runtime data JSON.
type hclRuntime struct {
	Keys            []hclJWK       `json:"keys"`
	VMConfiguration map[string]any `json:"vm-configuration"`
	UserData        string         `json:"user-data"`
}

// hclJWK is one key of the runtime data (RSA, JWK encoding).
type hclJWK struct {
	KID    string   `json:"kid"`
	KTY    string   `json:"kty"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	KeyOps []string `json:"key_ops"`
}

// parseHCLReport reads the HCL blob and checks that the SNP report's
// REPORT_DATA is the SHA-256 of the runtime data it carries.
func parseHCLReport(raw []byte) (*hclReport, error) {
	if len(raw) < hclHeaderLen+sevReportLen+hclRuntimeHeaderLen {
		return nil, fmt.Errorf("HCL report is %d bytes, shorter than header, SNP report and runtime header (%d)", len(raw), hclHeaderLen+sevReportLen+hclRuntimeHeaderLen)
	}
	if string(raw[:4]) != hclMagic {
		return nil, fmt.Errorf("HCL report does not start with %q", hclMagic)
	}
	snp, err := parseSEVSNPReport(raw[hclHeaderLen : hclHeaderLen+sevReportLen])
	if err != nil {
		return nil, fmt.Errorf("SNP report inside the HCL report: %w", err)
	}
	rt := raw[hclHeaderLen+sevReportLen:]
	version := binary.LittleEndian.Uint32(rt[4:8])
	reportType := binary.LittleEndian.Uint32(rt[8:12])
	hashType := binary.LittleEndian.Uint32(rt[12:16])
	payloadSize := binary.LittleEndian.Uint32(rt[16:20])
	if version != hclRuntimeVersion || reportType != hclReportTypeSNP || hashType != hclHashTypeSHA256 {
		return nil, fmt.Errorf("HCL runtime data header: version %d, report type %d, hash type %d; this verifier reads version %d, SNP (%d), SHA-256 (%d)",
			version, reportType, hashType, hclRuntimeVersion, hclReportTypeSNP, hclHashTypeSHA256)
	}
	if int(payloadSize) > len(rt)-hclRuntimeHeaderLen {
		return nil, fmt.Errorf("HCL runtime data payload %d bytes exceeds the %d present", payloadSize, len(rt)-hclRuntimeHeaderLen)
	}
	payload := rt[hclRuntimeHeaderLen : hclRuntimeHeaderLen+int(payloadSize)]
	sum := sha256.Sum256(payload)
	if [32]byte(snp.ReportData[:32]) != sum {
		return nil, errors.New("SNP REPORT_DATA is not the SHA-256 of the runtime data: the report does not vouch for these keys")
	}
	for _, b := range snp.ReportData[32:] {
		if b != 0 {
			return nil, errors.New("SNP REPORT_DATA[32:] is not zero")
		}
	}
	h := &hclReport{Raw: append([]byte(nil), raw...), SNP: snp, RuntimeData: append([]byte(nil), payload...)}
	if err := json.Unmarshal(payload, &h.Runtime); err != nil {
		return nil, fmt.Errorf("HCL runtime data is not JSON: %w", err)
	}
	return h, nil
}

// attestationKey is the vTPM's attestation key the chip vouched for.
func (h *hclReport) attestationKey() (*rsa.PublicKey, error) {
	for _, k := range h.Runtime.Keys {
		if k.KID != hclAKKeyID {
			continue
		}
		if k.KTY != "RSA" {
			return nil, fmt.Errorf("%s is %q, not RSA", hclAKKeyID, k.KTY)
		}
		signs := false
		for _, op := range k.KeyOps {
			if op == "sign" {
				signs = true
			}
		}
		if !signs {
			return nil, fmt.Errorf("%s is not a signing key (key_ops %v)", hclAKKeyID, k.KeyOps)
		}
		return rsaFromJWK(k.N, k.E)
	}
	return nil, fmt.Errorf("HCL runtime data names no %s", hclAKKeyID)
}

// rsaFromJWK builds an RSA public key from base64url modulus and exponent.
func rsaFromJWK(n, e string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("JWK n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("JWK e: %w", err)
	}
	if len(nb) < 256 || len(eb) == 0 || len(eb) > 4 {
		return nil, fmt.Errorf("JWK RSA key: modulus %d bytes, exponent %d bytes", len(nb), len(eb))
	}
	exp := 0
	for _, b := range eb {
		exp = exp<<8 | int(b)
	}
	if exp < 3 || exp%2 == 0 {
		return nil, fmt.Errorf("JWK RSA exponent %d", exp)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: exp}, nil
}

// sevProductName names the AMD product a report version 3 came from, by
// the CPUID family and model it carries; AMD KDS serves the VCEK and the
// certificate chain per product. Reports before version 3 carry no CPUID
// and are taken as Milan, the only product they were issued on.
func sevProductName(report *sevSNPReport) string {
	if len(report.Raw) < sevOffCPUIDFam+3 || binary.LittleEndian.Uint32(report.Raw[0:4]) < 3 {
		return "Milan"
	}
	fam, model := report.Raw[sevOffCPUIDFam], report.Raw[sevOffCPUIDFam+1]
	switch {
	case fam == 0x19 && model == 0x01:
		return "Milan"
	case fam == 0x19 && model == 0x11:
		return "Genoa"
	case fam == 0x1A && model == 0x02:
		return "Turin"
	}
	return fmt.Sprintf("family-%#x-model-%#x", fam, model)
}

// sevOffCPUIDFam is where a version-3 report carries CPUID_FAM_ID, then
// CPUID_MOD_ID and CPUID_STEP.
const sevOffCPUIDFam = 0x188

// parsePEMRSAPublicKey reads a PEM SubjectPublicKeyInfo holding an RSA key
// (what tpm2_readpublic -f pem writes).
func parsePEMRSAPublicKey(raw []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return k, nil
}
