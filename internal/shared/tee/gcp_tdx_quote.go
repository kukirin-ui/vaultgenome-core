// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Intel TDX quotes (version 4, ECDSA-P256 attestation key), as a Google
// Cloud Confidential VM (c3, a3 with Intel TDX) obtains them through the
// kernel's configfs-tsm interface (provider "tdx_guest"). The Quote
// Generation Service on the host signs the TD's report with a Quoting
// Enclave whose attestation key is itself certified by the platform's
// PCK certificate, which chains to the Intel SGX Root CA.
//
// Layout (Intel® TDX DCAP Quote Generation Library, quote v4):
//
//	 0   header (48): version u16 = 4, attestation key type u16 = 2
//	     (ECDSA-P256 with SHA-256), TEE type u32 = 0x81 (TDX), reserved,
//	     QE vendor id (16), user data (20)
//	48   TD report body (584): TEE_TCB_SVN (16), MRSEAM (48),
//	     MRSIGNERSEAM (48), SEAMATTRIBUTES (8), TDATTRIBUTES (8), XFAM (8),
//	     MRTD (48), MRCONFIGID (48), MROWNER (48), MROWNERCONFIG (48),
//	     RTMR0..3 (4×48), REPORTDATA (64)
//	632  signature data length u32, then the signature data:
//	     quote signature r||s (64) by the attestation key over bytes
//	     [0, 632); attestation public key x||y (64); certification data
//	     type u16 = 6 and size u32, then the QE report certification data:
//	     QE report (384, an SGX REPORT body) signed by the PCK certificate
//	     — signature r||s (64) — the QE authentication data (u16 length +
//	     bytes), and inner certification data type u16 = 5 and size u32:
//	     the PCK certificate chain, PEM (leaf, platform/processor CA, root).
//
// What binds what: the QE report's REPORTDATA is SHA-256(attestation
// key || QE authentication data) followed by 32 zero bytes, so the PCK
// certificate vouches for the attestation key, and the attestation key
// vouches for the TD report. The verifier walks exactly that chain.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	tdxQuoteVersion       = 4
	tdxAttKeyTypeECDSA256 = 2
	tdxTEEType            = 0x81
	tdxHeaderLen          = 48
	tdxBodyLen            = 584
	tdxSignedLen          = tdxHeaderLen + tdxBodyLen // what the attestation key signs
	tdxMinQuoteLen        = tdxSignedLen + 4
	tdxCertDataQEReport   = 6
	tdxCertDataPCKChain   = 5
	sgxReportBodyLen      = 384

	// TDATTRIBUTES bit 0: the TD runs in off-TD debug mode — its memory
	// is readable by the host. Never accepted.
	tdxAttrDebug = 1 << 0
)

// tdxQuote is a parsed TDX quote.
type tdxQuote struct {
	Raw []byte

	Version       uint16
	AttKeyType    uint16
	TEEType       uint32
	QESVN, PCESVN uint16
	QEVendorID    [16]byte

	// The TD report body.
	TEETCBSVN     [16]byte
	MRSEAM        [48]byte
	MRSIGNERSEAM  [48]byte
	SEAMAttrs     [8]byte
	TDAttrs       uint64
	XFAM          uint64
	MRTD          [48]byte
	MRCONFIGID    [48]byte
	MROWNER       [48]byte
	MROWNERCONFIG [48]byte
	RTMR          [4][48]byte
	ReportData    [64]byte

	// The signature data.
	Signature      [64]byte // r||s over Raw[:632]
	AttestationKey [64]byte // x||y, P-256
	QEReport       []byte   // 384 bytes
	QEReportSig    [64]byte // r||s over QEReport by the PCK leaf
	QEAuthData     []byte
	PCKChainPEM    []byte
}

// sgxReport is the part of an SGX REPORT body the verifier reads.
type sgxReport struct {
	CPUSVN     [16]byte
	MiscSelect [4]byte
	Attributes [16]byte
	MRENCLAVE  [32]byte
	MRSIGNER   [32]byte
	ISVProdID  uint16
	ISVSVN     uint16
	ReportData [64]byte
}

func parseSGXReport(b []byte) (sgxReport, error) {
	var r sgxReport
	if len(b) < sgxReportBodyLen {
		return r, fmt.Errorf("SGX report body is %d bytes, want %d", len(b), sgxReportBodyLen)
	}
	copy(r.CPUSVN[:], b[0:16])
	copy(r.MiscSelect[:], b[16:20])
	copy(r.Attributes[:], b[48:64])
	copy(r.MRENCLAVE[:], b[64:96])
	copy(r.MRSIGNER[:], b[128:160])
	r.ISVProdID = binary.LittleEndian.Uint16(b[256:258])
	r.ISVSVN = binary.LittleEndian.Uint16(b[258:260])
	copy(r.ReportData[:], b[320:384])
	return r, nil
}

// parseTDXQuote reads a version-4 TDX quote with ECDSA-P256 certification
// through a QE report and a PCK certificate chain — the shape the Google
// Cloud QGS produces. Anything else is refused: the verifier verifies only
// what it can walk to a root it pins.
func parseTDXQuote(raw []byte) (*tdxQuote, error) {
	if len(raw) < tdxMinQuoteLen {
		return nil, fmt.Errorf("quote is %d bytes, shorter than a header and TD report (%d)", len(raw), tdxMinQuoteLen)
	}
	q := &tdxQuote{Raw: append([]byte(nil), raw...)}
	q.Version = binary.LittleEndian.Uint16(raw[0:2])
	q.AttKeyType = binary.LittleEndian.Uint16(raw[2:4])
	q.TEEType = binary.LittleEndian.Uint32(raw[4:8])
	q.QESVN = binary.LittleEndian.Uint16(raw[8:10])
	q.PCESVN = binary.LittleEndian.Uint16(raw[10:12])
	copy(q.QEVendorID[:], raw[12:28])
	switch {
	case q.Version != tdxQuoteVersion:
		return nil, fmt.Errorf("quote version %d, this verifier reads version %d", q.Version, tdxQuoteVersion)
	case q.AttKeyType != tdxAttKeyTypeECDSA256:
		return nil, fmt.Errorf("attestation key type %d, this verifier reads ECDSA-P256 (%d)", q.AttKeyType, tdxAttKeyTypeECDSA256)
	case q.TEEType != tdxTEEType:
		return nil, fmt.Errorf("TEE type %#x, want TDX (%#x)", q.TEEType, tdxTEEType)
	}
	body := raw[tdxHeaderLen:tdxSignedLen]
	copy(q.TEETCBSVN[:], body[0:16])
	copy(q.MRSEAM[:], body[16:64])
	copy(q.MRSIGNERSEAM[:], body[64:112])
	copy(q.SEAMAttrs[:], body[112:120])
	q.TDAttrs = binary.LittleEndian.Uint64(body[120:128])
	q.XFAM = binary.LittleEndian.Uint64(body[128:136])
	copy(q.MRTD[:], body[136:184])
	copy(q.MRCONFIGID[:], body[184:232])
	copy(q.MROWNER[:], body[232:280])
	copy(q.MROWNERCONFIG[:], body[280:328])
	for i := range q.RTMR {
		copy(q.RTMR[i][:], body[328+48*i:376+48*i])
	}
	copy(q.ReportData[:], body[520:584])

	sigLen := int(binary.LittleEndian.Uint32(raw[tdxSignedLen : tdxSignedLen+4]))
	sd := raw[tdxMinQuoteLen:]
	if sigLen > len(sd) {
		return nil, fmt.Errorf("signature data length %d exceeds the %d bytes present", sigLen, len(sd))
	}
	sd = sd[:sigLen]
	if len(sd) < 64+64+2+4 {
		return nil, errors.New("signature data too short for a signature, an attestation key and certification data")
	}
	copy(q.Signature[:], sd[0:64])
	copy(q.AttestationKey[:], sd[64:128])
	certType := binary.LittleEndian.Uint16(sd[128:130])
	certSize := int(binary.LittleEndian.Uint32(sd[130:134]))
	if certType != tdxCertDataQEReport {
		return nil, fmt.Errorf("certification data type %d, this verifier reads a QE report (%d)", certType, tdxCertDataQEReport)
	}
	if certSize > len(sd)-134 {
		return nil, fmt.Errorf("certification data size %d exceeds the %d bytes present", certSize, len(sd)-134)
	}
	cd := sd[134 : 134+certSize]
	if len(cd) < sgxReportBodyLen+64+2 {
		return nil, errors.New("QE report certification data too short")
	}
	q.QEReport = append([]byte(nil), cd[0:sgxReportBodyLen]...)
	copy(q.QEReportSig[:], cd[sgxReportBodyLen:sgxReportBodyLen+64])
	authLen := int(binary.LittleEndian.Uint16(cd[448:450]))
	if 450+authLen+6 > len(cd) {
		return nil, errors.New("QE authentication data runs past the certification data")
	}
	q.QEAuthData = append([]byte(nil), cd[450:450+authLen]...)
	inner := cd[450+authLen:]
	innerType := binary.LittleEndian.Uint16(inner[0:2])
	innerSize := int(binary.LittleEndian.Uint32(inner[2:6]))
	if innerType != tdxCertDataPCKChain {
		return nil, fmt.Errorf("QE certification data type %d, this verifier reads a PCK certificate chain (%d)", innerType, tdxCertDataPCKChain)
	}
	if innerSize > len(inner)-6 {
		return nil, fmt.Errorf("PCK chain size %d exceeds the %d bytes present", innerSize, len(inner)-6)
	}
	q.PCKChainPEM = bytes.TrimRight(inner[6:6+innerSize], "\x00")
	return q, nil
}

// signedBytes is what the attestation key signs: the header and the TD
// report body.
func (q *tdxQuote) signedBytes() []byte { return q.Raw[:tdxSignedLen] }

// p256PublicKey builds a P-256 public key from an x||y point.
func p256PublicKey(xy [64]byte) (*ecdsa.PublicKey, error) {
	// The uncompressed point (0x04 || x || y) is checked to be on the
	// curve as it is parsed.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, xy[:]...))
	if err != nil {
		return nil, fmt.Errorf("attestation key is not a point on P-256: %w", err)
	}
	return pub, nil
}

// verifyP256Raw checks an r||s ECDSA-P256 signature over SHA-256(msg).
func verifyP256Raw(pub *ecdsa.PublicKey, msg []byte, sig [64]byte) bool {
	h := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, h[:], r, s)
}

// verifyQuoteSignatures checks the two signatures and the binding between
// them: the attestation key over the TD report, the PCK leaf over the QE
// report, and the QE report's REPORTDATA naming the attestation key.
// pckLeaf is the first certificate of the quote's chain, already chained
// to the pinned root by the caller.
func verifyQuoteSignatures(q *tdxQuote, pckLeaf *x509.Certificate) error {
	ak, err := p256PublicKey(q.AttestationKey)
	if err != nil {
		return err
	}
	if !verifyP256Raw(ak, q.signedBytes(), q.Signature) {
		return errors.New("the TD report's signature does not verify under the quote's attestation key")
	}
	pckPub, ok := pckLeaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pckPub.Curve != elliptic.P256() {
		return errors.New("the PCK certificate's key is not ECDSA P-256")
	}
	if !verifyP256Raw(pckPub, q.QEReport, q.QEReportSig) {
		return errors.New("the QE report's signature does not verify under the PCK certificate")
	}
	qe, err := parseSGXReport(q.QEReport)
	if err != nil {
		return err
	}
	want := sha256.Sum256(append(append([]byte(nil), q.AttestationKey[:]...), q.QEAuthData...))
	var expect [64]byte
	copy(expect[:], want[:])
	if qe.ReportData != expect {
		return errors.New("the QE report does not certify the quote's attestation key (REPORTDATA mismatch)")
	}
	return nil
}

// intelSGXRootCAPEM is the Intel SGX Root CA, the trust anchor of every
// PCK certificate chain and every PCS signing chain (subject "Intel SGX
// Root CA", valid 2018-05-21 to 2049-12-31, SHA-256 fingerprint
// 44a0196b2b99f889b8e149e95b807a350e74249643 99e885a7cbb8ccfab674d3).
// Captured with the quote on a Google Cloud TDX guest
// (scripts/hardware-test/gcp-tdx/capture); an operator with a different
// anchor overrides it in the verifier's configuration.
const intelSGXRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
`

// intelRootPool returns the pinned Intel SGX Root CA, or the operator's
// override.
func intelRootPool(override []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pemBytes := []byte(intelSGXRootCAPEM)
	if len(override) > 0 {
		pemBytes = override
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("no certificate in the Intel root PEM")
	}
	return pool, nil
}

// parsePEMCertificates reads every certificate in a PEM bundle, in order.
func parsePEMCertificates(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate in PEM")
	}
	return out, nil
}

// verifyChainToIntelRoot verifies chain[0] up to the pinned Intel root
// through the intermediates the chain carries, at time now. The chain's
// own last certificate is not trusted as a root: only the pinned one is.
func verifyChainToIntelRoot(chain []*x509.Certificate, rootOverride []byte, now time.Time) error {
	roots, err := intelRootPool(rootOverride)
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err = chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// The PCK certificate's SGX extension (OID 1.2.840.113741.1.13.1): a
// sequence of {oid, value} pairs — the platform's TCB (16 component SVNs
// and the PCE SVN), its PCE-ID and its FMSPC, which pick the TCB info the
// verifier evaluates the quote against.
var (
	oidSGXExtension = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	oidSGXTCB       = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 2}
	oidSGXPCEID     = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 3}
	oidSGXFMSPC     = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
)

type asn1Pair struct {
	OID   asn1.ObjectIdentifier
	Value asn1.RawValue
}

// pckPlatform is what the PCK leaf says about the platform.
type pckPlatform struct {
	FMSPC   [6]byte
	PCEID   [2]byte
	CPUSVNs [16]uint8 // TCB component SVNs 1..16
	PCESVN  uint16
}

func parsePCKExtension(leaf *x509.Certificate) (pckPlatform, error) {
	var p pckPlatform
	var raw []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSGXExtension) {
			raw = e.Value
		}
	}
	if raw == nil {
		return p, errors.New("the PCK certificate carries no SGX extension")
	}
	var pairs []asn1Pair
	if rest, err := asn1.Unmarshal(raw, &pairs); err != nil || len(rest) != 0 {
		return p, fmt.Errorf("SGX extension does not parse: %v", err)
	}
	var haveTCB, haveFMSPC, havePCEID bool
	for _, pr := range pairs {
		switch {
		case pr.OID.Equal(oidSGXFMSPC):
			if len(pr.Value.Bytes) != 6 {
				return p, errors.New("FMSPC is not 6 bytes")
			}
			copy(p.FMSPC[:], pr.Value.Bytes)
			haveFMSPC = true
		case pr.OID.Equal(oidSGXPCEID):
			if len(pr.Value.Bytes) != 2 {
				return p, errors.New("PCE-ID is not 2 bytes")
			}
			copy(p.PCEID[:], pr.Value.Bytes)
			havePCEID = true
		case pr.OID.Equal(oidSGXTCB):
			var comps []asn1Pair
			if rest, err := asn1.Unmarshal(pr.Value.FullBytes, &comps); err != nil || len(rest) != 0 {
				return p, fmt.Errorf("SGX TCB extension does not parse: %v", err)
			}
			for _, c := range comps {
				n := len(c.OID)
				if n != len(oidSGXTCB)+1 || !c.OID[:n-1].Equal(oidSGXTCB) {
					continue
				}
				idx := c.OID[n-1]
				var v int
				if rest, err := asn1.Unmarshal(c.Value.FullBytes, &v); err != nil || len(rest) != 0 {
					if idx == 18 { // CPUSVN, an octet string: derived from the components, not needed
						continue
					}
					return p, fmt.Errorf("SGX TCB component %d does not parse: %v", idx, err)
				}
				switch {
				case idx >= 1 && idx <= 16:
					p.CPUSVNs[idx-1] = uint8(v)
				case idx == 17:
					p.PCESVN = uint16(v)
				}
			}
			haveTCB = true
		}
	}
	if !haveTCB || !haveFMSPC || !havePCEID {
		return p, errors.New("the SGX extension lacks the TCB, FMSPC or PCE-ID")
	}
	return p, nil
}

// p256FromCert returns a certificate's ECDSA P-256 public key.
func p256FromCert(c *x509.Certificate) (*ecdsa.PublicKey, error) {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("certificate's key is not ECDSA P-256")
	}
	return pub, nil
}
