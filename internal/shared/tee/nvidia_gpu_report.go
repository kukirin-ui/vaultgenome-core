// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// The GPU's own word, read by this verifier: an NVIDIA H100's attestation
// report is the SPDM 1.1 GET_MEASUREMENTS exchange the driver had with the
// GPU — the request (with the verifier's nonce) followed by the signed
// MEASUREMENTS response: 64 DMTF measurement blocks, the GPU's nonce,
// NVIDIA's opaque data (driver and VBIOS versions, project, SKU, chip,
// the firmware id) and an ECDSA P-384 signature under the GPU's
// attestation certificate, whose chain ends at the NVIDIA Device Identity
// CA. NVIDIA's Remote Attestation Service evaluates that report and signs
// a verdict (nvidia_eat.go); this file is the evaluation this verifier
// makes itself, so an operator need not take the verdict on NVIDIA's word
// alone. The layouts follow DMTF SPDM 1.1 and NVIDIA's open-source
// verifier (github.com/NVIDIA/nvtrust, local_gpu_verifier).

const (
	spdmVersion11         = 0x11
	spdmGetMeasurements   = 0xE0
	spdmMeasurements      = 0x60
	gpuReportRequestLen   = 37 // version, code, param1, param2, nonce (32), slot id
	gpuReportNonceLen     = 32
	gpuReportSignatureLen = 96 // ECDSA P-384: r || s
	dmtfMeasurementSpec   = 1
)

// NVIDIA's opaque data field ids (the ones this verifier reads).
const (
	opaqueDriverVersion    = 3
	opaqueVBIOSVersion     = 6
	opaqueNVDEC0Status     = 11
	opaqueMeasurementCount = 12
	opaqueChipSKU          = 15
	opaqueProject          = 17
	opaqueProjectSKU       = 18
	opaqueFWID             = 20
	opaqueDataVersion      = 34
)

const nvdec0Disabled = 0x55 // NVIDIA's NVDEC0 status enum: enabled 0xAA, disabled 0x55

// GPUReport is a parsed attestation report.
type GPUReport struct {
	// RequestNonce is the nonce in the GET_MEASUREMENTS request — the one
	// the verifier gave the driver; ResponseNonce the GPU's own.
	RequestNonce  []byte
	ResponseNonce []byte
	// Blocks holds the DMTF measurement values by SPDM block index, which
	// counts from 1; NVIDIA's reference manifests count from 0
	// (Measurement gives a value by the manifest's index).
	Blocks map[int][]byte
	// Opaque holds NVIDIA's opaque data by field id.
	Opaque map[uint16][]byte
	// Signature is the P-384 signature (r || s) over everything before it:
	// the request and the response up to the signature.
	Signature []byte
	signed    []byte
}

// ParseGPUReport parses an attestation report as the NVIDIA driver hands
// it out: the SPDM GET_MEASUREMENTS request followed by the MEASUREMENTS
// response.
func ParseGPUReport(raw []byte) (*GPUReport, error) {
	if len(raw) < gpuReportRequestLen+8+gpuReportNonceLen+2+gpuReportSignatureLen {
		return nil, errors.New("nvidia: attestation report too short")
	}
	req, resp := raw[:gpuReportRequestLen], raw[gpuReportRequestLen:]
	if req[0] != spdmVersion11 || req[1] != spdmGetMeasurements {
		return nil, fmt.Errorf("nvidia: report does not start with an SPDM 1.1 GET_MEASUREMENTS request (%02x %02x)", req[0], req[1])
	}
	if resp[0] != spdmVersion11 || resp[1] != spdmMeasurements {
		return nil, fmt.Errorf("nvidia: report carries no SPDM 1.1 MEASUREMENTS response (%02x %02x)", resp[0], resp[1])
	}
	r := &GPUReport{RequestNonce: append([]byte(nil), req[4:4+gpuReportNonceLen]...), Blocks: map[int][]byte{}, Opaque: map[uint16][]byte{}}
	blocks := int(resp[4])
	recLen := int(resp[5]) | int(resp[6])<<8 | int(resp[7])<<16
	off := 8
	if len(resp) < off+recLen+gpuReportNonceLen+2 {
		return nil, errors.New("nvidia: measurement record runs past the report")
	}
	rec := resp[off : off+recLen]
	if blocks == 0 {
		return nil, errors.New("nvidia: the report carries no measurement blocks")
	}
	for i, p := 0, 0; i < blocks; i++ {
		if p+4 > len(rec) {
			return nil, errors.New("nvidia: measurement block header runs past the record")
		}
		index, spec := int(rec[p]), rec[p+1]
		size := int(binary.LittleEndian.Uint16(rec[p+2:]))
		p += 4
		if spec != dmtfMeasurementSpec {
			return nil, fmt.Errorf("nvidia: measurement block %d is not a DMTF measurement (specification %d)", index, spec)
		}
		if p+size > len(rec) || size < 3 {
			return nil, fmt.Errorf("nvidia: measurement block %d runs past the record", index)
		}
		m := rec[p : p+size]
		vsize := int(binary.LittleEndian.Uint16(m[1:]))
		if 3+vsize != size {
			return nil, fmt.Errorf("nvidia: measurement block %d declares %d value bytes in %d", index, vsize, size)
		}
		if _, dup := r.Blocks[index]; dup || index == 0 {
			return nil, fmt.Errorf("nvidia: measurement block index %d repeated or zero", index)
		}
		r.Blocks[index] = append([]byte(nil), m[3:]...)
		p += size
		if i == blocks-1 && p != len(rec) {
			return nil, errors.New("nvidia: measurement record has trailing bytes")
		}
	}
	off += recLen
	r.ResponseNonce = append([]byte(nil), resp[off:off+gpuReportNonceLen]...)
	off += gpuReportNonceLen
	opaqueLen := int(binary.LittleEndian.Uint16(resp[off:]))
	off += 2
	if len(resp) < off+opaqueLen+gpuReportSignatureLen {
		return nil, errors.New("nvidia: opaque data runs past the report")
	}
	opaque := resp[off : off+opaqueLen]
	for p := 0; p < len(opaque); {
		if p+4 > len(opaque) {
			return nil, errors.New("nvidia: opaque field header runs past the data")
		}
		id := binary.LittleEndian.Uint16(opaque[p:])
		size := int(binary.LittleEndian.Uint16(opaque[p+2:]))
		p += 4
		if p+size > len(opaque) {
			return nil, fmt.Errorf("nvidia: opaque field %d runs past the data", id)
		}
		r.Opaque[id] = append([]byte(nil), opaque[p:p+size]...)
		p += size
	}
	off += opaqueLen
	if len(resp)-off != gpuReportSignatureLen {
		return nil, fmt.Errorf("nvidia: %d bytes after the opaque data, want a %d-byte signature", len(resp)-off, gpuReportSignatureLen)
	}
	r.Signature = append([]byte(nil), resp[off:]...)
	r.signed = append([]byte(nil), raw[:len(raw)-gpuReportSignatureLen]...)
	return r, nil
}

// Measurement returns the runtime measurement at a reference manifest's
// index (the manifests count from 0, the SPDM blocks from 1).
func (r *GPUReport) Measurement(rimIndex int) ([]byte, bool) {
	v, ok := r.Blocks[rimIndex+1]
	return v, ok
}

// OpaqueString returns an opaque field as ASCII, trimmed of NULs and
// spaces; empty when absent.
func (r *GPUReport) OpaqueString(id uint16) string {
	return strings.Trim(string(r.Opaque[id]), "\x00 \t\r\n")
}

// DriverVersion is the driver version the report names.
func (r *GPUReport) DriverVersion() string { return r.OpaqueString(opaqueDriverVersion) }

// VBIOSVersion is the VBIOS version the report names, formatted as NVIDIA
// prints it (96.00.9F.00.04).
func (r *GPUReport) VBIOSVersion() (string, error) {
	raw, ok := r.Opaque[opaqueVBIOSVersion]
	if !ok {
		return "", errors.New("nvidia: the report names no VBIOS version")
	}
	return FormatVBIOSVersion(raw)
}

// FWID is the firmware id the report names (48 bytes), nil when absent.
func (r *GPUReport) FWID() []byte { return r.Opaque[opaqueFWID] }

// NVDEC0Disabled reports whether the GPU's NVDEC0 engine is disabled, in
// which case NVIDIA's reference manifests do not bind measurement 35.
func (r *GPUReport) NVDEC0Disabled() bool {
	v := r.Opaque[opaqueNVDEC0Status]
	return len(v) == 1 && v[0] == nvdec0Disabled
}

// OpaqueDataVersion is the version of the opaque data layout (0 when the
// field is absent).
func (r *GPUReport) OpaqueDataVersion() int {
	v := r.Opaque[opaqueDataVersion]
	if len(v) < 2 {
		return 0
	}
	return int(binary.LittleEndian.Uint16(v))
}

// DriverRIMID names the driver's reference integrity manifest at NVIDIA's
// RIM service, for a Hopper GPU.
func (r *GPUReport) DriverRIMID() string {
	return "NV_GPU_DRIVER_GH100_" + r.DriverVersion()
}

// VBIOSRIMID names the VBIOS's reference integrity manifest at NVIDIA's
// RIM service: the board's project, project SKU and chip SKU from the
// opaque data, and the VBIOS version without its dots.
func (r *GPUReport) VBIOSRIMID() (string, error) {
	project, sku, chip := r.OpaqueString(opaqueProject), r.OpaqueString(opaqueProjectSKU), r.OpaqueString(opaqueChipSKU)
	if project == "" || sku == "" || chip == "" {
		return "", errors.New("nvidia: the report names no project, project SKU or chip SKU")
	}
	v, err := r.VBIOSVersion()
	if err != nil {
		return "", err
	}
	return "NV_GPU_VBIOS_" + strings.ToUpper(project) + "_" + strings.ToUpper(sku) + "_" + strings.ToUpper(chip) + "_" + strings.ReplaceAll(v, ".", ""), nil
}

// FormatVBIOSVersion renders the 8-byte VBIOS version field the way
// NVIDIA does: the bytes read little-endian as hex, the second half
// followed by the byte before it, dotted in pairs, upper case.
func FormatVBIOSVersion(raw []byte) (string, error) {
	if len(raw) != 8 {
		return "", fmt.Errorf("nvidia: VBIOS version field is %d bytes, want 8", len(raw))
	}
	rev := make([]byte, len(raw))
	for i, b := range raw {
		rev[len(raw)-1-i] = b
	}
	value := hex.EncodeToString(rev) // 16 hex characters
	half := len(value) / 2
	temp := value[half:] + value[half-2:half]
	parts := make([]string, 0, len(temp)/2)
	for i := 0; i+2 <= len(temp); i += 2 {
		parts = append(parts, temp[i:i+2])
	}
	return strings.ToUpper(strings.Join(parts, ".")), nil
}

// VerifySignature checks the report's signature under the GPU's
// attestation certificate: ECDSA P-384 over SHA-384 of the request and
// the response up to the signature.
func (r *GPUReport) VerifySignature(leaf *x509.Certificate) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-384" {
		return errors.New("nvidia: the attestation certificate does not hold a P-384 key")
	}
	if len(r.Signature) != gpuReportSignatureLen {
		return errors.New("nvidia: signature is not 96 bytes")
	}
	digest := sha512.Sum384(r.signed)
	rr := new(big.Int).SetBytes(r.Signature[:48])
	ss := new(big.Int).SetBytes(r.Signature[48:])
	if !ecdsa.Verify(pub, digest[:], rr, ss) {
		return errors.New("nvidia: attestation report signature does not verify under the GPU's certificate")
	}
	return nil
}

// ParseGPUCertChain reads the GPU's attestation certificate chain as the
// driver hands it out: PEM, the attestation certificate first, the NVIDIA
// Device Identity CA last.
func ParseGPUCertChain(pemData []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := pemData
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
			return nil, fmt.Errorf("nvidia: certificate %d of the GPU chain: %w", len(chain), err)
		}
		chain = append(chain, c)
	}
	if len(chain) < 2 {
		return nil, fmt.Errorf("nvidia: the GPU chain holds %d certificates, want at least the attestation certificate and its issuers", len(chain))
	}
	return chain, nil
}

// VerifyGPUCertChain verifies the GPU's chain up to root, the NVIDIA
// Device Identity CA the operator pins: the chain must end at that very
// certificate, and every link must verify at now.
func VerifyGPUCertChain(chain []*x509.Certificate, root *x509.Certificate, now time.Time) error {
	if root == nil {
		return errors.New("nvidia: no device root to verify the GPU chain against")
	}
	if len(chain) < 2 {
		return errors.New("nvidia: GPU chain too short")
	}
	if !chain[len(chain)-1].Equal(root) {
		return errors.New("nvidia: the GPU chain does not end at the pinned NVIDIA device root")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range chain[1 : len(chain)-1] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("nvidia: GPU certificate chain: %w", err)
	}
	return nil
}

// tcgDICETcbInfoOID is the extension the GPU's attestation certificate
// carries its firmware id in (TCG DICE tcg-dice-TcbInfo).
var tcgDICETcbInfoOID = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}

// LeafFWID reads the firmware id the GPU's attestation certificate binds:
// the digest in its DICE extension (a SEQUENCE of a version, the key and a
// {algorithm, digest} pair on the H100), NVIDIA's rule being the last 48
// bytes of the extension.
func LeafFWID(leaf *x509.Certificate) ([]byte, error) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(tcgDICETcbInfoOID) {
			continue
		}
		var info struct {
			Version int
			Key     asn1.RawValue
			FWID    struct {
				Alg    asn1.ObjectIdentifier
				Digest []byte
			}
		}
		if rest, err := asn1.Unmarshal(ext.Value, &info); err == nil && len(rest) == 0 && len(info.FWID.Digest) == 48 {
			return info.FWID.Digest, nil
		}
		if len(ext.Value) >= 48 {
			return append([]byte(nil), ext.Value[len(ext.Value)-48:]...), nil
		}
		return nil, errors.New("nvidia: the attestation certificate's DICE extension holds no 48-byte firmware id")
	}
	return nil, errors.New("nvidia: the attestation certificate carries no DICE TcbInfo extension")
}
