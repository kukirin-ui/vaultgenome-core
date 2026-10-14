// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// certForKey self-signs a certificate for an existing P-384 key.
func certForKey(t *testing.T, key *ecdsa.PrivateKey, name string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func TestNRASParsersRefuseMalformedResponsesAndKeys(t *testing.T) {
	for raw, fragment := range map[string]string{
		`[1]`:                     "two-element array",
		`[["JWT"],{"GPU-0":"y"}]`: "first element",
		`[["JWT","x"],[]]`:        "second element",
		`[["JWT",""],{}]`:         "carries no tokens",
	} {
		_, err := parseNRASResponse([]byte(raw))
		require.ErrorContains(t, err, fragment, raw)
	}
	_, err := parseJWKSet([]byte("{"))
	require.ErrorContains(t, err, "JWKS")
	_, err = parseJWKSet([]byte(`{"keys":[]}`))
	require.ErrorContains(t, err, "no keys")
	require.Equal(t, `token signed by key "k", not in the JWKS`, (&errUnknownKID{kid: "k"}).Error())
	require.Equal(t, "", (&nrasJWKS{}).file())
	require.Equal(t, filepath.Join("cache", "nras-jwks.json"), (&nrasJWKS{dir: "cache"}).file())

	f := newFakeNRAS(t, "k")
	set, err := parseJWKSet(f.jwks)
	require.NoError(t, err)
	good := set.Keys[0]
	_, err = good.ecdsaKey()
	require.NoError(t, err)
	_, otherDER := selfSignedP384(t, "other", nil)
	rows := []struct {
		name     string
		edit     func(k *jsonWebKey)
		fragment string
	}{
		{"RSA key", func(k *jsonWebKey) { k.KTY = "RSA" }, "EC/P-384"},
		{"P-256 key", func(k *jsonWebKey) { k.CRV = "P-256" }, "EC/P-384"},
		{"x not base64", func(k *jsonWebKey) { k.X = "!!!" }, "x:"},
		{"y not base64", func(k *jsonWebKey) { k.Y = "!!!" }, "y:"},
		{"x of 47 bytes", func(k *jsonWebKey) { k.X = b64url(make([]byte, 47)) }, "coordinates of"},
		{"not on the curve", func(k *jsonWebKey) { k.X = b64url(bytes.Repeat([]byte{1}, 48)); k.Y = k.X }, "not a point"},
		{"x5c not base64", func(k *jsonWebKey) { k.X5C = []string{"!!!"} }, "x5c:"},
		{"x5c not a certificate", func(k *jsonWebKey) { k.X5C = []string{base64.StdEncoding.EncodeToString([]byte("junk"))} }, "x5c:"},
		{"x5c for another key", func(k *jsonWebKey) { k.X5C = []string{base64.StdEncoding.EncodeToString(otherDER)} }, "does not carry the JWK's key"},
	}
	for _, row := range rows {
		k := good
		row.edit(&k)
		_, err := k.ecdsaKey()
		require.ErrorContains(t, err, row.fragment, row.name)
	}
	withCert := good
	withCert.X5C = []string{base64.StdEncoding.EncodeToString(certForKey(t, f.key, "nras"))}
	pub, err := withCert.ecdsaKey()
	require.NoError(t, err)
	require.True(t, pub.Equal(&f.key.PublicKey))

	for token, fragment := range map[string]string{
		"a.b":                                 "three parts",
		"!!!.e30.AA":                          "token header",
		"e30.!!!.AA":                          "token claims",
		"e30.e30.!!!":                         "token signature",
		b64url([]byte("hi")) + ".e30.AA":      "token header",
		"e30." + b64url([]byte("hi")) + ".AA": "token claims",
	} {
		_, err := splitJWT(token)
		require.ErrorContains(t, err, fragment, token)
	}

	now := time.Date(2026, 9, 16, 14, 0, 0, 0, time.UTC)
	noKid := b64url([]byte(`{"alg":"ES384"}`)) + ".e30.AA"
	_, err = verifyES384JWT(noKid, set, now, time.Minute)
	require.ErrorContains(t, err, "names no key")
	signed := f.sign(t, overallClaims("00", now, true), "ES384")
	parts := strings.Split(signed, ".")
	_, err = verifyES384JWT(parts[0]+"."+parts[1]+"."+b64url(make([]byte, 10)), set, now, time.Minute)
	require.ErrorContains(t, err, "ES384 signature is 10 bytes")
	_, err = verifyES384JWT(f.sign(t, map[string]any{"nbf": float64(now.Add(time.Hour).Unix())}, "ES384"), set, now, time.Minute)
	require.ErrorContains(t, err, "not valid before")
	_, err = verifyES384JWT(signed, &jwkSet{Keys: []jsonWebKey{{KID: "k", KTY: "RSA"}}}, now, time.Minute)
	require.ErrorContains(t, err, "EC/P-384")

	dir := t.TempDir()
	offline := &nrasJWKS{url: "https://nras.example/jwks", dir: dir, get: func(string) ([]byte, error) { return nil, errors.New("offline") }}
	_, err = offline.load(false)
	require.ErrorContains(t, err, "fetch JWKS: offline")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nras-jwks.json"), []byte("corrupt"), 0o600))
	_, err = offline.load(false)
	require.ErrorContains(t, err, "fetch JWKS", "a corrupt cache file is ignored and the network is asked")
	empty := &nrasJWKS{url: "u", get: func(string) ([]byte, error) { return []byte(`{"keys":[]}`), nil }}
	_, err = empty.load(true)
	require.ErrorContains(t, err, "no keys")
	stale := &nrasJWKS{url: "u", dir: t.TempDir(), get: func(string) ([]byte, error) { return nil, errors.New("offline") }}
	require.NoError(t, os.WriteFile(stale.file(), f.jwks, 0o600))
	rotated := newFakeNRAS(t, "k2")
	_, err = stale.verify(rotated.sign(t, overallClaims("00", now, true), "ES384"), now, time.Minute)
	require.ErrorContains(t, err, "fetch JWKS", "an unknown key asks the network once, and reports the failure")

	nonce := strings.Repeat("ab", 32)
	overall := overallClaims(nonce, now, true)
	gpu := gpuClaims(nonce, now)
	_, err = evaluateGPUClaims(overall, nil, nonce, GPUClaimsPolicy{})
	require.ErrorContains(t, err, "names no GPU")
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": gpuClaims("ff"+nonce[2:], now)}, nonce, GPUClaimsPolicy{})
	require.ErrorContains(t, err, "token nonce")
	noSecureBoot := gpuClaims(nonce, now)
	noSecureBoot["secboot"] = false
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": noSecureBoot}, nonce, GPUClaimsPolicy{})
	require.ErrorContains(t, err, "secure boot")
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": noSecureBoot}, nonce, GPUClaimsPolicy{AllowSecureBootOff: true})
	require.NoError(t, err)
	unsigned := gpuClaims(nonce, now)
	unsigned["x-nvidia-gpu-vbios-rim-signature-verified"] = false
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": unsigned}, nonce, GPUClaimsPolicy{})
	require.ErrorContains(t, err, "rim-signature-verified")
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": unsigned}, nonce, GPUClaimsPolicy{AllowUnsignedRIM: true})
	require.NoError(t, err)
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": gpu}, nonce, GPUClaimsPolicy{AcceptableHWModels: []string{"H200"}})
	require.ErrorContains(t, err, "hardware model")
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": gpu}, nonce, GPUClaimsPolicy{AcceptableVBIOSVersions: []string{"00.00.00.00.00"}})
	require.ErrorContains(t, err, "VBIOS")

	v := GPUVerdict{HWModel: "GH100", DriverVersion: "595.71.05", VBIOSVersion: "96.00.9F.00.04"}
	require.NoError(t, GPUClaimsPolicy{}.holdsPins(v))
	require.NoError(t, GPUClaimsPolicy{AcceptableHWModels: []string{"gh100"}, AcceptableDriverVersions: []string{"595.71.05"}, AcceptableVBIOSVersions: []string{"96.00.9f.00.04"}}.holdsPins(v))
	require.ErrorContains(t, GPUClaimsPolicy{AcceptableHWModels: []string{"H200"}}.holdsPins(v), "hw model")
	require.ErrorContains(t, GPUClaimsPolicy{AcceptableDriverVersions: []string{"550.90.07"}}.holdsPins(v), "driver")
	require.ErrorContains(t, GPUClaimsPolicy{AcceptableVBIOSVersions: []string{"00"}}.holdsPins(v), "VBIOS")
}

func certWithExtension(t *testing.T, value []byte) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: tcgDICETcbInfoOID, Value: value}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func parseDER(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

func TestGPUReportHelpersRefuseWhatTheReportLacks(t *testing.T) {
	r := &GPUReport{Opaque: map[uint16][]byte{}, Blocks: map[int][]byte{}}
	_, err := r.VBIOSVersion()
	require.ErrorContains(t, err, "names no VBIOS version")
	require.Equal(t, 0, r.OpaqueDataVersion())
	r.Opaque[opaqueDataVersion] = []byte{3, 0}
	require.Equal(t, 3, r.OpaqueDataVersion())
	_, err = r.VBIOSRIMID()
	require.ErrorContains(t, err, "no project")
	r.Opaque[opaqueProject], r.Opaque[opaqueProjectSKU], r.Opaque[opaqueChipSKU] = []byte("1010\x00"), []byte("0210"), []byte("886")
	_, err = r.VBIOSRIMID()
	require.ErrorContains(t, err, "names no VBIOS version")
	r.Opaque[opaqueVBIOSVersion] = []byte{0x04, 0x00, 0x9F, 0x00, 0x96, 0x00, 0x00, 0x00}
	version, err := FormatVBIOSVersion(r.Opaque[opaqueVBIOSVersion])
	require.NoError(t, err)
	id, err := r.VBIOSRIMID()
	require.NoError(t, err)
	require.Equal(t, "NV_GPU_VBIOS_1010_0210_886_"+strings.ReplaceAll(version, ".", ""), id)
	require.Equal(t, "NV_GPU_DRIVER_GH100_", r.DriverRIMID())
	require.False(t, r.NVDEC0Disabled())

	_, p256 := selfSignedCA(t, "p256")
	require.ErrorContains(t, r.VerifySignature(p256), "does not hold a P-384 key")
	_, p384DER := selfSignedP384(t, "p384", nil)
	p384 := parseDER(t, p384DER)
	require.ErrorContains(t, r.VerifySignature(p384), "signature is not 96 bytes")
	r.Signature, r.signed = make([]byte, 96), []byte("signed bytes")
	require.ErrorContains(t, r.VerifySignature(p384), "does not verify")

	_, err = ParseGPUCertChain(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
	require.ErrorContains(t, err, "certificate 0 of the GPU chain")
	_, err = ParseGPUCertChain(certPEM(p384DER))
	require.ErrorContains(t, err, "holds 1 certificates")

	rootKey, rootDER := selfSignedP384(t, "NVIDIA GH100 Identity", nil)
	root := parseDER(t, rootDER)
	_, leafDER := issuedP384(t, "GPU", rootDER, rootKey)
	leaf := parseDER(t, leafDER)
	_, otherRootDER := selfSignedP384(t, "Other CA", nil)
	otherRoot := parseDER(t, otherRootDER)
	now := time.Now()
	require.NoError(t, VerifyGPUCertChain([]*x509.Certificate{leaf, root}, root, now))
	require.ErrorContains(t, VerifyGPUCertChain([]*x509.Certificate{leaf, root}, nil, now), "no device root")
	require.ErrorContains(t, VerifyGPUCertChain([]*x509.Certificate{leaf}, root, now), "too short")
	require.ErrorContains(t, VerifyGPUCertChain([]*x509.Certificate{leaf, root}, otherRoot, now), "does not end at")
	require.ErrorContains(t, VerifyGPUCertChain([]*x509.Certificate{leaf, otherRoot}, otherRoot, now), "GPU certificate chain:")
	require.Equal(t, "", hwModelFromChain([]*x509.Certificate{leaf}))
	require.Equal(t, "GH100", hwModelFromChain([]*x509.Certificate{leaf, root}))
	require.Equal(t, "Other CA", hwModelFromChain([]*x509.Certificate{leaf, otherRoot}))

	_, err = LeafFWID(leaf)
	require.ErrorContains(t, err, "carries no DICE")
	fwid, err := LeafFWID(certWithExtension(t, append([]byte{1, 2}, bytes.Repeat([]byte{0xAB}, 48)...)))
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{0xAB}, 48), fwid, "a non-ASN.1 extension still yields its last 48 bytes")
	_, err = LeafFWID(certWithExtension(t, []byte{1, 2, 3}))
	require.ErrorContains(t, err, "holds no 48-byte")
}

func TestGPUReportParserRefusesEachMalformedLayout(t *testing.T) {
	raw := readEvidence(t, "gpu0-attestation-report.bin")
	resp := gpuReportRequestLen
	recLen := int(raw[resp+5]) | int(raw[resp+6])<<8 | int(raw[resp+7])<<16
	rec := resp + 8
	size0 := int(binary.LittleEndian.Uint16(raw[rec+2:]))
	opaqueLenAt := rec + recLen + gpuReportNonceLen
	opaque := opaqueLenAt + 2
	rows := []struct {
		name     string
		edit     func(b []byte) []byte
		fragment string
	}{
		{"record runs past the report", func(b []byte) []byte { b[resp+5], b[resp+6], b[resp+7] = 0xFF, 0xFF, 0x7F; return b }, "runs past the report"},
		{"no blocks", func(b []byte) []byte { b[resp+4] = 0; return b }, "carries no measurement blocks"},
		{"more blocks than the record holds", func(b []byte) []byte { b[resp+4] = 200; return b }, "runs past the record"},
		{"fewer blocks than the record holds", func(b []byte) []byte { b[resp+4] = 1; return b }, "trailing bytes"},
		{"block size overflow", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[rec+2:], 0xFFFF); return b }, "runs past the record"},
		{"value size mismatch", func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[rec+5:], binary.LittleEndian.Uint16(b[rec+5:])+1)
			return b
		}, "declares"},
		{"index zero", func(b []byte) []byte { b[rec] = 0; return b }, "repeated or zero"},
		{"index repeated", func(b []byte) []byte { b[rec+4+size0] = b[rec]; return b }, "repeated or zero"},
		{"opaque data runs past the report", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[opaqueLenAt:], 0xFFFF); return b }, "opaque data runs past"},
		{"opaque field header runs past", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[opaqueLenAt:], 2); return b }, "opaque field header"},
		{"opaque field overflow", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[opaque+2:], 0xFFFF); return b }, "opaque field"},
		{"a byte after the signature", func(b []byte) []byte { return append(b, 0) }, "want a 96-byte signature"},
	}
	for _, row := range rows {
		_, err := ParseGPUReport(row.edit(append([]byte(nil), raw...)))
		require.Error(t, err, row.name)
		require.ErrorContains(t, err, row.fragment, row.name)
	}
}

func buildHCL(reportData [64]byte, runtime []byte, payloadSize uint32) []byte {
	report := make([]byte, sevReportLen)
	binary.LittleEndian.PutUint32(report[0:], 3)
	copy(report[sevOffReportData:], reportData[:])
	var hcl []byte
	hcl = append(hcl, []byte(hclMagic)...)
	hcl = append(hcl, make([]byte, hclHeaderLen-4)...)
	hcl = append(hcl, report...)
	rt := make([]byte, hclRuntimeHeaderLen)
	binary.LittleEndian.PutUint32(rt[0:], uint32(hclRuntimeHeaderLen+len(runtime)))
	binary.LittleEndian.PutUint32(rt[4:], hclRuntimeVersion)
	binary.LittleEndian.PutUint32(rt[8:], hclReportTypeSNP)
	binary.LittleEndian.PutUint32(rt[12:], hclHashTypeSHA256)
	binary.LittleEndian.PutUint32(rt[16:], payloadSize)
	return append(append(hcl, rt...), runtime...)
}

func TestHCLReportHelpersRefuseWhatTheyShould(t *testing.T) {
	report := func(version uint32, fam, model byte) *sevSNPReport {
		raw := make([]byte, sevReportLen)
		binary.LittleEndian.PutUint32(raw[0:], version)
		raw[sevOffCPUIDFam], raw[sevOffCPUIDFam+1] = fam, model
		return &sevSNPReport{Raw: raw}
	}
	require.Equal(t, "Milan", sevProductName(&sevSNPReport{Raw: []byte{1}}), "a report too short to name a family is a Milan")
	require.Equal(t, "Milan", sevProductName(report(2, 0x19, 0x11)), "before version 3 the family is not in the report")
	require.Equal(t, "Milan", sevProductName(report(3, 0x19, 0x01)))
	require.Equal(t, "Genoa", sevProductName(report(3, 0x19, 0x11)))
	require.Equal(t, "Turin", sevProductName(report(3, 0x1A, 0x02)))
	require.Equal(t, "family-0x19-model-0x99", sevProductName(report(3, 0x19, 0x99)))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	n := b64url(key.PublicKey.N.Bytes())
	ak := func(kty string, ops []string) *hclReport {
		return &hclReport{Runtime: hclRuntime{Keys: []hclJWK{{KID: hclAKKeyID, KTY: kty, N: n, E: "AQAB", KeyOps: ops}}}}
	}
	_, err = ak("EC", []string{"sign"}).attestationKey()
	require.ErrorContains(t, err, "not RSA")
	_, err = ak("RSA", []string{"encrypt"}).attestationKey()
	require.ErrorContains(t, err, "not a signing key")
	_, err = (&hclReport{}).attestationKey()
	require.ErrorContains(t, err, "names no "+hclAKKeyID)
	pub, err := ak("RSA", []string{"sign"}).attestationKey()
	require.NoError(t, err)
	require.True(t, pub.Equal(&key.PublicKey))

	_, err = rsaFromJWK(n, "!!!")
	require.ErrorContains(t, err, "JWK e")
	_, err = rsaFromJWK(b64url(make([]byte, 10)), "AQAB")
	require.ErrorContains(t, err, "modulus 10 bytes")
	_, err = rsaFromJWK(n, "Ag")
	require.ErrorContains(t, err, "exponent 2")

	_, err = parsePEMRSAPublicKey([]byte("junk"))
	require.ErrorContains(t, err, "no PEM block")
	_, err = parsePEMRSAPublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}))
	require.Error(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	_, err = parsePEMRSAPublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}))
	require.ErrorContains(t, err, "not an RSA public key")
	rsaDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	parsed, err := parsePEMRSAPublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER}))
	require.NoError(t, err)
	require.True(t, parsed.Equal(&key.PublicKey))

	runtime := []byte(`{"keys":[]}`)
	var rd [64]byte
	sum := sha256.Sum256(runtime)
	copy(rd[:], sum[:])
	h, err := parseHCLReport(buildHCL(rd, runtime, uint32(len(runtime))))
	require.NoError(t, err)
	require.Equal(t, runtime, h.RuntimeData)
	_, err = parseHCLReport(buildHCL(rd, runtime, uint32(len(runtime)+100)))
	require.ErrorContains(t, err, "exceeds")
	tail := rd
	tail[40] = 1
	_, err = parseHCLReport(buildHCL(tail, runtime, uint32(len(runtime))))
	require.ErrorContains(t, err, "REPORT_DATA[32:] is not zero")
	notJSON := []byte("not json")
	var rd2 [64]byte
	sum2 := sha256.Sum256(notJSON)
	copy(rd2[:], sum2[:])
	_, err = parseHCLReport(buildHCL(rd2, notJSON, uint32(len(notJSON))))
	require.ErrorContains(t, err, "not JSON")
}

const swidOpen = `<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:SHA384="http://www.w3.org/2001/04/xmlenc#sha384" xmlns:rim="https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" tagId="t1" name="GH100">`

func swidDoc(meta, payload, signature string) []byte {
	return []byte(swidOpen + meta + payload + signature + `</SoftwareIdentity>`)
}

func swidSignature(inner string) string {
	return `<ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"/></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue>` + inner + `</ds:Signature>`
}

func TestRIMParserRefusesEachMalformedManifest(t *testing.T) {
	_, der := selfSignedP384(t, "RIM signer", nil)
	keyInfo := `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(der) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`
	hash := strings.Repeat("ab", 48)
	measurement := func(attrs string) string {
		return `<Resource type="Measurement" name="m" ` + attrs + `/>`
	}
	goodMeasurement := measurement(`index="1" active="True" size="48" alternatives="1" SHA384:Hash0="` + hash + `"`)
	meta := `<Meta colloquialVersion="595.71.05" rim:FirmwareManufacturerId="5703"/>`
	payload := `<Payload>` + goodMeasurement + `</Payload>`
	full := swidDoc(meta, payload, swidSignature(keyInfo))

	rim, err := ParseRIM(full)
	require.NoError(t, err)
	require.Equal(t, "t1", rim.TagID)
	require.Equal(t, "GH100", rim.Product)
	require.Equal(t, "595.71.05", rim.ColloquialVersion)
	require.Equal(t, "5703", rim.ManufacturerID)
	require.Len(t, rim.Certs, 1)
	require.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", rim.SignatureAlgorithm)
	require.Equal(t, "http://www.w3.org/2006/12/xml-c14n11", rim.CanonicalizationMethod)
	m := rim.Measurements[1]
	require.True(t, m.Active)
	require.Equal(t, 48, m.Size)
	want, _ := hex.DecodeString(hash)
	require.Equal(t, [][]byte{want}, m.Values)

	rows := []struct {
		name     string
		raw      []byte
		fragment string
	}{
		{"not XML", []byte("<"), "RIM:"},
		{"another root", []byte(`<other xmlns="x"/>`), "want a SoftwareIdentity"},
		{"no Meta", swidDoc("", payload, swidSignature(keyInfo)), "no Meta element"},
		{"no version", swidDoc(`<Meta/>`, payload, swidSignature(keyInfo)), "colloquialVersion"},
		{"no Payload", swidDoc(meta, "", swidSignature(keyInfo)), "no Payload"},
		{"measurement without index", swidDoc(meta, `<Payload>`+measurement(`size="48" alternatives="1"`)+`</Payload>`, swidSignature(keyInfo)), "without index"},
		{"measurement index not a number", swidDoc(meta, `<Payload>`+measurement(`index="x" size="48" alternatives="1"`)+`</Payload>`, swidSignature(keyInfo)), `index "x"`},
		{"measurement of size 0", swidDoc(meta, `<Payload>`+measurement(`index="1" size="0" alternatives="1"`)+`</Payload>`, swidSignature(keyInfo)), "size"},
		{"measurement without alternatives", swidDoc(meta, `<Payload>`+measurement(`index="1" size="48" alternatives="0"`)+`</Payload>`, swidSignature(keyInfo)), "alternatives"},
		{"measurement missing a hash", swidDoc(meta, `<Payload>`+measurement(`index="1" size="48" alternatives="2" SHA384:Hash0="`+hash+`"`)+`</Payload>`, swidSignature(keyInfo)), "no Hash1"},
		{"measurement hash not hex", swidDoc(meta, `<Payload>`+measurement(`index="1" size="48" alternatives="1" SHA384:Hash0="zz"`)+`</Payload>`, swidSignature(keyInfo)), "Hash0:"},
		{"index bound twice", swidDoc(meta, `<Payload>`+goodMeasurement+goodMeasurement+`</Payload>`, swidSignature(keyInfo)), "twice"},
		{"no measurements", swidDoc(meta, `<Payload><Resource type="File"/></Payload>`, swidSignature(keyInfo)), "no golden measurements"},
		{"no signature", swidDoc(meta, payload, ""), "no XML signature"},
		{"no KeyInfo", swidDoc(meta, payload, swidSignature("")), "no KeyInfo"},
		{"no X509Data", swidDoc(meta, payload, swidSignature(`<ds:KeyInfo/>`)), "no X509Data"},
		{"certificate not base64", swidDoc(meta, payload, swidSignature(`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>!!!</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`)), "certificate 0"},
		{"certificate not DER", swidDoc(meta, payload, swidSignature(`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>anVuaw==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`)), "certificate 0"},
		{"no certificate", swidDoc(meta, payload, swidSignature(`<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>`)), "carries no certificate"},
	}
	for _, row := range rows {
		_, err := ParseRIM(row.raw)
		require.Error(t, err, row.name)
		require.ErrorContains(t, err, row.fragment, row.name)
	}

	_, err = ParseRIMResponse([]byte("{"))
	require.ErrorContains(t, err, "RIM service response")
	_, err = ParseRIMResponse([]byte(`{"rim":""}`))
	require.ErrorContains(t, err, "no manifest")
	_, err = ParseRIMResponse([]byte(`{"rim":"!!!"}`))
	require.ErrorContains(t, err, "RIM service response")
	encoded := base64.StdEncoding.EncodeToString(full)
	_, err = ParseRIMResponse([]byte(`{"rim":"` + encoded + `","sha256":"00"}`))
	require.ErrorContains(t, err, "SHA-256")
	sum := sha256.Sum256(full)
	withID, err := ParseRIMResponse([]byte(`{"id":"X","rim":"` + encoded + `","sha256":"` + strings.ToUpper(hex.EncodeToString(sum[:])) + `"}`))
	require.NoError(t, err)
	require.Equal(t, "X", withID.ID)

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if strings.HasSuffix(r.URL.Path, "/good") {
			_, _ = w.Write([]byte(`{"id":"good","rim":"` + encoded + `"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	f := &RIMFetcher{BaseURL: srv.URL + "/v1/rim/", CacheDir: t.TempDir(), Client: srv.Client()}
	for _, id := range []string{"", "a b", "a/b"} {
		_, err := f.Fetch(context.Background(), id)
		require.ErrorContains(t, err, "RIM id", id)
	}
	_, err = f.Fetch(context.Background(), "bad")
	require.ErrorContains(t, err, "HTTP 500")
	require.NoError(t, os.WriteFile(filepath.Join(f.CacheDir, "good.json"), []byte("corrupt"), 0o600))
	got, err := f.Fetch(context.Background(), "good")
	require.NoError(t, err)
	require.Equal(t, "good", got.ID)
	require.Equal(t, 2, hits, "a corrupt cache entry is replaced from the service")
	cached, err := os.ReadFile(filepath.Join(f.CacheDir, "good.json"))
	require.NoError(t, err)
	require.Contains(t, string(cached), `"id":"good"`)
	dead := &RIMFetcher{BaseURL: "http://127.0.0.1:1/v1/rim/", Client: &http.Client{Timeout: time.Second}}
	_, err = dead.Fetch(context.Background(), "good")
	require.ErrorContains(t, err, "RIM service:")

	root := parseDER(t, der)
	require.ErrorContains(t, VerifyRIMCertChain(rim, nil, time.Now()), "no RIM root")
	require.ErrorContains(t, VerifyRIMCertChain(&RIM{}, root, time.Now()), "carries no certificate")
	require.NoError(t, VerifyRIMCertChain(rim, root, time.Now()))

	now := time.Now()
	require.ErrorContains(t, VerifyRIMSignature(nil, now), "no signing certificate")
	wrongC14N := *rim
	wrongC14N.CanonicalizationMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	require.ErrorContains(t, VerifyRIMSignature(&wrongC14N, now), "not Canonical XML 1.1")
	wrongMethod := *rim
	wrongMethod.SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	require.ErrorContains(t, VerifyRIMSignature(&wrongMethod, now), "not ECDSA-SHA384")
	for name, raw := range map[string][]byte{
		"not XML":                   []byte("<"),
		"no Signature element":      swidDoc(meta, payload, ""),
		"no SignatureValue":         swidDoc(meta, payload, `<ds:Signature>`+keyInfo+`</ds:Signature>`),
		"SignatureValue not base64": swidDoc(meta, payload, `<ds:Signature><ds:SignatureValue>!!!</ds:SignatureValue>`+keyInfo+`</ds:Signature>`),
		"raw P-384 signature":       swidDoc(meta, payload, `<ds:Signature><ds:SignedInfo/><ds:SignatureValue>`+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 96))+`</ds:SignatureValue>`+keyInfo+`</ds:Signature>`),
		"DER signature":             swidDoc(meta, payload, `<ds:Signature><ds:SignedInfo/><ds:SignatureValue>`+base64.StdEncoding.EncodeToString(append([]byte{0x30}, bytes.Repeat([]byte{1}, 95)...))+`</ds:SignatureValue>`+keyInfo+`</ds:Signature>`),
	} {
		r := *rim
		r.Raw = raw
		err := VerifyRIMSignature(&r, now)
		require.Error(t, err, name)
		require.Contains(t, err.Error(), "RIM", name)
	}

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(swidDoc(meta, payload, `<ds:Signature><ds:SignatureValue>`+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 96))+`</ds:SignatureValue></ds:Signature>`)))
	require.NoError(t, derEncodeXMLDSigECDSASignature(doc.Root()))
	value := doc.Root().FindElement("//SignatureValue")
	require.NotNil(t, value)
	converted, err := base64.StdEncoding.DecodeString(value.Text())
	require.NoError(t, err)
	require.Equal(t, byte(0x30), converted[0], "r||s becomes a DER SEQUENCE for the verifier")
	require.NoError(t, doc.ReadFromBytes(swidDoc(meta, payload, `<ds:Signature><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>`)))
	require.NoError(t, derEncodeXMLDSigECDSASignature(doc.Root()), "a value that is not 96 bytes is left for the verifier to refuse")

	driver := &RIM{Measurements: map[int]RIMMeasurement{1: {Index: 1, Active: true, Size: 1, Values: [][]byte{{1}}}}}
	vbios := &RIM{Measurements: map[int]RIMMeasurement{1: {Index: 1, Active: true, Size: 1, Values: [][]byte{{2}}}}}
	_, err = GoldenMeasurements(driver, vbios)
	require.ErrorContains(t, err, "both bind")
	inactive := &RIM{Measurements: map[int]RIMMeasurement{1: {Index: 1, Active: false}}}
	_, err = GoldenMeasurements(inactive, inactive)
	require.ErrorContains(t, err, "bind no measurement")
	vbios.Measurements = map[int]RIMMeasurement{3: {Index: 3, Active: true, Size: 1, Values: [][]byte{{3}}}, 35: {Index: 35, Active: true, Size: 1, Values: [][]byte{{5}}}}
	golden, err := GoldenMeasurements(driver, vbios)
	require.NoError(t, err)
	require.Len(t, golden, 3)
	rep := &GPUReport{Blocks: map[int][]byte{2: {1}}, Opaque: map[uint16][]byte{}}
	_, err = CompareMeasurements(rep, golden)
	require.ErrorContains(t, err, "carries 1 measurements")
	rep.Blocks[4], rep.Blocks[36] = []byte{9}, []byte{9}
	missed, err := CompareMeasurements(rep, golden)
	require.NoError(t, err)
	require.Equal(t, []int{3, 35}, missed)
	rep.Opaque[opaqueNVDEC0Status] = []byte{nvdec0Disabled}
	missed, err = CompareMeasurements(rep, golden)
	require.NoError(t, err)
	require.Equal(t, []int{3}, missed, "index 35 is not compared when NVDEC0 is disabled")
}

func TestGPUEvaluatorRecordsWhatItCannotDo(t *testing.T) {
	device, rimRoot := nvidiaRoots(t)
	report, chain, nonce := readEvidence(t, "gpu0-attestation-report.bin"), readEvidence(t, "gpu0-cert-chain.pem"), capturedNonce(t)
	noRIMs := &GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: func() time.Time { return captureTime }}
	e := noRIMs.Evaluate(context.Background(), report, chain, nonce)
	require.Equal(t, "no RIM source configured", e.DriverRIM.Error)
	require.Equal(t, "no RIM source configured", e.VBIOSRIM.Error)
	require.False(t, e.Complete())
	require.True(t, e.SignatureVerified && e.ChainVerified && e.NonceMatch)

	e = (&GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: noRIMs.Now}).Evaluate(context.Background(), report, []byte("not a chain"), nonce)
	require.False(t, e.ChainVerified)
	require.NotEmpty(t, e.Errors)

	wrongRoot := &GPUEvaluator{DeviceRoot: rimRoot, RIMRoot: rimRoot, Now: noRIMs.Now, OCSP: &OCSPChecker{URL: "http://127.0.0.1:1"}}
	e = wrongRoot.Evaluate(context.Background(), report, chain, nonce)
	require.False(t, e.ChainVerified)
	require.Contains(t, strings.Join(e.Errors, ";"), "revocation not checked")
}

func p256CertValid(t *testing.T, name string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(500 + serials.Add(1)), Subject: pkix.Name{CommonName: name}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

func TestOCSPCheckerRefusalsAndCache(t *testing.T) {
	caKey, caCert := selfSignedCA(t, "root")
	_, leaf := issuedCert(t, "leaf", caCert, caKey, false, nil)
	now := time.Now().Truncate(time.Second)
	c := &OCSPChecker{Now: func() time.Time { return now }}
	statuses, good := c.CheckChain(context.Background(), []*x509.Certificate{leaf})
	require.False(t, good)
	require.Contains(t, statuses[0].Error, "too short")
	_, err := c.post(context.Background(), "http://[::1]:namedport", nil)
	require.Error(t, err)

	respond := func(responder *x509.Certificate, key *ecdsa.PrivateKey, tmpl ocsp.Response) []byte {
		tmpl.Certificate = responder
		tmpl.SerialNumber = leaf.SerialNumber
		raw, err := ocsp.CreateResponse(caCert, responder, tmpl, key)
		require.NoError(t, err)
		return raw
	}
	expiredKey, expired := p256CertValid(t, "old responder", caCert, caKey, now.Add(-48*time.Hour), now.Add(-24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})
	_, err = verifyOCSPResponse(respond(expired, expiredKey, ocsp.Response{Status: ocsp.Good, ThisUpdate: now, NextUpdate: now.Add(time.Hour)}), leaf, caCert, nil, now)
	require.ErrorContains(t, err, "not valid now")
	respKey, resp := p256CertValid(t, "responder", caCert, caKey, now.Add(-time.Hour), now.Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})
	_, err = verifyOCSPResponse(respond(resp, respKey, ocsp.Response{Status: ocsp.Good, ThisUpdate: now.Add(time.Hour), NextUpdate: now.Add(2 * time.Hour)}), leaf, caCert, nil, now)
	require.ErrorContains(t, err, "from the future")
	withNonce := respond(resp, respKey, ocsp.Response{Status: ocsp.Good, ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: ocspNonceOID, Value: []byte{0x04, 0x01, 0xAA}}}})
	_, err = verifyOCSPResponse(withNonce, leaf, caCert, []byte{0xBB}, now)
	require.ErrorContains(t, err, "nonce")
	_, err = verifyOCSPResponse(withNonce, leaf, caCert, nil, now)
	require.NoError(t, err, "without a nonce of our own, the responder's is not checked")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, OCSPCacheName(leaf)), []byte("garbage"), 0o600))
	cached := &OCSPChecker{URL: srv.URL, CacheDir: dir, Client: srv.Client(), Now: func() time.Time { return now }}
	st := cached.check(context.Background(), leaf, caCert, now)
	require.Equal(t, "error", st.Status)
	require.Contains(t, st.Error, "HTTP 500", "a cache entry that does not verify is ignored and the responder is asked")
}
