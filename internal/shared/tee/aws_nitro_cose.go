// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The AWS Nitro attestation document, read from AWS's specification
// ("Verifying the root of trust", the attestation document specification
// and its validation process) and from RFC 9052 (COSE) for the envelope:
//
//	18(                       ; COSE_Sign1, the tag is optional
//	  [ h'A1013822',          ; protected header {1: -35}, ECDSA P-384 with SHA-384
//	    {},                   ; unprotected header, empty
//	    payload,              ; the attestation document, a CBOR map
//	    signature ])          ; ECDSA r ‖ s, 96 bytes
//
//	AttestationDocument = {
//	  module_id: text,                ; the issuing hypervisor module
//	  timestamp: uint .size 8,        ; milliseconds since the epoch, UTC
//	  digest: "SHA384",
//	  pcrs: { + index => pcr },       ; index 0..31, pcr 32, 48 or 64 bytes
//	  certificate: cert,              ; the signing key's certificate, DER, 1..1024 bytes
//	  cabundle: [* cert],             ; [ROOT, INTERM_1, …, INTERM_N]
//	  ? public_key: bytes .size (0..1024),
//	  ? user_data: bytes .size (0..1024),
//	  ? nonce: bytes .size (0..1024) }
//
// Validation, in AWS's order: decode the envelope, extract the document,
// verify the certificate chain — every certificate within its validity
// at the time of verification, no revocation — then verify the signature.
// The chain is anchored at the root this repository pins (or the
// operator's), never at the root the document carries; the document's
// cabundle[0] must be that root, as the specification orders it.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	// coseAlgES384 is the COSE algorithm identifier of ECDSA with SHA-384
	// (RFC 9053 §2.1); the only algorithm the Nitro hypervisor signs with.
	coseAlgES384 = -35

	// coseHeaderAlg and coseHeaderCrit are the common header parameters
	// "alg" and "crit" (RFC 9052 §3.1).
	coseHeaderAlg  = 1
	coseHeaderCrit = 2

	// es384SignatureSize is r ‖ s over P-384, 48 bytes each (RFC 9053 §2.1).
	es384SignatureSize = 96

	// nitroFieldMax bounds the certificates and the optional byte fields
	// (cert .size (1..1024), user_data .size (0..1024)).
	nitroFieldMax = 1024

	// nitroPCRMax is the highest PCR index the document may carry.
	nitroPCRMax = 31
)

// coseSign1 is the envelope: the protected header as the exact bytes
// that were signed, the payload and the signature.
type coseSign1 struct {
	ProtectedRaw []byte
	Payload      []byte
	Signature    []byte
}

// nitroAttestationDoc is the decoded document.
type nitroAttestationDoc struct {
	ModuleID    string
	Timestamp   time.Time
	Digest      string
	PCRs        map[int][]byte
	Certificate []byte   // the signing certificate, DER
	CABundle    [][]byte // [root, intermediates…], DER
	Nonce       []byte   // nil when the document carries none
	UserData    []byte
	PublicKey   []byte
}

// parseCOSESign1 decodes the envelope and checks its protected header
// names ES384 and nothing this verifier must understand and does not.
func parseCOSESign1(ev []byte) (*coseSign1, error) {
	top, err := cborDecode(ev)
	if err != nil {
		return nil, err
	}
	if top.kind == cborTag {
		if top.u != 18 {
			return nil, fmt.Errorf("cose: tag %d is not COSE_Sign1 (18)", top.u)
		}
		top = top.tagged
	}
	if top.kind != cborArray || len(top.items) != 4 {
		return nil, errors.New("cose: COSE_Sign1 must be an array of four items")
	}
	protected, unprotected, payload, signature := top.items[0], top.items[1], top.items[2], top.items[3]
	if protected.kind != cborBytes {
		return nil, errors.New("cose: protected header must be a byte string")
	}
	if unprotected.kind != cborMap {
		return nil, errors.New("cose: unprotected header must be a map")
	}
	if payload.kind != cborBytes || len(payload.b) == 0 {
		return nil, errors.New("cose: payload must be a non-empty byte string (detached payloads are not accepted)")
	}
	if signature.kind != cborBytes || len(signature.b) != es384SignatureSize {
		return nil, fmt.Errorf("cose: signature must be %d bytes for ES384", es384SignatureSize)
	}

	hdr, err := cborDecode(protected.b)
	if err != nil {
		return nil, fmt.Errorf("cose: protected header: %w", err)
	}
	if hdr.kind != cborMap {
		return nil, errors.New("cose: protected header must be a map")
	}
	alg, dup := hdr.mapLookupInt(coseHeaderAlg)
	if dup || alg == nil || alg.kind != cborNInt || alg.u != uint64(-1-coseAlgES384) {
		return nil, errors.New("cose: protected header must name ES384 (alg -35) once")
	}
	if crit, dup := hdr.mapLookupInt(coseHeaderCrit); crit != nil || dup {
		return nil, errors.New("cose: critical header parameters are not accepted")
	}
	return &coseSign1{
		ProtectedRaw: protected.b,
		Payload:      payload.b,
		Signature:    signature.b,
	}, nil
}

// decodeNitroAttestationDoc decodes the payload against the document
// specification, refusing a field that is missing, repeated, mistyped,
// out of its size, or not in the specification at all.
func decodeNitroAttestationDoc(payload []byte) (*nitroAttestationDoc, error) {
	top, err := cborDecode(payload)
	if err != nil {
		return nil, err
	}
	if top.kind != cborMap {
		return nil, errors.New("nitro: attestation document must be a map")
	}
	known := map[string]bool{
		"module_id": true, "timestamp": true, "digest": true, "pcrs": true,
		"certificate": true, "cabundle": true, "public_key": true, "user_data": true, "nonce": true,
	}
	for i := 0; i+1 < len(top.items); i += 2 {
		k := top.items[i]
		if k.kind != cborText || !known[string(k.b)] {
			return nil, errors.New("nitro: attestation document has a field outside the specification")
		}
	}
	field := func(name string) (*cborItem, error) {
		v, dup := top.mapLookup(name)
		if dup {
			return nil, fmt.Errorf("nitro: field %q occurs more than once", name)
		}
		return v, nil
	}
	text := func(name string) (string, error) {
		v, err := field(name)
		if err != nil {
			return "", err
		}
		if v == nil || v.kind != cborText || len(v.b) == 0 {
			return "", fmt.Errorf("nitro: field %q must be a non-empty text string", name)
		}
		return string(v.b), nil
	}
	optBytes := func(name string) ([]byte, error) {
		v, err := field(name)
		if err != nil {
			return nil, err
		}
		if v == nil || v.kind == cborNull {
			return nil, nil
		}
		if v.kind != cborBytes || len(v.b) > nitroFieldMax {
			return nil, fmt.Errorf("nitro: field %q must be a byte string of at most %d bytes", name, nitroFieldMax)
		}
		return append([]byte(nil), v.b...), nil
	}

	doc := &nitroAttestationDoc{PCRs: make(map[int][]byte)}
	if doc.ModuleID, err = text("module_id"); err != nil {
		return nil, err
	}
	if doc.Digest, err = text("digest"); err != nil {
		return nil, err
	}
	if doc.Digest != "SHA384" {
		return nil, fmt.Errorf("nitro: digest %q is not SHA384", doc.Digest)
	}
	ts, err := field("timestamp")
	if err != nil {
		return nil, err
	}
	if ts == nil || ts.kind != cborUint || ts.u == 0 || ts.u > uint64(1<<53) {
		return nil, errors.New("nitro: timestamp must be a positive integer of milliseconds")
	}
	doc.Timestamp = time.UnixMilli(int64(ts.u)).UTC()

	pcrs, err := field("pcrs")
	if err != nil {
		return nil, err
	}
	if pcrs == nil || pcrs.kind != cborMap || len(pcrs.items) == 0 {
		return nil, errors.New("nitro: pcrs must be a non-empty map")
	}
	for i := 0; i+1 < len(pcrs.items); i += 2 {
		k, v := pcrs.items[i], pcrs.items[i+1]
		if k.kind != cborUint || k.u > nitroPCRMax {
			return nil, errors.New("nitro: PCR index must be an integer from 0 to 31")
		}
		if v.kind != cborBytes || (len(v.b) != 32 && len(v.b) != 48 && len(v.b) != 64) {
			return nil, fmt.Errorf("nitro: PCR%d must be 32, 48 or 64 bytes", k.u)
		}
		if _, seen := doc.PCRs[int(k.u)]; seen {
			return nil, fmt.Errorf("nitro: PCR%d occurs more than once", k.u)
		}
		doc.PCRs[int(k.u)] = append([]byte(nil), v.b...)
	}

	cert, err := field("certificate")
	if err != nil {
		return nil, err
	}
	if cert == nil || cert.kind != cborBytes || len(cert.b) == 0 || len(cert.b) > nitroFieldMax {
		return nil, fmt.Errorf("nitro: certificate must be a DER byte string of 1 to %d bytes", nitroFieldMax)
	}
	doc.Certificate = append([]byte(nil), cert.b...)

	bundle, err := field("cabundle")
	if err != nil {
		return nil, err
	}
	if bundle == nil || bundle.kind != cborArray || len(bundle.items) == 0 {
		return nil, errors.New("nitro: cabundle must be a non-empty array")
	}
	for i, c := range bundle.items {
		if c.kind != cborBytes || len(c.b) == 0 || len(c.b) > nitroFieldMax {
			return nil, fmt.Errorf("nitro: cabundle[%d] must be a DER byte string of 1 to %d bytes", i, nitroFieldMax)
		}
		doc.CABundle = append(doc.CABundle, append([]byte(nil), c.b...))
	}

	if doc.PublicKey, err = optBytes("public_key"); err != nil {
		return nil, err
	}
	if doc.UserData, err = optBytes("user_data"); err != nil {
		return nil, err
	}
	if doc.Nonce, err = optBytes("nonce"); err != nil {
		return nil, err
	}
	return doc, nil
}

// verifyNitroCertChain builds the path [certificate, INTERM_N … INTERM_1]
// to a pinned root and verifies it at the given time, without revocation
// (AWS: "CRL must be disabled"). cabundle[0] must be one of the pinned
// roots: the document names its anchor, and the verifier's anchor must be
// the same one. Returns the signing certificate, whose key must be P-384.
func verifyNitroCertChain(leafDER []byte, cabundle, pinnedRoots [][]byte, now time.Time) (*x509.Certificate, error) {
	if len(pinnedRoots) == 0 {
		return nil, errors.New("no pinned root")
	}
	roots := x509.NewCertPool()
	pinned := false
	for _, der := range pinnedRoots {
		root, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("pinned root: %w", err)
		}
		roots.AddCert(root)
		if len(cabundle) > 0 && bytes.Equal(cabundle[0], der) {
			pinned = true
		}
	}
	if !pinned {
		return nil, errors.New("cabundle[0] is not a pinned root")
	}
	inter := x509.NewCertPool()
	for i, der := range cabundle[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("cabundle[%d]: %w", i+1, err)
		}
		inter.AddCert(c)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, errors.New("certificate's key is not ECDSA P-384")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, err
	}
	return leaf, nil
}

// verifyCOSESignature checks the ES384 signature over the Sig_structure
// of RFC 9052 §4.4: ["Signature1", protected, external_aad = h”, payload].
func verifyCOSESignature(cose *coseSign1, leaf *x509.Certificate) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return errors.New("signing key is not ECDSA P-384")
	}
	if len(cose.Signature) != es384SignatureSize {
		return fmt.Errorf("signature must be %d bytes", es384SignatureSize)
	}
	var e cborEncoder
	e.array(4)
	e.text("Signature1")
	e.bytes(cose.ProtectedRaw)
	e.bytes(nil)
	e.bytes(cose.Payload)
	digest := sha512.Sum384(e.buf)
	r := new(big.Int).SetBytes(cose.Signature[:48])
	s := new(big.Int).SetBytes(cose.Signature[48:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("ECDSA P-384 signature does not verify")
	}
	return nil
}

// AWSNitroDocumentReport is what an attestation document says, once its
// envelope, chain and signature have been verified.
type AWSNitroDocumentReport struct {
	ModuleID  string         `json:"module_id"`
	Timestamp time.Time      `json:"timestamp"`
	PCRs      map[int][]byte `json:"pcrs"`
	Nonce     []byte         `json:"nonce,omitempty"`
	UserData  []byte         `json:"user_data,omitempty"`
	PublicKey []byte         `json:"public_key,omitempty"`
	// Chain lists the subjects from the signing certificate to the root.
	Chain []string `json:"chain"`
	// SigningCertNotBefore and SigningCertNotAfter are the signing
	// certificate's validity; the hypervisor issues it for about three hours.
	SigningCertNotBefore time.Time `json:"signing_cert_not_before"`
	SigningCertNotAfter  time.Time `json:"signing_cert_not_after"`
	// Debug is true when PCR0 is all zeroes, the mark of a debug-mode enclave.
	Debug bool `json:"debug"`
}

// AuditAWSNitroDocument verifies a captured attestation document offline —
// the envelope, the chain to the pinned roots (the built-in root when
// none are given) at the given time, and the signature — and reports what
// it says. It does not check freshness, a nonce or a PCR policy: those
// belong to a Verifier with a challenge. A zero time audits the document
// at its own timestamp, which is the question to ask of a capture: the
// hypervisor's signing certificate expires hours after it signed.
func AuditAWSNitroDocument(ev []byte, pinnedRoots [][]byte, at time.Time) (*AWSNitroDocumentReport, error) {
	if len(pinnedRoots) == 0 {
		pinnedRoots = awsNitroPinnedRoots()
	}
	_, doc, leaf, err := verifyNitroEnvelope(ev, pinnedRoots, at)
	if err != nil {
		return nil, err
	}
	report := &AWSNitroDocumentReport{
		ModuleID:             doc.ModuleID,
		Timestamp:            doc.Timestamp,
		PCRs:                 doc.PCRs,
		Nonce:                doc.Nonce,
		UserData:             doc.UserData,
		PublicKey:            doc.PublicKey,
		SigningCertNotBefore: leaf.NotBefore.UTC(),
		SigningCertNotAfter:  leaf.NotAfter.UTC(),
		Debug:                isDebugAttestation(doc),
	}
	report.Chain = append(report.Chain, leaf.Subject.String())
	for i := len(doc.CABundle) - 1; i >= 0; i-- {
		c, err := x509.ParseCertificate(doc.CABundle[i])
		if err != nil {
			return nil, fmt.Errorf("aws-nitro: cabundle[%d]: %w", i, err)
		}
		report.Chain = append(report.Chain, c.Subject.String())
	}
	return report, nil
}

// verifyNitroEnvelope is the part of verification that needs no
// challenge: envelope, document, chain at the given time, signature. A
// zero time means the document's own timestamp — the question an offline
// audit asks is whether the chain was valid when the hypervisor signed.
func verifyNitroEnvelope(ev []byte, pinnedRoots [][]byte, now time.Time) (*coseSign1, *nitroAttestationDoc, *x509.Certificate, error) {
	cose, err := parseCOSESign1(ev)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aws-nitro: parse COSE_Sign1: %w", err)
	}
	doc, err := decodeNitroAttestationDoc(cose.Payload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aws-nitro: decode attestation document: %w", err)
	}
	if now.IsZero() {
		now = doc.Timestamp
	}
	leaf, err := verifyNitroCertChain(doc.Certificate, doc.CABundle, pinnedRoots, now)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("aws-nitro: certificate chain: %w", err)
	}
	if err := verifyCOSESignature(cose, leaf); err != nil {
		return nil, nil, nil, fmt.Errorf("aws-nitro: COSE signature: %w", err)
	}
	return cose, doc, leaf, nil
}
