// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// A synthetic Nitro attestation PKI for the tests: a five-certificate
// chain shaped like AWS's (root → regional → zonal → instance → signing
// certificate), all ECDSA P-384, and a document builder that signs the
// same COSE_Sign1 envelope the hypervisor does. The verifier under test
// pins the synthetic root through AWSNitroVerifierConfig.PinnedRoots, so
// every byte of the production codec and chain logic runs; only the key
// that signs is ours.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type nitroTestChain struct {
	rootDER []byte
	bundle  [][]byte // [root, regional, zonal, instance], as the document carries them
	leafDER []byte
	leafKey *ecdsa.PrivateKey
	leaf    *x509.Certificate
}

// newNitroTestChain issues a chain valid around now: the CAs for a year
// either side, the signing certificate for three hours from a few seconds
// before now, as the hypervisor does.
func newNitroTestChain(t testing.TB, now time.Time) *nitroTestChain {
	t.Helper()
	type ca struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
		der  []byte
	}
	issue := func(cn string, isCA bool, notBefore, notAfter time.Time, parent *ca) *ca {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("fixture: key: %v", err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			t.Fatalf("fixture: serial: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"Amazon"}, OrganizationalUnit: []string{"AWS"}, Country: []string{"US"}},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			BasicConstraintsValid: true,
			IsCA:                  isCA,
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		}
		parentCert, parentKey := tmpl, key
		if parent != nil {
			parentCert, parentKey = parent.cert, parent.key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatalf("fixture: certificate %q: %v", cn, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("fixture: parse %q: %v", cn, err)
		}
		return &ca{cert: cert, key: key, der: der}
	}
	year := 365 * 24 * time.Hour
	root := issue("aws.nitro-enclaves", true, now.Add(-year), now.Add(30*year), nil)
	regional := issue("77af59e854502979.us-east-2.aws.nitro-enclaves", true, now.Add(-year), now.Add(year), root)
	zonal := issue("ed0a5aa9a2f05a5.zonal.us-east-2.aws.nitro-enclaves", true, now.Add(-year), now.Add(year), regional)
	instance := issue("i-0e35190ae3157095d.us-east-2.aws.nitro-enclaves", true, now.Add(-year), now.Add(year), zonal)
	leaf := issue("i-0e35190ae3157095d-enc019e0512a5715d4f.us-east-2.aws", false, now.Add(-3*time.Second), now.Add(3*time.Hour), instance)
	return &nitroTestChain{
		rootDER: root.der,
		bundle:  [][]byte{root.der, regional.der, zonal.der, instance.der},
		leafDER: leaf.der,
		leafKey: leaf.key,
		leaf:    leaf.cert,
	}
}

// nitroTestDoc is the document to sign. Zero fields take the values a
// real document would have; the knobs at the end make bad documents.
type nitroTestDoc struct {
	ModuleID  string
	Timestamp time.Time
	PCRs      map[int][]byte
	Nonce     []byte
	UserData  []byte
	PublicKey []byte

	Tagged        bool   // wrap the envelope in CBOR tag 18
	Alg           int64  // protected header alg; 0 means ES384
	Digest        string // "" means SHA384
	ExtraField    bool   // add a field outside the specification
	OmitCABundle  bool
	Certificate   []byte   // overrides the chain's signing certificate
	CABundle      [][]byte // overrides the chain's bundle
	SignWith      *ecdsa.PrivateKey
	BadSignature  bool // flip a byte of the signature
	Unprotected   bool // put "alg" in the unprotected header instead
	CritHeader    bool // add a "crit" parameter
	DetachPayload bool // encode the payload as null
}

// nitroPCR derives a 48-byte PCR value for a label and index.
func nitroPCR(label string, idx int) []byte {
	h := sha512.Sum384([]byte("vg-nitro-pcr-" + label + "-" + string(rune('0'+idx))))
	return h[:]
}

// encodeNitroDoc writes the attestation document map.
func (c *nitroTestChain) encodeNitroDoc(d nitroTestDoc) []byte {
	if d.ModuleID == "" {
		d.ModuleID = "i-0e35190ae3157095d-enc019e0512a5715d4f"
	}
	if d.Timestamp.IsZero() {
		d.Timestamp = time.Now()
	}
	if d.Digest == "" {
		d.Digest = "SHA384"
	}
	if d.PCRs == nil {
		d.PCRs = map[int][]byte{0: nitroPCR("default", 0), 1: nitroPCR("default", 1), 2: nitroPCR("default", 2)}
	}
	cert := c.leafDER
	if d.Certificate != nil {
		cert = d.Certificate
	}
	bundle := c.bundle
	if d.CABundle != nil {
		bundle = d.CABundle
	}
	n := 9
	if d.ExtraField {
		n++
	}
	if d.OmitCABundle {
		n--
	}
	var e cborEncoder
	e.mapping(n)
	e.text("module_id")
	e.text(d.ModuleID)
	e.text("digest")
	e.text(d.Digest)
	e.text("timestamp")
	e.uint(uint64(d.Timestamp.UnixMilli()))
	e.text("pcrs")
	e.mapping(len(d.PCRs))
	for i := 0; i <= nitroPCRMax; i++ { // deterministic order
		if v, ok := d.PCRs[i]; ok {
			e.uint(uint64(i))
			e.bytes(v)
		}
	}
	e.text("certificate")
	e.bytes(cert)
	if !d.OmitCABundle {
		e.text("cabundle")
		e.array(len(bundle))
		for _, b := range bundle {
			e.bytes(b)
		}
	}
	opt := func(name string, v []byte) {
		e.text(name)
		if v == nil {
			e.null()
		} else {
			e.bytes(v)
		}
	}
	opt("public_key", d.PublicKey)
	opt("user_data", d.UserData)
	opt("nonce", d.Nonce)
	if d.ExtraField {
		e.text("vendor_extension")
		e.uint(1)
	}
	return e.buf
}

// sign wraps the document in a COSE_Sign1 envelope signed by the chain's
// signing key (or d.SignWith).
func (c *nitroTestChain) sign(t testing.TB, d nitroTestDoc) []byte {
	t.Helper()
	payload := c.encodeNitroDoc(d)
	alg := d.Alg
	if alg == 0 {
		alg = coseAlgES384
	}
	var ph cborEncoder
	if d.Unprotected {
		ph.mapping(0)
	} else if d.CritHeader {
		ph.mapping(2)
		ph.uint(coseHeaderAlg)
		ph.nint(alg)
		ph.uint(coseHeaderCrit)
		ph.array(1)
		ph.uint(coseHeaderAlg)
	} else {
		ph.mapping(1)
		ph.uint(coseHeaderAlg)
		ph.nint(alg)
	}
	var sig cborEncoder
	sig.array(4)
	sig.text("Signature1")
	sig.bytes(ph.buf)
	sig.bytes(nil)
	sig.bytes(payload)
	digest := sha512.Sum384(sig.buf)
	key := c.leafKey
	if d.SignWith != nil {
		key = d.SignWith
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("fixture: sign: %v", err)
	}
	signature := make([]byte, es384SignatureSize)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	if d.BadSignature {
		signature[10] ^= 0x01
	}

	var e cborEncoder
	if d.Tagged {
		e.tag(18)
	}
	e.array(4)
	e.bytes(ph.buf)
	if d.Unprotected {
		e.mapping(1)
		e.uint(coseHeaderAlg)
		e.nint(alg)
	} else {
		e.mapping(0)
	}
	if d.DetachPayload {
		e.null()
	} else {
		e.bytes(payload)
	}
	e.bytes(signature)
	return e.buf
}
