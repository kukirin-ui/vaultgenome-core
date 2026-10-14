// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"encoding/asn1"
	"math/big"
)

// NVIDIA's reference integrity manifests (RIMs) are the golden
// measurements a GPU's firmware and driver must present: one manifest per
// driver version, one per VBIOS build, each a signed SWID tag (ISO 19770-2
// XML, TCG RIM information model) served by NVIDIA's RIM service. The
// evaluation compares the report's runtime measurements with the active
// golden measurements of both manifests, index by index.

// DefaultRIMServiceURL is NVIDIA's RIM service.
const DefaultRIMServiceURL = "https://rim.attestation.nvidia.com/v1/rim/"

const (
	swidNamespace   = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
	sha384Namespace = "http://www.w3.org/2001/04/xmlenc#sha384"
	rimIMNamespace  = "https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/"
	xmldsigNS       = "http://www.w3.org/2000/09/xmldsig#"
)

// RIMMeasurement is one golden measurement of a manifest: the values
// allowed at an index (alternatives), whether the index is bound (active),
// and the value size in bytes.
type RIMMeasurement struct {
	Index  int
	Name   string
	Active bool
	Size   int
	Values [][]byte
}

// RIM is a parsed reference integrity manifest.
type RIM struct {
	ID                string // the RIM service id it was fetched under, when known
	Raw               []byte // the signed SWID tag as served
	TagID             string
	Product           string
	ColloquialVersion string // the driver or VBIOS version the manifest is for
	ManufacturerID    string
	Measurements      map[int]RIMMeasurement
	// Certs are the certificates the manifest's signature carries, the
	// signing certificate first.
	Certs []*x509.Certificate
	// SignatureAlgorithm and CanonicalizationMethod are what the
	// manifest's XML signature declares; VerifyRIMSignature holds them to
	// what NVIDIA signs with and verifies the signature.
	SignatureAlgorithm     string
	CanonicalizationMethod string
}

// VerifyRIMSignature verifies the manifest's enveloped XML signature
// under its own signing certificate (Certs[0]) — which the caller chains
// to the NVIDIA CoRIM signing root first (VerifyRIMCertChain). The signed
// bytes are Canonical XML 1.1 of the tag with the signature removed, the
// signature ECDSA-SHA384: exactly what NVIDIA signs with, and nothing
// else is admitted. The canonicalisation and the signature check are
// goxmldsig's (docs/dependencies/goxmldsig.md); which certificate is
// trusted stays this verifier's decision.
func VerifyRIMSignature(rim *RIM, now time.Time) error {
	if rim == nil || len(rim.Certs) == 0 {
		return errors.New("nvidia: RIM carries no signing certificate")
	}
	if dsig.AlgorithmID(rim.CanonicalizationMethod) != dsig.CanonicalXML11AlgorithmId {
		return fmt.Errorf("nvidia: RIM canonicalization %q is not Canonical XML 1.1", rim.CanonicalizationMethod)
	}
	if rim.SignatureAlgorithm != dsig.ECDSASHA384SignatureMethod {
		return fmt.Errorf("nvidia: RIM signature method %q is not ECDSA-SHA384", rim.SignatureAlgorithm)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rim.Raw); err != nil {
		return fmt.Errorf("nvidia: RIM XML: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return errors.New("nvidia: RIM XML has no root element")
	}
	if err := derEncodeXMLDSigECDSASignature(root); err != nil {
		return fmt.Errorf("nvidia: RIM signature value: %w", err)
	}
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{rim.Certs[0]}})
	ctx.Clock = dsig.NewFakeClockAt(now)
	if _, err := ctx.Validate(root); err != nil {
		return fmt.Errorf("nvidia: RIM signature does not verify: %w", err)
	}
	return nil
}

// rimNode is a generic XML node: the manifests are small and their
// layout is walked, not bound to fixed structs.
type rimNode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Nodes   []rimNode  `xml:",any"`
	Text    string     `xml:",chardata"`
}

func (n *rimNode) attr(space, local string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name.Local == local && (space == "" || a.Name.Space == space) {
			return a.Value, true
		}
	}
	return "", false
}

func (n *rimNode) child(space, local string) *rimNode {
	for i := range n.Nodes {
		c := &n.Nodes[i]
		if c.XMLName.Local == local && (space == "" || c.XMLName.Space == space) {
			return c
		}
	}
	return nil
}

func (n *rimNode) children(space, local string) []*rimNode {
	var out []*rimNode
	for i := range n.Nodes {
		c := &n.Nodes[i]
		if c.XMLName.Local == local && (space == "" || c.XMLName.Space == space) {
			out = append(out, c)
		}
	}
	return out
}

// ParseRIM parses a signed SWID tag as NVIDIA's RIM service serves it.
func ParseRIM(raw []byte) (*RIM, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	var root rimNode
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("nvidia: RIM: %w", err)
	}
	if root.XMLName.Local != "SoftwareIdentity" || root.XMLName.Space != swidNamespace {
		return nil, fmt.Errorf("nvidia: RIM root is %s, want a SoftwareIdentity tag", root.XMLName.Local)
	}
	rim := &RIM{Raw: append([]byte(nil), raw...), Measurements: map[int]RIMMeasurement{}}
	rim.TagID, _ = root.attr("", "tagId")
	rim.Product, _ = root.attr("", "name")
	meta := root.child(swidNamespace, "Meta")
	if meta == nil {
		return nil, errors.New("nvidia: RIM carries no Meta element")
	}
	v, ok := meta.attr("", "colloquialVersion")
	if !ok || v == "" {
		return nil, errors.New("nvidia: RIM names no colloquialVersion")
	}
	rim.ColloquialVersion = v
	rim.ManufacturerID, _ = meta.attr(rimIMNamespace, "FirmwareManufacturerId")
	payload := root.child(swidNamespace, "Payload")
	if payload == nil {
		return nil, errors.New("nvidia: RIM carries no Payload")
	}
	for _, res := range payload.children(swidNamespace, "Resource") {
		if t, _ := res.attr("", "type"); t != "Measurement" {
			continue
		}
		m, err := parseRIMMeasurement(res)
		if err != nil {
			return nil, err
		}
		if _, dup := rim.Measurements[m.Index]; dup {
			return nil, fmt.Errorf("nvidia: RIM binds index %d twice", m.Index)
		}
		rim.Measurements[m.Index] = m
	}
	if len(rim.Measurements) == 0 {
		return nil, errors.New("nvidia: RIM carries no golden measurements")
	}
	sig := root.child(xmldsigNS, "Signature")
	if sig == nil {
		return nil, errors.New("nvidia: RIM carries no XML signature")
	}
	if si := sig.child(xmldsigNS, "SignedInfo"); si != nil {
		if c := si.child(xmldsigNS, "CanonicalizationMethod"); c != nil {
			rim.CanonicalizationMethod, _ = c.attr("", "Algorithm")
		}
		if s := si.child(xmldsigNS, "SignatureMethod"); s != nil {
			rim.SignatureAlgorithm, _ = s.attr("", "Algorithm")
		}
	}
	ki := sig.child(xmldsigNS, "KeyInfo")
	if ki == nil {
		return nil, errors.New("nvidia: RIM signature carries no KeyInfo")
	}
	x509Data := ki.child(xmldsigNS, "X509Data")
	if x509Data == nil {
		return nil, errors.New("nvidia: RIM signature carries no X509Data")
	}
	for i, c := range x509Data.children(xmldsigNS, "X509Certificate") {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.Text), ""))
		if err != nil {
			return nil, fmt.Errorf("nvidia: RIM certificate %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("nvidia: RIM certificate %d: %w", i, err)
		}
		rim.Certs = append(rim.Certs, cert)
	}
	if len(rim.Certs) == 0 {
		return nil, errors.New("nvidia: RIM signature carries no certificate")
	}
	return rim, nil
}

func parseRIMMeasurement(res *rimNode) (RIMMeasurement, error) {
	var m RIMMeasurement
	m.Name, _ = res.attr("", "name")
	idx, ok := res.attr("", "index")
	if !ok {
		return m, errors.New("nvidia: RIM measurement without index")
	}
	var err error
	if m.Index, err = strconv.Atoi(idx); err != nil || m.Index < 0 {
		return m, fmt.Errorf("nvidia: RIM measurement index %q", idx)
	}
	active, _ := res.attr("", "active")
	m.Active = !strings.EqualFold(active, "False")
	size, _ := res.attr("", "size")
	if m.Size, err = strconv.Atoi(size); err != nil || m.Size <= 0 {
		return m, fmt.Errorf("nvidia: RIM measurement %d: size %q", m.Index, size)
	}
	alts, _ := res.attr("", "alternatives")
	n, err := strconv.Atoi(alts)
	if err != nil || n < 1 {
		return m, fmt.Errorf("nvidia: RIM measurement %d: alternatives %q", m.Index, alts)
	}
	for i := 0; i < n; i++ {
		h, ok := res.attr(sha384Namespace, "Hash"+strconv.Itoa(i))
		if !ok {
			return m, fmt.Errorf("nvidia: RIM measurement %d: no Hash%d", m.Index, i)
		}
		v, err := hex.DecodeString(h)
		if err != nil {
			return m, fmt.Errorf("nvidia: RIM measurement %d: Hash%d: %w", m.Index, i, err)
		}
		m.Values = append(m.Values, v)
	}
	return m, nil
}

// rimServiceResponse is what the RIM service returns for an id.
type rimServiceResponse struct {
	ID     string `json:"id"`
	RIM    string `json:"rim"` // the signed SWID tag, base64
	SHA256 string `json:"sha256"`
}

// ParseRIMResponse parses a RIM service response and the manifest in it;
// the manifest's bytes must hash to the SHA-256 the service states.
func ParseRIMResponse(raw []byte) (*RIM, error) {
	var resp rimServiceResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("nvidia: RIM service response: %w", err)
	}
	if resp.RIM == "" {
		return nil, errors.New("nvidia: RIM service response carries no manifest")
	}
	tag, err := base64.StdEncoding.DecodeString(resp.RIM)
	if err != nil {
		return nil, fmt.Errorf("nvidia: RIM service response: %w", err)
	}
	if resp.SHA256 != "" {
		sum := sha256.Sum256(tag)
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(strings.ToLower(resp.SHA256))) != 1 {
			return nil, errors.New("nvidia: the manifest does not hash to the SHA-256 the RIM service states")
		}
	}
	rim, err := ParseRIM(tag)
	if err != nil {
		return nil, err
	}
	rim.ID = resp.ID
	return rim, nil
}

// RIMFetcher fetches manifests from a RIM service, keeping a copy of each
// under CacheDir (`<id>.json`, the service's response) so a verifier off
// the network can still evaluate what it has seen before.
type RIMFetcher struct {
	BaseURL  string
	CacheDir string
	Client   *http.Client
}

// Fetch returns the manifest for id, from the cache when present.
func (f *RIMFetcher) Fetch(ctx context.Context, id string) (*RIM, error) {
	if id == "" || strings.ContainsAny(id, "/\\ ") {
		return nil, fmt.Errorf("nvidia: RIM id %q", id)
	}
	var cache string
	if f.CacheDir != "" {
		cache = filepath.Join(f.CacheDir, id+".json")
		if raw, err := os.ReadFile(cache); err == nil {
			rim, err := ParseRIMResponse(raw)
			if err == nil {
				return rim, nil
			}
		}
	}
	base := f.BaseURL
	if base == "" {
		base = DefaultRIMServiceURL
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvidia: RIM service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("nvidia: RIM service: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvidia: RIM service: HTTP %d for %s", resp.StatusCode, id)
	}
	rim, err := ParseRIMResponse(raw)
	if err != nil {
		return nil, err
	}
	if cache != "" {
		if err := os.MkdirAll(f.CacheDir, 0o700); err == nil {
			_ = os.WriteFile(cache, raw, 0o600)
		}
	}
	return rim, nil
}

// VerifyRIMCertChain verifies the manifest's signing certificate up to
// root, the NVIDIA CoRIM signing root the operator pins. The manifest
// may carry the root itself; only the pinned one counts.
func VerifyRIMCertChain(rim *RIM, root *x509.Certificate, now time.Time) error {
	if root == nil {
		return errors.New("nvidia: no RIM root to verify the manifest's chain against")
	}
	if len(rim.Certs) == 0 {
		return errors.New("nvidia: the manifest carries no certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range rim.Certs[1:] {
		if !c.Equal(root) {
			inter.AddCert(c)
		}
	}
	if _, err := rim.Certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("nvidia: RIM certificate chain: %w", err)
	}
	return nil
}

// GoldenMeasurements combines the active measurements of the driver and
// VBIOS manifests by index; an index both manifests bind is a conflict.
func GoldenMeasurements(driver, vbios *RIM) (map[int]RIMMeasurement, error) {
	out := map[int]RIMMeasurement{}
	for _, m := range driver.Measurements {
		if m.Active {
			out[m.Index] = m
		}
	}
	for _, m := range vbios.Measurements {
		if !m.Active {
			continue
		}
		if _, dup := out[m.Index]; dup {
			return nil, fmt.Errorf("nvidia: the driver and VBIOS manifests both bind measurement %d", m.Index)
		}
		out[m.Index] = m
	}
	if len(out) == 0 {
		return nil, errors.New("nvidia: the manifests bind no measurement")
	}
	return out, nil
}

// CompareMeasurements holds the report's runtime measurements to the
// golden ones: at every bound index the runtime value must be one of the
// manifest's alternatives, of the manifest's size. Index 35 is not bound
// when the GPU's NVDEC0 engine is disabled (NVIDIA's rule). It returns the
// indices that miss, sorted.
func CompareMeasurements(rep *GPUReport, golden map[int]RIMMeasurement) ([]int, error) {
	if len(rep.Blocks) < len(golden) {
		return nil, fmt.Errorf("nvidia: the report carries %d measurements, the manifests bind %d", len(rep.Blocks), len(golden))
	}
	var missed []int
	for idx, g := range golden {
		if idx == 35 && rep.NVDEC0Disabled() {
			continue
		}
		runtime, ok := rep.Measurement(idx)
		if !ok {
			missed = append(missed, idx)
			continue
		}
		matched := false
		for _, v := range g.Values {
			if len(runtime) == g.Size && bytes.Equal(v, runtime) {
				matched = true
				break
			}
		}
		if !matched {
			missed = append(missed, idx)
		}
	}
	sort.Ints(missed)
	return missed, nil
}

// RIMStatus is what the evaluation found about one manifest.
type RIMStatus struct {
	ID                string `json:"id"`
	Fetched           bool   `json:"fetched"`
	VersionMatch      bool   `json:"version_match"`
	ChainVerified     bool   `json:"chain_verified"`
	SignatureVerified bool   `json:"signature_verified"`
	Measurements      int    `json:"measurements"`
	Error             string `json:"error,omitempty"`
}

// GPUEvaluation is this verifier's own evaluation of a GPU's attestation
// report: every check it makes, each on the record.
type GPUEvaluation struct {
	ReportParsed      bool      `json:"report_parsed"`
	NonceMatch        bool      `json:"nonce_match"`
	ChainVerified     bool      `json:"chain_verified"`
	FWIDMatch         bool      `json:"fwid_match"`
	SignatureVerified bool      `json:"signature_verified"`
	DriverVersion     string    `json:"driver_version,omitempty"`
	VBIOSVersion      string    `json:"vbios_version,omitempty"`
	HWModel           string    `json:"hw_model,omitempty"`
	UEID              string    `json:"ueid,omitempty"`
	DriverRIM         RIMStatus `json:"driver_rim"`
	VBIOSRIM          RIMStatus `json:"vbios_rim"`
	MeasurementsMatch bool      `json:"measurements_match"`
	Mismatched        []int     `json:"mismatched,omitempty"`
	// RevocationChecked says the policy asked NVIDIA's responder about the
	// chain; Revocation is what it said, certificate by certificate;
	// RevocationGood that every answer was good.
	RevocationChecked bool         `json:"revocation_checked"`
	RevocationGood    bool         `json:"revocation_good,omitempty"`
	Revocation        []OCSPStatus `json:"revocation,omitempty"`
	Errors            []string     `json:"errors,omitempty"`
}

// Complete reports whether every check passed: the report's structure,
// nonce, chain, firmware id and signature; both manifests' versions,
// chains and XML signatures; and the measurements.
func (e GPUEvaluation) Complete() bool {
	return (!e.RevocationChecked || e.RevocationGood) && e.ReportParsed && e.NonceMatch && e.ChainVerified && e.FWIDMatch && e.SignatureVerified &&
		e.DriverRIM.Fetched && e.DriverRIM.VersionMatch && e.DriverRIM.ChainVerified && e.DriverRIM.SignatureVerified &&
		e.VBIOSRIM.Fetched && e.VBIOSRIM.VersionMatch && e.VBIOSRIM.ChainVerified && e.VBIOSRIM.SignatureVerified &&
		e.MeasurementsMatch
}

// RIMSignaturesVerified reports whether both manifests' XML signatures
// verified under the certificates chained to NVIDIA's CoRIM signing root.
func (e GPUEvaluation) RIMSignaturesVerified() bool {
	return e.DriverRIM.SignatureVerified && e.VBIOSRIM.SignatureVerified
}

// GPUEvaluator holds what the evaluation needs besides the report: the
// pinned roots and a source of manifests.
type GPUEvaluator struct {
	DeviceRoot *x509.Certificate // the NVIDIA Device Identity CA
	RIMRoot    *x509.Certificate // the NVIDIA CoRIM signing Root CA
	RIMs       *RIMFetcher
	// OCSP, when set, asks NVIDIA's responder for the revocation status
	// of the chain's certificates; a complete evaluation then needs
	// every answer good. Nil leaves revocation unchecked, on the record.
	OCSP *OCSPChecker
	Now  func() time.Time
}

// Evaluate makes every check this build can on a report, its chain and
// the nonce it was taken for. It does not stop at the first failure: the
// result records each check, so the operator sees what held and what did
// not.
func (ev *GPUEvaluator) Evaluate(ctx context.Context, reportRaw, chainPEM, nonce []byte) GPUEvaluation {
	var e GPUEvaluation
	fail := func(err error) { e.Errors = append(e.Errors, err.Error()) }
	now := time.Now()
	if ev.Now != nil {
		now = ev.Now()
	}
	rep, err := ParseGPUReport(reportRaw)
	if err != nil {
		fail(err)
		return e
	}
	e.ReportParsed = true
	e.DriverVersion = rep.DriverVersion()
	if v, err := rep.VBIOSVersion(); err == nil {
		e.VBIOSVersion = v
	} else {
		fail(err)
	}
	e.NonceMatch = len(nonce) == gpuReportNonceLen && subtle.ConstantTimeCompare(rep.RequestNonce, nonce) == 1
	if !e.NonceMatch {
		fail(errors.New("nvidia: the report was not taken for this nonce"))
	}
	chain, err := ParseGPUCertChain(chainPEM)
	if err != nil {
		fail(err)
		return e
	}
	e.UEID = chain[0].SerialNumber.String()
	e.HWModel = hwModelFromChain(chain)
	if err := VerifyGPUCertChain(chain, ev.DeviceRoot, now); err != nil {
		fail(err)
	} else {
		e.ChainVerified = true
	}
	if ev.OCSP != nil {
		e.RevocationChecked = true
		if e.ChainVerified {
			e.Revocation, e.RevocationGood = ev.OCSP.CheckChain(ctx, chain)
			if !e.RevocationGood {
				for _, st := range e.Revocation {
					if st.Status != "good" && st.Status != "not served" {
						fail(fmt.Errorf("nvidia: revocation: %s: %s: %s", st.Subject, st.Status, st.Error))
					}
				}
			}
		} else {
			fail(errors.New("nvidia: revocation not checked: the chain did not verify"))
		}
	}
	if fwid := rep.FWID(); len(fwid) == 0 {
		e.FWIDMatch = true // a report without a firmware id binds none (NVIDIA's rule)
	} else if certFWID, err := LeafFWID(chain[0]); err != nil {
		fail(err)
	} else if !bytes.Equal(certFWID, fwid) {
		fail(errors.New("nvidia: the firmware id in the attestation certificate is not the one in the report"))
	} else {
		e.FWIDMatch = true
	}
	if err := rep.VerifySignature(chain[0]); err != nil {
		fail(err)
	} else {
		e.SignatureVerified = true
	}
	driver := ev.manifest(ctx, rep.DriverRIMID(), e.DriverVersion, now, &e.DriverRIM)
	vbiosID, err := rep.VBIOSRIMID()
	var vbios *RIM
	if err != nil {
		e.VBIOSRIM.Error = err.Error()
		fail(err)
	} else {
		vbios = ev.manifest(ctx, vbiosID, e.VBIOSVersion, now, &e.VBIOSRIM)
	}
	if driver != nil && vbios != nil {
		golden, err := GoldenMeasurements(driver, vbios)
		if err != nil {
			fail(err)
			return e
		}
		missed, err := CompareMeasurements(rep, golden)
		if err != nil {
			fail(err)
			return e
		}
		e.Mismatched = missed
		e.MeasurementsMatch = len(missed) == 0
		if !e.MeasurementsMatch {
			fail(fmt.Errorf("nvidia: runtime measurements miss the golden ones at %v", missed))
		}
	}
	return e
}

// manifest fetches and checks one manifest, recording what it found.
func (ev *GPUEvaluator) manifest(ctx context.Context, id, version string, now time.Time, st *RIMStatus) *RIM {
	st.ID = id
	if ev.RIMs == nil {
		st.Error = "no RIM source configured"
		return nil
	}
	rim, err := ev.RIMs.Fetch(ctx, id)
	if err != nil {
		st.Error = err.Error()
		return nil
	}
	st.Fetched = true
	st.Measurements = len(rim.Measurements)
	st.VersionMatch = strings.EqualFold(rim.ColloquialVersion, version)
	if !st.VersionMatch {
		st.Error = fmt.Sprintf("the manifest is for %s, the report names %s", rim.ColloquialVersion, version)
	}
	if err := VerifyRIMCertChain(rim, ev.RIMRoot, now); err != nil {
		st.Error = err.Error()
		return rim
	}
	st.ChainVerified = true
	// The manifest's XML signature, under the certificate just chained.
	if err := VerifyRIMSignature(rim, now); err != nil {
		st.Error = err.Error()
	} else {
		st.SignatureVerified = true
	}
	return rim
}

// hwModelFromChain names the GPU's model from its certificate chain: the
// issuer whose name is "NVIDIA <model> Identity" (NVIDIA's per-model CA,
// e.g. "NVIDIA GH100 Identity"), or the leaf's issuer when no such CA is
// in the chain.
func hwModelFromChain(chain []*x509.Certificate) string {
	for _, c := range chain[1:] {
		if m, ok := strings.CutSuffix(c.Subject.CommonName, " Identity"); ok && m != "" {
			return strings.TrimPrefix(m, "NVIDIA ") // "NVIDIA GH100 Identity" names GH100, as NVIDIA's tokens do
		}
	}
	if len(chain) > 1 {
		return chain[1].Subject.CommonName
	}
	return ""
}

// derEncodeXMLDSigECDSASignature re-encodes the document's ECDSA
// SignatureValue from the form XMLDSig prescribes (RFC 4050: r and s
// concatenated, each the curve's size) to the ASN.1 DER form crypto/x509
// takes, which is what goxmldsig hands the signature to. The value sits
// outside the signed bytes — SignedInfo is what is signed, and the whole
// Signature element is removed before the reference digest — so the
// re-encoding changes nothing that is verified. A value that is already
// DER, or of another size, is left as it is.
func derEncodeXMLDSigECDSASignature(root *etree.Element) error {
	sig := root.FindElement("./*[namespace-uri()='" + xmldsigNS + "'][local-name()='Signature']")
	if sig == nil {
		for _, c := range root.ChildElements() {
			if c.Tag == "Signature" {
				sig = c
				break
			}
		}
	}
	if sig == nil {
		return errors.New("no Signature element")
	}
	var value *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag == "SignatureValue" {
			value = c
			break
		}
	}
	if value == nil {
		return errors.New("no SignatureValue element")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value.Text()), ""))
	if err != nil {
		return err
	}
	if len(raw) != 96 || raw[0] == 0x30 { // not r||s over P-384; DER already, or something else for the verifier to refuse
		return nil
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:48]), new(big.Int).SetBytes(raw[48:])})
	if err != nil {
		return err
	}
	value.SetText(base64.StdEncoding.EncodeToString(der))
	return nil
}
