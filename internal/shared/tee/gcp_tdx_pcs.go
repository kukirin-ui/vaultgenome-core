// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Intel Provisioning Certification Service (PCS): the documents a TDX
// quote is evaluated against, and how the verifier trusts them.
//
//   - TCB info (GET /tdx/certification/v4/tcb?fmspc=…): for the platform
//     family the PCK certificate names (FMSPC), the TCB levels Intel has
//     rated — each a set of component SVNs, a PCE SVN, the TDX module's
//     SVNs, and a status (UpToDate, SWHardeningNeeded, OutOfDate, …) — and
//     the TDX module identities.
//   - QE identity (GET /tdx/certification/v4/qe/identity): what the
//     Quoting Enclave that signed the quote must look like (MRSIGNER,
//     ISVPRODID, attributes) and which ISV SVNs are current.
//
// Both are JSON documents signed by the Intel SGX TCB Signing certificate,
// whose chain the service returns in a response header; the signature is
// ECDSA-P256 over the exact bytes of the inner object as served. The
// verifier checks that signature under the chain, chained to the pinned
// Intel root, before it reads a byte of the document. A cache directory
// keeps the documents between runs (PCS rate-limits); a cached document
// is re-fetched once past its nextUpdate, and is checked like a fresh one.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultIntelPCSURL is Intel's public PCS.
const DefaultIntelPCSURL = "https://api.trustedservices.intel.com"

// TCB statuses Intel assigns.
const (
	TCBUpToDate                          = "UpToDate"
	TCBSWHardeningNeeded                 = "SWHardeningNeeded"
	TCBConfigurationNeeded               = "ConfigurationNeeded"
	TCBConfigurationAndSWHardeningNeeded = "ConfigurationAndSWHardeningNeeded"
	TCBOutOfDate                         = "OutOfDate"
	TCBOutOfDateConfigurationNeeded      = "OutOfDateConfigurationNeeded"
	TCBRevoked                           = "Revoked"
)

// tcbStatusRank orders statuses from best to worst; the platform's status
// is the worst of the parts.
var tcbStatusRank = map[string]int{
	TCBUpToDate: 0, TCBSWHardeningNeeded: 1, TCBConfigurationNeeded: 2, TCBConfigurationAndSWHardeningNeeded: 3,
	TCBOutOfDate: 4, TCBOutOfDateConfigurationNeeded: 5, TCBRevoked: 6,
}

func worseTCBStatus(a, b string) string {
	ra, oka := tcbStatusRank[a]
	rb, okb := tcbStatusRank[b]
	switch {
	case !oka:
		return a
	case !okb:
		return b
	case rb > ra:
		return b
	}
	return a
}

// pcsDocument is a signed PCS document as served: the body and the
// issuer chain from the response header.
type pcsDocument struct {
	Body        []byte
	IssuerChain []byte // PEM, leaf first
}

// tdxPCSGet fetches a PCS URL and returns the body with the issuer chain
// its header carries. A var so tests serve captured documents.
var tdxPCSGet = realPCSGet

func realPCSGet(u string) (pcsDocument, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return pcsDocument{}, err
	}
	req.Header.Set("User-Agent", "vault-genome/tee (Intel PCS)")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return pcsDocument{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return pcsDocument{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return pcsDocument{}, fmt.Errorf("PCS %s: HTTP %d", u, resp.StatusCode)
	}
	var chain string
	for k, v := range resp.Header {
		if strings.HasSuffix(strings.ToLower(k), "issuer-chain") && len(v) > 0 {
			chain = v[0]
		}
	}
	if chain == "" {
		return pcsDocument{}, fmt.Errorf("PCS %s: no issuer chain header", u)
	}
	decoded, err := url.PathUnescape(chain)
	if err != nil {
		return pcsDocument{}, fmt.Errorf("PCS %s: issuer chain header: %w", u, err)
	}
	return pcsDocument{Body: body, IssuerChain: []byte(decoded)}, nil
}

// pcsCache keeps documents on disk: <name>.json and <name>.issuer-chain.pem.
type pcsCache struct{ dir string }

func (c pcsCache) load(name string) (pcsDocument, bool) {
	if c.dir == "" {
		return pcsDocument{}, false
	}
	body, err := os.ReadFile(filepath.Join(c.dir, name+".json"))
	if err != nil {
		return pcsDocument{}, false
	}
	chain, err := os.ReadFile(filepath.Join(c.dir, name+".issuer-chain.pem"))
	if err != nil {
		return pcsDocument{}, false
	}
	return pcsDocument{Body: body, IssuerChain: chain}, true
}

func (c pcsCache) store(name string, d pcsDocument) {
	if c.dir == "" {
		return
	}
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(c.dir, name+".json"), d.Body, 0o644)
	_ = os.WriteFile(filepath.Join(c.dir, name+".issuer-chain.pem"), d.IssuerChain, 0o644)
}

// verifyPCSSignature checks the document's signature: ECDSA-P256 by the
// issuer chain's leaf over the exact bytes of the inner object, the chain
// verified to the pinned Intel root at time now. It returns the inner
// object's bytes.
func verifyPCSSignature(d pcsDocument, key string, rootOverride []byte, now time.Time) ([]byte, error) {
	prefix := []byte(`{"` + key + `":`)
	if !bytes.HasPrefix(d.Body, prefix) {
		return nil, fmt.Errorf("PCS document does not begin with %q", string(prefix))
	}
	sigMark := []byte(`,"signature":"`)
	i := bytes.LastIndex(d.Body, sigMark)
	if i < 0 {
		return nil, errors.New("PCS document carries no signature")
	}
	inner := d.Body[len(prefix):i]
	sigHex := d.Body[i+len(sigMark):]
	end := bytes.IndexByte(sigHex, '"')
	if end < 0 {
		return nil, errors.New("PCS document's signature is not terminated")
	}
	sig, err := hex.DecodeString(string(sigHex[:end]))
	if err != nil || len(sig) != 64 {
		return nil, errors.New("PCS document's signature is not 64 hex-encoded bytes")
	}
	chain, err := parsePEMCertificates(d.IssuerChain)
	if err != nil {
		return nil, fmt.Errorf("PCS issuer chain: %w", err)
	}
	if err := verifyChainToIntelRoot(chain, rootOverride, now); err != nil {
		return nil, fmt.Errorf("PCS issuer chain does not chain to the Intel root: %w", err)
	}
	pub, err := p256FromCert(chain[0])
	if err != nil {
		return nil, err
	}
	var raw [64]byte
	copy(raw[:], sig)
	if !verifyP256Raw(pub, inner, raw) {
		return nil, errors.New("PCS document's signature does not verify under the Intel TCB signing certificate")
	}
	return inner, nil
}

// tcbInfo is the TDX TCB info document's inner object.
type tcbInfo struct {
	ID                      string             `json:"id"`
	Version                 int                `json:"version"`
	IssueDate               time.Time          `json:"issueDate"`
	NextUpdate              time.Time          `json:"nextUpdate"`
	FMSPC                   string             `json:"fmspc"`
	PCEID                   string             `json:"pceId"`
	TCBType                 int                `json:"tcbType"`
	TCBEvaluationDataNumber int                `json:"tcbEvaluationDataNumber"`
	TDXModule               tdxModuleIdentity  `json:"tdxModule"`
	TDXModuleIdentities     []tdxModuleVersion `json:"tdxModuleIdentities"`
	TCBLevels               []tcbLevel         `json:"tcbLevels"`
}

type tdxModuleIdentity struct {
	MRSigner       string `json:"mrsigner"`
	Attributes     string `json:"attributes"`
	AttributesMask string `json:"attributesMask"`
}

type tdxModuleVersion struct {
	ID             string           `json:"id"`
	MRSigner       string           `json:"mrsigner"`
	Attributes     string           `json:"attributes"`
	AttributesMask string           `json:"attributesMask"`
	TCBLevels      []tdxModuleLevel `json:"tcbLevels"`
}

type tdxModuleLevel struct {
	TCB struct {
		ISVSVN int `json:"isvsvn"`
	} `json:"tcb"`
	TCBDate   time.Time `json:"tcbDate"`
	TCBStatus string    `json:"tcbStatus"`
}

type tcbComponent struct {
	SVN      int    `json:"svn"`
	Category string `json:"category,omitempty"`
	Type     string `json:"type,omitempty"`
}

type tcbLevel struct {
	TCB struct {
		SGXComponents []tcbComponent `json:"sgxtcbcomponents"`
		PCESVN        int            `json:"pcesvn"`
		TDXComponents []tcbComponent `json:"tdxtcbcomponents"`
	} `json:"tcb"`
	TCBDate     time.Time `json:"tcbDate"`
	TCBStatus   string    `json:"tcbStatus"`
	AdvisoryIDs []string  `json:"advisoryIDs,omitempty"`
}

// qeIdentity is the TD QE identity document's inner object.
type qeIdentity struct {
	ID                      string    `json:"id"`
	Version                 int       `json:"version"`
	IssueDate               time.Time `json:"issueDate"`
	NextUpdate              time.Time `json:"nextUpdate"`
	TCBEvaluationDataNumber int       `json:"tcbEvaluationDataNumber"`
	MiscSelect              string    `json:"miscselect"`
	MiscSelectMask          string    `json:"miscselectMask"`
	Attributes              string    `json:"attributes"`
	AttributesMask          string    `json:"attributesMask"`
	MRSigner                string    `json:"mrsigner"`
	ISVProdID               int       `json:"isvprodid"`
	TCBLevels               []struct {
		TCB struct {
			ISVSVN int `json:"isvsvn"`
		} `json:"tcb"`
		TCBDate   time.Time `json:"tcbDate"`
		TCBStatus string    `json:"tcbStatus"`
	} `json:"tcbLevels"`
}

// pcsClient fetches and verifies PCS documents through the cache.
type pcsClient struct {
	baseURL      string
	cache        pcsCache
	rootOverride []byte
	now          func() time.Time
}

// document returns the verified inner object of a PCS document: from the
// cache while it is current, else fetched and stored.
func (c pcsClient) document(name, path, key string) ([]byte, error) {
	now := c.now()
	if d, ok := c.cache.load(name); ok {
		inner, err := verifyPCSSignature(d, key, c.rootOverride, now)
		if err == nil && documentCurrent(inner, now) {
			return inner, nil
		}
	}
	base := c.baseURL
	if base == "" {
		base = DefaultIntelPCSURL
	}
	d, err := tdxPCSGet(base + path)
	if err != nil {
		return nil, err
	}
	inner, err := verifyPCSSignature(d, key, c.rootOverride, now)
	if err != nil {
		return nil, err
	}
	if !documentCurrent(inner, now) {
		return nil, fmt.Errorf("PCS %s is not current (issueDate/nextUpdate)", name)
	}
	c.cache.store(name, d)
	return inner, nil
}

// documentCurrent reads issueDate and nextUpdate off any PCS inner object.
func documentCurrent(inner []byte, now time.Time) bool {
	var dates struct {
		IssueDate  time.Time `json:"issueDate"`
		NextUpdate time.Time `json:"nextUpdate"`
	}
	if json.Unmarshal(inner, &dates) != nil || dates.NextUpdate.IsZero() {
		return false
	}
	return !now.Before(dates.IssueDate.Add(-5*time.Minute)) && now.Before(dates.NextUpdate)
}

func (c pcsClient) tcbInfo(fmspc [6]byte) (*tcbInfo, error) {
	hexFMSPC := hex.EncodeToString(fmspc[:])
	inner, err := c.document("tdx-tcb-"+hexFMSPC, "/tdx/certification/v4/tcb?fmspc="+hexFMSPC, "tcbInfo")
	if err != nil {
		return nil, err
	}
	var t tcbInfo
	if err := json.Unmarshal(inner, &t); err != nil {
		return nil, fmt.Errorf("TCB info does not decode: %w", err)
	}
	switch {
	case t.ID != "TDX":
		return nil, fmt.Errorf("TCB info is for %q, want TDX", t.ID)
	case t.Version != 3:
		return nil, fmt.Errorf("TCB info version %d, this verifier reads 3", t.Version)
	case !strings.EqualFold(t.FMSPC, hexFMSPC):
		return nil, fmt.Errorf("TCB info is for FMSPC %s, the platform is %s", t.FMSPC, hexFMSPC)
	case len(t.TCBLevels) == 0:
		return nil, errors.New("TCB info lists no TCB levels")
	}
	return &t, nil
}

func (c pcsClient) qeIdentity() (*qeIdentity, error) {
	inner, err := c.document("tdx-qe-identity", "/tdx/certification/v4/qe/identity", "enclaveIdentity")
	if err != nil {
		return nil, err
	}
	var q qeIdentity
	if err := json.Unmarshal(inner, &q); err != nil {
		return nil, fmt.Errorf("QE identity does not decode: %w", err)
	}
	switch {
	case q.ID != "TD_QE":
		return nil, fmt.Errorf("QE identity is for %q, want TD_QE", q.ID)
	case q.Version != 2:
		return nil, fmt.Errorf("QE identity version %d, this verifier reads 2", q.Version)
	case len(q.TCBLevels) == 0:
		return nil, errors.New("QE identity lists no TCB levels")
	}
	return &q, nil
}

// tcbEvaluation is what the TCB info says about the quote's platform.
type tcbEvaluation struct {
	PlatformStatus string
	PlatformDate   time.Time
	ModuleID       string
	ModuleStatus   string
	Status         string // the worse of the two
	AdvisoryIDs    []string
}

// evaluateTCB rates the platform the quote came from against the TCB
// info: the first level whose every SGX component SVN, PCE SVN and TDX
// component SVN the platform meets is the platform's level; the TDX
// module is rated by its own identity's levels against TEE_TCB_SVN.
func evaluateTCB(t *tcbInfo, p pckPlatform, q *tdxQuote) (tcbEvaluation, error) {
	var ev tcbEvaluation
	if !strings.EqualFold(t.PCEID, hex.EncodeToString(p.PCEID[:])) {
		return ev, fmt.Errorf("TCB info is for PCE-ID %s, the platform is %x", t.PCEID, p.PCEID)
	}
	for _, l := range t.TCBLevels {
		if len(l.TCB.SGXComponents) != 16 || len(l.TCB.TDXComponents) != 16 {
			continue
		}
		ok := p.PCESVN >= uint16(l.TCB.PCESVN)
		for i := 0; ok && i < 16; i++ {
			if int(p.CPUSVNs[i]) < l.TCB.SGXComponents[i].SVN || int(q.TEETCBSVN[i]) < l.TCB.TDXComponents[i].SVN {
				ok = false
			}
		}
		if ok {
			ev.PlatformStatus, ev.PlatformDate, ev.AdvisoryIDs = l.TCBStatus, l.TCBDate, l.AdvisoryIDs
			break
		}
	}
	if ev.PlatformStatus == "" {
		return ev, errors.New("the platform's TCB is below every level the TCB info rates")
	}
	// The TDX module: TEE_TCB_SVN[1] is its major version; a non-zero one
	// names an identity with its own levels, rated by TEE_TCB_SVN[0].
	mrsigner, attrs := t.TDXModule.MRSigner, t.TDXModule.Attributes
	mask := t.TDXModule.AttributesMask
	ev.ModuleStatus = TCBUpToDate
	if major := q.TEETCBSVN[1]; major > 0 {
		id := fmt.Sprintf("TDX_%02d", major)
		var found *tdxModuleVersion
		for i := range t.TDXModuleIdentities {
			if t.TDXModuleIdentities[i].ID == id {
				found = &t.TDXModuleIdentities[i]
			}
		}
		if found == nil {
			return ev, fmt.Errorf("the TCB info names no TDX module identity %s", id)
		}
		ev.ModuleID = id
		mrsigner, attrs, mask = found.MRSigner, found.Attributes, found.AttributesMask
		ev.ModuleStatus = ""
		for _, l := range found.TCBLevels {
			if int(q.TEETCBSVN[0]) >= l.TCB.ISVSVN {
				ev.ModuleStatus = l.TCBStatus
				break
			}
		}
		if ev.ModuleStatus == "" {
			return ev, fmt.Errorf("the TDX module's SVN %d is below every level identity %s rates", q.TEETCBSVN[0], id)
		}
	}
	if err := matchMasked("TDX module MRSIGNERSEAM", q.MRSIGNERSEAM[:], mrsigner, ""); err != nil {
		return ev, err
	}
	if err := matchMasked("TDX module SEAMATTRIBUTES", q.SEAMAttrs[:], attrs, mask); err != nil {
		return ev, err
	}
	ev.Status = worseTCBStatus(ev.PlatformStatus, ev.ModuleStatus)
	return ev, nil
}

// evaluateQE checks the Quoting Enclave that signed the quote against its
// identity and returns its TCB status.
func evaluateQE(id *qeIdentity, report []byte) (string, error) {
	qe, err := parseSGXReport(report)
	if err != nil {
		return "", err
	}
	if err := matchMasked("QE MRSIGNER", qe.MRSIGNER[:], id.MRSigner, ""); err != nil {
		return "", err
	}
	if err := matchMasked("QE ATTRIBUTES", qe.Attributes[:], id.Attributes, id.AttributesMask); err != nil {
		return "", err
	}
	if err := matchMasked("QE MISCSELECT", qe.MiscSelect[:], id.MiscSelect, id.MiscSelectMask); err != nil {
		return "", err
	}
	if int(qe.ISVProdID) != id.ISVProdID {
		return "", fmt.Errorf("QE ISVPRODID %d, the identity says %d", qe.ISVProdID, id.ISVProdID)
	}
	for _, l := range id.TCBLevels {
		if int(qe.ISVSVN) >= l.TCB.ISVSVN {
			return l.TCBStatus, nil
		}
	}
	return "", fmt.Errorf("QE ISVSVN %d is below every level its identity rates", qe.ISVSVN)
}

// matchMasked compares got (bytes) with want (hex) under mask (hex, or
// all ones when empty).
func matchMasked(what string, got []byte, wantHex, maskHex string) error {
	want, err := hex.DecodeString(wantHex)
	if err != nil || len(want) != len(got) {
		return fmt.Errorf("%s: the identity's value %q is not %d bytes of hex", what, wantHex, len(got))
	}
	mask := bytes.Repeat([]byte{0xFF}, len(got))
	if maskHex != "" {
		if mask, err = hex.DecodeString(maskHex); err != nil || len(mask) != len(got) {
			return fmt.Errorf("%s: the identity's mask %q is not %d bytes of hex", what, maskHex, len(got))
		}
	}
	for i := range got {
		if got[i]&mask[i] != want[i]&mask[i] {
			return fmt.Errorf("%s %x does not match the identity's %s", what, got, wantHex)
		}
	}
	return nil
}
