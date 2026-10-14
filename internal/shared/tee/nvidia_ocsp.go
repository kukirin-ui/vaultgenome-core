// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
)

// NVIDIAOCSPURL is NVIDIA's OCSP responder for the GPU attestation
// certificate chains: the URL the intermediates carry in their authority
// information access, and the one used for the certificates that carry
// none.
const NVIDIAOCSPURL = "http://ocsp.ndis.nvidia.com"

// ocspNonceOID is id-pkix-ocsp-nonce (RFC 6960 §4.4.1).
var ocspNonceOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// OCSPStatus is the revocation status of one certificate of the GPU's
// chain, as NVIDIA's responder said it — or why it could not be asked.
type OCSPStatus struct {
	Subject string `json:"subject"`
	// Status is good, revoked or unknown as the responder said; "not
	// served" for the per-GPU leaf, which NVIDIA's responder does not
	// answer for (its issuer's status stands for it); "error" when the
	// responder could not be asked or its answer did not verify.
	Status     string `json:"status"`
	Responder  string `json:"responder,omitempty"`
	ThisUpdate string `json:"this_update,omitempty"`
	NextUpdate string `json:"next_update,omitempty"`
	FromCache  bool   `json:"from_cache,omitempty"`
	Error      string `json:"error,omitempty"`
}

// OCSPChecker asks NVIDIA's responder for the revocation status of the
// certificates of a GPU's attestation chain (ADR 0021): each certificate
// between the leaf and the pinned root, asked by its issuer, with a SHA-256
// certificate id and a nonce; the answer's signature verified under the
// responder certificate it carries, which the issuer must have signed for
// OCSP signing (RFC 6960 §4.2.2.2), or under the issuer itself; the nonce
// echoed; the answer inside its validity. A good answer is kept under
// CacheDir until its nextUpdate, so a verifier asks once a day per
// certificate and works through a responder outage inside that day.
type OCSPChecker struct {
	// URL is the responder for certificates that carry no OCSP URL of
	// their own (default NVIDIAOCSPURL); a certificate's own URL wins.
	URL      string
	CacheDir string
	Client   *http.Client
	// Now is the clock the answers' validity is judged by (default time.Now).
	Now func() time.Time
}

// CheckChain asks for every certificate between the leaf and the root of
// a verified chain (leaf first, root last) and reports whether every
// answer was good. The leaf is recorded as not served.
func (c *OCSPChecker) CheckChain(ctx context.Context, chain []*x509.Certificate) ([]OCSPStatus, bool) {
	if len(chain) < 2 {
		return []OCSPStatus{{Status: "error", Error: "nvidia: GPU chain too short for a revocation check"}}, false
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	statuses := []OCSPStatus{{Subject: chain[0].Subject.CommonName, Status: "not served"}}
	good := true
	for i := 1; i < len(chain)-1; i++ {
		st := c.check(ctx, chain[i], chain[i+1], now)
		if st.Status != "good" {
			good = false
		}
		statuses = append(statuses, st)
	}
	return statuses, good
}

// OCSPCacheName is the file a certificate's cached answer lives under.
func OCSPCacheName(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "ocsp-" + hex.EncodeToString(sum[:16]) + ".der"
}

func (c *OCSPChecker) check(ctx context.Context, cert, issuer *x509.Certificate, now time.Time) OCSPStatus {
	st := OCSPStatus{Subject: cert.Subject.CommonName}
	var cachePath string
	if c.CacheDir != "" {
		cachePath = filepath.Join(c.CacheDir, OCSPCacheName(cert))
		if raw, err := os.ReadFile(cachePath); err == nil {
			if resp, err := verifyOCSPResponse(raw, cert, issuer, nil, now); err == nil && resp.Status == ocsp.Good {
				fill(&st, resp)
				st.FromCache = true
				return st
			}
		}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		st.Status, st.Error = "error", "nvidia: ocsp nonce: "+err.Error()
		return st
	}
	req, err := buildOCSPRequest(cert, issuer, nonce)
	if err != nil {
		st.Status, st.Error = "error", "nvidia: ocsp request: "+err.Error()
		return st
	}
	url := c.URL
	if url == "" {
		url = NVIDIAOCSPURL
	}
	if len(cert.OCSPServer) > 0 && cert.OCSPServer[0] != "" {
		url = cert.OCSPServer[0]
	}
	raw, err := c.post(ctx, url, req)
	if err != nil {
		st.Status, st.Error = "error", "nvidia: ocsp "+url+": "+err.Error()
		return st
	}
	resp, err := verifyOCSPResponse(raw, cert, issuer, nonce, now)
	if err != nil {
		st.Status, st.Error = "error", "nvidia: ocsp "+url+": "+err.Error()
		return st
	}
	fill(&st, resp)
	if resp.Status == ocsp.Good && cachePath != "" {
		if err := os.MkdirAll(c.CacheDir, 0o700); err == nil {
			_ = os.WriteFile(cachePath, raw, 0o600)
		}
	}
	return st
}

func fill(st *OCSPStatus, resp *ocsp.Response) {
	switch resp.Status {
	case ocsp.Good:
		st.Status = "good"
	case ocsp.Revoked:
		st.Status = "revoked"
		st.Error = fmt.Sprintf("revoked at %s (reason %d)", resp.RevokedAt.UTC().Format(time.RFC3339), resp.RevocationReason)
	default:
		st.Status = "unknown"
		st.Error = "the responder does not know the certificate"
	}
	if resp.Certificate != nil {
		st.Responder = resp.Certificate.Subject.CommonName
	}
	st.ThisUpdate = resp.ThisUpdate.UTC().Format(time.RFC3339)
	if !resp.NextUpdate.IsZero() {
		st.NextUpdate = resp.NextUpdate.UTC().Format(time.RFC3339)
	}
}

func (c *OCSPChecker) post(ctx context.Context, url string, body []byte) ([]byte, error) {
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// verifyOCSPResponse parses an answer for cert and holds it to what a
// verifier must: the responder's own status successful; the signature
// under the responder certificate the answer carries — issued by the
// issuer, marked for OCSP signing, valid now — or under the issuer; the
// certificate id the issuer's; the nonce echoed when one was sent; the
// answer's validity covering now.
func verifyOCSPResponse(raw []byte, cert, issuer *x509.Certificate, nonce []byte, now time.Time) (*ocsp.Response, error) {
	resp, err := ocsp.ParseResponseForCert(raw, cert, issuer)
	if err != nil {
		return nil, err
	}
	if resp.Certificate != nil {
		if !slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
			return nil, errors.New("the responder certificate is not marked for OCSP signing")
		}
		if now.Before(resp.Certificate.NotBefore) || now.After(resp.Certificate.NotAfter) {
			return nil, errors.New("the responder certificate is not valid now")
		}
	}
	if nonce != nil {
		want, _ := asn1.Marshal(nonce)
		got := ocspResponseNonce(raw, resp)
		if got == nil || !(bytes.Equal(got, want) || bytes.Equal(got, nonce)) {
			return nil, errors.New("the answer does not carry the request's nonce")
		}
	}
	if now.Before(resp.ThisUpdate.Add(-5 * time.Minute)) {
		return nil, fmt.Errorf("the answer is from the future (thisUpdate %s)", resp.ThisUpdate.UTC().Format(time.RFC3339))
	}
	if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
		return nil, fmt.Errorf("the answer has expired (nextUpdate %s)", resp.NextUpdate.UTC().Format(time.RFC3339))
	}
	return resp, nil
}

// The request, RFC 6960 §4.1.1, with the nonce extension x/crypto's
// CreateRequest does not write.
type ocspRequestDER struct {
	TBSRequest ocspTBSRequestDER
}

type ocspTBSRequestDER struct {
	Version     int `asn1:"explicit,tag:0,default:0,optional"`
	RequestList []ocspSingleRequestDER
	Extensions  []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type ocspSingleRequestDER struct {
	Cert ocspCertIDDER
}

type ocspCertIDDER struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

// buildOCSPRequest is a request for cert's status with a SHA-256
// certificate id (the issuer's name and key hashed) and the nonce.
func buildOCSPRequest(cert, issuer *x509.Certificate, nonce []byte) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("issuer public key: %w", err)
	}
	nameHash := sha256.Sum256(issuer.RawSubject)
	keyHash := sha256.Sum256(spki.PublicKey.RightAlign())
	nonceValue, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ocspRequestDER{TBSRequest: ocspTBSRequestDER{
		RequestList: []ocspSingleRequestDER{{Cert: ocspCertIDDER{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Parameters: asn1.NullRawValue},
			NameHash:      nameHash[:],
			IssuerKeyHash: keyHash[:],
			SerialNumber:  cert.SerialNumber,
		}}},
		Extensions: []pkix.Extension{{Id: ocspNonceOID, Value: nonceValue}},
	}})
}

// hashForOCSP is the hash the certificate ids are made with.
var _ = crypto.SHA256

// The answer's outer structures (RFC 6960 §4.2.1), mirrored from x/crypto
// for the one field it does not read: responseExtensions, where a
// responder echoes the nonce. (x/crypto's Response.Extensions is the
// single response's singleExtensions; NVIDIA's responder, like RFC 6960,
// puts the nonce in responseExtensions — the first live handshake caught
// this check looking in the wrong place.)
type ocspResponseASN1 struct {
	Status   asn1.Enumerated
	Response ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspBasicResponse struct {
	TBSResponseData ocspResponseData
	// the signature and certificates follow; not needed here
}

type ocspResponseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []asn1.RawValue
	Extensions     []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

// ocspResponseNonce is the nonce the answer echoes: from its
// responseExtensions, or, failing that, the single response's extensions
// x/crypto exposes. Nil when there is none.
func ocspResponseNonce(raw []byte, resp *ocsp.Response) []byte {
	var outer ocspResponseASN1
	if rest, err := asn1.Unmarshal(raw, &outer); err == nil && len(rest) == 0 {
		var basic ocspBasicResponse
		if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err == nil {
			for _, ext := range basic.TBSResponseData.Extensions {
				if ext.Id.Equal(ocspNonceOID) {
					return ext.Value
				}
			}
		}
	}
	for _, ext := range resp.Extensions {
		if ext.Id.Equal(ocspNonceOID) {
			return ext.Value
		}
	}
	return nil
}
