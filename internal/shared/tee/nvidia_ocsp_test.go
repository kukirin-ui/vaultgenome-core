// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// ocspTestDir holds NVIDIA's answers for the captured H100's chain.
const ocspTestDir = "testdata/nvidia/ocsp"

// insideNVIDIAAnswers is a moment inside the stored answers' day.
var insideNVIDIAAnswers = time.Date(2026, 9, 17, 1, 0, 0, 0, time.UTC)

func capturedGPUChain(t *testing.T) []*x509.Certificate {
	t.Helper()
	chain, err := ParseGPUCertChain(readEvidence(t, "gpu0-cert-chain.pem"))
	require.NoError(t, err)
	require.Len(t, chain, 5)
	return chain
}

// The stored NVIDIA answers put under the cache, by the names the checker
// looks for.
func nvidiaAnswersCache(t *testing.T, chain []*x509.Certificate) string {
	t.Helper()
	dir := t.TempDir()
	for i, name := range map[int]string{1: "gh100-a01-gsp-brom.der", 2: "gh100-provisioner-ica1.der", 3: "gh100-identity.der"} {
		raw, err := os.ReadFile(filepath.Join(ocspTestDir, name))
		if err != nil {
			t.Skip("NVIDIA OCSP answers not present: " + name)
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, OCSPCacheName(chain[i])), raw, 0o600))
	}
	return dir
}

// noNetwork refuses every request: the check must not reach out.
var noNetworkClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("no network in this test") })}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// NVIDIA's answers for the captured chain verify: each signed by the
// delegated responder of its level, the responder certificate issued by
// the certificate's issuer and marked for OCSP signing; the BROM
// certificate, the Provisioner ICA and the GH100 Identity CA good; the
// per-GPU leaf not served; nothing asked over the network from the cache.
func TestOCSP_NVIDIAsAnswersForTheCapturedChain(t *testing.T) {
	chain := capturedGPUChain(t)
	dir := nvidiaAnswersCache(t, chain)
	c := &OCSPChecker{CacheDir: dir, Client: noNetworkClient, Now: func() time.Time { return insideNVIDIAAnswers }}
	statuses, good := c.CheckChain(context.Background(), chain)
	require.True(t, good, "%+v", statuses)
	require.Len(t, statuses, 4)
	require.Equal(t, "not served", statuses[0].Status)
	require.Equal(t, "GH100 A01 GSP FMC LF", statuses[0].Subject)
	for i, want := range []string{"GH100 A01 GSP BROM", "NVIDIA GH100 Provisioner ICA 1", "NVIDIA GH100 Identity"} {
		st := statuses[i+1]
		require.Equal(t, "good", st.Status, "%+v", st)
		require.Equal(t, want, st.Subject)
		require.True(t, st.FromCache)
		require.Contains(t, st.Responder, "NVIDIA OCSP Responder")
		require.Equal(t, "2026-09-16T23:21:39Z", st.ThisUpdate)
		require.Equal(t, "2026-09-17T23:21:39Z", st.NextUpdate)
	}

	// An answer for one certificate is no answer for another: the
	// Identity CA's answer under the ICA's name is refused, and with the
	// network refused the status is an error, not good.
	swapped := t.TempDir()
	raw, err := os.ReadFile(filepath.Join(ocspTestDir, "gh100-identity.der"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(swapped, OCSPCacheName(chain[2])), raw, 0o600))
	c.CacheDir = swapped
	statuses, good = c.CheckChain(context.Background(), chain)
	require.False(t, good)
	require.Equal(t, "error", statuses[2].Status)
	require.Contains(t, statuses[2].Error, "no network in this test")

	// Past the answers' day they are stale: asked again, refused here.
	c.CacheDir = dir
	c.Now = func() time.Time { return insideNVIDIAAnswers.Add(48 * time.Hour) }
	statuses, good = c.CheckChain(context.Background(), chain)
	require.False(t, good)
	for _, st := range statuses[1:] {
		require.Equal(t, "error", st.Status)
	}
}

// The evaluation of the captured report with revocation checked from the
// stored answers is complete, and says so; with revocation unchecked it
// says that too.
func TestGPUEvaluator_RevocationOnTheRecord(t *testing.T) {
	chainPEM := readEvidence(t, "gpu0-cert-chain.pem")
	chain := capturedGPUChain(t)
	dir := nvidiaAnswersCache(t, chain)
	srv, _ := rimServer(t)
	device, err := parseNVIDIARoot(nil, NVIDIADeviceRootPEM)
	require.NoError(t, err)
	rimRoot, err := parseNVIDIARoot(nil, NVIDIARIMRootPEM)
	require.NoError(t, err)
	report, nonce := readEvidence(t, "gpu0-attestation-report.bin"), capturedNonce(t)
	now := func() time.Time { return insideNVIDIAAnswers }
	e := (&GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: now,
		RIMs: &RIMFetcher{BaseURL: srv.URL + "/v1/rim/", CacheDir: t.TempDir()},
		OCSP: &OCSPChecker{CacheDir: dir, Client: noNetworkClient, Now: now}}).Evaluate(context.Background(), report, chainPEM, nonce)
	require.True(t, e.Complete(), "%+v", e)
	require.True(t, e.RevocationChecked)
	require.True(t, e.RevocationGood)
	require.Len(t, e.Revocation, 4)

	unchecked := (&GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: now,
		RIMs: &RIMFetcher{BaseURL: srv.URL + "/v1/rim/", CacheDir: t.TempDir()}}).Evaluate(context.Background(), report, chainPEM, nonce)
	require.True(t, unchecked.Complete())
	require.False(t, unchecked.RevocationChecked)
	require.Empty(t, unchecked.Revocation)

	refused := (&GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: now,
		RIMs: &RIMFetcher{BaseURL: srv.URL + "/v1/rim/", CacheDir: t.TempDir()},
		OCSP: &OCSPChecker{CacheDir: t.TempDir(), Client: noNetworkClient, Now: now}}).Evaluate(context.Background(), report, chainPEM, nonce)
	require.False(t, refused.Complete(), "no answer, no completion")
	require.True(t, refused.RevocationChecked)
	require.False(t, refused.RevocationGood)
	require.NotEmpty(t, refused.Errors)
}

// A synthetic chain with a responder of its own: every way an answer can
// be wrong is refused, a good answer is cached, and a revoked one is what
// it says.
func TestOCSP_SyntheticResponder(t *testing.T) {
	t.Parallel()
	caKey, caCert := selfSignedCA(t, "test root")
	icaKey, icaCert := issuedCert(t, "test ICA", caCert, caKey, true, nil)
	_, leafCert := issuedCert(t, "test leaf", icaCert, icaKey, false, nil)
	respKey, respCert := issuedCert(t, "test responder", caCert, caKey, false, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})
	plainKey, plainCert := issuedCert(t, "not a responder", caCert, caKey, false, nil)
	chain := []*x509.Certificate{leafCert, icaCert, caCert}
	now := time.Now().Truncate(time.Second)

	var mode string
	var answers int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answers++
		body, _ := io.ReadAll(r.Body)
		var req ocspRequestDER
		_, err := asn1.Unmarshal(body, &req)
		if err != nil || len(req.TBSRequest.RequestList) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var nonce []byte
		for _, ext := range req.TBSRequest.Extensions {
			if ext.Id.Equal(ocspNonceOID) {
				nonce = ext.Value
			}
		}
		tmpl := ocsp.Response{Status: ocsp.Good, SerialNumber: req.TBSRequest.RequestList[0].Cert.SerialNumber,
			ThisUpdate: now, NextUpdate: now.Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: ocspNonceOID, Value: nonce}}}
		signer, signerKey := respCert, respKey
		tmpl.Certificate = signer // the delegated responder's certificate, embedded (RFC 6960 §4.2.2.2)
		switch mode {
		case "revoked":
			tmpl.Status, tmpl.RevokedAt, tmpl.RevocationReason = ocsp.Revoked, now.Add(-time.Hour), ocsp.KeyCompromise
		case "unknown":
			tmpl.Status = ocsp.Unknown
		case "no nonce":
			tmpl.ExtraExtensions = nil
		case "expired":
			tmpl.ThisUpdate, tmpl.NextUpdate = now.Add(-3*time.Hour), now.Add(-2*time.Hour)
		case "not a responder":
			signer, signerKey = plainCert, plainKey
			tmpl.Certificate = signer
		case "http 500":
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		der, err := ocsp.CreateResponse(caCert, signer, tmpl, signerKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)

	// Good, and cached: the second check asks nothing.
	dir := t.TempDir()
	c := &OCSPChecker{URL: srv.URL, CacheDir: dir, Client: srv.Client(), Now: func() time.Time { return now.Add(time.Minute) }}
	statuses, good := c.CheckChain(context.Background(), chain)
	require.True(t, good, "%+v", statuses)
	require.Len(t, statuses, 2)
	require.Equal(t, "not served", statuses[0].Status)
	require.Equal(t, "good", statuses[1].Status)
	require.Equal(t, "test responder", statuses[1].Responder)
	require.False(t, statuses[1].FromCache)
	require.FileExists(t, filepath.Join(dir, OCSPCacheName(icaCert)))
	asked := answers
	statuses, good = c.CheckChain(context.Background(), chain)
	require.True(t, good)
	require.True(t, statuses[1].FromCache)
	require.Equal(t, asked, answers, "a cached good answer is not asked again")

	for _, tc := range []struct{ mode, status, errPart string }{
		{"revoked", "revoked", "revoked at"},
		{"unknown", "unknown", "does not know"},
		{"no nonce", "error", "nonce"},
		{"expired", "error", "expired"},
		{"not a responder", "error", "OCSP signing"},
		{"http 500", "error", "HTTP 500"},
	} {
		mode = tc.mode
		c := &OCSPChecker{URL: srv.URL, CacheDir: t.TempDir(), Client: srv.Client(), Now: func() time.Time { return now.Add(time.Minute) }}
		statuses, good := c.CheckChain(context.Background(), chain)
		require.False(t, good, tc.mode)
		require.Equal(t, tc.status, statuses[1].Status, tc.mode)
		require.Contains(t, statuses[1].Error, tc.errPart, tc.mode)
		require.NoFileExists(t, filepath.Join(c.CacheDir, OCSPCacheName(icaCert)), "%s: nothing but a good answer is cached", tc.mode)
	}
	mode = ""

	// The certificate's own OCSP URL wins over the checker's.
	_, withURL := issuedCert(t, "ICA with AIA", caCert, caKey, true, nil, srv.URL+"/aia")
	dead := &OCSPChecker{URL: "http://127.0.0.1:9/dead", Client: srv.Client(), Now: func() time.Time { return now.Add(time.Minute) }}
	statuses, good = dead.CheckChain(context.Background(), []*x509.Certificate{leafCert, withURL, caCert})
	require.True(t, good, "%+v", statuses)
}

// The request is RFC 6960's, with a SHA-256 certificate id and a nonce.
func TestOCSP_RequestShape(t *testing.T) {
	t.Parallel()
	caKey, caCert := selfSignedCA(t, "req root")
	_, ica := issuedCert(t, "req ICA", caCert, caKey, true, nil)
	nonce := []byte("0123456789abcdef")
	der, err := buildOCSPRequest(ica, caCert, nonce)
	require.NoError(t, err)
	parsed, err := ocsp.ParseRequest(der)
	require.NoError(t, err)
	require.Equal(t, crypto.SHA256, parsed.HashAlgorithm)
	nameHash := sha256.Sum256(caCert.RawSubject)
	require.Equal(t, nameHash[:], parsed.IssuerNameHash)
	require.Equal(t, ica.SerialNumber, parsed.SerialNumber)
	var req ocspRequestDER
	_, err = asn1.Unmarshal(der, &req)
	require.NoError(t, err)
	require.Len(t, req.TBSRequest.Extensions, 1)
	want, _ := asn1.Marshal(nonce)
	require.Equal(t, want, req.TBSRequest.Extensions[0].Value)
}

func selfSignedCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// serials numbers the synthetic certificates; parallel tests share it.
var serials atomic.Int64

func issuedCert(t *testing.T, name string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, isCA bool, eku []x509.ExtKeyUsage, ocspURL ...string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(100 + serials.Add(1)), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku, OCSPServer: ocspURL}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

// NVIDIA's responder echoes the nonce in the answer's responseExtensions
// (RFC 6960 §4.4.1), not in the single response's extensions x/crypto
// exposes: the stored answers carry the nonces the fetch sent, and the
// check finds them there; another nonce is refused.
func TestOCSP_NVIDIAsAnswersCarryTheNonceInResponseExtensions(t *testing.T) {
	chain := capturedGPUChain(t)
	for i, name := range map[int]string{1: "gh100-a01-gsp-brom.der", 2: "gh100-provisioner-ica1.der", 3: "gh100-identity.der"} {
		raw, err := os.ReadFile(filepath.Join(ocspTestDir, name))
		if err != nil {
			t.Skip("NVIDIA OCSP answers not present: " + name)
		}
		parsed, err := ocsp.ParseResponseForCert(raw, chain[i], chain[i+1])
		require.NoError(t, err, name)
		require.Empty(t, parsed.Extensions, "%s: x/crypto sees no nonce in the single response", name)
		echoed := ocspResponseNonce(raw, parsed)
		require.NotNil(t, echoed, "%s: the nonce is in responseExtensions", name)
		var nonce []byte
		_, err = asn1.Unmarshal(echoed, &nonce)
		require.NoError(t, err)
		require.Len(t, nonce, 16, "%s: openssl's 16-byte nonce, as an OCTET STRING", name)
		_, err = verifyOCSPResponse(raw, chain[i], chain[i+1], nonce, insideNVIDIAAnswers)
		require.NoError(t, err, name)
		_, err = verifyOCSPResponse(raw, chain[i], chain[i+1], []byte("0123456789abcdef"), insideNVIDIAAnswers)
		require.ErrorContains(t, err, "nonce", name)
	}
}
