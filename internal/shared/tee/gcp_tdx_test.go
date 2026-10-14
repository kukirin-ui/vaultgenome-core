// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The verifier against a genuine TDX quote from a Google Cloud c3
// Confidential VM, with the Intel PCS documents captured beside it
// (scripts/hardware-test/gcp-tdx/capture, run 20260916T031937Z): every
// signature walked to the pinned Intel root, the TCB evaluated, the nonce
// bound, the measurement compared. The capture's clock is pinned so the
// documents are current forever in this test.

const tdxCapture = "../../../scripts/hardware-test/gcp-tdx/capture/evidence/20260916T031937Z"

// tdxCaptureNonce is the challenge whose SHA-256 the capture put in
// REPORTDATA — the pre-image, so the producer/verifier binding holds.
const tdxCaptureNonce = "vault-genome tdx capture 20260916T031937Z challenge 1"

var tdxCaptureTime = time.Date(2026, 9, 16, 3, 30, 0, 0, time.UTC)

func tdxEvidence(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(tdxCapture, name))
	if err != nil {
		t.Skipf("TDX capture evidence not present (%v)", err)
	}
	return b
}

// tdxCacheDir fills a PCS cache from the capture, so no network is asked.
func tdxCacheDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range [][2]string{
		{"tcb-info.json", "tdx-tcb-00806f050000.json"},
		{"tcb-info.json.issuer-chain.pem", "tdx-tcb-00806f050000.issuer-chain.pem"},
		{"qe-identity.json", "tdx-qe-identity.json"},
		{"qe-identity.json.issuer-chain.pem", "tdx-qe-identity.issuer-chain.pem"},
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, f[1]), tdxEvidence(t, f[0]), 0o644))
	}
	return dir
}

// noNetwork fails any PCS fetch: the cache must serve everything.
func noNetwork(t *testing.T) {
	t.Helper()
	prev := tdxPCSGet
	tdxPCSGet = func(u string) (pcsDocument, error) { return pcsDocument{}, errors.New("no network in this test: " + u) }
	t.Cleanup(func() { tdxPCSGet = prev })
}

func tdxVerifier(t *testing.T, expected Measurement, mutate ...func(*GCPTDXVerifierConfig)) *GCPTDXVerifier {
	t.Helper()
	cfg := GCPTDXVerifierConfig{PCSCacheDir: tdxCacheDir(t), Now: func() time.Time { return tdxCaptureTime }}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := NewGCPTDXVerifier(nil, expected, cfg)
	require.NoError(t, err)
	return v
}

func TestTDXQuoteParsesAsCaptured(t *testing.T) {
	q, err := parseTDXQuote(tdxEvidence(t, "q1.quote.bin"))
	require.NoError(t, err)
	require.Equal(t, uint16(4), q.Version)
	require.Equal(t, uint32(0x81), q.TEEType)
	require.Equal(t, "0f010a00000000000000000000000000", hex.EncodeToString(q.TEETCBSVN[:]))
	require.Equal(t, uint64(0x10000000), q.TDAttrs, "SEPT_VE_DISABLE, as dmesg on the guest said; not DEBUG")
	require.Equal(t, uint64(0x602e7), q.XFAM)
	require.Equal(t, "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5", hex.EncodeToString(q.MRTD[:]))
	require.Equal(t, "60d411d629fe0d9d", hex.EncodeToString(q.RTMR[0][:8]))
	require.True(t, bytes.Equal(q.RTMR[3][:], make([]byte, 48)), "RTMR3 untouched at capture")
	sum := sha256.Sum256([]byte(tdxCaptureNonce))
	require.Equal(t, sum[:], q.ReportData[:32])
	require.True(t, bytes.Equal(q.ReportData[32:], make([]byte, 32)))
	require.Len(t, q.QEReport, 384)
	require.Len(t, q.QEAuthData, 32)
	require.Contains(t, string(q.PCKChainPEM), "BEGIN CERTIFICATE")
	chain, err := parsePEMCertificates(q.PCKChainPEM)
	require.NoError(t, err)
	require.Len(t, chain, 3)
	require.Equal(t, "Intel SGX PCK Certificate", chain[0].Subject.CommonName)
	require.Equal(t, "Intel SGX Root CA", chain[2].Subject.CommonName)
	platform, err := parsePCKExtension(chain[0])
	require.NoError(t, err)
	require.Equal(t, "00806f050000", hex.EncodeToString(platform.FMSPC[:]))
	require.Equal(t, "0000", hex.EncodeToString(platform.PCEID[:]))
	require.Equal(t, [16]uint8{9, 9, 2, 2, 4, 1, 0, 6}, platform.CPUSVNs)
	require.Equal(t, uint16(11), platform.PCESVN)
}

func TestTDXVerifierAcceptsTheCapturedQuote(t *testing.T) {
	noNetwork(t)
	q, err := parseTDXQuote(tdxEvidence(t, "q1.quote.bin"))
	require.NoError(t, err)
	want := tdxMeasurement(q.MRTD, q.RTMR)
	v := tdxVerifier(t, want)
	verdict, err := v.VerifyQuote(tdxEvidence(t, "q1.quote.bin"), Nonce(tdxCaptureNonce))
	require.NoError(t, err)
	require.True(t, verdict.Measurement.Equal(want))
	require.Len(t, verdict.Measurement, 48)
	require.Equal(t, TCBUpToDate, verdict.TCBStatus)
	require.Equal(t, TCBUpToDate, verdict.QEStatus)
	require.Equal(t, q.MRTD, verdict.MRTD)

	// Through the Verifier interface, and through the factory.
	m, err := v.Verify(tdxEvidence(t, "q1.quote.bin"), Nonce(tdxCaptureNonce))
	require.NoError(t, err)
	require.True(t, m.Equal(want))
	built, err := BuildVerifier(VerifierSpec{Provider: ProviderGCPTDX, ExpectedMeasurement: want,
		GCPTDX: GCPTDXVerifierConfig{PCSCacheDir: tdxCacheDir(t), Now: func() time.Time { return tdxCaptureTime }}})
	require.NoError(t, err)
	m, err = built.Verify(tdxEvidence(t, "q1.quote.bin"), Nonce(tdxCaptureNonce))
	require.NoError(t, err)
	require.True(t, m.Equal(want))

	// The second quote of the capture: same guest, another challenge.
	q2 := tdxEvidence(t, "q2.quote.bin")
	_, err = v.Verify(q2, Nonce(tdxCaptureNonce))
	require.Error(t, err, "quote 2 answers challenge 2, not challenge 1")
	m, err = v.Verify(q2, Nonce("vault-genome tdx capture 20260916T031937Z challenge 2"))
	require.NoError(t, err)
	require.True(t, m.Equal(want))
}

func TestTDXVerifierRefusesWhatItShould(t *testing.T) {
	noNetwork(t)
	raw := tdxEvidence(t, "q1.quote.bin")
	q, err := parseTDXQuote(raw)
	require.NoError(t, err)
	want := tdxMeasurement(q.MRTD, q.RTMR)
	v := tdxVerifier(t, want)
	ok := Nonce(tdxCaptureNonce)

	integrity := func(err error, msg string) {
		t.Helper()
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
		require.Contains(t, err.Error(), msg)
	}
	flip := func(off int) []byte {
		b := append([]byte(nil), raw...)
		b[off] ^= 0x01
		return b
	}
	_, err = v.Verify(raw, Nonce("another challenge, sixteen bytes long"))
	integrity(err, "REPORTDATA does not bind")
	_, err = v.Verify(flip(48+136), ok) // MRTD
	integrity(err, "TD report's signature")
	_, err = v.Verify(flip(48+520), ok) // REPORTDATA
	integrity(err, "TD report's signature")
	_, err = v.Verify(flip(636), ok) // the quote signature
	integrity(err, "TD report's signature")
	_, err = v.Verify(flip(636+64), ok) // the attestation key
	integrity(err, "signature")
	_, err = v.Verify(flip(636+134+64), ok) // the QE report's MRENCLAVE
	integrity(err, "QE report's signature")
	_, err = v.Verify(flip(636+134+384), ok) // the QE report's signature
	integrity(err, "QE report's signature")
	_, err = v.Verify(raw[:2000], ok)
	integrity(err, "parse quote")
	_, err = v.Verify(raw[:100], ok)
	integrity(err, "parse quote")
	_, err = v.Verify(raw, Nonce("short"))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// Another measurement pinned; a debuggable TD; a TCB the operator does
	// not accept; the wrong root; documents no longer current.
	other := tdxVerifier(t, Measurement(bytes.Repeat([]byte{1}, 48)))
	_, err = other.Verify(raw, ok)
	integrity(err, "not in acceptable set")
	debug := append([]byte(nil), raw...)
	debug[48+120] |= tdxAttrDebug
	_, err = v.Verify(debug, ok)
	integrity(err, "signature") // the signature no longer covers it; the DEBUG gate is behind it
	strict := tdxVerifier(t, want, func(c *GCPTDXVerifierConfig) { c.AcceptableTCBStatuses = []string{TCBUpToDate} })
	_, err = strict.Verify(raw, ok)
	require.NoError(t, err)
	_, err = NewGCPTDXVerifier(nil, want, GCPTDXVerifierConfig{AcceptableTCBStatuses: []string{TCBOutOfDate}})
	require.Error(t, err, "OutOfDate is never accepted")
	_, err = NewGCPTDXVerifier(nil, want, GCPTDXVerifierConfig{AcceptableTCBStatuses: []string{"Fine"}})
	require.Error(t, err)
	wrongRoot := tdxVerifier(t, want, func(c *GCPTDXVerifierConfig) { c.IntelRootPEM = otherRootPEM(t) })
	_, err = wrongRoot.Verify(raw, ok)
	integrity(err, "Intel root")
	// Months later the cached documents are past nextUpdate: the verifier
	// asks PCS again and, with no PCS to ask, fails closed.
	stale := tdxVerifier(t, want, func(c *GCPTDXVerifierConfig) { c.Now = func() time.Time { return tdxCaptureTime.AddDate(0, 3, 0) } })
	_, err = stale.Verify(raw, ok)
	integrity(err, "TCB info")
	require.Contains(t, err.Error(), "no network")
}

// otherRootPEM is a self-signed CA that is not Intel's root.
func otherRootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Not Intel"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// The TCB and QE evaluations, on the captured documents and on synthetic
// ones: a level is met only when every SVN is met, the TDX module is
// rated by its own identity, and a status the operator does not accept
// is refused.
func TestTDXTCBEvaluation(t *testing.T) {
	noNetwork(t)
	q, err := parseTDXQuote(tdxEvidence(t, "q1.quote.bin"))
	require.NoError(t, err)
	chain, err := parsePEMCertificates(q.PCKChainPEM)
	require.NoError(t, err)
	platform, err := parsePCKExtension(chain[0])
	require.NoError(t, err)
	client := pcsClient{cache: pcsCache{dir: tdxCacheDir(t)}, now: func() time.Time { return tdxCaptureTime }}
	info, err := client.tcbInfo(platform.FMSPC)
	require.NoError(t, err)
	require.Len(t, info.TCBLevels, 6)
	ev, err := evaluateTCB(info, platform, q)
	require.NoError(t, err)
	require.Equal(t, TCBUpToDate, ev.PlatformStatus)
	require.Equal(t, "TDX_01", ev.ModuleID)
	require.Equal(t, TCBUpToDate, ev.ModuleStatus)
	require.Equal(t, TCBUpToDate, ev.Status)

	// An older platform: one component SVN below the top level lands on
	// the next level, OutOfDate.
	older := platform
	older.CPUSVNs[0] = 8
	ev, err = evaluateTCB(info, older, q)
	require.NoError(t, err)
	require.Equal(t, TCBOutOfDate, ev.PlatformStatus)
	require.Equal(t, TCBOutOfDate, ev.Status)
	ancient := platform
	ancient.PCESVN = 1
	_, err = evaluateTCB(info, ancient, q)
	require.ErrorContains(t, err, "below every level")
	// An older TDX module lands on its identity's lower level.
	oldModule := *q
	oldModule.TEETCBSVN[0] = 5
	ev, err = evaluateTCB(info, platform, &oldModule)
	require.NoError(t, err)
	require.Equal(t, TCBOutOfDate, ev.ModuleStatus)
	require.Equal(t, TCBOutOfDate, ev.Status, "the worse of platform and module")
	unknownModule := *q
	unknownModule.TEETCBSVN[1] = 9
	_, err = evaluateTCB(info, platform, &unknownModule)
	require.ErrorContains(t, err, "TDX_09")
	wrongSigner := *q
	wrongSigner.MRSIGNERSEAM[0] = 1
	_, err = evaluateTCB(info, platform, &wrongSigner)
	require.ErrorContains(t, err, "MRSIGNERSEAM")
	wrongPCE := platform
	wrongPCE.PCEID = [2]byte{0, 1}
	_, err = evaluateTCB(info, wrongPCE, q)
	require.ErrorContains(t, err, "PCE-ID")

	id, err := client.qeIdentity()
	require.NoError(t, err)
	status, err := evaluateQE(id, q.QEReport)
	require.NoError(t, err)
	require.Equal(t, TCBUpToDate, status)
	report := append([]byte(nil), q.QEReport...)
	report[128] ^= 1 // MRSIGNER
	_, err = evaluateQE(id, report)
	require.ErrorContains(t, err, "MRSIGNER")
	report = append([]byte(nil), q.QEReport...)
	report[258], report[259] = 1, 0 // ISVSVN 1
	_, err = evaluateQE(id, report)
	require.ErrorContains(t, err, "ISVSVN")
	report = append([]byte(nil), q.QEReport...)
	report[256] = 3 // ISVPRODID
	_, err = evaluateQE(id, report)
	require.ErrorContains(t, err, "ISVPRODID")

	// A verifier that accepts hardening statuses still refuses OutOfDate.
	lenient, err := NewGCPTDXVerifier(nil, nil, GCPTDXVerifierConfig{AcceptableTCBStatuses: []string{TCBUpToDate, TCBSWHardeningNeeded}})
	require.NoError(t, err)
	require.True(t, lenient.statuses[TCBSWHardeningNeeded])
	require.False(t, lenient.statuses[TCBOutOfDate])
	require.Equal(t, TCBRevoked, worseTCBStatus(TCBUpToDate, TCBRevoked))
	require.Equal(t, TCBOutOfDate, worseTCBStatus(TCBOutOfDate, TCBSWHardeningNeeded))
}

// A PCS document is read only after its signature verifies under the
// Intel TCB signing chain; a byte changed anywhere in it is refused, and
// a stale cache entry is not used.
func TestTDXPCSDocumentsAreVerifiedBeforeUse(t *testing.T) {
	now := func() time.Time { return tdxCaptureTime }
	body := tdxEvidence(t, "tcb-info.json")
	chain := tdxEvidence(t, "tcb-info.json.issuer-chain.pem")
	inner, err := verifyPCSSignature(pcsDocument{Body: body, IssuerChain: chain}, "tcbInfo", nil, now())
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(inner, []byte(`{"id":"TDX"`)))
	edited := bytes.Replace(body, []byte(`"tcbStatus":"OutOfDate"`), []byte(`"tcbStatus":"UpToDate"`), 1)
	require.NotEqual(t, body, edited)
	_, err = verifyPCSSignature(pcsDocument{Body: edited, IssuerChain: chain}, "tcbInfo", nil, now())
	require.ErrorContains(t, err, "does not verify")
	_, err = verifyPCSSignature(pcsDocument{Body: body, IssuerChain: chain}, "enclaveIdentity", nil, now())
	require.ErrorContains(t, err, "does not begin with")
	_, err = verifyPCSSignature(pcsDocument{Body: body, IssuerChain: []byte("junk")}, "tcbInfo", nil, now())
	require.ErrorContains(t, err, "issuer chain")
	_, err = verifyPCSSignature(pcsDocument{Body: body, IssuerChain: chain}, "tcbInfo", otherRootPEM(t), now())
	require.ErrorContains(t, err, "Intel root")

	// The client: cache first; a fetch when the cache is stale; a fetch
	// that fails, or serves a document that does not verify, is an error.
	dir := tdxCacheDir(t)
	fetched := 0
	prev := tdxPCSGet
	tdxPCSGet = func(u string) (pcsDocument, error) {
		fetched++
		require.Contains(t, u, "/tdx/certification/v4/tcb?fmspc=00806f050000")
		return pcsDocument{Body: body, IssuerChain: chain}, nil
	}
	t.Cleanup(func() { tdxPCSGet = prev })
	c := pcsClient{cache: pcsCache{dir: dir}, now: now}
	fmspc := [6]byte{0x00, 0x80, 0x6f, 0x05, 0, 0}
	_, err = c.tcbInfo(fmspc)
	require.NoError(t, err)
	require.Equal(t, 0, fetched, "served from the cache")
	later := pcsClient{cache: pcsCache{dir: dir}, now: func() time.Time { return tdxCaptureTime.AddDate(0, 2, 0) }}
	_, err = later.tcbInfo(fmspc)
	require.ErrorContains(t, err, "not current")
	require.Equal(t, 1, fetched, "the stale cache was refreshed from PCS, which served the same stale document")
	tdxPCSGet = func(u string) (pcsDocument, error) { return pcsDocument{Body: edited, IssuerChain: chain}, nil }
	empty := pcsClient{cache: pcsCache{dir: t.TempDir()}, now: now}
	_, err = empty.tcbInfo(fmspc)
	require.ErrorContains(t, err, "does not verify")
	tdxPCSGet = func(u string) (pcsDocument, error) { return pcsDocument{}, errors.New("PCS down") }
	_, err = empty.tcbInfo(fmspc)
	require.ErrorContains(t, err, "PCS down")
	_, err = empty.tcbInfo([6]byte{9, 9, 9, 9, 9, 9})
	require.Error(t, err)
	// A fresh fetch fills the cache for the next verifier.
	tdxPCSGet = func(u string) (pcsDocument, error) { return pcsDocument{Body: body, IssuerChain: chain}, nil }
	_, err = empty.tcbInfo(fmspc)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(empty.cache.dir, "tdx-tcb-00806f050000.json"))
	require.NoError(t, err)
}

// fakeTDXTSM answers configfs-tsm requests with the captured quotes: the
// one whose REPORTDATA matches the request, as the guest would.
type fakeTDXTSM struct {
	quotes [][]byte
	calls  int
}

func (f *fakeTDXTSM) report(reportData [64]byte, _ uint32) ([]byte, error) {
	f.calls++
	for _, q := range f.quotes {
		if bytes.Equal(q[48+520:48+584], reportData[:]) {
			return q, nil
		}
	}
	return nil, errors.New("fake TDX guest: no captured quote answers this REPORTDATA")
}

// The producer reads its measurement from a first quote and answers a
// challenge with a quote that binds it; the verifier accepts the pair.
func TestTDXProducerAndVerifierRoundTrip(t *testing.T) {
	noNetwork(t)
	q1, q2 := tdxEvidence(t, "q1.quote.bin"), tdxEvidence(t, "q2.quote.bin")
	// The producer's initial quote uses a fixed dummy nonce; the fake
	// guest answers it with quote 2 by fitting it with that REPORTDATA.
	dummy := make([]byte, NonceMinBytes)
	for i := range dummy {
		dummy[i] = byte(i)
	}
	prefix := computeReportDataPrefix(dummy)
	initial := append([]byte(nil), q2...)
	copy(initial[48+520:48+552], prefix[:])
	tsm := &fakeTDXTSM{quotes: [][]byte{initial, q1}}
	p, err := newGCPTDXProducer(GCPTDXProducerConfig{}, tsm)
	require.NoError(t, err)
	parsed, err := parseTDXQuote(q1)
	require.NoError(t, err)
	require.True(t, p.Measurement().Equal(tdxMeasurement(parsed.MRTD, parsed.RTMR)))
	require.Equal(t, parsed.MRTD, p.MRTD())
	require.Equal(t, parsed.RTMR, p.RTMRs())

	ev, err := p.Quote(Nonce(tdxCaptureNonce))
	require.NoError(t, err)
	v := tdxVerifier(t, p.Measurement())
	m, err := v.Verify(ev, Nonce(tdxCaptureNonce))
	require.NoError(t, err)
	require.True(t, m.Equal(p.Measurement()))

	_, err = p.Quote(Nonce("short"))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	_, err = p.Quote(Nonce("a challenge the fake guest has no quote for"))
	require.ErrorContains(t, err, "no captured quote")
	require.NoError(t, p.Close())
	_, err = p.Quote(Nonce(tdxCaptureNonce))
	require.ErrorContains(t, err, "closed")

	// A guest whose MRTD changed underneath the producer is refused.
	moved := append([]byte(nil), q1...)
	moved[48+136] ^= 1
	p2, err := newGCPTDXProducer(GCPTDXProducerConfig{}, &fakeTDXTSM{quotes: [][]byte{initial, moved}})
	require.NoError(t, err)
	_, err = p2.Quote(Nonce(tdxCaptureNonce))
	require.ErrorContains(t, err, "different MRTD")

	// No configfs-tsm here: the real constructor says so.
	_, err = NewGCPTDXProducer(GCPTDXProducerConfig{TSMReportDir: filepath.Join(t.TempDir(), "absent")})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "configfs-tsm"))
	if ok, _ := Capability(ProviderGCPTDX); ok {
		t.Log("this host has configfs-tsm")
	}
}
