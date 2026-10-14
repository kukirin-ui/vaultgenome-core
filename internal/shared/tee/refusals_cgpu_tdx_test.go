// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// hclWithRuntime keeps the fixture's SNP report but binds it to other
// runtime data, as the HCL does when the key set it reports changes.
func hclWithRuntime(base []byte, runtime []byte) []byte {
	report := append([]byte(nil), base[hclHeaderLen:hclHeaderLen+sevReportLen]...)
	sum := sha256.Sum256(runtime)
	copy(report[sevOffReportData:], sum[:])
	for i := 32; i < 64; i++ {
		report[sevOffReportData+i] = 0
	}
	var hcl []byte
	hcl = append(hcl, base[:hclHeaderLen]...)
	hcl = append(hcl, report...)
	rt := make([]byte, hclRuntimeHeaderLen)
	binary.LittleEndian.PutUint32(rt[0:], uint32(hclRuntimeHeaderLen+len(runtime)))
	binary.LittleEndian.PutUint32(rt[4:], hclRuntimeVersion)
	binary.LittleEndian.PutUint32(rt[8:], hclReportTypeSNP)
	binary.LittleEndian.PutUint32(rt[12:], hclHashTypeSHA256)
	binary.LittleEndian.PutUint32(rt[16:], uint32(len(runtime)))
	return append(append(hcl, rt...), runtime...)
}

func TestAzureCGPUVerifierRefusesMoreDefects(t *testing.T) {
	f := newAzureCGPUFixture(t)
	stubAMD(t, true)
	v := azureCGPUVerifier(t, f, nil)
	nonce := Nonce("a return-path challenge, thirty-two bytes")
	good := f.evidence(t, nonce)

	_, err := v.Verify(good, Nonce("short"))
	requireStructuralErr(t, err, "nonce too short")

	envelope := func(edit func(e *azureCGPUEvidence)) Evidence {
		var e azureCGPUEvidence
		require.NoError(t, json.Unmarshal(good, &e))
		edit(&e)
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		return Evidence(raw)
	}
	hclEdit := func(edit func(h []byte)) Evidence {
		return envelope(func(e *azureCGPUEvidence) {
			h := append([]byte(nil), e.HCLReport...)
			edit(h)
			e.HCLReport = h
		})
	}
	_, err = v.Verify(envelope(func(e *azureCGPUEvidence) { e.HCLReport = e.HCLReport[:10] }), nonce)
	requireIntegrityErr(t, err, "HCL report:")
	_, err = v.Verify(envelope(func(e *azureCGPUEvidence) { e.QuoteMessage = []byte("junk") }), nonce)
	requireIntegrityErr(t, err, "TPM quote:")
	_, err = v.Verify(envelope(func(e *azureCGPUEvidence) { e.GPUToken = json.RawMessage(`{}`) }), nonce)
	requireIntegrityErr(t, err, "GPU token:")
	_, err = v.Verify(hclEdit(func(h []byte) { binary.LittleEndian.PutUint32(h[hclHeaderLen+sevOffSigAlgo:], 2) }), nonce)
	requireIntegrityErr(t, err, "algorithm 2")
	_, err = v.Verify(hclEdit(func(h []byte) { binary.LittleEndian.PutUint32(h[hclHeaderLen+sevOffVMPL:], 1) }), nonce)
	requireIntegrityErr(t, err, "VMPL 1")
	strict := azureCGPUVerifier(t, f, func(c *AzureCGPUVerifierConfig) { c.MinReportedTCB = ^uint64(0) })
	_, err = strict.Verify(good, nonce)
	requireIntegrityErr(t, err, "ReportedTCB")
	noAK := []byte(`{"keys":[{"kid":"HCLEkPub","kty":"RSA","e":"AQAB","n":"AA","key_ops":["encrypt"]}],"vm-configuration":{},"user-data":""}`)
	_, err = v.Verify(envelope(func(e *azureCGPUEvidence) { e.HCLReport = hclWithRuntime(f.hcl, noAK) }), nonce)
	requireIntegrityErr(t, err, hclAKKeyID)

	fetch, chain := amdKDSGetVCEKFor, verifyAMDChain
	t.Cleanup(func() { amdKDSGetVCEKFor, verifyAMDChain = fetch, chain })
	amdKDSGetVCEKFor = func(string, string, [64]byte, uint64) ([]byte, error) { return nil, errors.New("kds unreachable") }
	fresh := azureCGPUVerifier(t, f, nil)
	_, err = fresh.Verify(good, nonce)
	requireIntegrityErr(t, err, "fetch VCEK")
	amdKDSGetVCEKFor = fetch
	verifyAMDChain = func([]byte, []byte) error { return errors.New("not AMD's") }
	_, err = fresh.Verify(good, nonce)
	requireIntegrityErr(t, err, "AMD chain (Genoa)")
	verifyAMDChain = chain

	parsed, err := parseHCLReport(f.hcl)
	require.NoError(t, err)
	dir := t.TempDir()
	key := fmt.Sprintf("%s-%x-%d", "genoa", parsed.SNP.ChipID, parsed.SNP.ReportedTCB)
	require.NoError(t, os.WriteFile(filepath.Join(dir, key+".der"), []byte("vcek-from-disk"), 0o600))
	amdKDSGetVCEKFor = func(string, string, [64]byte, uint64) ([]byte, error) { return nil, errors.New("must not be asked") }
	onDisk := azureCGPUVerifier(t, f, func(c *AzureCGPUVerifierConfig) { c.VCEKCacheDir = dir })
	_, err = onDisk.Verify(good, nonce)
	require.NoError(t, err, "a VCEK on disk is served without asking AMD")
	amdKDSGetVCEKFor = fetch

	m, detail, err := v.VerifyDetailed(good, nonce)
	require.NoError(t, err)
	require.True(t, m.Equal(f.measurement))
	require.Equal(t, ProviderAzureCGPU, detail.Provider)
	require.Equal(t, "Genoa", detail.Product)
	require.Equal(t, "sha256:0,1,2,3,4,5,6,7", detail.PCRSelection)
	require.Len(t, detail.GPUs, 1)
	require.NotEmpty(t, detail.ChipIDHex)
	_, _, err = v.VerifyDetailed(good, Nonce("short"))
	require.Error(t, err)

	_, err = NewAzureCGPUVerifier(nil, f.measurement, AzureCGPUVerifierConfig{AMDRootPEM: []byte("junk")})
	requireStructuralErr(t, err, "AMDRootPEM:")
	_, err = NewAzureCGPUVerifier(nil, f.measurement, AzureCGPUVerifierConfig{AMDRootPEM: f.chain, GPUEvaluation: GPUEvaluationOwn, NVIDIADeviceRootPEM: []byte("junk")})
	requireStructuralErr(t, err, "NVIDIA device root")
	_, err = NewAzureCGPUVerifier(nil, f.measurement, AzureCGPUVerifierConfig{AMDRootPEM: f.chain, GPUEvaluation: GPUEvaluationOwn, NVIDIARIMRootPEM: []byte("junk")})
	requireStructuralErr(t, err, "NVIDIA RIM root")
	_, err = NewAzureCGPUVerifier(nil, f.measurement, AzureCGPUVerifierConfig{AMDRootPEM: f.chain, GPUEvaluation: GPUEvaluationBoth, GPURevocation: "weird"})
	requireStructuralErr(t, err, "GPURevocation")
	withOCSP, err := NewAzureCGPUVerifier(nil, f.measurement, AzureCGPUVerifierConfig{AMDRootPEM: f.chain, GPUEvaluation: GPUEvaluationBoth})
	require.NoError(t, err)
	require.NotNil(t, withOCSP.gpuEval.OCSP, "revocation is checked unless switched off")

	own := azureCGPUVerifier(t, f, func(c *AzureCGPUVerifierConfig) {
		c.GPUEvaluation = GPUEvaluationOwn
		c.GPURevocation = GPURevocationOff
	})
	_, err = own.Verify(good, nonce)
	requireIntegrityErr(t, err, "no report to evaluate")
	both := azureCGPUVerifier(t, f, func(c *AzureCGPUVerifierConfig) {
		c.GPUEvaluation = GPUEvaluationBoth
		c.GPURevocation = GPURevocationOff
	})
	twoReports := envelope(func(e *azureCGPUEvidence) {
		e.GPUEvidence = []gpuEvidenceItem{{Report: []byte{1}, CertChain: []byte{1}}, {Report: []byte{1}, CertChain: []byte{1}}}
	})
	_, err = both.Verify(twoReports, nonce)
	requireIntegrityErr(t, err, "2 reports in the evidence, 1 GPUs")
}

func TestAzureCGPUProducerRefusesToolFailures(t *testing.T) {
	f := newAzureCGPUFixture(t)
	stubAMD(t, true)
	akPEM := pemPublicKey(t, &f.ak.PublicKey)
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	fail := map[string]error{}
	hclBytes, tokenBytes := f.hcl, []byte(nil)
	quoteSigner, quoteWrites := f.ak, true
	runCommand = func(_ time.Duration, argv ...string) ([]byte, error) {
		name := filepath.Base(argv[0])
		if err := fail[name]; err != nil {
			return nil, err
		}
		switch name {
		case "tpm2_nvread":
			return hclBytes, nil
		case "tpm2_getcap":
			return []byte("- 0x81000003\n"), nil
		case "tpm2_readpublic":
			return nil, os.WriteFile(argv[len(argv)-1], akPEM, 0o600)
		case "tpm2_quote":
			if !quoteWrites {
				return nil, nil
			}
			var msgPath, sigPath, q string
			for i := range argv {
				switch argv[i] {
				case "-m":
					msgPath = argv[i+1]
				case "-s":
					sigPath = argv[i+1]
				case "-q":
					q = argv[i+1]
				}
			}
			extra, _ := hex.DecodeString(q)
			digest := sha256.Sum256([]byte("pcrs"))
			msg := buildTPMQuote(extra, digest[:])
			sum := sha256.Sum256(msg)
			sig, err := rsa.SignPKCS1v15(rand.Reader, quoteSigner, crypto.SHA256, sum[:])
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(msgPath, msg, 0o600))
			return nil, os.WriteFile(sigPath, sig, 0o600)
		case "gpu-token":
			if tokenBytes != nil {
				return tokenBytes, nil
			}
			return f.nras.response(t, argv[len(argv)-1], f.now), nil
		}
		return nil, os.ErrNotExist
	}
	cfg := AzureCGPUProducerConfig{GPUAttestCommand: []string{"/usr/local/bin/gpu-token"}}

	fail["tpm2_nvread"] = errors.New("no NV index")
	_, err := NewAzureCGPUProducer(cfg)
	require.ErrorContains(t, err, "read the HCL report")
	delete(fail, "tpm2_nvread")
	hclBytes = []byte("junk")
	_, err = NewAzureCGPUProducer(cfg)
	require.ErrorContains(t, err, "HCL report:")
	hclBytes = f.hcl
	fail["tpm2_getcap"] = errors.New("tpm busy")
	_, err = NewAzureCGPUProducer(cfg)
	require.ErrorContains(t, err, "tpm busy")
	delete(fail, "tpm2_getcap")
	fail["tpm2_readpublic"] = errors.New("no such handle")
	_, err = NewAzureCGPUProducer(cfg)
	require.ErrorContains(t, err, "no persistent vTPM key")
	delete(fail, "tpm2_readpublic")
	fail["tpm2_quote"] = errors.New("quote refused")
	_, err = NewAzureCGPUProducer(cfg)
	require.ErrorContains(t, err, "initial TPM quote")
	delete(fail, "tpm2_quote")
	quoteWrites = false
	_, err = NewAzureCGPUProducer(cfg)
	require.ErrorContains(t, err, "initial TPM quote")
	quoteWrites = true
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	quoteSigner = other
	_, err = NewAzureCGPUProducer(cfg)
	require.ErrorContains(t, err, "does not verify under the attestation key")
	quoteSigner = f.ak

	pinned := cfg
	pinned.AKHandle = "0x81000003"
	p, err := NewAzureCGPUProducer(pinned)
	require.NoError(t, err)
	nonce := Nonce("a return-path challenge, thirty-two bytes")
	fail["gpu-token"] = errors.New("no GPU")
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "GPU attestation:")
	delete(fail, "gpu-token")
	tokenBytes = []byte("junk")
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "GPU attestation command output")
	tokenBytes = nil
	fail["tpm2_quote"] = errors.New("quote refused")
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "TPM quote")
	delete(fail, "tpm2_quote")
	_, err = p.Quote(Nonce("short"))
	requireStructuralErr(t, err, "nonce")
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	_, err = azureCGPUVerifier(t, f, nil).Verify(ev, nonce)
	require.NoError(t, err)
}

func TestIntelPCSDocumentsDecodeOnlyWhatTheVerifierReads(t *testing.T) {
	rootKey, root := selfSignedCA(t, "my root")
	signKey, signing := issuedCert(t, "TCB signing", root, rootKey, false, nil)
	rootPEM := certPEM(root.Raw)
	chainPEM := certPEM(signing.Raw, root.Raw)
	now := time.Now().UTC().Truncate(time.Second)
	dates := `"issueDate":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","nextUpdate":"` + now.Add(30*24*time.Hour).Format(time.RFC3339) + `"`
	sign := func(key, inner string, signer *ecdsa.PrivateKey, chain []byte) pcsDocument {
		h := sha256.Sum256([]byte(inner))
		r, s, err := ecdsa.Sign(rand.Reader, signer, h[:])
		require.NoError(t, err)
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return pcsDocument{Body: []byte(`{"` + key + `":` + inner + `,"signature":"` + hex.EncodeToString(sig) + `"}`), IssuerChain: chain}
	}
	inner := `{"id":"TDX","version":3,"fmspc":"00806F050000","pceId":"0000","tcbLevels":[{"tcb":{"pcesvn":1},"tcbStatus":"UpToDate"}],` + dates + `}`
	got, err := verifyPCSSignature(sign("tcbInfo", inner, signKey, chainPEM), "tcbInfo", rootPEM, now)
	require.NoError(t, err)
	require.Equal(t, inner, string(got))

	_, err = verifyPCSSignature(pcsDocument{Body: []byte(`{"tcbInfo":{}}`)}, "tcbInfo", rootPEM, now)
	require.ErrorContains(t, err, "carries no signature")
	_, err = verifyPCSSignature(pcsDocument{Body: []byte(`{"tcbInfo":{},"signature":"abcd`)}, "tcbInfo", rootPEM, now)
	require.ErrorContains(t, err, "not terminated")
	_, err = verifyPCSSignature(pcsDocument{Body: []byte(`{"tcbInfo":{},"signature":"zz"}`)}, "tcbInfo", rootPEM, now)
	require.ErrorContains(t, err, "not 64 hex")
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = verifyPCSSignature(sign("tcbInfo", inner, otherKey, chainPEM), "tcbInfo", rootPEM, now)
	require.ErrorContains(t, err, "does not verify")
	_, otherRoot := selfSignedCA(t, "other root")
	_, err = verifyPCSSignature(sign("tcbInfo", inner, signKey, chainPEM), "tcbInfo", certPEM(otherRoot.Raw), now)
	require.ErrorContains(t, err, "Intel root")
	key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "P-384 signer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der384, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key384.PublicKey, rootKey)
	require.NoError(t, err)
	_, err = verifyPCSSignature(sign("tcbInfo", inner, signKey, certPEM(der384, root.Raw)), "tcbInfo", rootPEM, now)
	require.ErrorContains(t, err, "not ECDSA P-256")

	prev := tdxPCSGet
	t.Cleanup(func() { tdxPCSGet = prev })
	var served pcsDocument
	tdxPCSGet = func(string) (pcsDocument, error) { return served, nil }
	client := func() pcsClient {
		return pcsClient{cache: pcsCache{dir: t.TempDir()}, rootOverride: rootPEM, now: func() time.Time { return now }}
	}
	fmspc := [6]byte{0x00, 0x80, 0x6f, 0x05, 0, 0}
	served = sign("tcbInfo", `{"id":"TDX","version":3,"fmspc":"00806F050000","tcbLevels":[{"tcbStatus":"UpToDate"}],"issueDate":"2026-01-01T00:00:00Z","nextUpdate":"2026-02-01T00:00:00Z"}`, signKey, chainPEM)
	_, err = client().tcbInfo(fmspc)
	require.ErrorContains(t, err, "not current", "a document past its nextUpdate is refused even when it verifies")
	for _, row := range []struct{ inner, fragment string }{
		{`{"id":5,` + dates + `}`, "does not decode"},
		{`{"id":"SGX",` + dates + `}`, `is for "SGX"`},
		{`{"id":"TDX","version":2,` + dates + `}`, "version 2"},
		{`{"id":"TDX","version":3,"fmspc":"ffffffffffff",` + dates + `}`, "is for FMSPC"},
		{`{"id":"TDX","version":3,"fmspc":"00806f050000",` + dates + `}`, "lists no TCB levels"},
	} {
		served = sign("tcbInfo", row.inner, signKey, chainPEM)
		_, err := client().tcbInfo(fmspc)
		require.ErrorContains(t, err, row.fragment, row.inner)
	}
	served = sign("tcbInfo", inner, signKey, chainPEM)
	info, err := client().tcbInfo(fmspc)
	require.NoError(t, err)
	require.Equal(t, "00806F050000", info.FMSPC)
	for _, row := range []struct{ inner, fragment string }{
		{`{"id":5,` + dates + `}`, "does not decode"},
		{`{"id":"SGX_QE",` + dates + `}`, `is for "SGX_QE"`},
		{`{"id":"TD_QE","version":1,` + dates + `}`, "version 1"},
		{`{"id":"TD_QE","version":2,` + dates + `}`, "lists no TCB levels"},
	} {
		served = sign("enclaveIdentity", row.inner, signKey, chainPEM)
		_, err := client().qeIdentity()
		require.ErrorContains(t, err, row.fragment, row.inner)
	}
	served = sign("enclaveIdentity", `{"id":"TD_QE","version":2,"tcbLevels":[{"tcb":{"isvsvn":1},"tcbStatus":"UpToDate"}],`+dates+`}`, signKey, chainPEM)
	qe, err := client().qeIdentity()
	require.NoError(t, err)
	require.Equal(t, "TD_QE", qe.ID)
}

func TestVTPMSealerRefusesOddToolOutput(t *testing.T) {
	realInput, realRun := runCommandInput, runCommand
	f := newFakeVTPM(t)
	s, err := NewVTPMSealer(VTPMSealerConfig{PCRs: "sha256:0,1,2,3,4,5,6,7"})
	require.NoError(t, err)
	aad := []byte("aad")
	sealed, err := s.Seal([]byte("secret"), aad)
	require.NoError(t, err)

	inner := runCommandInput
	runCommandInput = func(timeout time.Duration, stdin []byte, argv ...string) ([]byte, error) {
		if filepath.Base(argv[0]) == "tpm2_create" {
			for i := range argv {
				if argv[i] == "-u" || argv[i] == "-r" {
					require.NoError(t, os.WriteFile(argv[i+1], nil, 0o600))
				}
			}
			return nil, nil
		}
		return inner(timeout, stdin, argv...)
	}
	_, err = s.Seal([]byte("secret"), aad)
	require.ErrorContains(t, err, "empty sealed object")
	runCommandInput = inner

	run := runCommand
	runCommand = func(timeout time.Duration, argv ...string) ([]byte, error) {
		if filepath.Base(argv[0]) == "tpm2_unseal" {
			return []byte("short"), nil
		}
		return run(timeout, argv...)
	}
	_, err = s.Unseal(sealed, aad)
	requireIntegrityErr(t, err, "returned 5 bytes")
	runCommand = run
	require.NotEmpty(t, f.calls)

	var blob vtpmSealedBlob
	require.NoError(t, json.Unmarshal(sealed, &blob))
	blob.Box[len(blob.Box)-1] ^= 1
	tampered, err := json.Marshal(blob)
	require.NoError(t, err)
	_, err = s.Unseal(tampered, aad)
	requireIntegrityErr(t, err, "AEAD open")
	_, err = s.Unseal(sealed, []byte("other"))
	requireIntegrityErr(t, err, "AEAD open")

	out, err := realInput(5*time.Second, []byte("ping"), "/bin/cat")
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), out)
	_, err = realInput(5*time.Second, nil, "/bin/sh", "-c", "echo bad >&2; exit 3")
	require.ErrorContains(t, err, "bad")
	_, err = realRun(5*time.Second, "/bin/sh", "-c", "echo worse >&2; exit 2")
	require.ErrorContains(t, err, "worse")
}

func TestPCKExtensionParserRefusesEachMalformedExtension(t *testing.T) {
	type pair struct {
		OID   asn1.ObjectIdentifier
		Value []byte
	}
	type intPair struct {
		OID   asn1.ObjectIdentifier
		Value int
	}
	type tcbPair struct {
		OID   asn1.ObjectIdentifier
		Comps []intPair
	}
	type oddPair struct {
		OID   asn1.ObjectIdentifier
		Comps []pair
	}
	tcbOID := func(i int) asn1.ObjectIdentifier { return append(append(asn1.ObjectIdentifier(nil), oidSGXTCB...), i) }
	elem := func(v any) []byte {
		b, err := asn1.Marshal(v)
		require.NoError(t, err)
		return b
	}
	seq := func(elems ...[]byte) []byte {
		b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(elems, nil)})
		require.NoError(t, err)
		return b
	}
	cert := func(ext []byte) *x509.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "PCK"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: oidSGXExtension, Value: ext}}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		return parseDER(t, der)
	}
	fmspcOK := elem(pair{oidSGXFMSPC, []byte{0, 0x80, 0x6f, 5, 0, 0}})
	pceOK := elem(pair{oidSGXPCEID, []byte{0, 0}})
	tcbOK := elem(tcbPair{oidSGXTCB, []intPair{{tcbOID(1), 3}, {tcbOID(16), 4}, {tcbOID(17), 11}}})

	p, err := parsePCKExtension(cert(seq(fmspcOK, pceOK, tcbOK)))
	require.NoError(t, err)
	require.Equal(t, [6]byte{0, 0x80, 0x6f, 5, 0, 0}, p.FMSPC)
	require.Equal(t, uint8(3), p.CPUSVNs[0])
	require.Equal(t, uint8(4), p.CPUSVNs[15])
	require.Equal(t, uint16(11), p.PCESVN)
	withCPUSVN := elem(tcbPair{oidSGXTCB, []intPair{{tcbOID(1), 3}}})
	octet := elem(oddPair{oidSGXTCB, []pair{{tcbOID(18), bytes.Repeat([]byte{1}, 16)}, {tcbOID(17), []byte{1}}}})
	_ = withCPUSVN
	_, err = parsePCKExtension(cert(seq(fmspcOK, pceOK, octet)))
	require.ErrorContains(t, err, "component 17 does not parse", "an octet string is only tolerated for CPUSVN (18)")

	rows := []struct {
		name     string
		ext      []byte
		fragment string
	}{
		{"not a sequence", []byte{1, 2, 3}, "does not parse"},
		{"FMSPC of 5 bytes", seq(elem(pair{oidSGXFMSPC, make([]byte, 5)}), pceOK, tcbOK), "FMSPC is not 6 bytes"},
		{"PCE-ID of 3 bytes", seq(fmspcOK, elem(pair{oidSGXPCEID, make([]byte, 3)}), tcbOK), "PCE-ID is not 2 bytes"},
		{"TCB not a sequence", seq(fmspcOK, pceOK, elem(pair{oidSGXTCB, []byte{1}})), "SGX TCB extension does not parse"},
		{"TCB without FMSPC", seq(pceOK, tcbOK), "lacks"},
		{"only the CPUSVN octet", seq(fmspcOK, pceOK, elem(oddPair{oidSGXTCB, []pair{{tcbOID(18), make([]byte, 16)}}})), ""},
	}
	for _, row := range rows {
		_, err := parsePCKExtension(cert(row.ext))
		if row.fragment == "" {
			require.NoError(t, err, row.name)
			continue
		}
		require.Error(t, err, row.name)
		require.ErrorContains(t, err, row.fragment, row.name)
	}
}

func TestTDXQuoteSignatureChecksRefuseEachForgery(t *testing.T) {
	raw := tdxEvidence(t, "q1.quote.bin")
	q, err := parseTDXQuote(raw)
	require.NoError(t, err)
	expected := tdxMeasurement(q.MRTD, q.RTMR)
	noNetwork(t)
	v := tdxVerifier(t, expected)
	nonce := Nonce(tdxCaptureNonce)
	sd := tdxMinQuoteLen
	cd := sd + 134
	authLen := int(binary.LittleEndian.Uint16(raw[cd+448:]))

	rows := []struct {
		name     string
		edit     func(b []byte) []byte
		fragment string
	}{
		{"attestation key off the curve", func(b []byte) []byte { copy(b[sd+64:sd+128], make([]byte, 64)); return b }, "not a point"},
		{"TD report edited", func(b []byte) []byte { b[tdxHeaderLen+520] ^= 1; return b }, "does not verify under the quote's attestation key"},
		{"QE report signature edited", func(b []byte) []byte { b[cd+sgxReportBodyLen] ^= 1; return b }, "QE report's signature does not verify"},
		{"PCK chain mangled", func(b []byte) []byte {
			tail := bytes.ReplaceAll(b[cd:], []byte("BEGIN CERTIFICATE"), []byte("BEGIN CERTIFICATF"))
			require.NotEqual(t, b[cd:], tail)
			copy(b[cd:], tail)
			return b
		}, "PCK chain:"},
	}
	if authLen > 0 {
		rows = append(rows, struct {
			name     string
			edit     func(b []byte) []byte
			fragment string
		}{"QE authentication data edited", func(b []byte) []byte { b[cd+450] ^= 1; return b }, "does not certify"})
	}
	for _, row := range rows {
		_, err := v.VerifyQuote(Evidence(row.edit(append([]byte(nil), raw...))), nonce)
		require.Error(t, err, row.name)
		require.ErrorContains(t, err, row.fragment, row.name)
	}

	onlyTCB := t.TempDir()
	for _, f := range [][2]string{{"tcb-info.json", "tdx-tcb-00806f050000.json"}, {"tcb-info.json.issuer-chain.pem", "tdx-tcb-00806f050000.issuer-chain.pem"}} {
		require.NoError(t, os.WriteFile(filepath.Join(onlyTCB, f[1]), tdxEvidence(t, f[0]), 0o644))
	}
	noQE := tdxVerifier(t, expected, func(c *GCPTDXVerifierConfig) { c.PCSCacheDir = onlyTCB })
	_, err = noQE.VerifyQuote(Evidence(raw), nonce)
	requireIntegrityErr(t, err, "QE identity:")
	empty := tdxVerifier(t, expected, func(c *GCPTDXVerifierConfig) { c.PCSCacheDir = t.TempDir() })
	_, err = empty.VerifyQuote(Evidence(raw), nonce)
	requireIntegrityErr(t, err, "TCB info:")
}
