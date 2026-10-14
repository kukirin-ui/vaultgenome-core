// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The capture of an Azure NCC H100 v5 (scripts/hardware-test/azure-cgpu,
// run 20260916T133506Z): the report the driver handed out for nonce 1,
// the GPU's certificate chain, and the two manifests NVIDIA's RIM
// service returned for that driver and VBIOS (testdata/nvidia).
const capturedAzureCGPUDir = "../../../scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z"

const (
	capturedDriverRIM = "NV_GPU_DRIVER_GH100_595.71.05"
	capturedVBIOSRIM  = "NV_GPU_VBIOS_1010_0210_886_96009F0004"
)

func readEvidence(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(capturedAzureCGPUDir, name))
	if err != nil {
		t.Skipf("captured evidence not available: %v", err)
	}
	return raw
}

func capturedNonce(t *testing.T) []byte {
	t.Helper()
	for _, line := range strings.Split(string(readEvidence(t, "nonces.txt")), "\n") {
		if strings.HasPrefix(line, "nonce_1=") {
			n, err := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "nonce_1=")))
			require.NoError(t, err)
			return n
		}
	}
	t.Fatal("no nonce_1 in nonces.txt")
	return nil
}

func pemCert(t *testing.T, pemText string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	require.NotNil(t, block)
	c, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return c
}

// nvidiaRoots are the roots pinned in the binary (nvidia_roots.go): the
// NVIDIA Device Identity CA and the NVIDIA CoRIM signing Root CA.
func nvidiaRoots(t *testing.T) (device, rim *x509.Certificate) {
	t.Helper()
	return pemCert(t, NVIDIADeviceRootPEM), pemCert(t, NVIDIARIMRootPEM)
}

// captureTime is a moment the captured chain and manifests were valid at.
var captureTime = time.Date(2026, 9, 16, 14, 0, 0, 0, time.UTC)

func capturedReport(t *testing.T) (*GPUReport, []*x509.Certificate) {
	t.Helper()
	rep, err := ParseGPUReport(readEvidence(t, "gpu0-attestation-report.bin"))
	require.NoError(t, err)
	chain, err := ParseGPUCertChain(readEvidence(t, "gpu0-cert-chain.pem"))
	require.NoError(t, err)
	return rep, chain
}

func TestGPUReport_ParsesTheCapturedH100Report(t *testing.T) {
	rep, chain := capturedReport(t)
	require.Len(t, rep.Blocks, 64)
	for i := 1; i <= 64; i++ {
		require.Len(t, rep.Blocks[i], 48, "block %d is a SHA-384", i)
	}
	require.Equal(t, capturedNonce(t), rep.RequestNonce)
	require.Len(t, rep.ResponseNonce, 32)
	require.Equal(t, "595.71.05", rep.DriverVersion())
	v, err := rep.VBIOSVersion()
	require.NoError(t, err)
	require.Equal(t, "96.00.9F.00.04", v, "formatted the way NVIDIA's claims print it")
	require.Equal(t, capturedDriverRIM, rep.DriverRIMID())
	id, err := rep.VBIOSRIMID()
	require.NoError(t, err)
	require.Equal(t, capturedVBIOSRIM, id)
	require.Len(t, rep.FWID(), 48)
	require.Equal(t, 1, rep.OpaqueDataVersion())
	require.True(t, rep.NVDEC0Disabled(), "an H100 in confidential-computing mode runs with NVDEC0 disabled (opaque field 11 = 0x55)")
	require.Len(t, chain, 5)
	require.Equal(t, "GH100 A01 GSP FMC LF", chain[0].Subject.CommonName)
	require.Equal(t, "NVIDIA Device Identity CA", chain[4].Subject.CommonName)

	// The manifests count from 0 where the SPDM blocks count from 1.
	m, ok := rep.Measurement(1)
	require.True(t, ok)
	require.Equal(t, rep.Blocks[2], m)
}

func TestGPUReport_SignatureUnderTheGPUsCertificate(t *testing.T) {
	rep, chain := capturedReport(t)
	require.NoError(t, rep.VerifySignature(chain[0]))
	require.Error(t, rep.VerifySignature(chain[1]), "another certificate's key does not verify it")

	raw := readEvidence(t, "gpu0-attestation-report.bin")
	tampered := append([]byte(nil), raw...)
	tampered[60] ^= 0x01 // inside the first measurement's value
	rep2, err := ParseGPUReport(tampered)
	require.NoError(t, err, "the structure still parses")
	require.ErrorContains(t, rep2.VerifySignature(chain[0]), "does not verify")

	badSig := append([]byte(nil), raw...)
	badSig[len(badSig)-1] ^= 0x01
	rep3, err := ParseGPUReport(badSig)
	require.NoError(t, err)
	require.Error(t, rep3.VerifySignature(chain[0]))
}

func TestGPUReport_ChainToThePinnedNVIDIARootAndFirmwareID(t *testing.T) {
	rep, chain := capturedReport(t)
	device, rimRoot := nvidiaRoots(t)
	require.NoError(t, VerifyGPUCertChain(chain, device, captureTime))
	require.ErrorContains(t, VerifyGPUCertChain(chain, rimRoot, captureTime), "pinned NVIDIA device root")
	require.Error(t, VerifyGPUCertChain(chain[:2], device, captureTime), "a chain cut short does not reach the root")

	fwid, err := LeafFWID(chain[0])
	require.NoError(t, err)
	require.Equal(t, rep.FWID(), fwid, "the certificate binds the firmware the report names")
	_, err = LeafFWID(chain[1])
	require.ErrorContains(t, err, "no DICE")
}

func TestGPUReport_RefusesWhatIsNotAReport(t *testing.T) {
	raw := readEvidence(t, "gpu0-attestation-report.bin")
	for name, mutate := range map[string]func([]byte) []byte{
		"too short":           func(b []byte) []byte { return b[:50] },
		"not a request":       func(b []byte) []byte { c := append([]byte(nil), b...); c[1] = 0x61; return c },
		"not a response":      func(b []byte) []byte { c := append([]byte(nil), b...); c[38] = 0x61; return c },
		"record overflow":     func(b []byte) []byte { c := append([]byte(nil), b...); c[43] = 0xff; return c },
		"not DMTF":            func(b []byte) []byte { c := append([]byte(nil), b...); c[46] = 2; return c },
		"signature truncated": func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseGPUReport(mutate(raw))
			require.Error(t, err)
		})
	}
	_, err := ParseGPUCertChain([]byte("not pem"))
	require.Error(t, err)
}

func TestFormatVBIOSVersion(t *testing.T) {
	raw, err := hex.DecodeString("009f009604000000")
	require.NoError(t, err)
	v, err := FormatVBIOSVersion(raw)
	require.NoError(t, err)
	require.Equal(t, "96.00.9F.00.04", v)
	_, err = FormatVBIOSVersion(raw[:4])
	require.Error(t, err)
}

func capturedRIMs(t *testing.T) (driver, vbios *RIM) {
	t.Helper()
	d, err := os.ReadFile("testdata/nvidia/rim-" + capturedDriverRIM + ".json")
	require.NoError(t, err)
	driver, err = ParseRIMResponse(d)
	require.NoError(t, err)
	v, err := os.ReadFile("testdata/nvidia/rim-" + capturedVBIOSRIM + ".json")
	require.NoError(t, err)
	vbios, err = ParseRIMResponse(v)
	require.NoError(t, err)
	return driver, vbios
}

func TestRIM_ParsesNVIDIAsManifests(t *testing.T) {
	driver, vbios := capturedRIMs(t)
	require.Equal(t, capturedDriverRIM, driver.ID)
	require.Equal(t, "595.71.05", driver.ColloquialVersion)
	require.Equal(t, "96.00.9F.00.04", vbios.ColloquialVersion)
	require.Equal(t, "GH100", driver.Product)
	require.Equal(t, "5703", driver.ManufacturerID)
	require.Len(t, driver.Measurements, 64)
	require.Len(t, vbios.Measurements, 64)
	require.NotEmpty(t, driver.Certs)
	require.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", driver.SignatureAlgorithm)
	require.Equal(t, "http://www.w3.org/2006/12/xml-c14n11", driver.CanonicalizationMethod)
	m := vbios.Measurements[1]
	require.True(t, m.Active)
	require.Equal(t, 48, m.Size)
	require.Len(t, m.Values, 1)

	_, rimRoot := nvidiaRoots(t)
	device, _ := nvidiaRoots(t)
	require.NoError(t, VerifyRIMCertChain(driver, rimRoot, captureTime))
	require.NoError(t, VerifyRIMCertChain(vbios, rimRoot, captureTime))
	require.Error(t, VerifyRIMCertChain(driver, device, captureTime), "the device root does not sign manifests")

	// The service's SHA-256 binds the manifest's bytes.
	d, err := os.ReadFile("testdata/nvidia/rim-" + capturedDriverRIM + ".json")
	require.NoError(t, err)
	tampered := strings.Replace(string(d), `"sha256":"`, `"sha256":"00`, 1)
	if tampered == string(d) {
		tampered = strings.Replace(string(d), `"sha256": "`, `"sha256": "00`, 1)
	}
	_, err = ParseRIMResponse([]byte(tampered))
	require.ErrorContains(t, err, "SHA-256")
	_, err = ParseRIM([]byte("<other/>"))
	require.Error(t, err)
}

func TestRIM_GoldenMeasurementsMatchTheCapturedReport(t *testing.T) {
	rep, _ := capturedReport(t)
	driver, vbios := capturedRIMs(t)
	golden, err := GoldenMeasurements(driver, vbios)
	require.NoError(t, err)
	require.NotEmpty(t, golden)
	missed, err := CompareMeasurements(rep, golden)
	require.NoError(t, err)
	require.Empty(t, missed, "the H100 runs the firmware and driver NVIDIA published golden values for")

	// One runtime measurement changed: that index misses.
	idx := -1
	for i := range golden {
		if i != 35 && golden[i].Active {
			idx = i
			break
		}
	}
	require.GreaterOrEqual(t, idx, 0)
	rep.Blocks[idx+1] = append([]byte(nil), rep.Blocks[idx+1]...)
	rep.Blocks[idx+1][0] ^= 0x01
	missed, err = CompareMeasurements(rep, golden)
	require.NoError(t, err)
	require.Equal(t, []int{idx}, missed)

	// A driver manifest and a VBIOS manifest binding the same index conflict.
	conflict := &RIM{Measurements: map[int]RIMMeasurement{}}
	for i, m := range driver.Measurements {
		conflict.Measurements[i] = m
	}
	_, err = GoldenMeasurements(driver, conflict)
	require.ErrorContains(t, err, "both bind")

	// Index 35 is bound only while NVDEC0 is enabled: this GPU runs with it
	// disabled, so a changed measurement 35 is not held against it — and
	// would be with the engine enabled.
	rep2, _ := capturedReport(t)
	if g, ok := golden[35]; ok && g.Active {
		rep2.Blocks[36] = make([]byte, 48)
		missed, err = CompareMeasurements(rep2, golden)
		require.NoError(t, err)
		require.Empty(t, missed)
		rep2.Opaque[opaqueNVDEC0Status] = []byte{0xAA}
		missed, err = CompareMeasurements(rep2, golden)
		require.NoError(t, err)
		require.Equal(t, []int{35}, missed)
	}
}

// rimServer serves the two captured manifests the way NVIDIA's RIM
// service does, counting requests.
func rimServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		id := strings.TrimPrefix(r.URL.Path, "/v1/rim/")
		raw, err := os.ReadFile("testdata/nvidia/rim-" + id + ".json")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestRIMFetcher_FetchesAndCaches(t *testing.T) {
	srv, hits := rimServer(t)
	dir := t.TempDir()
	f := &RIMFetcher{BaseURL: srv.URL + "/v1/rim/", CacheDir: dir, Client: srv.Client()}
	rim, err := f.Fetch(context.Background(), capturedDriverRIM)
	require.NoError(t, err)
	require.Equal(t, "595.71.05", rim.ColloquialVersion)
	require.Equal(t, 1, *hits)
	require.FileExists(t, filepath.Join(dir, capturedDriverRIM+".json"))
	srv.Close()
	rim, err = f.Fetch(context.Background(), capturedDriverRIM)
	require.NoError(t, err, "served from the cache with the service gone")
	require.Equal(t, "595.71.05", rim.ColloquialVersion)
	require.Equal(t, 1, *hits)
	_, err = f.Fetch(context.Background(), "NV_GPU_DRIVER_GH100_0.0.0")
	require.Error(t, err)
	_, err = f.Fetch(context.Background(), "../etc")
	require.Error(t, err)
}

func TestGPUEvaluator_EvaluatesTheCapturedH100(t *testing.T) {
	srv, _ := rimServer(t)
	device, rimRoot := nvidiaRoots(t)
	ev := &GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: func() time.Time { return captureTime },
		RIMs: &RIMFetcher{BaseURL: srv.URL + "/v1/rim/", CacheDir: t.TempDir(), Client: srv.Client()}}
	report, chain, nonce := readEvidence(t, "gpu0-attestation-report.bin"), readEvidence(t, "gpu0-cert-chain.pem"), capturedNonce(t)

	e := ev.Evaluate(context.Background(), report, chain, nonce)
	require.Empty(t, e.Errors)
	require.True(t, e.Complete(), "%+v", e)
	require.True(t, e.RIMSignaturesVerified(), "both manifests' XML signatures verified under their certificates chained to NVIDIA's CoRIM root")
	require.Equal(t, "595.71.05", e.DriverVersion)
	require.Equal(t, "96.00.9F.00.04", e.VBIOSVersion)
	require.Equal(t, "GH100", e.HWModel, "the model NVIDIA's per-model identity CA names, as NVIDIA's tokens do")
	require.NotEmpty(t, e.UEID)
	require.Equal(t, capturedDriverRIM, e.DriverRIM.ID)
	require.Equal(t, capturedVBIOSRIM, e.VBIOSRIM.ID)
	require.True(t, e.DriverRIM.ChainVerified && e.VBIOSRIM.ChainVerified)
	require.Equal(t, 64, e.DriverRIM.Measurements)

	// Another nonce: the report was not taken for it.
	other := append([]byte(nil), nonce...)
	other[0] ^= 0x01
	e = ev.Evaluate(context.Background(), report, chain, other)
	require.False(t, e.NonceMatch)
	require.False(t, e.Complete())
	require.True(t, e.SignatureVerified && e.MeasurementsMatch, "the rest still holds, and is on the record")

	// The manifests unreachable: fetched false, the evaluation incomplete.
	off := &GPUEvaluator{DeviceRoot: device, RIMRoot: rimRoot, Now: ev.Now,
		RIMs: &RIMFetcher{BaseURL: "http://127.0.0.1:1/v1/rim/", CacheDir: t.TempDir(), Client: &http.Client{Timeout: time.Second}}}
	e = off.Evaluate(context.Background(), report, chain, nonce)
	require.False(t, e.DriverRIM.Fetched)
	require.False(t, e.Complete())
	require.True(t, e.SignatureVerified && e.ChainVerified)

	// The wrong device root: the chain does not verify.
	wrong := &GPUEvaluator{DeviceRoot: rimRoot, RIMRoot: rimRoot, Now: ev.Now, RIMs: ev.RIMs}
	e = wrong.Evaluate(context.Background(), report, chain, nonce)
	require.False(t, e.ChainVerified)
	require.False(t, e.Complete())

	// Not a report at all.
	e = ev.Evaluate(context.Background(), []byte("junk"), chain, nonce)
	require.False(t, e.ReportParsed)
	require.NotEmpty(t, e.Errors)
}
