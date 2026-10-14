// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func capturedRIM(t *testing.T, id string) *RIM {
	t.Helper()
	raw, err := os.ReadFile("testdata/nvidia/rim-" + id + ".json")
	if err != nil {
		t.Skip("captured manifest not present: " + id)
	}
	rim, err := ParseRIMResponse(raw)
	require.NoError(t, err)
	return rim
}

// NVIDIA's captured manifests verify: Canonical XML 1.1 of the tag with
// the signature removed, ECDSA-SHA384 under the signing certificate the
// manifest carries — and a manifest touched anywhere does not.
func TestRIM_SignaturesVerifyAndRefuseATouchedManifest(t *testing.T) {
	driver := capturedRIM(t, "NV_GPU_DRIVER_GH100_595.71.05")
	vbios := capturedRIM(t, "NV_GPU_VBIOS_1010_0210_886_96009F0004")
	for _, rim := range []*RIM{driver, vbios} {
		require.Equal(t, "http://www.w3.org/2006/12/xml-c14n11", rim.CanonicalizationMethod)
		require.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", rim.SignatureAlgorithm)
		require.NoError(t, VerifyRIMSignature(rim, captureTime), rim.ID)
	}

	// One hex digit of one golden measurement changed: the digest over the
	// canonical bytes no longer matches the signed one.
	raw := driver.Raw
	i := bytes.Index(raw, []byte(`Hash0="`))
	require.Greater(t, i, 0)
	touched := append([]byte(nil), raw...)
	j := i + len(`Hash0="`) + 3
	if touched[j] == 'a' {
		touched[j] = 'b'
	} else {
		touched[j] = 'a'
	}
	rim, err := ParseRIM(touched)
	require.NoError(t, err, "the touched manifest still parses")
	err = VerifyRIMSignature(rim, captureTime)
	require.ErrorContains(t, err, "signature does not verify")

	// Another certificate as the trusted one: the VBIOS manifest's signer
	// does not vouch for the driver's manifest.
	swapped := *driver
	swapped.Certs = vbios.Certs
	if !vbios.Certs[0].Equal(driver.Certs[0]) {
		require.Error(t, VerifyRIMSignature(&swapped, captureTime))
	}

	// Only what NVIDIA signs with is admitted.
	rsa := *driver
	rsa.SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	require.ErrorContains(t, VerifyRIMSignature(&rsa, captureTime), "ECDSA-SHA384")
	c10 := *driver
	c10.CanonicalizationMethod = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	require.ErrorContains(t, VerifyRIMSignature(&c10, captureTime), "Canonical XML 1.1")
	require.Error(t, VerifyRIMSignature(&RIM{}, captureTime))
}

// The evaluation's completeness now includes both signatures.
func TestGPUEvaluation_CompleteRequiresTheManifestSignatures(t *testing.T) {
	t.Parallel()
	e := GPUEvaluation{ReportParsed: true, NonceMatch: true, ChainVerified: true, FWIDMatch: true, SignatureVerified: true, MeasurementsMatch: true,
		DriverRIM: RIMStatus{Fetched: true, VersionMatch: true, ChainVerified: true, SignatureVerified: true},
		VBIOSRIM:  RIMStatus{Fetched: true, VersionMatch: true, ChainVerified: true, SignatureVerified: true}}
	require.True(t, e.Complete())
	require.True(t, e.RIMSignaturesVerified())
	e.VBIOSRIM.SignatureVerified = false
	require.False(t, e.Complete())
	require.False(t, e.RIMSignaturesVerified())
}
