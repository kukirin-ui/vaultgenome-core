// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// azureHCLEvidence is the HCL report captured from a live Azure
// Confidential VM (scripts/hardware-test/azure-sev-snp/live-evidence).
func azureHCLEvidence(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", "hardware-test", "azure-sev-snp", "live-evidence", "hcl-report.b64"))
	if err != nil {
		t.Skip("azure live-evidence not present")
	}
	blob, err := base64.StdEncoding.DecodeString(string(raw))
	require.NoError(t, err)
	return blob
}

func TestHCLReportBindsTheRuntimeDataAndNamesTheAttestationKey(t *testing.T) {
	blob := azureHCLEvidence(t)
	h, err := parseHCLReport(blob)
	require.NoError(t, err)
	require.Len(t, h.SNP.Raw, sevReportLen)
	require.Equal(t, "Milan", sevProductName(h.SNP), "a DC4as_v5 is a Milan chip (CPUID family 0x19 model 0x01)")
	sum := sha256.Sum256(h.RuntimeData)
	require.Equal(t, sum[:], h.SNP.ReportData[:32])
	ak, err := h.attestationKey()
	require.NoError(t, err)
	require.Equal(t, 2048, ak.N.BitLen())
	require.Equal(t, 65537, ak.E)
	require.Equal(t, true, h.Runtime.VMConfiguration["secure-boot"])
	require.Equal(t, true, h.Runtime.VMConfiguration["tpm-enabled"])
}

func TestHCLReportRefusesWhatDoesNotBind(t *testing.T) {
	blob := azureHCLEvidence(t)

	// A byte of the runtime data changed: REPORT_DATA no longer names it.
	edited := append([]byte(nil), blob...)
	edited[hclHeaderLen+sevReportLen+hclRuntimeHeaderLen+10] ^= 0x01 // inside the JSON
	_, err := parseHCLReport(edited)
	require.ErrorContains(t, err, "not the SHA-256 of the runtime data")

	// Not an HCL report at all.
	_, err = parseHCLReport(append([]byte("XXXX"), blob[4:]...))
	require.ErrorContains(t, err, `does not start with "HCLA"`)

	// Too short.
	_, err = parseHCLReport(blob[:hclHeaderLen+sevReportLen])
	require.ErrorContains(t, err, "shorter than")

	// A runtime header of another kind.
	other := append([]byte(nil), blob...)
	other[hclHeaderLen+sevReportLen+8] = 9 // report type
	_, err = parseHCLReport(other)
	require.ErrorContains(t, err, "report type 9")
}

func TestRSAFromJWKRefusesWeakOrMalformedKeys(t *testing.T) {
	_, err := rsaFromJWK("AAAA", "AQAB")
	require.ErrorContains(t, err, "modulus")
	_, err = rsaFromJWK(base64.RawURLEncoding.EncodeToString(make([]byte, 256)), "AQ")
	require.ErrorContains(t, err, "exponent 1")
	_, err = rsaFromJWK("!!", "AQAB")
	require.Error(t, err)
}
