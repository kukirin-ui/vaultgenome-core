// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Proof that the REAL SEV-SNP verify path works on a GENUINE AZURE hardware
// report — the second cloud after GCP. The report under
// scripts/hardware-test/azure-sev-snp/live-evidence/ was extracted from a live
// Azure Confidential VM (Standard_DC4as_v5, AMD SEV-SNP, production) via the
// vTPM/HCL report at NV index 0x1400001. Azure mediates SNP through the
// paravisor + vTPM, so the raw AMD-signed report is embedded in the HCL blob;
// report.bin is the extracted 1184-byte SNP report (signing_key=VCEK,
// mask_chip_key=0). The report's REPORT_DATA binds the Azure runtime data
// (runtime-data.bin), not our own key — binding our key would run through the
// vTPM AK, a follow-up. This test proves the report chains to AMD ARK-Milan.
//
// VCEK + cert chain are fetched from AMD KDS on first run and cached next to the
// report for offline CI thereafter.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRealSEVSNP_VerifiesGenuineAzureReport(t *testing.T) {
	dir := "../../../scripts/hardware-test/azure-sev-snp/live-evidence"
	raw, err := os.ReadFile(filepath.Join(dir, "report.bin"))
	if err != nil {
		t.Skip("azure live-evidence not present; skipping real-hardware verification test")
	}

	// 1. Parse at fixed offsets; measurement + chip_id must be real.
	report, err := realParseSEVSNPReport(raw)
	require.NoError(t, err)
	require.Len(t, report.Measurement[:], 48, "SEV-SNP MEASUREMENT is 48 bytes (SHA-384)")
	require.False(t, isAllZero(report.Measurement[:]), "measurement must be non-zero")
	require.False(t, isAllZero(report.ChipID[:]), "CHIP_ID must be real (mask_chip_key=0, production)")

	// 2. VCEK + chain: cached (offline) or fetched live from AMD KDS.
	vcekPath := filepath.Join(dir, "vcek.bin")
	chainPath := filepath.Join(dir, "cert_chain.pem")
	vcek, err1 := os.ReadFile(vcekPath)
	chain, err2 := os.ReadFile(chainPath)
	if err1 != nil || err2 != nil {
		if testing.Short() {
			t.Skip("no cached VCEK/chain and -short set (live fetch needs network)")
		}
		vcek, err = realAMDKDSGetVCEK("", report.ChipID, report.ReportedTCB)
		require.NoError(t, err, "fetch VCEK from AMD KDS")
		chain, err = realAMDKDSGetCertChain("")
		require.NoError(t, err, "fetch cert chain from AMD KDS")
		require.NoError(t, os.WriteFile(vcekPath, vcek, 0o644))
		require.NoError(t, os.WriteFile(chainPath, chain, 0o644))
	}

	// 3. ECDSA-P384 signature under the VCEK.
	require.NoError(t, realVerifySEVReportSignature(report, vcek),
		"Azure report must verify under its genuine VCEK")

	// 4. VCEK -> ASK -> ARK-Milan chain.
	require.NoError(t, realVerifyAMDChain(vcek, chain),
		"Azure VCEK must chain to AMD ARK-Milan")
}
