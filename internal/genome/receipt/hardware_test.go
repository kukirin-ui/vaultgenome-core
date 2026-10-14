// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package receipt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// genuineReceiptRun is a restore on a real AMD SEV-SNP chip (GCP
// n2d-standard-2, us-central1-c): the destination restored a sealed
// genome with a released key and its chip signed this receipt.
const genuineReceiptRun = "../../../scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/evidence/20260914T223735Z"

// The receipt verifies offline, the way the source verified it: the
// report is signed by the chip's VCEK, the VCEK chains to AMD ARK-Milan,
// the guest policy is production, and REPORT_DATA binds these exact
// receipt bytes. Change one byte of the receipt and it no longer does.
func TestVerify_GenuineSEVSNPReceipt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(genuineReceiptRun, "receipt.json"))
	if err != nil {
		t.Skip("hardware evidence not present")
	}
	var s Signed
	require.NoError(t, json.Unmarshal(raw, &s))
	chain, err := os.ReadFile("../../../scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem")
	require.NoError(t, err)

	// The chip's VCEK is kept beside the evidence (a public certificate);
	// without it the verifier would fetch it from AMD KDS.
	cache := filepath.Join(genuineReceiptRun, "vcek-cache")
	if entries, _ := os.ReadDir(cache); len(entries) == 0 && testing.Short() {
		t.Skip("no cached VCEK and -short set (fetching it needs AMD KDS)")
	}

	claimed, err := Parse(s.Receipt)
	require.NoError(t, err)
	m, err := hex.DecodeString(claimed.DestinationMeasurement)
	require.NoError(t, err)
	v, err := tee.NewGCPSEVVerifier(nil, tee.Measurement(m), tee.GCPSEVVerifierConfig{AMDRootPEM: chain, VCEKCacheDir: cache})
	require.NoError(t, err)

	rc, got, err := Verify(s, v)
	require.NoError(t, err)
	require.Equal(t, tee.Measurement(m), got)
	require.Len(t, got, 48, "SEV-SNP launch measurement, SHA-384")
	require.Equal(t, "gcp-sev-snp", rc.DestinationKind)
	require.Equal(t, "1a0505a04b799eb297dc8079c06b0974174adea0c418efc9e3f1cab1cc87ad1f", rc.TreeSHA256)
	require.Equal(t, 3, rc.Files)

	edited := s
	edited.Receipt = bytes.Replace(s.Receipt, []byte(`"files":3`), []byte(`"files":4`), 1)
	require.NotEqual(t, s.Receipt, edited.Receipt)
	_, _, err = Verify(edited, v)
	require.ErrorContains(t, err, "does not verify", "the chip signed the receipt as it was")
}
