// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Proof that the REAL SEV-SNP verify path works on a GENUINE hardware report.
// The fixtures under scripts/hardware-test/gcp-sev-snp/keybind-evidence/ were
// captured on a live Google Confidential VM (AMD Milan, production mode) that
// generated an X25519 key inside the enclave and bound its public key into the
// report via REPORT_DATA = SHA-512(pubkey || challenger-nonce). This test runs
// fully offline against those committed bytes — no hardware, no network.

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func genuineEvidenceDir(t *testing.T) string {
	t.Helper()
	matches, err := filepath.Glob("../../../scripts/hardware-test/gcp-sev-snp/keybind-evidence/*/report-vaultgenome.bin")
	require.NoError(t, err)
	if len(matches) == 0 {
		t.Skip("genuine keybind-evidence not present; skipping real-hardware verification test")
	}
	return filepath.Dir(matches[0])
}

func TestRealSEVSNP_VerifiesGenuineHardwareReport(t *testing.T) {
	dir := genuineEvidenceDir(t)
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err, name)
		return b
	}

	raw := read("report-vaultgenome.bin")
	vcek := read("cert-VCEK.bin")
	chain := read("kds-vcek-cert_chain.pem")
	pub := read("x25519-pub.der")
	nonceHex := strings.TrimSpace(string(read("vg-nonce.hex")))
	nonce, err := hex.DecodeString(nonceHex)
	require.NoError(t, err)

	// 1. Parse the report at fixed offsets.
	report, err := realParseSEVSNPReport(raw)
	require.NoError(t, err)
	require.Len(t, report.Measurement[:], 48, "SEV-SNP MEASUREMENT is 48 bytes (SHA-384)")
	require.False(t, isAllZero(report.Measurement[:]), "measurement must be non-zero")
	require.False(t, isAllZero(report.ChipID[:]), "CHIP_ID must be non-zero (production, not debug)")
	require.Zero(t, report.Policy&sevPolicyDebug, "a production guest: DEBUG not allowed")
	require.Equal(t, uint64(0x30000), report.Policy, "GCP default policy: SMT allowed, reserved bit set")
	require.Zero(t, report.VMPL)
	require.Equal(t, uint32(1), report.SignatureAlgo, "ECDSA P-384 / SHA-384")
	require.Zero(t, report.SigningKey, "signed by the VCEK")

	// 2. ECDSA-P384 signature under the VCEK.
	require.NoError(t, realVerifySEVReportSignature(report, vcek),
		"report must verify under the genuine VCEK")

	// 3. VCEK -> ASK -> ARK-Milan chain (offline, from the KDS-fetched bundle).
	require.NoError(t, realVerifyAMDChain(vcek, chain),
		"VCEK must chain to AMD ARK-Milan")

	// 4. The X25519 public key is bound to this attestation:
	//    REPORT_DATA == SHA-512(pubkey || nonce).
	want := sha512.Sum512(append(append([]byte(nil), pub...), nonce...))
	require.Equal(t, want[:], report.ReportData[:],
		"REPORT_DATA must bind the TEE-generated public key and the challenger nonce")
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
