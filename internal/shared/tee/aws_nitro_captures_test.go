// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The verifier against the hypervisor's own documents: the four
// production-mode attestation documents captured in May 2026 on real
// Nitro Enclaves in three Ohio zones and one Irish one
// (scripts/hardware-test/aws-nitro/evidence, sanitized excerpts). The raw
// COSE_Sign1 documents are shared under NDA and are not in the
// repository; point VG_NITRO_CAPTURE_DIR at a directory of cohort
// directories, each holding 04-attestation-document.bin,
// 02d-expected-pcrs.json and 01-vaultgenome-enclave-build-manifest.json,
// and the test runs on them.

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAWSNitro_GenuineProductionCaptures(t *testing.T) {
	dir := os.Getenv("VG_NITRO_CAPTURE_DIR")
	if dir == "" {
		t.Skip("VG_NITRO_CAPTURE_DIR is not set: the raw attestation documents are shared under NDA and are not in the repository")
	}
	docs, err := filepath.Glob(filepath.Join(dir, "*", "04-attestation-document.bin"))
	require.NoError(t, err)
	require.NotEmpty(t, docs, "no */04-attestation-document.bin under %s", dir)

	for _, path := range docs {
		cohort := filepath.Base(filepath.Dir(path))
		t.Run(cohort, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			require.NoError(t, err)

			// The document audits at its own timestamp against the built-in root.
			report, err := AuditAWSNitroDocument(raw, nil, time.Time{})
			require.NoError(t, err)
			t.Logf("module %s signed %s; chain %d certificates, root %q", report.ModuleID, report.Timestamp.Format(time.RFC3339Nano), len(report.Chain), report.Chain[len(report.Chain)-1])
			require.Len(t, report.Chain, 5)
			require.Contains(t, report.Chain[4], "CN=aws.nitro-enclaves")
			require.Contains(t, report.Chain[0], report.ModuleID)
			require.False(t, report.Debug, "production-mode enclave: PCR0 is not zero")
			require.Nil(t, report.Nonce, "the May 2026 kit asked the NSM for no nonce")
			require.Len(t, report.PCRs, 16)
			require.WithinDuration(t, report.Timestamp, report.SigningCertNotBefore, 10*time.Second)
			require.Equal(t, 3*time.Hour, report.SigningCertNotAfter.Sub(report.Timestamp).Round(time.Minute))

			// PCR0..2 equal what `nitro-cli describe-eif` printed for the image.
			var expected struct {
				PCR0 string `json:"expected_pcr0"`
				PCR1 string `json:"expected_pcr1"`
				PCR2 string `json:"expected_pcr2"`
			}
			raw2, err := os.ReadFile(filepath.Join(filepath.Dir(path), "02d-expected-pcrs.json"))
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw2, &expected))
			require.Equal(t, expected.PCR0, hex.EncodeToString(report.PCRs[0]))
			require.Equal(t, expected.PCR1, hex.EncodeToString(report.PCRs[1]))
			require.Equal(t, expected.PCR2, hex.EncodeToString(report.PCRs[2]))

			// user_data is the SHA-512 of the build manifest the kit bound.
			manifest, err := os.ReadFile(filepath.Join(filepath.Dir(path), "01-vaultgenome-enclave-build-manifest.json"))
			require.NoError(t, err)
			sum := sha512.Sum512(manifest)
			require.True(t, bytes.Equal(sum[:], report.UserData), "user_data is not the manifest's SHA-512")

			// The same document at today's clock: the signing certificate
			// expired three hours after capture, and the chain check says so.
			_, err = AuditAWSNitroDocument(raw, nil, time.Now())
			require.Error(t, err)
			require.Contains(t, err.Error(), "certificate chain")

			// A Verifier with a challenge refuses the document even at its
			// capture time: it carries no nonce, and a nonce is mandatory.
			v, err := NewAWSNitroVerifier(nil, Measurement(report.PCRs[0]), AWSNitroVerifierConfig{Now: func() time.Time { return report.Timestamp }})
			require.NoError(t, err)
			_, err = v.Verify(raw, bytes.Repeat([]byte{0x42}, NonceMinBytes))
			require.Error(t, err)
			require.Contains(t, err.Error(), "nonce")

			// A byte flipped anywhere in the signature is caught by the
			// signature check, and in the payload by the same check.
			for _, off := range []int{len(raw) - 1, len(raw) / 2} {
				tampered := append([]byte(nil), raw...)
				tampered[off] ^= 0x01
				_, err = AuditAWSNitroDocument(tampered, nil, time.Time{})
				require.Error(t, err, "flip at %d", off)
			}
		})
	}
}
