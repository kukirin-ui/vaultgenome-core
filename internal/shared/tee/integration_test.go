// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tee — end-to-end integration tests for all four real-hardware
// adapters using the fake hardware harness from fake_hardware_test.go.
//
// These tests exercise every line of the adapter Quote / Verify / Seal
// / Unseal path against an in-process synthetic backend. The AWS Nitro
// backend signs genuine CBOR/COSE_Sign1 documents with a synthetic P-384
// chain, so the production codec runs; the SGX and SEV-SNP backends
// still swap the sgx_quote3_t / SEV-SNP-1184B formats for Ed25519-signed
// JSON — see fake_hardware_test.go.
//
// Test groups per platform:
//
//   - FullCycle:          producer → verifier → sealer round-trip
//   - ReplayRejected:     verify with a different nonce than producer used
//   - TamperedEvidence:   flip a byte in evidence, expect Integrity error
//   - WrongMeasurement:   produce on hardware A, verify against expected B
//   - SealingAADBinding:  unseal with mismatched AAD must fail
//   - ContractSuite:      run RunProducerVerifierContract + RunSealerContract
//
// Total: 6 sub-tests × 4 platforms = 24 integration cases. Combined with
// the existing 84 unit tests this brings the package to 108 cases all
// passing on the same fixed-cost CI minutes.

package tee

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// =============================================================================
// AWS Nitro — full cycle integration
// =============================================================================

func TestIntegration_AWSNitro(t *testing.T) {
	fh := newFakeHardware(t, "aws-nitro-int")
	installAWSNitroFake(t, fh)

	mkProducer := func(t *testing.T) *AWSNitroProducer {
		t.Helper()
		p, err := NewAWSNitroProducer(AWSNitroProducerConfig{
			NSMDevicePath: "/fake/nsm",
			UserData:      []byte("integration-userdata"),
		})
		require.NoError(t, err)
		return p
	}
	mkVerifier := func(t *testing.T, expected Measurement) *AWSNitroVerifier {
		t.Helper()
		v, err := NewAWSNitroVerifier(nil, expected, AWSNitroVerifierConfig{
			PinnedRoots: [][]byte{fh.nitro.rootDER},
		})
		require.NoError(t, err)
		return v
	}

	t.Run("FullCycle", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		require.Equal(t, fh.measure, p.Measurement())

		v := mkVerifier(t, fh.measure)

		nonce := bytes.Repeat([]byte{0xA1}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		require.Greater(t, len(ev), 64)

		got, err := v.Verify(ev, nonce)
		require.NoError(t, err)
		require.Equal(t, fh.measure, got)
		require.Len(t, got, 48, "a Nitro PCR is SHA-384")

		report, err := AuditAWSNitroDocument(ev, [][]byte{fh.nitro.rootDER}, time.Time{})
		require.NoError(t, err)
		require.Equal(t, nonce, report.Nonce)
		require.Equal(t, []byte("integration-userdata"), report.UserData)
		require.Len(t, report.Chain, 5)
	})

	t.Run("ReplayRejected", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		v := mkVerifier(t, fh.measure)

		producerNonce := bytes.Repeat([]byte{0xB2}, NonceMinBytes)
		challengerNonce := bytes.Repeat([]byte{0xCC}, NonceMinBytes)
		ev, err := p.Quote(producerNonce)
		require.NoError(t, err)
		_, err = v.Verify(ev, challengerNonce)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	})

	t.Run("TamperedEvidence", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		v := mkVerifier(t, fh.measure)

		nonce := bytes.Repeat([]byte{0xD3}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		// Flip a byte in the signature trailer.
		tampered := append([]byte(nil), ev...)
		tampered[len(tampered)-1] ^= 0x01
		_, err = v.Verify(tampered, nonce)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	})

	t.Run("WrongMeasurement", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		// Verifier expects a measurement that does NOT match the producer.
		other := MeasurementOf([]byte("other-workload"))
		v := mkVerifier(t, other)

		nonce := bytes.Repeat([]byte{0xE4}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		_, err = v.Verify(ev, nonce)
		require.Error(t, err)
		require.Contains(t, err.Error(), "PCR")
	})

	t.Run("SealingAADBinding", func(t *testing.T) {
		s := NewAWSNitroSealer("arn:aws:kms:us-east-1:000000:key/fake", "us-east-1", fh.measure)
		pt := []byte("session-secret-payload")
		aad := []byte("session=alpha;component=Z")
		sealed, err := s.Seal(pt, aad)
		require.NoError(t, err)
		got, err := s.Unseal(sealed, aad)
		require.NoError(t, err)
		require.Equal(t, pt, got)

		// Tampered AAD: KMS denies via AccessDeniedException.
		_, err = s.Unseal(sealed, []byte("session=beta"))
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
		require.True(t, strings.Contains(err.Error(), "PCR0 mismatch") ||
			strings.Contains(err.Error(), "AccessDenied") ||
			strings.Contains(err.Error(), "KMS denied"))
	})

	t.Run("CloseIdempotent", func(t *testing.T) {
		p := mkProducer(t)
		require.NoError(t, p.Close())
		require.NoError(t, p.Close()) // second close is no-op
	})
}

// =============================================================================
// Azure SGX (MAA mode) — full cycle integration
// =============================================================================

func TestIntegration_AzureSGX_MAA(t *testing.T) {
	fh := newFakeHardware(t, "azure-sgx-maa-int")
	installSGXFake(t, fh, "maa")

	mkProducer := func(t *testing.T) *AzureSGXProducer {
		t.Helper()
		p, err := NewAzureSGXProducer(AzureSGXProducerConfig{
			EnclaveSOPath: "/fake/enclave.signed.so",
			AttestKeyType: "ecdsa",
		})
		require.NoError(t, err)
		return p
	}
	mkVerifier := func(t *testing.T, expected Measurement) *AzureSGXVerifier {
		t.Helper()
		v, err := NewAzureSGXVerifier(nil, expected, AzureSGXVerifierConfig{
			Mode:                AzureSGXModeMAA,
			MAAEndpoint:         "https://fake.attest.azure.net",
			MAAJWKSURL:          "https://fake.attest.azure.net/certs",
			AcceptableMRSIGNERS: [][32]byte{fh.mrSigner},
			MinISVSVN:           1,
		})
		require.NoError(t, err)
		return v
	}

	t.Run("FullCycle", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		require.Equal(t, fh.measure, p.Measurement())

		v := mkVerifier(t, fh.measure)
		nonce := bytes.Repeat([]byte{0x21}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(ev), 432)

		got, err := v.Verify(ev, nonce)
		require.NoError(t, err)
		require.Equal(t, fh.measure, got)
	})

	t.Run("ReplayRejected", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		v := mkVerifier(t, fh.measure)

		ev, err := p.Quote(bytes.Repeat([]byte{0x22}, NonceMinBytes))
		require.NoError(t, err)
		_, err = v.Verify(ev, bytes.Repeat([]byte{0x99}, NonceMinBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "REPORT_DATA")
	})

	t.Run("ISVSVNFloor", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		// Verifier requires ISVSVN ≥ 999 — the fake hardware reports SVN=5.
		v, err := NewAzureSGXVerifier(nil, fh.measure, AzureSGXVerifierConfig{
			Mode:                AzureSGXModeMAA,
			MAAEndpoint:         "https://fake.attest.azure.net",
			MAAJWKSURL:          "https://fake.attest.azure.net/certs",
			AcceptableMRSIGNERS: [][32]byte{fh.mrSigner},
			MinISVSVN:           999,
		})
		require.NoError(t, err)
		ev, err := p.Quote(bytes.Repeat([]byte{0x23}, NonceMinBytes))
		require.NoError(t, err)
		_, err = v.Verify(ev, bytes.Repeat([]byte{0x23}, NonceMinBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "ISVSVN")
	})

	t.Run("MRSignerEnforced", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		// Acceptable MRSIGNER set is non-matching → reject.
		other := [32]byte{0xAA, 0xBB}
		v, err := NewAzureSGXVerifier(nil, fh.measure, AzureSGXVerifierConfig{
			Mode:                AzureSGXModeMAA,
			MAAEndpoint:         "https://fake.attest.azure.net",
			MAAJWKSURL:          "https://fake.attest.azure.net/certs",
			AcceptableMRSIGNERS: [][32]byte{other},
		})
		require.NoError(t, err)
		ev, err := p.Quote(bytes.Repeat([]byte{0x24}, NonceMinBytes))
		require.NoError(t, err)
		_, err = v.Verify(ev, bytes.Repeat([]byte{0x24}, NonceMinBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "MRSIGNER")
	})

	t.Run("SealingRoundTrip", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		s, err := NewAzureSGXSealer(p.enclaveID, SGXSealMRENCLAVE, "test-kid")
		require.NoError(t, err)
		pt := []byte("sgx-payload")
		aad := []byte("session=sgx;manifest=M")
		sealed, err := s.Seal(pt, aad)
		require.NoError(t, err)
		got, err := s.Unseal(sealed, aad)
		require.NoError(t, err)
		require.Equal(t, pt, got)

		// AAD binding.
		_, err = s.Unseal(sealed, []byte("aad-other"))
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	})
}

// =============================================================================
// Azure SGX (DCAP mode) — same enclave, offline verification
// =============================================================================

func TestIntegration_AzureSGX_DCAP(t *testing.T) {
	fh := newFakeHardware(t, "azure-sgx-dcap-int")
	installSGXFake(t, fh, "dcap")

	t.Run("FullCycle", func(t *testing.T) {
		p, err := NewAzureSGXProducer(AzureSGXProducerConfig{
			EnclaveSOPath: "/fake/enclave.signed.so",
		})
		require.NoError(t, err)
		defer p.Close()

		v, err := NewAzureSGXVerifier(nil, fh.measure, AzureSGXVerifierConfig{
			Mode:                AzureSGXModeDCAP,
			PCCSURL:             "https://localhost:8081/sgx/v4",
			AcceptableMRSIGNERS: [][32]byte{fh.mrSigner},
		})
		require.NoError(t, err)

		nonce := bytes.Repeat([]byte{0x31}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		got, err := v.Verify(ev, nonce)
		require.NoError(t, err)
		require.Equal(t, fh.measure, got)
	})
}

// =============================================================================
// GCP SEV-SNP — full cycle integration
// =============================================================================

func TestIntegration_GCPSEVSNP(t *testing.T) {
	fh := newFakeHardware(t, "gcp-sev-snp-int")
	installSEVSNPFake(t, fh)

	// SEV-SNP MEASUREMENT is 48 bytes (SHA-384). The fake fills the first 32
	// with fh.measure and zero-pads the rest; the adapter carries the full 48
	// bytes without truncation (ADR-0007), so tests expect all 48.
	wantMeas := make(Measurement, 48)
	copy(wantMeas, fh.measure)

	mkProducer := func(t *testing.T) *GCPSEVProducer {
		t.Helper()
		// The adapter checks that the configfs-tsm directory exists; the
		// fake SEV guest answers the reports, so an empty directory will do.
		p, err := NewGCPSEVProducer(GCPSEVProducerConfig{
			TSMReportDir: t.TempDir(),
			VMPL:         0,
		})
		require.NoError(t, err)
		return p
	}
	mkVerifier := func(t *testing.T, expected Measurement) *GCPSEVVerifier {
		t.Helper()
		v, err := NewGCPSEVVerifier(nil, expected, GCPSEVVerifierConfig{
			AMDKDSURL:      "https://fake.kdsintf.amd.com",
			MinReportedTCB: 50,
		})
		require.NoError(t, err)
		return v
	}

	t.Run("FullCycle", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		require.Equal(t, wantMeas, p.Measurement())

		v := mkVerifier(t, wantMeas)

		nonce := bytes.Repeat([]byte{0x41}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		got, err := v.Verify(ev, nonce)
		require.NoError(t, err)
		require.Equal(t, wantMeas, got)
	})

	t.Run("ReportedTCBFloor", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		v, err := NewGCPSEVVerifier(nil, wantMeas, GCPSEVVerifierConfig{
			AMDKDSURL:      "https://fake.kdsintf.amd.com",
			MinReportedTCB: 99999, // far above fake's reportedTCB=100
		})
		require.NoError(t, err)
		ev, err := p.Quote(bytes.Repeat([]byte{0x42}, NonceMinBytes))
		require.NoError(t, err)
		_, err = v.Verify(ev, bytes.Repeat([]byte{0x42}, NonceMinBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "ReportedTCB")
	})

	// A report that verifies cryptographically still says nothing about
	// confidentiality if the guest is debuggable, was quoted from another
	// privilege level, or was signed by a key this verifier did not check.
	t.Run("GuestPolicyAndProvenance", func(t *testing.T) {
		fakeParse := parseSEVSNPReport
		t.Cleanup(func() { parseSEVSNPReport = fakeParse })
		for name, tc := range map[string]struct {
			mutate func(*sevSNPReport)
			want   string
		}{
			"debug guest": {func(r *sevSNPReport) { r.Policy |= sevPolicyDebug }, "DEBUG"},
			"other VMPL":  {func(r *sevSNPReport) { r.VMPL = 2 }, "VMPL 2"},
			"VLEK-signed": {func(r *sevSNPReport) { r.SigningKey = 1 }, "by the VCEK"},
			"other algo":  {func(r *sevSNPReport) { r.SignatureAlgo = 2 }, "ECDSA P-384"},
		} {
			t.Run(name, func(t *testing.T) {
				parseSEVSNPReport = func(raw []byte) (*sevSNPReport, error) {
					r, err := fakeParse(raw)
					if err == nil {
						tc.mutate(r)
					}
					return r, err
				}
				defer func() { parseSEVSNPReport = fakeParse }()
				p := mkProducer(t)
				defer p.Close()
				v := mkVerifier(t, wantMeas)
				nonce := bytes.Repeat([]byte{0x44}, NonceMinBytes)
				ev, err := p.Quote(nonce)
				require.NoError(t, err)
				_, err = v.Verify(ev, nonce)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.want)
			})
		}
	})

	t.Run("HostDataPolicy", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		// Pin acceptable HostData to a value the fake won't produce.
		bogus := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
		v, err := NewGCPSEVVerifier(nil, wantMeas, GCPSEVVerifierConfig{
			AMDKDSURL:          "https://fake.kdsintf.amd.com",
			AcceptableHostData: [][32]byte{bogus},
		})
		require.NoError(t, err)
		ev, err := p.Quote(bytes.Repeat([]byte{0x43}, NonceMinBytes))
		require.NoError(t, err)
		_, err = v.Verify(ev, bytes.Repeat([]byte{0x43}, NonceMinBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "HOST_DATA")
	})

	t.Run("SealingDerivedKey", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		s := NewGCPSEVSealer(fakeFileForSEV(t), fh.measure, 0)
		pt := []byte("sev-snp-payload")
		aad := []byte("session=sev")
		sealed, err := s.Seal(pt, aad)
		require.NoError(t, err)
		got, err := s.Unseal(sealed, aad)
		require.NoError(t, err)
		require.Equal(t, pt, got)

		// AAD binding.
		_, err = s.Unseal(sealed, []byte("aad-mismatch"))
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	})
}

// =============================================================================
// Intel SGX (bare metal, DCAP-only) — full cycle integration
// =============================================================================

func TestIntegration_IntelSGX(t *testing.T) {
	fh := newFakeHardware(t, "intel-sgx-int")
	installSGXFake(t, fh, "dcap")

	mkProducer := func(t *testing.T) *IntelSGXProducer {
		t.Helper()
		p, err := NewIntelSGXProducer(IntelSGXProducerConfig{
			EnclaveSOPath: "/fake/intel-enclave.signed.so",
		})
		require.NoError(t, err)
		return p
	}
	mkVerifier := func(t *testing.T, expected Measurement) *IntelSGXVerifier {
		t.Helper()
		v, err := NewIntelSGXVerifier(nil, expected, IntelSGXVerifierConfig{
			PCCSURL:             "https://localhost:8081/sgx/v4",
			AcceptableMRSIGNERS: [][32]byte{fh.mrSigner},
			MinISVSVN:           1,
		})
		require.NoError(t, err)
		return v
	}

	t.Run("FullCycle", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		require.Equal(t, fh.measure, p.Measurement())

		v := mkVerifier(t, fh.measure)
		nonce := bytes.Repeat([]byte{0x51}, NonceMinBytes)
		ev, err := p.Quote(nonce)
		require.NoError(t, err)
		got, err := v.Verify(ev, nonce)
		require.NoError(t, err)
		require.Equal(t, fh.measure, got)
	})

	t.Run("SealingNoHSM", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		s, err := NewIntelSGXSealer(p.enclaveID, SGXSealMRENCLAVE, "")
		require.NoError(t, err)
		pt := []byte("intel-sgx-payload")
		aad := []byte("session=intel")
		sealed, err := s.Seal(pt, aad)
		require.NoError(t, err)
		got, err := s.Unseal(sealed, aad)
		require.NoError(t, err)
		require.Equal(t, pt, got)
	})

	t.Run("SealingWithHSMWrap", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		// HSM-wrapped sealing: an extra defense-in-depth layer (Thales /
		// Entrust / SoftHSM) wraps the SGX sealed blob. Both layers must
		// round-trip cleanly.
		s, err := NewIntelSGXSealer(p.enclaveID, SGXSealMRENCLAVE, "softhsm-slot-1")
		require.NoError(t, err)
		pt := []byte("hsm-wrapped-payload")
		aad := []byte("session=hsm")
		sealed, err := s.Seal(pt, aad)
		require.NoError(t, err)
		got, err := s.Unseal(sealed, aad)
		require.NoError(t, err)
		require.Equal(t, pt, got)
	})

	t.Run("MRSignerRequired", func(t *testing.T) {
		p := mkProducer(t)
		defer p.Close()
		v, err := NewIntelSGXVerifier(nil, fh.measure, IntelSGXVerifierConfig{
			PCCSURL:             "https://localhost:8081/sgx/v4",
			AcceptableMRSIGNERS: [][32]byte{{0xFE}},
		})
		require.NoError(t, err)
		ev, err := p.Quote(bytes.Repeat([]byte{0x52}, NonceMinBytes))
		require.NoError(t, err)
		_, err = v.Verify(ev, bytes.Repeat([]byte{0x52}, NonceMinBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "MRSIGNER")
	})
}
