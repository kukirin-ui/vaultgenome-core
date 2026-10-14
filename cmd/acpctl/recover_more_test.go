// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// simulatedVault seals plaintext under the simulated TEE and writes the
// vault envelope to a file in dir, returning the vault's path.
func simulatedVault(t *testing.T, dir string, plaintext, aad []byte) string {
	t.Helper()
	descriptor := []byte("recover-more-workload")
	seed := bytes.Repeat([]byte{0x5A}, shared_crypto.Ed25519SeedSize)
	sim, err := tee.NewSimulated(descriptor, seed)
	require.NoError(t, err)
	sealed, err := sim.Seal(plaintext, aad)
	require.NoError(t, err)
	blob, err := EncodeVault(VaultEnvelope{
		TEEProvider:                 "simulated",
		AAD:                         aad,
		SimulatedWorkloadDescriptor: descriptor,
		SimulatedSeed:               seed,
	}, sealed)
	require.NoError(t, err)
	path := filepath.Join(dir, "sim.vault")
	require.NoError(t, os.WriteFile(path, blob, 0o600))
	return path
}

// unsealVault builds the sealer the envelope names and refuses, before any
// hardware is touched, an envelope that lacks what that sealer needs. Every
// hardware backend's own constructor then refuses on a host without it.
func TestUnsealVault_RefusesPerProvider(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	devFile := filepath.Join(dir, "not-a-sev-device")
	require.NoError(t, os.WriteFile(devFile, nil, 0o600))
	enclave := filepath.Join(dir, "enclave.signed.so")
	require.NoError(t, os.WriteFile(enclave, []byte("not an enclave"), 0o600))

	for name, tc := range map[string]struct {
		env       VaultEnvelope
		enclaveSO string
		sevDev    string
		want      string
	}{
		"simulated without descriptor": {
			env:  VaultEnvelope{TEEProvider: "simulated"},
			want: "missing simulated_workload_descriptor",
		},
		"simulated with a short seed": {
			env:  VaultEnvelope{TEEProvider: "simulated", SimulatedWorkloadDescriptor: []byte("w"), SimulatedSeed: []byte("short")},
			want: "seed must be 32 bytes",
		},
		"aws-nitro without a KMS key": {
			env:  VaultEnvelope{TEEProvider: "aws-nitro"},
			want: "missing aws_kms_key_arn",
		},
		"aws-nitro with a PCR0 of the wrong width": {
			env:  VaultEnvelope{TEEProvider: "aws-nitro", AWSKMSKeyARN: "arn:aws:kms:eu-west-1:1:key/k", AWSExpectedPCR0: []byte{1, 2, 3}},
			want: "aws_expected_pcr0 must be 32 bytes (got 3)",
		},
		"azure-sgx without an enclave": {
			env:  VaultEnvelope{TEEProvider: "azure-sgx"},
			want: "--enclave-so is required",
		},
		"azure-sgx cannot load an enclave here": {
			env:       VaultEnvelope{TEEProvider: "azure-sgx"},
			enclaveSO: enclave,
			want:      "azure-sgx: load enclave",
		},
		"intel-sgx-dcap without an enclave": {
			env:  VaultEnvelope{TEEProvider: "intel-sgx-dcap"},
			want: "--enclave-so is required",
		},
		"intel-sgx-dcap cannot load an enclave here": {
			env:       VaultEnvelope{TEEProvider: "intel-sgx-dcap", HSMSlot: "slot-0"},
			enclaveSO: enclave,
			want:      "intel-sgx-dcap: load enclave",
		},
		"gcp-sev-snp without the guest device": {
			env:    VaultEnvelope{TEEProvider: "gcp-sev-snp"},
			sevDev: filepath.Join(dir, "absent-device"),
			want:   "gcp-sev-snp: open",
		},
		"gcp-sev-snp with a measurement of the wrong width": {
			env:    VaultEnvelope{TEEProvider: "gcp-sev-snp", SEVMeasurement: []byte{1, 2}},
			sevDev: devFile,
			want:   "sev_measurement must be the 48-byte launch measurement (got 2 bytes)",
		},
		"gcp-sev-snp derives no key from a plain file": {
			env:    VaultEnvelope{TEEProvider: "gcp-sev-snp", SEVMeasurement: bytes.Repeat([]byte{7}, 48)},
			sevDev: devFile,
			want:   "gcp-sev-sealer: derive key",
		},
		"gcp-tdx has no vault sealer": {
			env:  VaultEnvelope{TEEProvider: "gcp-tdx"},
			want: `unsupported provider "gcp-tdx"`,
		},
		"azure-cgpu has no vault sealer": {
			env:  VaultEnvelope{TEEProvider: "azure-cgpu"},
			want: `unsupported provider "azure-cgpu"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := tc.env
			plain, err := unsealVault(&env, []byte("sealed-bytes"), tc.enclaveSO, tc.sevDev)
			require.Error(t, err)
			require.Nil(t, plain)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// A pinned MRENCLAVE must be 32 bytes and equal the live one; an envelope
// that pins nothing trusts the TEE itself.
func TestAssertMeasurementMatches(t *testing.T) {
	t.Parallel()
	live := tee.Measurement(bytes.Repeat([]byte{0xAB}, 32))
	other := append([]byte(nil), live...)
	other[31] ^= 1
	for name, tc := range map[string]struct {
		expected []byte
		want     string
	}{
		"nothing pinned": {expected: nil},
		"same enclave":   {expected: live},
		"wrong width":    {expected: []byte{1, 2, 3}, want: "envelope sgx_mrenclave must be 32 bytes (got 3)"},
		"other enclave":  {expected: other, want: "measurement mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := assertMeasurementMatches(live, tc.expected, "sgx_mrenclave")
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// The envelope's seal policy maps onto the SGX policies; anything else
// falls back to the strict MRENCLAVE binding.
func TestDecodeSGXPolicy(t *testing.T) {
	t.Parallel()
	require.Equal(t, tee.SGXSealMRSIGNER, decodeSGXPolicy(int(tee.SGXSealMRSIGNER)))
	require.Equal(t, tee.SGXSealMRENCLAVE, decodeSGXPolicy(int(tee.SGXSealMRENCLAVE)))
	require.Equal(t, tee.SGXSealMRENCLAVE, decodeSGXPolicy(0))
	require.Equal(t, tee.SGXSealMRENCLAVE, decodeSGXPolicy(99))
}

// Each result type has an operator-readable form and a JSON form.
func TestEmitResult_Forms(t *testing.T) {
	t.Parallel()
	dry := dryRunResult{OK: true, Provider: "simulated", Available: true, Reason: "always", SealedBytes: 40, AAD: 3, SealedAt: "2026-04-01T12:00:00Z"}
	rec := recoverResult{OK: true, Provider: "simulated", PlaintextBytes: 12, Output: "/tmp/out", SealedAt: "2026-04-01T12:00:00Z"}

	var buf bytes.Buffer
	emitResult(&buf, false, dry)
	for _, want := range []string{"vault provider:   simulated", "tee available:    true (always)", "sealed bytes:     40", "sealed at (UTC):  2026-04-01T12:00:00Z", "dry-run: ok"} {
		require.Contains(t, buf.String(), want)
	}

	buf.Reset()
	emitResult(&buf, false, rec)
	require.Contains(t, buf.String(), "recovered 12 bytes from simulated vault → /tmp/out")
	require.Contains(t, buf.String(), "sealed at (UTC): 2026-04-01T12:00:00Z")

	buf.Reset()
	emitResult(&buf, true, rec)
	var back recoverResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &back))
	require.Equal(t, rec, back)

	buf.Reset()
	emitResult(&buf, false, struct{}{})
	require.Empty(t, buf.String(), "an unknown result type prints nothing")
}

// A dry run without --json reports in the operator-readable form.
func TestRecoverCmd_DryRunText(t *testing.T) {
	t.Parallel()
	vault := simulatedVault(t, t.TempDir(), []byte("payload"), []byte("aad"))
	var stdout, stderr bytes.Buffer
	rc := recoverCmd([]string{"--vault", vault, "--dry-run"}, &stdout, &stderr)
	require.Equal(t, 0, rc, stderr.String())
	require.Contains(t, stdout.String(), "vault provider:   simulated")
	require.Contains(t, stdout.String(), "tee available:    true")
	require.Contains(t, stdout.String(), "dry-run: ok")
}

// Refusals before anything is unsealed, each with its exit code.
func TestRecoverCmd_Refusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vault := simulatedVault(t, dir, []byte("payload"), nil)
	notVault := filepath.Join(dir, "not.vault")
	require.NoError(t, os.WriteFile(notVault, []byte("hello, world: this is not a vault"), 0o600))

	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"unknown flag":          {[]string{"--vault", vault, "--nope"}, 2, "flag provided but not defined"},
		"not a vault":           {[]string{"--vault", notVault, "--output", filepath.Join(dir, "o")}, 1, "magic mismatch"},
		"output dir is missing": {[]string{"--vault", vault, "--output", filepath.Join(dir, "absent", "o")}, 1, "write output"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			rc := recoverCmd(tc.args, &stdout, &stderr)
			require.Equal(t, tc.code, rc, stderr.String())
			require.Contains(t, stderr.String(), tc.want)
		})
	}
}

// A vault sealed to a hardware TEE this host lacks is refused with exit 3
// and the capability reason, and a dry run still describes it.
func TestRecoverCmd_UnavailableBackend(t *testing.T) {
	t.Parallel()
	if available, _ := tee.Capability(tee.ProviderAWSNitro); available {
		t.Skip("this host is a Nitro enclave; the backend is available here")
	}
	blob, err := EncodeVault(VaultEnvelope{TEEProvider: "aws-nitro", AWSKMSKeyARN: "arn:aws:kms:eu-west-1:1:key/k", AWSExpectedPCR0: bytes.Repeat([]byte{1}, 32)}, []byte("sealed"))
	require.NoError(t, err)
	dir := t.TempDir()
	vault := filepath.Join(dir, "nitro.vault")
	require.NoError(t, os.WriteFile(vault, blob, 0o600))

	var stdout, stderr bytes.Buffer
	rc := recoverCmd([]string{"--vault", vault, "--output", filepath.Join(dir, "out")}, &stdout, &stderr)
	require.Equal(t, 3, rc)
	require.Contains(t, stderr.String(), `TEE backend "aws-nitro" not available on this host`)
	_, err = os.Stat(filepath.Join(dir, "out"))
	require.True(t, os.IsNotExist(err), "nothing is written")

	stdout.Reset()
	rc = recoverCmd([]string{"--vault", vault, "--dry-run", "--json"}, &stdout, &stderr)
	require.Equal(t, 0, rc)
	var res dryRunResult
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &res))
	require.Equal(t, "aws-nitro", res.Provider)
	require.False(t, res.Available)
	require.Contains(t, res.Reason, "Nitro")
	require.Equal(t, 6, res.SealedBytes)
}

// Every malformed envelope is named for what it is.
func TestDecodeVault_Malformed(t *testing.T) {
	t.Parallel()
	frame := func(meta string, sealed []byte) []byte {
		var buf bytes.Buffer
		buf.WriteString(vaultEnvelopeMagic)
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(meta)))
		buf.Write(n[:])
		buf.WriteString(meta)
		buf.Write(sealed)
		return buf.Bytes()
	}
	truncated := frame(`{"format":"vault-genome-v1"}`, nil)
	binary.BigEndian.PutUint32(truncated[len(vaultEnvelopeMagic):], 1<<20)

	for name, tc := range map[string]struct {
		blob []byte
		want string
	}{
		"too short":          {[]byte(vaultEnvelopeMagic), "blob too short"},
		"wrong magic":        {append([]byte("VG-GENOME-01\x00\x00\x00\x00"), make([]byte, 8)...), "magic mismatch"},
		"truncated metadata": {truncated, "truncated metadata"},
		"metadata not json":  {frame(`{"format":`, nil), "metadata json"},
		"unsupported format": {frame(`{"format":"vault-genome-v9"}`, nil), `unsupported format "vault-genome-v9"`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env, sealed, err := DecodeVault(tc.blob)
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, env)
			require.Nil(t, sealed)
		})
	}
}

// Metadata is bounded at 1 MiB so a corrupt length can never make the
// recovery side allocate without limit.
func TestEncodeVault_RefusesOversizedMetadata(t *testing.T) {
	t.Parallel()
	_, err := EncodeVault(VaultEnvelope{TEEProvider: "simulated", AAD: bytes.Repeat([]byte{1}, 1<<20)}, nil)
	require.ErrorContains(t, err, "metadata > 1 MiB")
	require.Contains(t, err.Error(), "refusing")
	require.False(t, strings.Contains(err.Error(), "json"), "the size, not the encoding, is what was refused")
}
