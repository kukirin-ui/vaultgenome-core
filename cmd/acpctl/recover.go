// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// VaultEnvelope is the on-disk format produced by sagvd when it seals
// material to a TEE, and consumed by `acpctl recover` to bring that
// material back inside a fresh enclave.
//
// The envelope carries everything the recovery side needs to choose +
// configure the right Sealer:
//
//   - Provider: which TEE backend the seal targeted
//   - Provider-specific knobs the Sealer's constructor requires
//     (KMS ARN + expected PCR0 for Nitro, MRENCLAVE / seal policy for
//     SGX, MEASUREMENT + guest policy for SEV-SNP, workload descriptor
//     for the simulated backend)
//   - The original AAD so unseal authentication binds identically
//
// The envelope itself is unencrypted JSON metadata + an opaque sealed
// blob the chosen TEE Sealer can interpret. Compromise of the envelope
// does NOT compromise the plaintext — the sealed bytes are unsealable
// only by a TEE that meets the original measurement / policy.
type VaultEnvelope struct {
	Format      string `json:"format"`       // "vault-genome-v1"
	TEEProvider string `json:"tee_provider"` // tee.Provider value
	AAD         []byte `json:"aad,omitempty"`
	SealedAt    int64  `json:"sealed_at"` // unix nano

	// AWS Nitro
	AWSExpectedPCR0 []byte `json:"aws_expected_pcr0,omitempty"`
	AWSKMSKeyARN    string `json:"aws_kms_key_arn,omitempty"`
	AWSRegion       string `json:"aws_region,omitempty"`

	// SGX (Azure / Intel bare-metal share these fields)
	SGXMRENCLAVE  []byte `json:"sgx_mrenclave,omitempty"`
	SGXSealPolicy int    `json:"sgx_seal_policy,omitempty"`
	HSMSlot       string `json:"hsm_slot,omitempty"`

	// GCP SEV-SNP
	SEVMeasurement []byte `json:"sev_measurement,omitempty"`
	SEVPolicy      uint64 `json:"sev_policy,omitempty"`

	// Simulated (tests + doctrine demo only — never production)
	SimulatedWorkloadDescriptor []byte `json:"simulated_workload_descriptor,omitempty"`
	SimulatedSeed               []byte `json:"simulated_seed,omitempty"`
}

// vaultEnvelopeMagic is a 16-byte identifier so an operator who runs the
// command on the wrong file gets a clear "not a vault" error instead of
// a JSON-unmarshal stack trace.
const vaultEnvelopeMagic = "VG-VAULT-01\x00\x00\x00\x00\x00"

// EncodeVault produces a single binary blob for `acpctl recover` consumption.
// Format: magic || u32-BE metadata-length || JSON-metadata || sealed-bytes.
// Used by sagvd at seal time and by the recover_test.go harness; no public
// import path is exposed yet — tighten before Phase 2 if external callers
// emerge.
func EncodeVault(env VaultEnvelope, sealed []byte) ([]byte, error) {
	if env.Format == "" {
		env.Format = "vault-genome-v1"
	}
	if env.SealedAt == 0 {
		env.SealedAt = time.Now().UnixNano()
	}
	meta, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("vault encode: %w", err)
	}
	if len(meta) > 1<<20 {
		return nil, fmt.Errorf("vault encode: metadata > 1 MiB (%d bytes) — refusing", len(meta))
	}
	var buf bytes.Buffer
	buf.WriteString(vaultEnvelopeMagic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(meta)))
	buf.Write(lenBuf[:])
	buf.Write(meta)
	buf.Write(sealed)
	return buf.Bytes(), nil
}

// DecodeVault reverses EncodeVault. Returns the parsed envelope + the
// raw sealed bytes for the chosen TEE Sealer.
func DecodeVault(blob []byte) (*VaultEnvelope, []byte, error) {
	if len(blob) < len(vaultEnvelopeMagic)+4 {
		return nil, nil, errors.New("vault decode: blob too short")
	}
	if string(blob[:len(vaultEnvelopeMagic)]) != vaultEnvelopeMagic {
		return nil, nil, errors.New("vault decode: magic mismatch (not a Vault Genome envelope)")
	}
	off := len(vaultEnvelopeMagic)
	metaLen := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	if uint32(len(blob)-off) < metaLen {
		return nil, nil, errors.New("vault decode: truncated metadata")
	}
	var env VaultEnvelope
	if err := json.Unmarshal(blob[off:off+int(metaLen)], &env); err != nil {
		return nil, nil, fmt.Errorf("vault decode: metadata json: %w", err)
	}
	if env.Format != "vault-genome-v1" {
		return nil, nil, fmt.Errorf("vault decode: unsupported format %q (want vault-genome-v1)", env.Format)
	}
	sealed := blob[off+int(metaLen):]
	return &env, sealed, nil
}

// recoverCmd implements `acpctl recover` — restores a previously-sealed
// vault using the TEE backend recorded in the envelope. Exits the
// process with a non-zero status on any failure so operators can rely
// on shell exit codes in scripts.
func recoverCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		vaultPath     = fs.String("vault", "", "Path to sealed vault file (required)")
		outputPath    = fs.String("output", "", "Path to write recovered plaintext (required unless --dry-run)")
		enclaveSOPath = fs.String("enclave-so", "", "Path to .signed.so SGX enclave (required for SGX backends)")
		sevDevicePath = fs.String("sev-device", "/dev/sev-guest", "Path to SEV guest device (default /dev/sev-guest)")
		dryRun        = fs.Bool("dry-run", false, "Validate capability + envelope without unsealing")
		jsonOut       = fs.Bool("json", false, "Emit machine-readable JSON output")
		force         = fs.Bool("force", false, "Overwrite output file if it exists")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl recover --vault PATH [--output PATH] [--dry-run] [--json] [--force]")
		fmt.Fprintln(stderr, "                      [--enclave-so PATH] [--sev-device PATH]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Restore a previously-sealed vault from its TEE-bound ciphertext.")
		fmt.Fprintln(stderr, "Per-provider flag requirements:")
		fmt.Fprintln(stderr, "  - aws-nitro / simulated:   no extra flags (envelope is self-contained)")
		fmt.Fprintln(stderr, "  - azure-sgx / intel-sgx-dcap: --enclave-so PATH")
		fmt.Fprintln(stderr, "  - gcp-sev-snp:             --sev-device PATH (default /dev/sev-guest)")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Exits 0 on success, non-zero on any failure.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *vaultPath == "" {
		fmt.Fprintln(stderr, "acpctl recover: --vault is required")
		fs.Usage()
		return 2
	}
	if !*dryRun && *outputPath == "" {
		fmt.Fprintln(stderr, "acpctl recover: --output is required (unless --dry-run)")
		return 2
	}
	if !*dryRun && !*force {
		if _, err := os.Stat(*outputPath); err == nil {
			fmt.Fprintf(stderr, "acpctl recover: refusing to overwrite %s (pass --force to override)\n", *outputPath)
			return 2
		}
	}

	blob, err := os.ReadFile(*vaultPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl recover: read vault: %v\n", err)
		return 1
	}
	env, sealed, err := DecodeVault(blob)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl recover: %v\n", err)
		return 1
	}

	provider, err := tee.ParseProvider(env.TEEProvider)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl recover: %v\n", err)
		return 1
	}

	available, reason := tee.Capability(provider)

	if *dryRun {
		emitResult(stdout, *jsonOut, dryRunResult{
			OK:          true,
			Provider:    string(provider),
			Available:   available,
			Reason:      reason,
			SealedBytes: len(sealed),
			AAD:         len(env.AAD),
			SealedAt:    time.Unix(0, env.SealedAt).UTC().Format(time.RFC3339),
		})
		return 0
	}

	if !available {
		fmt.Fprintf(stderr, "acpctl recover: TEE backend %q not available on this host: %s\n", provider, reason)
		return 3
	}

	plaintext, err := unsealVault(env, sealed, *enclaveSOPath, *sevDevicePath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl recover: unseal: %v\n", err)
		return 4
	}

	if err := os.WriteFile(*outputPath, plaintext, 0600); err != nil {
		fmt.Fprintf(stderr, "acpctl recover: write output: %v\n", err)
		return 1
	}

	emitResult(stdout, *jsonOut, recoverResult{
		OK:             true,
		Provider:       string(provider),
		PlaintextBytes: len(plaintext),
		Output:         *outputPath,
		SealedAt:       time.Unix(0, env.SealedAt).UTC().Format(time.RFC3339),
	})
	return 0
}

type dryRunResult struct {
	OK          bool   `json:"ok"`
	Provider    string `json:"provider"`
	Available   bool   `json:"capability_available"`
	Reason      string `json:"capability_reason"`
	SealedBytes int    `json:"sealed_bytes"`
	AAD         int    `json:"aad_bytes"`
	SealedAt    string `json:"sealed_at"`
}

type recoverResult struct {
	OK             bool   `json:"ok"`
	Provider       string `json:"provider"`
	PlaintextBytes int    `json:"plaintext_bytes"`
	Output         string `json:"output"`
	SealedAt       string `json:"sealed_at"`
}

func emitResult(w io.Writer, asJSON bool, v any) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	switch r := v.(type) {
	case dryRunResult:
		fmt.Fprintf(w, "vault provider:   %s\n", r.Provider)
		fmt.Fprintf(w, "tee available:    %v (%s)\n", r.Available, r.Reason)
		fmt.Fprintf(w, "sealed bytes:     %d\n", r.SealedBytes)
		fmt.Fprintf(w, "sealed at (UTC):  %s\n", r.SealedAt)
		fmt.Fprintln(w, "dry-run: ok")
	case recoverResult:
		fmt.Fprintf(w, "recovered %d bytes from %s vault → %s\n", r.PlaintextBytes, r.Provider, r.Output)
		fmt.Fprintf(w, "sealed at (UTC): %s\n", r.SealedAt)
	}
}

// unsealVault constructs the appropriate TEE Sealer from the envelope
// metadata + per-provider runtime flags, then performs the unseal.
//
// For backends that need an enclave handle (Azure / Intel SGX) or a
// device handle (SEV-SNP) we build a Producer first and pass its handle
// to the Sealer constructor. The Producer's measurement readback is also
// sanity-checked against the envelope's expected measurement so an
// operator who runs `acpctl recover` from the wrong enclave image gets a
// clear error before KMS / dcap denies them at the cryptographic layer.
func unsealVault(env *VaultEnvelope, sealed []byte, enclaveSO, sevDev string) ([]byte, error) {
	provider, _ := tee.ParseProvider(env.TEEProvider)

	switch provider {
	case tee.ProviderSimulated:
		if len(env.SimulatedWorkloadDescriptor) == 0 {
			return nil, errors.New("simulated: vault missing simulated_workload_descriptor")
		}
		s, err := tee.NewSimulated(env.SimulatedWorkloadDescriptor, env.SimulatedSeed)
		if err != nil {
			return nil, err
		}
		return s.Unseal(sealed, env.AAD)

	case tee.ProviderAWSNitro:
		if env.AWSKMSKeyARN == "" {
			return nil, errors.New("aws-nitro: vault missing aws_kms_key_arn")
		}
		if len(env.AWSExpectedPCR0) != 32 {
			return nil, fmt.Errorf("aws-nitro: aws_expected_pcr0 must be 32 bytes (got %d)", len(env.AWSExpectedPCR0))
		}
		var pcr0 tee.Measurement
		copy(pcr0[:], env.AWSExpectedPCR0)
		s := tee.NewAWSNitroSealer(env.AWSKMSKeyARN, env.AWSRegion, pcr0)
		return s.Unseal(sealed, env.AAD)

	case tee.ProviderAzureSGX:
		if enclaveSO == "" {
			return nil, errors.New("azure-sgx: --enclave-so is required for SGX recovery")
		}
		p, err := tee.NewAzureSGXProducer(tee.AzureSGXProducerConfig{EnclaveSOPath: enclaveSO})
		if err != nil {
			return nil, fmt.Errorf("azure-sgx: load enclave: %w", err)
		}
		defer func() { _ = p.Close() }()
		if err := assertMeasurementMatches(p.Measurement(), env.SGXMRENCLAVE, "sgx_mrenclave"); err != nil {
			return nil, err
		}
		policy := decodeSGXPolicy(env.SGXSealPolicy)
		s, err := tee.NewAzureSGXSealer(p.EnclaveID(), policy, "acpctl-recover")
		if err != nil {
			return nil, err
		}
		return s.Unseal(sealed, env.AAD)

	case tee.ProviderIntelSGXDCAP:
		if enclaveSO == "" {
			return nil, errors.New("intel-sgx-dcap: --enclave-so is required for SGX recovery")
		}
		p, err := tee.NewIntelSGXProducer(tee.IntelSGXProducerConfig{
			EnclaveSOPath: enclaveSO,
			HSMSlot:       env.HSMSlot,
		})
		if err != nil {
			return nil, fmt.Errorf("intel-sgx-dcap: load enclave: %w", err)
		}
		defer func() { _ = p.Close() }()
		if err := assertMeasurementMatches(p.Measurement(), env.SGXMRENCLAVE, "sgx_mrenclave"); err != nil {
			return nil, err
		}
		policy := decodeSGXPolicy(env.SGXSealPolicy)
		s, err := tee.NewIntelSGXSealer(p.EnclaveID(), policy, env.HSMSlot)
		if err != nil {
			return nil, err
		}
		return s.Unseal(sealed, env.AAD)

	case tee.ProviderGCPSEVSNP:
		dev, err := os.OpenFile(sevDev, os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("gcp-sev-snp: open %s: %w", sevDev, err)
		}
		defer func() { _ = dev.Close() }()
		if len(env.SEVMeasurement) != 48 {
			return nil, fmt.Errorf("gcp-sev-snp: sev_measurement must be the 48-byte launch measurement (got %d bytes)", len(env.SEVMeasurement))
		}
		s := tee.NewGCPSEVSealer(dev, tee.Measurement(env.SEVMeasurement), env.SEVPolicy)
		return s.Unseal(sealed, env.AAD)

	default:
		return nil, fmt.Errorf("unsupported provider %q", provider)
	}
}

// assertMeasurementMatches refuses to unseal if the live enclave's
// measurement diverges from what the envelope was sealed against.
// Without this check the Sealer would happily run and the underlying
// TEE-derived key would simply differ — operator gets a confusing
// "AEAD authentication failed" instead of "wrong enclave image".
func assertMeasurementMatches(live tee.Measurement, expected []byte, fieldName string) error {
	if len(expected) == 0 {
		return nil // envelope didn't pin a measurement; trust the TEE itself
	}
	if len(expected) != 32 {
		return fmt.Errorf("envelope %s must be 32 bytes (got %d)", fieldName, len(expected))
	}
	for i := 0; i < 32; i++ {
		if live[i] != expected[i] {
			return fmt.Errorf("measurement mismatch: live enclave %x != envelope %x (recovery from wrong enclave image?)", live[:], expected)
		}
	}
	return nil
}

func decodeSGXPolicy(v int) tee.SGXSealPolicy {
	if v == int(tee.SGXSealMRSIGNER) {
		return tee.SGXSealMRSIGNER
	}
	return tee.SGXSealMRENCLAVE
}
