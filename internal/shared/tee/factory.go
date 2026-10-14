// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"fmt"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Provider names the concrete TEE backend selected by configuration.
//
// The MVP daemon ships with one Provider: ProviderSimulated. Phase 2 plugs
// in real hardware backends (AWS Nitro Enclaves, Azure SGX, GCP SEV-SNP,
// Intel SGX bare metal) without changing call sites — the daemon's
// keystore.LoadMaterials() switches on the configured provider name and
// the rest of the system continues to talk to Producer / Verifier / Sealer
// interfaces.
//
// New providers are added by:
//  1. Implementing Producer + Verifier + Sealer in a new file
//  2. Adding a Provider constant here
//  3. Adding a case to BuildProducer / BuildVerifier in this file
//  4. Passing the contract_test.go suite from a new *_test.go
type Provider string

const (
	// ProviderSimulated is the software-only MVP backend (Ed25519 + AES-GCM).
	// NOT for production. Documented in detail in simulated.go.
	ProviderSimulated Provider = "simulated"

	// ProviderAWSNitro is the AWS Nitro Enclaves backend. Uses the Nitro
	// Secure Module (NSM) on /dev/nsm to produce CBOR-encoded COSE_Sign1
	// attestation documents signed by the AWS PCA root. See aws_nitro.go.
	ProviderAWSNitro Provider = "aws-nitro"

	// ProviderAzureSGX is the Azure Confidential Computing backend (Intel
	// SGX). Uses Microsoft Azure Attestation (MAA) for verification and the
	// SGX SDK for sealing. See azure_sgx.go.
	ProviderAzureSGX Provider = "azure-sgx"

	// ProviderGCPSEVSNP is the GCP Confidential VMs backend (AMD SEV-SNP).
	// Uses /dev/sev-guest for attestation reports signed by the AMD VCEK.
	// See gcp_sev_snp.go.
	ProviderGCPSEVSNP Provider = "gcp-sev-snp"

	// ProviderIntelSGXDCAP is the Intel SGX bare-metal backend using the
	// DCAP attestation flow (no Intel Attestation Service round-trip).
	// Suitable for on-premise sovereign / banking deployments where the
	// operator runs their own Provisioning Certificate Caching Service
	// (PCCS). See intel_sgx_dcap.go.
	ProviderIntelSGXDCAP Provider = "intel-sgx-dcap"

	// ProviderGCPTDX is the GCP Confidential VMs backend on Intel TDX (c3,
	// and a3 with an H100 in confidential mode). Quotes come through
	// configfs-tsm and chain to the Intel SGX Root CA; the platform's TCB
	// is evaluated against Intel PCS. See gcp_tdx.go.
	ProviderGCPTDX Provider = "gcp-tdx"

	// ProviderAzureCGPU is the Azure Confidential VM with NVIDIA H100
	// backend (NCC H100 v5): the SEV-SNP report from the vTPM's HCL report
	// bound to a caller's nonce through a TPM quote by the attestation key
	// the chip named, and NVIDIA's signed attestation tokens for the GPU.
	// See azure_cgpu.go.
	ProviderAzureCGPU Provider = "azure-cgpu"
)

// AllProviders returns every Provider compiled into this binary, in
// stable order. Used by health checks and CLI listings.
func AllProviders() []Provider {
	return []Provider{
		ProviderSimulated,
		ProviderAWSNitro,
		ProviderAzureSGX,
		ProviderGCPSEVSNP,
		ProviderIntelSGXDCAP,
		ProviderGCPTDX,
		ProviderAzureCGPU,
	}
}

// ParseProvider parses a string into a Provider, normalising case and
// hyphenation. Returns an error if the value is not recognised.
func ParseProvider(s string) (Provider, error) {
	norm := Provider(strings.ToLower(strings.TrimSpace(s)))
	for _, p := range AllProviders() {
		if p == norm {
			return p, nil
		}
	}
	return "", shared_errors.Structural(
		shared_errors.CodeFieldValueInvalid,
		fmt.Sprintf("tee: unknown provider %q (valid: %v)", s, AllProviders()),
		nil,
	)
}

// ProducerSpec carries everything BuildProducer needs to materialise a
// Producer for any backend. Fields not relevant to a given Provider are
// ignored — they are documented per-Provider in the constructor for that
// backend.
type ProducerSpec struct {
	// Provider is required.
	Provider Provider

	// WorkloadDescriptor is the canonical bytes describing the workload
	// (e.g., "sagvd-phase1-demo-v1"). For simulated TEE this is hashed
	// into the measurement; for real hardware this is informational and
	// the measurement comes from the chip.
	WorkloadDescriptor []byte

	// SeedPath is the path to a 32-byte Ed25519 seed. Used by simulated
	// only.
	SeedPath string

	// SeedBytes is an in-memory alternative to SeedPath. Used by tests.
	SeedBytes []byte

	// AWS Nitro / Azure / GCP / Intel-specific configuration. Each backend
	// inspects only its own fields.
	AWSNitro  AWSNitroProducerConfig
	AzureSGX  AzureSGXProducerConfig
	GCPSEV    GCPSEVProducerConfig
	IntelSGX  IntelSGXProducerConfig
	GCPTDX    GCPTDXProducerConfig
	AzureCGPU AzureCGPUProducerConfig
}

// VerifierSpec is the verifier-side counterpart to ProducerSpec.
type VerifierSpec struct {
	Provider Provider

	// AttestorPubKey is the producer's signing public key (Ed25519 for
	// simulated; for hardware this is the certificate chain anchor —
	// AWS PCA root, AMD VCEK chain, Intel attestation key).
	AttestorPubKey crypto.PublicKey

	// ExpectedMeasurement is the measurement the producer must attest to.
	// Mismatches return Integrity errors.
	ExpectedMeasurement Measurement

	AWSNitro  AWSNitroVerifierConfig
	AzureSGX  AzureSGXVerifierConfig
	GCPSEV    GCPSEVVerifierConfig
	IntelSGX  IntelSGXVerifierConfig
	GCPTDX    GCPTDXVerifierConfig
	AzureCGPU AzureCGPUVerifierConfig
}

// BuildProducer constructs a Producer for the given Provider. This is the
// single dispatch point for daemon startup — keystore.LoadMaterials calls
// it once after parsing the daemon's TEE configuration.
//
// Backends that require hardware not present on the host return a
// Structural error so the operator sees a clear "you tried to load
// X-backend on a host that doesn't have X capability" message at boot.
func BuildProducer(spec ProducerSpec) (Producer, error) {
	switch spec.Provider {
	case ProviderSimulated:
		seed := spec.SeedBytes
		if seed == nil && spec.SeedPath != "" {
			// Reading from disk is the daemon's responsibility, not this
			// package — leave SeedBytes nil and let the daemon read.
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"tee: simulated provider requires SeedBytes; daemon must read seed file before BuildProducer",
				nil,
			)
		}
		return NewSimulated(spec.WorkloadDescriptor, seed)
	case ProviderAWSNitro:
		return NewAWSNitroProducer(spec.AWSNitro)
	case ProviderAzureSGX:
		return NewAzureSGXProducer(spec.AzureSGX)
	case ProviderGCPSEVSNP:
		return NewGCPSEVProducer(spec.GCPSEV)
	case ProviderIntelSGXDCAP:
		return NewIntelSGXProducer(spec.IntelSGX)
	case ProviderGCPTDX:
		return NewGCPTDXProducer(spec.GCPTDX)
	case ProviderAzureCGPU:
		return NewAzureCGPUProducer(spec.AzureCGPU)
	default:
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee: BuildProducer: unknown provider %q", spec.Provider),
			nil,
		)
	}
}

// BuildVerifier constructs a Verifier for the given Provider.
//
// Verifier construction never touches hardware (all verification math is
// CPU-bound on standard CRYPTO primitives), so this can be called from any
// host — including a bank's air-gapped review machine that holds expected
// measurements but has no enclave of its own.
func BuildVerifier(spec VerifierSpec) (Verifier, error) {
	switch spec.Provider {
	case ProviderSimulated:
		return NewSimulatedVerifier(spec.AttestorPubKey, spec.ExpectedMeasurement), nil
	case ProviderAWSNitro:
		return NewAWSNitroVerifier(spec.AttestorPubKey, spec.ExpectedMeasurement, spec.AWSNitro)
	case ProviderAzureSGX:
		return NewAzureSGXVerifier(spec.AttestorPubKey, spec.ExpectedMeasurement, spec.AzureSGX)
	case ProviderGCPSEVSNP:
		return NewGCPSEVVerifier(spec.AttestorPubKey, spec.ExpectedMeasurement, spec.GCPSEV)
	case ProviderIntelSGXDCAP:
		return NewIntelSGXVerifier(spec.AttestorPubKey, spec.ExpectedMeasurement, spec.IntelSGX)
	case ProviderGCPTDX:
		return NewGCPTDXVerifier(spec.AttestorPubKey, spec.ExpectedMeasurement, spec.GCPTDX)
	case ProviderAzureCGPU:
		return NewAzureCGPUVerifier(spec.AttestorPubKey, spec.ExpectedMeasurement, spec.AzureCGPU)
	default:
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee: BuildVerifier: unknown provider %q", spec.Provider),
			nil,
		)
	}
}

// Capability reports whether the running binary has the libraries +
// runtime environment to actually use a given Provider. Returns a tuple
// (available, reason) — when available is false, reason is a human
// readable diagnostic suitable for daemon startup logs.
//
// The MVP build returns "always available" for ProviderSimulated and
// "compiled but hardware not present" for every other backend. When the
// real adapter is wired (Phase 2), each backend's *_check.go files
// override the Capability() return for that provider.
func Capability(p Provider) (available bool, reason string) {
	switch p {
	case ProviderSimulated:
		return true, "simulated TEE always available (software-only)"
	case ProviderAWSNitro:
		return awsNitroCapability()
	case ProviderAzureSGX:
		return azureSGXCapability()
	case ProviderGCPSEVSNP:
		return gcpSEVCapability()
	case ProviderIntelSGXDCAP:
		return intelSGXCapability()
	case ProviderGCPTDX:
		return gcpTDXCapability()
	case ProviderAzureCGPU:
		return azureCGPUCapability()
	default:
		return false, fmt.Sprintf("unknown provider %q", p)
	}
}
