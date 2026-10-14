// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// materials bundles every piece of key/identity material the daemon
// loads from disk at startup. It is the single construction point for
// the worker's cryptographic surface — main() passes this bundle into
// Daemon, Daemon hands the relevant pieces into returnpath/client at
// session time, and nothing in the hot path ever touches the filesystem.
//
// Lifecycle: produced by LoadMaterials; owned by Daemon until shutdown;
// Zeroize() is called on shutdown to wipe the in-memory keystore.
type materials struct {
	// Store is the InMemoryStore that holds the worker's signing private
	// half and the session-sealing key. It is handed to client.SessionConfig
	// as both Signer and (wrapped as KeyStoreOpener) Opener.
	Store *keys.InMemoryStore

	// SigningKeyID is the kid under which the worker's signing key is
	// registered. The vault side's PublicKeyResolver MUST have the
	// matching VerifyingKey (same kid, same 32-byte pubkey) registered
	// for CandidateOutputFrame signatures to verify.
	SigningKeyID ids.KeyID

	// SigningPublicKey is the 32-byte Ed25519 public key corresponding
	// to SigningKeyID. Exposed only so the daemon can log it once at
	// startup (operators copy it into sagvd config).
	SigningPublicKey crypto.PublicKey

	// SealingKeyID is the kid under which the session-sealing material
	// is registered. JobRequest.SealedMaterialRef.RecipientKeyID on the
	// wire MUST match this string form.
	SealingKeyID ids.KeyID

	// Producer is the worker's TEE: the chip (gcp-sev-snp) or the
	// simulated one, per tee.provider. The daemon wiring is the same.
	Producer tee.Producer

	// Provider names what Producer is.
	Provider tee.Provider

	// Verifier verifies sagvd's TEE evidence during the 4-frame
	// handshake, built for the peer's provider and pinned to its
	// measurement (and, for a simulated peer, its key).
	Verifier tee.Verifier

	// PeerProvider names what Verifier verifies.
	PeerProvider tee.Provider
}

// LoadMaterials reads all key material referenced by cfg from disk,
// registers the signing and sealing keys in a fresh InMemoryStore, and
// constructs the local TEE producer plus the peer verifier.
//
// File formats (all raw binary, no encoding):
//   - TEE seed file:            32 bytes (Ed25519 seed; simulated provider only)
//   - Worker signing seed file: 32 bytes (Ed25519 seed for CandidateOutputFrame signing)
//   - Session sealing key file: 32 bytes (AES-256 key, pre-shared with sagvd)
//   - Peer TEE pubkey file:     32 bytes (Ed25519 public key; simulated peer only)
//   - Peer TEE measurement:     32 bytes (simulated) or 48 bytes (SEV-SNP launch measurement)
//   - Peer AMD cert chain:      PEM, ASK then ARK (SEV-SNP peer only)
//
// Every file is read with strict length checking; anything else is a
// Structural configuration error. Modes are not inspected here — operator
// hygiene is a deployment concern, not a runtime one.
func LoadMaterials(cfg Config, clock shared_time.Clock) (*materials, error) {
	// 1. Local TEE producer per tee.provider.
	provider, producer, err := buildTEEProducer(cfg.TEE)
	if err != nil {
		return nil, err
	}

	// 2. Peer verifier per tee.peer.provider, pinned to the peer's measurement.
	peerProvider, verifier, err := buildPeerVerifier(cfg.TEE.Peer)
	if err != nil {
		return nil, err
	}

	// 3. Worker signing seed → register under cfg.Keys.WorkerSigning.KeyID.
	signingSeed, err := readSecret(cfg.TEE, cfg.Keys.WorkerSigning.SeedPath, crypto.Ed25519SeedSize, "keys.worker_signing.seed_path")
	if err != nil {
		return nil, err
	}
	store := keys.NewInMemoryStore(clock)
	signingKID := ids.KeyID(cfg.Keys.WorkerSigning.KeyID)
	vk, err := store.RegisterSigningFromSeed(signingKID, keys.PurposeSigningAuthority, signingSeed)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: register worker signing key: %w", err)
	}

	// 4. Session sealing key → register under cfg.Keys.SessionSealing.KeyID.
	sealingMat, err := readSecret(cfg.TEE, cfg.Keys.SessionSealing.MaterialPath, crypto.AES256KeySize, "keys.session_sealing.material_path")
	if err != nil {
		return nil, err
	}
	sealingKID := ids.KeyID(cfg.Keys.SessionSealing.KeyID)
	if err := store.RegisterSealing(sealingKID, sealingMat); err != nil {
		return nil, fmt.Errorf("acp-compute: register session sealing key: %w", err)
	}
	// Sealing material has been defensively copied inside the store;
	// wipe our in-process copy so a post-mortem core dump does not leak
	// it through this code path.
	for i := range sealingMat {
		sealingMat[i] = 0
	}

	return &materials{
		Store:            store,
		SigningKeyID:     signingKID,
		SigningPublicKey: vk.PublicKey,
		SealingKeyID:     sealingKID,
		Producer:         producer,
		Provider:         provider,
		Verifier:         verifier,
		PeerProvider:     peerProvider,
	}, nil
}

// buildTEEProducer constructs the local TEE producer per cfg.Provider:
// the chip through configfs-tsm, or the simulated one from its seed.
func buildTEEProducer(cfg TEEConfig) (tee.Provider, tee.Producer, error) {
	provider, err := cfg.ProviderKind()
	if err != nil {
		return "", nil, fmt.Errorf("acp-compute: tee.provider: %w", err)
	}
	switch provider {
	case tee.ProviderGCPSEVSNP:
		p, err := tee.NewGCPSEVProducer(tee.GCPSEVProducerConfig{TSMReportDir: cfg.TSMReportDir})
		if err != nil {
			return "", nil, fmt.Errorf("acp-compute: tee.provider=gcp-sev-snp: %w", err)
		}
		return provider, p, nil
	case tee.ProviderGCPTDX:
		p, err := tee.NewGCPTDXProducer(tee.GCPTDXProducerConfig{TSMReportDir: cfg.TSMReportDir})
		if err != nil {
			return "", nil, fmt.Errorf("acp-compute: tee.provider=gcp-tdx: %w", err)
		}
		return provider, p, nil
	case tee.ProviderAzureCGPU:
		p, err := tee.NewAzureCGPUProducer(tee.AzureCGPUProducerConfig{GPUAttestCommand: cfg.GPUAttestCommand, TPM2ToolsDir: cfg.TPM2ToolsDir, AKHandle: cfg.AKHandle})
		if err != nil {
			return "", nil, fmt.Errorf("acp-compute: tee.provider=azure-cgpu: %w", err)
		}
		return provider, p, nil
	case tee.ProviderSimulated:
		seed, err := readExactly(cfg.SeedPath, crypto.Ed25519SeedSize, "tee.seed_path")
		if err != nil {
			return "", nil, err
		}
		p, err := tee.NewSimulated([]byte(cfg.WorkloadDescriptor), seed)
		if err != nil {
			return "", nil, fmt.Errorf("acp-compute: construct simulated TEE: %w", err)
		}
		return provider, p, nil
	default:
		return "", nil, fmt.Errorf("acp-compute: tee.provider %q is not available in this build (supported: %v)", cfg.Provider, supportedProviders)
	}
}

// buildPeerVerifier constructs the verifier for the vault's TEE per
// cfg.Provider, pinned to the measurement file: by attestation key for a
// simulated peer, by the AMD certificate chain for a SEV-SNP peer.
func buildPeerVerifier(cfg PeerTEEConfig) (tee.Provider, tee.Verifier, error) {
	provider, err := cfg.ProviderKind()
	if err != nil {
		return "", nil, fmt.Errorf("acp-compute: tee.peer.provider: %w", err)
	}
	measurement, err := readMeasurement(cfg.MeasurementPath, "tee.peer.measurement_path")
	if err != nil {
		return "", nil, err
	}
	spec := tee.VerifierSpec{Provider: provider, ExpectedMeasurement: measurement}
	switch provider {
	case tee.ProviderSimulated:
		pub, err := readExactly(cfg.PublicKeyPath, crypto.Ed25519PublicKeySize, "tee.peer.public_key_path")
		if err != nil {
			return "", nil, err
		}
		spec.AttestorPubKey = crypto.PublicKey(pub)
	case tee.ProviderGCPSEVSNP:
		if len(measurement) != 48 {
			return "", nil, fmt.Errorf("acp-compute: tee.peer.measurement_path (%q) must hold a 48-byte SEV-SNP launch measurement (got %d bytes)", cfg.MeasurementPath, len(measurement))
		}
		chain, err := os.ReadFile(cfg.AMDCertChainPath)
		if err != nil {
			return "", nil, fmt.Errorf("acp-compute: read tee.peer.amd_cert_chain_path (%q): %w", cfg.AMDCertChainPath, err)
		}
		spec.GCPSEV = tee.GCPSEVVerifierConfig{
			AMDRootPEM:     chain,
			AMDKDSURL:      cfg.AMDKDSURL,
			VCEKCacheDir:   cfg.VCEKCacheDir,
			MinReportedTCB: cfg.MinReportedTCB,
		}
	case tee.ProviderGCPTDX:
		if len(measurement) != 48 {
			return "", nil, fmt.Errorf("acp-compute: tee.peer.measurement_path (%q) must hold the 48-byte TDX measurement (SHA-384 of MRTD and RTMR0..3, as `identity` prints it; got %d bytes)", cfg.MeasurementPath, len(measurement))
		}
		spec.GCPTDX = tee.GCPTDXVerifierConfig{PCSURL: cfg.PCSURL, PCSCacheDir: cfg.PCSCacheDir, AcceptableTCBStatuses: cfg.AcceptableTCBStatuses}
	case tee.ProviderAzureCGPU:
		if len(measurement) != 48 {
			return "", nil, fmt.Errorf("acp-compute: tee.peer.measurement_path (%q) must hold a 48-byte SEV-SNP launch measurement (got %d bytes)", cfg.MeasurementPath, len(measurement))
		}
		chain, err := os.ReadFile(cfg.AMDCertChainPath)
		if err != nil {
			return "", nil, fmt.Errorf("acp-compute: read tee.peer.amd_cert_chain_path (%q): %w", cfg.AMDCertChainPath, err)
		}
		digests, err := pcrDigests(cfg.PCRDigests)
		if err != nil {
			return "", nil, fmt.Errorf("acp-compute: tee.peer.%w", err)
		}
		spec.AzureCGPU = tee.AzureCGPUVerifierConfig{AMDRootPEM: chain, AMDKDSURL: cfg.AMDKDSURL, VCEKCacheDir: cfg.VCEKCacheDir, MinReportedTCB: cfg.MinReportedTCB,
			NRASJWKSURL: cfg.NRASJWKSURL, NRASCacheDir: cfg.NRASCacheDir, GPU: cfg.GPUPolicy.policy(), AcceptablePCRDigests: digests}
		if err := cfg.GPUPolicy.apply(&spec.AzureCGPU); err != nil {
			return "", nil, fmt.Errorf("acp-compute: tee.peer.%w", err)
		}
	default:
		return "", nil, fmt.Errorf("acp-compute: tee.peer.provider %q: no verifier this build can run end to end (supported: %v)", cfg.Provider, supportedProviders)
	}
	v, err := tee.BuildVerifier(spec)
	if err != nil {
		return "", nil, fmt.Errorf("acp-compute: build verifier for tee.peer.provider=%s: %w", provider, err)
	}
	return provider, v, nil
}

// readExactly reads path and returns its contents if and only if the
// file is exactly wantLen bytes. Any other length is a Structural error
// wrapped with the logical config field name for operator diagnosis.
// Errors are plain errors (not shared_errors.*) because this is main-
// package provisioning, not contract-surface logic.
func readExactly(path string, wantLen int, fieldName string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: read %s (%q): %w", fieldName, path, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf(
			"acp-compute: %s (%q) must be exactly %d bytes (got %d)",
			fieldName, path, wantLen, len(b))
	}
	return b, nil
}

// readMeasurement reads a whole TEE measurement: 32 bytes (SHA-256), or
// 48 / 64 bytes as SEV-SNP, Nitro and SHA-512 measurements are. It is
// pinned exactly as the hardware reports it, never truncated to fit
// (ADR 0007).
func readMeasurement(path, fieldName string) (tee.Measurement, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: read %s (%q): %w", fieldName, path, err)
	}
	m, err := tee.MeasurementFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("acp-compute: %s (%q): %w", fieldName, path, err)
	}
	return m, nil
}
