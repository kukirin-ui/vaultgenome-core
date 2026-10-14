// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/server"
	"github.com/vault-genome/vaultgenome-core/internal/observability/teemetrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// materials bundles every piece of key / identity material the sagvd
// daemon loads from disk at startup. It is the single construction
// point for the vault's cryptographic surface — main() passes this
// bundle into Daemon, Daemon hands the relevant pieces into
// returnpath/server at session time, and nothing in the hot path ever
// touches the filesystem.
//
// Lifecycle: produced by LoadMaterials; owned by Daemon until
// shutdown; Zeroize() is called on shutdown to wipe the in-memory
// keystore.
type materials struct {
	// Store is the InMemoryStore that holds the vault's authority-
	// signing private half and the session-sealing key. It is used
	// as Signer (for authority artifacts, Phase 3 forward) and as
	// Sealer (for SealedMaterialRef production on every JobRequest).
	Store *keys.InMemoryStore

	// AuthoritySigningKeyID is the kid under which the vault's
	// authority-signing key is registered.
	AuthoritySigningKeyID ids.KeyID

	// AuthoritySigningPublicKey is the 32-byte Ed25519 public key
	// corresponding to AuthoritySigningKeyID. Exposed only so the
	// daemon can log it once at startup.
	AuthoritySigningPublicKey crypto.PublicKey

	// SessionSealingKeyID is the kid under which the session-sealing
	// material is registered. JobRequest.SealedMaterialRef.RecipientKeyID
	// on the wire equals this string form.
	SessionSealingKeyID ids.KeyID

	// Producer is the vault's TEE: the chip (gcp-sev-snp) or the
	// simulated one, per tee.provider. The daemon wiring is the same.
	Producer tee.Producer

	// Provider names what Producer is.
	Provider tee.Provider

	// Verifier verifies the worker's TEE evidence during the 4-frame
	// handshake, built for the peer's provider and pinned to its
	// measurement (and, for a simulated peer, its key).
	Verifier tee.Verifier

	// PeerProvider names what Verifier verifies.
	PeerProvider tee.Provider

	// WorkerResolver is the read-only keys.Resolver that produces a
	// VerifyingKey for each CandidateOutputFrame.WorkerSigningKeyID
	// the server receives. Loaded from the workers.registry_path
	// JSON file.
	WorkerResolver *server.PublicKeyResolver

	// WorkerEntries is the parsed registry file (kid + note),
	// exposed only so the daemon can log accepted workers once at
	// startup.
	WorkerEntries []WorkerEntry

	// Escrow is the authority's escrow private key, opened in memory
	// from the sealed file key_escrow_path names (ADR 0016); nil when
	// no escrow key is configured. EscrowSource says how it was kept
	// on disk: "sealed:<tee>" or "plaintext" (simulation only).
	Escrow       *ecdh.PrivateKey
	EscrowSource string

	tee     TEEConfig
	sealer  tee.Sealer
	closers []io.Closer
}

// TEESealer is the sealer of this host's TEE: the simulated one, or the
// chip's derived key through the sev-guest device, opened on first use.
func (m *materials) TEESealer() (tee.Sealer, error) {
	if m.sealer != nil {
		return m.sealer, nil
	}
	// The chip's derived key on SEV-SNP (ADR 0016), the guest's vTPM under a
	// policy of this boot's PCRs on TDX and the Azure confidential GPU host
	// (ADR 0022), the simulated TEE's weak key off hardware.
	s, closer, err := tee.SealerFor(m.Producer, tee.SealerOptions{SEVGuestDevice: m.tee.SEVDevice(), TPM2ToolsDir: m.tee.TPM2ToolsDir, VTPMSealPCRs: m.tee.VTPMSealPCRs})
	if err != nil {
		return nil, fmt.Errorf("sagvd: tee.provider %s (tee.sev_guest_device, tee.tpm2_tools_dir, tee.vtpm_seal_pcrs): %w", m.Provider, err)
	}
	if closer != nil {
		m.closers = append(m.closers, closer)
	}
	m.sealer = s
	return m.sealer, nil
}

// Close releases what the materials hold open.
func (m *materials) Close() error {
	var errs []error
	for _, c := range m.closers {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	m.closers = nil
	return errors.Join(errs...)
}

// LoadMaterials reads all key material referenced by cfg from disk,
// registers the authority-signing and session-sealing keys in a fresh
// InMemoryStore, constructs the local simulated TEE plus the peer
// verifier, and builds a PublicKeyResolver over the worker registry.
//
// File formats (all raw binary, no encoding — matches the shapes
// acp-compute uses):
//
//   - TEE seed file:              32 bytes (Ed25519 seed)
//   - Authority signing seed:     32 bytes (Ed25519 seed)
//   - Session sealing key file:   32 bytes (AES-256 key, pre-shared with worker)
//   - Peer (worker) TEE pubkey:   32 bytes (Ed25519 public key)
//   - Peer (worker) TEE measure:  32 bytes (SHA-256 measurement)
//
// Worker registry file is JSON — see workers.go.
//
// Every binary file is read with strict length checking; anything
// else is a Structural configuration error. File modes are not
// inspected here — operator hygiene is a deployment concern, not a
// runtime one.
func LoadMaterials(cfg Config, clock shared_time.Clock) (*materials, error) {
	// 1. Local TEE producer per tee.provider.
	provider, producer, err := buildTEEProducer(cfg.TEE)
	if err != nil {
		return nil, err
	}

	// 2. Peer verifier per tee.peer.provider, pinned to the worker's
	//    measurement. The vault accepts exactly one worker TEE identity.
	peerProvider, verifier, err := buildPeerVerifier(cfg.TEE.Peer)
	if err != nil {
		return nil, err
	}

	// 3. Authority signing seed → register under cfg.Keys.AuthoritySigning.KeyID.
	authSeed, err := readSecret(cfg.TEE, cfg.Keys.AuthoritySigning.SeedPath, crypto.Ed25519SeedSize, "keys.authority_signing.seed_path")
	if err != nil {
		return nil, err
	}
	store := keys.NewInMemoryStore(clock)
	authKID := ids.KeyID(cfg.Keys.AuthoritySigning.KeyID)
	vk, err := store.RegisterSigningFromSeed(authKID, keys.PurposeSigningAuthority, authSeed)
	if err != nil {
		return nil, fmt.Errorf("sagvd: register authority signing key: %w", err)
	}

	// 4. Session sealing key → register under cfg.Keys.SessionSealing.KeyID.
	sealingMat, err := readSecret(cfg.TEE, cfg.Keys.SessionSealing.MaterialPath, crypto.AES256KeySize, "keys.session_sealing.material_path")
	if err != nil {
		return nil, err
	}
	sealingKID := ids.KeyID(cfg.Keys.SessionSealing.KeyID)
	if err := store.RegisterSealing(sealingKID, sealingMat); err != nil {
		return nil, fmt.Errorf("sagvd: register session sealing key: %w", err)
	}
	// Sealing material has been defensively copied inside the store;
	// wipe our in-process copy so a post-mortem core dump does not
	// leak it through this code path.
	for i := range sealingMat {
		sealingMat[i] = 0
	}

	// 5. Worker registry → PublicKeyResolver for CandidateOutputFrame
	//    signature verification.
	resolver, entries, err := LoadWorkerRegistry(cfg.Workers.RegistryPath)
	if err != nil {
		return nil, err
	}

	m := &materials{
		Store:                     store,
		AuthoritySigningKeyID:     authKID,
		AuthoritySigningPublicKey: vk.PublicKey,
		SessionSealingKeyID:       sealingKID,
		Producer:                  producer,
		Provider:                  provider,
		Verifier:                  verifier,
		PeerProvider:              peerProvider,
		WorkerResolver:            resolver,
		WorkerEntries:             entries,
		tee:                       cfg.TEE,
	}

	// 6. The escrow private key, when configured: unsealed on this host's
	//    TEE and held in memory (ADR 0016).
	if path := cfg.EscrowKeyPath(); path != "" {
		m.Escrow, m.EscrowSource, err = loadEscrowKey(path, m)
		if err != nil {
			_ = m.Close()
			return nil, err
		}
	}
	return m, nil
}

// buildTEEProducer constructs the local TEE producer per cfg.Provider:
// the chip through configfs-tsm, or the simulated one from its seed.
func buildTEEProducer(cfg TEEConfig) (tee.Provider, tee.Producer, error) {
	provider, err := cfg.ProviderKind()
	if err != nil {
		return "", nil, fmt.Errorf("sagvd: tee.provider: %w", err)
	}
	switch provider {
	case tee.ProviderGCPSEVSNP:
		p, err := tee.NewGCPSEVProducer(tee.GCPSEVProducerConfig{TSMReportDir: cfg.TSMReportDir})
		if err != nil {
			return "", nil, fmt.Errorf("sagvd: tee.provider=gcp-sev-snp: %w", err)
		}
		return provider, p, nil
	case tee.ProviderGCPTDX:
		p, err := tee.NewGCPTDXProducer(tee.GCPTDXProducerConfig{TSMReportDir: cfg.TSMReportDir})
		if err != nil {
			return "", nil, fmt.Errorf("sagvd: tee.provider=gcp-tdx: %w", err)
		}
		return provider, p, nil
	case tee.ProviderAzureCGPU:
		p, err := tee.NewAzureCGPUProducer(tee.AzureCGPUProducerConfig{GPUAttestCommand: cfg.GPUAttestCommand, TPM2ToolsDir: cfg.TPM2ToolsDir, AKHandle: cfg.AKHandle})
		if err != nil {
			return "", nil, fmt.Errorf("sagvd: tee.provider=azure-cgpu: %w", err)
		}
		return provider, p, nil
	case tee.ProviderSimulated:
		seed, err := readExactly(cfg.SeedPath, crypto.Ed25519SeedSize, "tee.seed_path")
		if err != nil {
			return "", nil, err
		}
		p, err := tee.NewSimulated([]byte(cfg.WorkloadDescriptor), seed)
		if err != nil {
			return "", nil, fmt.Errorf("sagvd: construct simulated TEE: %w", err)
		}
		return provider, p, nil
	default:
		return "", nil, fmt.Errorf("sagvd: tee.provider %q is not available in this build (supported: %v)", cfg.Provider, supportedProviders)
	}
}

// buildPeerVerifier constructs the verifier for the worker's TEE per
// cfg.Provider, pinned to the measurement file: by attestation key for a
// simulated peer, by the AMD certificate chain for a SEV-SNP peer.
func buildPeerVerifier(cfg PeerTEEConfig) (tee.Provider, tee.Verifier, error) {
	provider, err := cfg.ProviderKind()
	if err != nil {
		return "", nil, fmt.Errorf("sagvd: tee.peer.provider: %w", err)
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
			return "", nil, fmt.Errorf("sagvd: tee.peer.measurement_path (%q) must hold a 48-byte SEV-SNP launch measurement (got %d bytes)", cfg.MeasurementPath, len(measurement))
		}
		chain, err := os.ReadFile(cfg.AMDCertChainPath)
		if err != nil {
			return "", nil, fmt.Errorf("sagvd: read tee.peer.amd_cert_chain_path (%q): %w", cfg.AMDCertChainPath, err)
		}
		spec.GCPSEV = tee.GCPSEVVerifierConfig{
			AMDRootPEM:     chain,
			AMDKDSURL:      cfg.AMDKDSURL,
			VCEKCacheDir:   cfg.VCEKCacheDir,
			MinReportedTCB: cfg.MinReportedTCB,
		}
	case tee.ProviderGCPTDX:
		if len(measurement) != 48 {
			return "", nil, fmt.Errorf("sagvd: tee.peer.measurement_path (%q) must hold the 48-byte TDX measurement (SHA-384 of MRTD and RTMR0..3, as `identity` prints it; got %d bytes)", cfg.MeasurementPath, len(measurement))
		}
		spec.GCPTDX = tee.GCPTDXVerifierConfig{PCSURL: cfg.PCSURL, PCSCacheDir: cfg.PCSCacheDir, AcceptableTCBStatuses: cfg.AcceptableTCBStatuses}
	case tee.ProviderAzureCGPU:
		if len(measurement) != 48 {
			return "", nil, fmt.Errorf("sagvd: tee.peer.measurement_path (%q) must hold a 48-byte SEV-SNP launch measurement (got %d bytes)", cfg.MeasurementPath, len(measurement))
		}
		chain, err := os.ReadFile(cfg.AMDCertChainPath)
		if err != nil {
			return "", nil, fmt.Errorf("sagvd: read tee.peer.amd_cert_chain_path (%q): %w", cfg.AMDCertChainPath, err)
		}
		digests, err := pcrDigests(cfg.PCRDigests)
		if err != nil {
			return "", nil, fmt.Errorf("sagvd: tee.peer.%w", err)
		}
		spec.AzureCGPU = tee.AzureCGPUVerifierConfig{AMDRootPEM: chain, AMDKDSURL: cfg.AMDKDSURL, VCEKCacheDir: cfg.VCEKCacheDir, MinReportedTCB: cfg.MinReportedTCB,
			NRASJWKSURL: cfg.NRASJWKSURL, NRASCacheDir: cfg.NRASCacheDir, GPU: cfg.GPUPolicy.policy(), AcceptablePCRDigests: digests}
		if err := cfg.GPUPolicy.apply(&spec.AzureCGPU); err != nil {
			return "", nil, fmt.Errorf("sagvd: tee.peer.%w", err)
		}
	default:
		return "", nil, fmt.Errorf("sagvd: tee.peer.provider %q: no verifier this build can run end to end (supported: %v)", cfg.Provider, supportedProviders)
	}
	v, err := tee.BuildVerifier(spec)
	if err != nil {
		return "", nil, fmt.Errorf("sagvd: build verifier for tee.peer.provider=%s: %w", provider, err)
	}
	return provider, v, nil
}

// InstrumentTEE wraps the materials' Producer and Verifier with the
// teemetrics.Recorder so every Quote / Verify call records the
// vg_tee_attestation_* counters and histograms. Call this once during
// daemon startup after the metrics registry has been created and
// before the daemon takes ownership of the materials.
//
// The provider label is "simulated" in Phase 1; when the daemon's
// keystore loader supports the real-hardware backends (AWS Nitro,
// Azure SGX, GCP SEV-SNP, Intel SGX bare metal), the value moves to
// the configured tee.Provider name and the wrapper is identical.
func (m *materials) InstrumentTEE(rec *teemetrics.Recorder, provider string) {
	if rec == nil || m == nil {
		return
	}
	if m.Producer != nil {
		m.Producer = rec.WrapProducer(provider, m.Producer)
	}
	if m.Verifier != nil {
		m.Verifier = rec.WrapVerifier(provider, m.Verifier)
	}
}

// readExactly reads path and returns its contents if and only if the
// file is exactly wantLen bytes. Any other length is a Structural
// error wrapped with the logical config field name for operator
// diagnosis. Errors are plain errors (not shared_errors.*) because
// this is main-package provisioning, not contract-surface logic.
func readExactly(path string, wantLen int, fieldName string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read %s (%q): %w", fieldName, path, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf(
			"sagvd: %s (%q) must be exactly %d bytes (got %d)",
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
		return nil, fmt.Errorf("sagvd: read %s (%q): %w", fieldName, path, err)
	}
	m, err := tee.MeasurementFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("sagvd: %s (%q): %w", fieldName, path, err)
	}
	return m, nil
}
