// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Config is the full on-disk configuration for the acp-compute
// worker daemon. Every field is frozen for the Phase-1 investor
// demo; additions are a minor-version change and must update
// `cmd/acp-compute/doc.go`.
type Config struct {
	// Vault is where to dial sagvd and how.
	Vault VaultConfig `json:"vault"`

	// TEE configures the simulated TEE the worker presents during
	// the Return-Path handshake. In Phase 3 this section is replaced
	// by a hardware-backed backend with identical surface.
	TEE TEEConfig `json:"tee"`

	// Keys points at the on-disk material the worker uses to sign
	// CandidateOutputFrame and to unseal SealedMaterial.
	Keys KeysConfig `json:"keys"`

	// Genome configures the reconstruction backend: the door the worker
	// runs to bring a sealed genome's model back in memory and recompute
	// its reference fixtures (internal/compute/worker.GenomeReconstructor).
	Genome GenomeConfig `json:"genome"`

	// Runtime tunables for the dial/serve loop.
	Runtime RuntimeConfig `json:"runtime"`

	// Health controls the local HTTP server that exposes /healthz,
	// /readyz and /metrics. Empty ListenAddress disables the server
	// (useful in tests).
	Health HealthConfig `json:"health"`

	// Log controls structured-logging format and verbosity.
	Log LogConfig `json:"log"`
}

// VaultConfig aggregates how the worker reaches sagvd.
type VaultConfig struct {
	// Address is the host:port the worker dials (outbound only).
	Address string `json:"address"`

	// TLS configures mutual TLS. When Enabled=false the worker dials
	// plain TCP — permitted only for loopback / demo use.
	TLS TLSConfig `json:"tls"`
}

// TLSConfig holds client-side mTLS material. All file paths are
// resolved relative to the process working directory.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CABundle   string `json:"ca_bundle"`
	ServerName string `json:"server_name"`
}

// TEEConfig names the TEE this worker attests with on the Return Path
// and pins the vault's TEE it will accept.
type TEEConfig struct {
	// Provider is the local TEE backend: "gcp-sev-snp" (AMD SEV-SNP
	// reports through the kernel's configfs-tsm, on any SEV-SNP guest
	// with Linux 6.7 or later — the chip signs) or "simulated" (a key
	// read from SeedPath signs; no hardware isolation; development and
	// tests only). Default "simulated".
	Provider string `json:"provider,omitempty"`

	// WorkloadDescriptor names this workload. The simulated provider
	// hashes it into its measurement; a hardware provider records it
	// and attests with the launch measurement the chip reports.
	WorkloadDescriptor string `json:"workload_descriptor"`

	// SeedPath is a 32-byte file holding the Ed25519 seed the simulated
	// provider signs Evidence with. Sensitive — chmod 0600. Simulated
	// only.
	SeedPath string `json:"seed_path,omitempty"`

	// TSMReportDir overrides the configfs-tsm report directory (default
	// /sys/kernel/config/tsm/report). gcp-sev-snp only.
	TSMReportDir string `json:"tsm_report_dir,omitempty"`

	// GPUAttestCommand, TPM2ToolsDir and AKHandle configure the
	// azure-cgpu producer: the command that obtains NVIDIA's signed
	// attestation tokens for a nonce (the nonce is appended; required),
	// where tpm2-tools live (default PATH), and the vTPM handle of the
	// HCL attestation key (default: found by its public key). azure-cgpu
	// only.
	GPUAttestCommand []string `json:"gpu_attest_command,omitempty"`
	TPM2ToolsDir     string   `json:"tpm2_tools_dir,omitempty"`
	AKHandle         string   `json:"ak_handle,omitempty"`

	// SEVGuestDevice is the sev-guest device a gcp-sev-snp host seals its
	// key files through (default /dev/sev-guest); VTPMSealPCRs the PCR
	// selection a gcp-tdx or azure-cgpu host seals them to (default
	// sha256:0-14). ADR 0023: `acp-compute seal-keys`.
	SEVGuestDevice string `json:"sev_guest_device,omitempty"`
	VTPMSealPCRs   string `json:"vtpm_seal_pcrs,omitempty"`

	// Peer holds the trust-anchor material for sagvd's side.
	Peer PeerTEEConfig `json:"peer"`

	// InsecureSimulation must be true to run the simulated provider:
	// its Evidence is signed by a key read from SeedPath, with no
	// hardware isolation. The flag puts that in the config itself.
	// Simulated only.
	InsecureSimulation bool `json:"insecure_simulation,omitempty"`
}

// PeerTEEConfig pins the vault-side TEE the worker will accept.
type PeerTEEConfig struct {
	// Provider is the vault's TEE backend: "simulated" (default) or
	// "gcp-sev-snp". The verifier for it runs here; verification never
	// needs hardware.
	Provider string `json:"provider,omitempty"`

	// PublicKeyPath is the vault's 32-byte raw Ed25519 attestation key.
	// Simulated peers only; a SEV-SNP report is signed by the chip's
	// VCEK, which chains to AMD.
	PublicKeyPath string `json:"public_key_path,omitempty"`

	// MeasurementPath is the vault's launch measurement, raw: 32 bytes
	// for a simulated peer, 48 for SEV-SNP (never truncated, ADR 0007).
	MeasurementPath string `json:"measurement_path"`

	// AMDCertChainPath is the AMD ASK+ARK certificate chain (PEM) the
	// vault's VCEK must chain to. gcp-sev-snp peers only; required.
	AMDCertChainPath string `json:"amd_cert_chain_path,omitempty"`

	// AMDKDSURL overrides the AMD KDS base URL (a mirror). gcp-sev-snp
	// peers only.
	AMDKDSURL string `json:"amd_kds_url,omitempty"`

	// VCEKCacheDir keeps fetched VCEK certificates on disk so each chip
	// is asked of AMD KDS once; a cached certificate is still checked
	// against the pinned chain on every use. gcp-sev-snp peers only.
	VCEKCacheDir string `json:"vcek_cache_dir,omitempty"`

	// MinReportedTCB is the lowest REPORTED_TCB accepted from the vault.
	// gcp-sev-snp peers only.
	MinReportedTCB uint64 `json:"min_reported_tcb,omitempty"`
	// PCSURL overrides the Intel PCS base URL (a mirror, a PCCS); PCSCacheDir
	// keeps the TCB info and QE identity documents between runs, each
	// checked like a fresh one on every use; AcceptableTCBStatuses lists
	// the Intel TCB statuses accepted (default UpToDate only; OutOfDate and
	// Revoked never). gcp-tdx peers only.
	PCSURL                string   `json:"pcs_url,omitempty"`
	PCSCacheDir           string   `json:"pcs_cache_dir,omitempty"`
	AcceptableTCBStatuses []string `json:"acceptable_tcb_statuses,omitempty"`

	// NRASJWKSURL overrides NVIDIA's attestation key-set URL; NRASCacheDir
	// keeps the key set between runs; GPUPolicy is what the GPU's claims
	// must say. azure-cgpu peers only, which also take the AMD fields
	// above (amd_cert_chain_path is the Genoa chain for NCC H100 v5).
	NRASJWKSURL  string           `json:"nras_jwks_url,omitempty"`
	NRASCacheDir string           `json:"nras_cache_dir,omitempty"`
	GPUPolicy    *GPUPolicyConfig `json:"gpu_policy,omitempty"`
	// PCRDigests (hex, 32 bytes each), when set, pin what the peer's vTPM
	// measured of its boot: the quote's PCR digest must be one of them
	// (`identity` prints it as vtpm.pcr_digest_hex). azure-cgpu peers only.
	PCRDigests []string `json:"pcr_digests,omitempty"`
}

// pcrDigests decodes PCRDigests; a malformed entry is a config error.
func pcrDigests(hexes []string) ([][]byte, error) {
	out := make([][]byte, 0, len(hexes))
	for _, h := range hexes {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("pcr_digests: %q is not a 32-byte hex digest", h)
		}
		out = append(out, b)
	}
	return out, nil
}

// GPUPolicyConfig is the operator's word on NVIDIA's per-GPU claims.
type GPUPolicyConfig struct {
	AllowSecureBootOff bool     `json:"allow_secure_boot_off,omitempty"`
	AllowDebug         bool     `json:"allow_debug,omitempty"`
	AllowUnsignedRIM   bool     `json:"allow_unsigned_rim,omitempty"`
	HWModels           []string `json:"hw_models,omitempty"`
	DriverVersions     []string `json:"driver_versions,omitempty"`
	VBIOSVersions      []string `json:"vbios_versions,omitempty"`
	// Evaluation says whose evaluation of the GPU's report the verdict
	// rests on: "nras" (default) takes NVIDIA's signed tokens; "both"
	// requires them and the verifier's own evaluation of the attestation
	// report the evidence carries — the chain to NVIDIA's device root,
	// the report's signature and nonce, the firmware id, and the runtime
	// measurements against NVIDIA's reference manifests (ADR 0021).
	// "own" is refused by this build (the manifests' XML signatures are
	// not verified). With "both", RIMServiceURL and RIMCacheDir say where
	// the manifests come from and are kept; the NVIDIA roots are pinned in
	// the binary unless NVIDIADeviceRootPath / NVIDIARIMRootPath name
	// other PEM files.
	Evaluation           string `json:"evaluation,omitempty"`
	RIMServiceURL        string `json:"rim_service_url,omitempty"`
	RIMCacheDir          string `json:"rim_cache_dir,omitempty"`
	NVIDIADeviceRootPath string `json:"nvidia_device_root_path,omitempty"`
	NVIDIARIMRootPath    string `json:"nvidia_rim_root_path,omitempty"`
}

func (g *GPUPolicyConfig) policy() tee.GPUClaimsPolicy {
	if g == nil {
		return tee.GPUClaimsPolicy{}
	}
	return tee.GPUClaimsPolicy{AllowSecureBootOff: g.AllowSecureBootOff, AllowDebug: g.AllowDebug, AllowUnsignedRIM: g.AllowUnsignedRIM,
		AcceptableHWModels: g.HWModels, AcceptableDriverVersions: g.DriverVersions, AcceptableVBIOSVersions: g.VBIOSVersions}
}

// validate checks the evaluation named, if any.
func (g *GPUPolicyConfig) validate() error {
	if g == nil {
		return nil
	}
	switch g.Evaluation {
	case "", tee.GPUEvaluationNRAS, tee.GPUEvaluationBoth:
		return nil
	case tee.GPUEvaluationOwn:
		return errors.New("gpu_policy.evaluation \"own\" would rest the verdict on the verifier's evaluation alone, and this build does not verify the manifests' XML signatures; use \"both\"")
	default:
		return fmt.Errorf("gpu_policy.evaluation %q (one of nras, both)", g.Evaluation)
	}
}

// apply sets the evaluation fields of a verifier config from the policy,
// reading the root PEM files it names.
func (g *GPUPolicyConfig) apply(cfg *tee.AzureCGPUVerifierConfig) error {
	if g == nil {
		return nil
	}
	cfg.GPUEvaluation, cfg.RIMServiceURL, cfg.RIMCacheDir = g.Evaluation, g.RIMServiceURL, g.RIMCacheDir
	var err error
	if g.NVIDIADeviceRootPath != "" {
		if cfg.NVIDIADeviceRootPEM, err = os.ReadFile(g.NVIDIADeviceRootPath); err != nil {
			return fmt.Errorf("gpu_policy.nvidia_device_root_path: %w", err)
		}
	}
	if g.NVIDIARIMRootPath != "" {
		if cfg.NVIDIARIMRootPEM, err = os.ReadFile(g.NVIDIARIMRootPath); err != nil {
			return fmt.Errorf("gpu_policy.nvidia_rim_root_path: %w", err)
		}
	}
	return nil
}

// supportedProviders are the TEE backends this build can attest with
// on the Return Path, and verify a peer's Evidence for.
var supportedProviders = []tee.Provider{tee.ProviderGCPSEVSNP, tee.ProviderGCPTDX, tee.ProviderAzureCGPU, tee.ProviderSimulated}

// DefaultSEVGuestDevice is where the Linux sev-guest driver appears.
const DefaultSEVGuestDevice = "/dev/sev-guest"

// SEVDevice is the sev-guest device the sealer opens.
func (t TEEConfig) SEVDevice() string {
	if t.SEVGuestDevice != "" {
		return t.SEVGuestDevice
	}
	return DefaultSEVGuestDevice
}

// ProviderKind parses TEEConfig.Provider, defaulting to simulated.
func (t TEEConfig) ProviderKind() (tee.Provider, error) {
	if strings.TrimSpace(t.Provider) == "" {
		return tee.ProviderSimulated, nil
	}
	return tee.ParseProvider(t.Provider)
}

// ProviderKind parses PeerTEEConfig.Provider, defaulting to simulated.
func (p PeerTEEConfig) ProviderKind() (tee.Provider, error) {
	if strings.TrimSpace(p.Provider) == "" {
		return tee.ProviderSimulated, nil
	}
	return tee.ParseProvider(p.Provider)
}

// KeysConfig bundles the two key-material slots the worker uses.
type KeysConfig struct {
	// WorkerSigning is the Ed25519 key the worker uses to sign each
	// CandidateOutputFrame. The public half MUST be registered with
	// sagvd's PublicKeyResolver out-of-band (operator config in
	// Phase 1; attestation-bound in Phase 3).
	WorkerSigning SigningKeyConfig `json:"worker_signing"`

	// SessionSealing is the AES-256 key pre-shared between sagvd and
	// this worker, used to unseal SealedMaterial carried inside
	// JobRequest.
	SessionSealing SealingKeyConfig `json:"session_sealing"`
}

// SigningKeyConfig points at a 32-byte Ed25519 seed file.
type SigningKeyConfig struct {
	KeyID    string `json:"kid"`
	SeedPath string `json:"seed_path"`
}

// SealingKeyConfig points at a 32-byte AES-256 key-material file.
type SealingKeyConfig struct {
	KeyID        string `json:"kid"`
	MaterialPath string `json:"material_path"`
}

// GenomeConfig configures the model side of a job.
type GenomeConfig struct {
	// Door is the program that restores a genome and answers its
	// prompts: the vg_genome door (workers/genome).
	Door DoorConfig `json:"door"`
}

// DoorConfig is the door command and its bounds.
type DoorConfig struct {
	// Command runs the door. It reads the job — the genome's
	// description, its adapter and the fixtures' prompts, as one JSON
	// document — on stdin, loads the public base model from this
	// worker's disk, applies the adapter in memory, and writes the
	// model's outputs to stdout. The reference door:
	//
	//	["python3", "-m", "vg_genome", "door", "--stdin-genome",
	//	 "--base", "/models/Qwen2.5-0.5B-Instruct", "--device", "cpu"]
	//
	// Required: a worker with no door cannot serve a job.
	Command []string `json:"command"`

	// Env is extra environment for the door, KEY=VALUE — for example
	// PYTHONPATH=/opt/vg/workers/genome.
	Env []string `json:"env,omitempty"`

	// TimeoutSeconds bounds one door run. 0 leaves the job's own
	// deadline and runtime.job_timeout_seconds as the only bounds.
	TimeoutSeconds int `json:"timeout_seconds"`
}

// Timeout returns DoorConfig.TimeoutSeconds as a Duration.
func (d DoorConfig) Timeout() time.Duration {
	return time.Duration(d.TimeoutSeconds) * time.Second
}

// RuntimeConfig bounds the dial and serve loop timings.
type RuntimeConfig struct {
	JobTimeoutSeconds       int `json:"job_timeout_seconds"`
	HandshakeTimeoutSeconds int `json:"handshake_timeout_seconds"`
	DialBackoffInitialMs    int `json:"dial_backoff_initial_ms"`
	DialBackoffMaxMs        int `json:"dial_backoff_max_ms"`
	// IdleBetweenJobsMs is a brief pause after a successful job
	// before the next dial attempt, bounding reconnect churn.
	IdleBetweenJobsMs int `json:"idle_between_jobs_ms"`
}

// JobTimeout returns RuntimeConfig.JobTimeoutSeconds as a Duration.
func (r RuntimeConfig) JobTimeout() time.Duration {
	return time.Duration(r.JobTimeoutSeconds) * time.Second
}

// HandshakeTimeout returns RuntimeConfig.HandshakeTimeoutSeconds as
// a Duration.
func (r RuntimeConfig) HandshakeTimeout() time.Duration {
	return time.Duration(r.HandshakeTimeoutSeconds) * time.Second
}

// DialBackoffInitial returns the initial backoff as a Duration.
func (r RuntimeConfig) DialBackoffInitial() time.Duration {
	return time.Duration(r.DialBackoffInitialMs) * time.Millisecond
}

// DialBackoffMax returns the cap on backoff as a Duration.
func (r RuntimeConfig) DialBackoffMax() time.Duration {
	return time.Duration(r.DialBackoffMaxMs) * time.Millisecond
}

// IdleBetweenJobs returns the post-success pause as a Duration.
func (r RuntimeConfig) IdleBetweenJobs() time.Duration {
	return time.Duration(r.IdleBetweenJobsMs) * time.Millisecond
}

// HealthConfig controls the local /healthz /readyz /metrics server.
type HealthConfig struct {
	ListenAddress string `json:"listen_address"`
}

// LogConfig picks log verbosity and format.
type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// validateTEE checks the local provider and the peer pin as a pair of
// choices: a simulated producer needs its seed and the operator's
// acknowledgement; a hardware producer signs with the chip and refuses
// both; a simulated peer is pinned by key and measurement; a SEV-SNP
// peer by measurement and the AMD chain.
func validateTEE(t TEEConfig) []error {
	var errs []error
	switch provider, err := t.ProviderKind(); {
	case err != nil:
		errs = append(errs, fmt.Errorf("tee.provider invalid: %w", err))
	case !slices.Contains(supportedProviders, provider):
		errs = append(errs, fmt.Errorf("tee.provider %q is not available in this build (supported: %v)", provider, supportedProviders))
	case provider == tee.ProviderSimulated:
		if t.SeedPath == "" {
			errs = append(errs, errors.New("tee.seed_path required when tee.provider=simulated"))
		}
		if !t.InsecureSimulation {
			errs = append(errs, errors.New("tee.provider=simulated has no hardware isolation: set tee.insecure_simulation=true to run it, for development and tests only"))
		}
		if t.TSMReportDir != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir applies to gcp-sev-snp and gcp-tdx only"))
		}
	case provider == tee.ProviderGCPSEVSNP || provider == tee.ProviderGCPTDX:
		if t.SeedPath != "" {
			errs = append(errs, errors.New("tee.seed_path applies to the simulated provider only; a hardware TEE signs with its own key"))
		}
		if t.InsecureSimulation {
			errs = append(errs, errors.New("tee.insecure_simulation applies to the simulated provider only"))
		}
	case provider == tee.ProviderAzureCGPU:
		if t.SeedPath != "" || t.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
		}
		if t.TSMReportDir != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir does not apply to azure-cgpu (the report comes from the vTPM)"))
		}
		if len(t.GPUAttestCommand) == 0 {
			errs = append(errs, errors.New("tee.gpu_attest_command required when tee.provider=azure-cgpu (the command that obtains NVIDIA's attestation tokens for a nonce)"))
		}
	}
	if lp, _ := t.ProviderKind(); lp != tee.ProviderAzureCGPU && (len(t.GPUAttestCommand) > 0 || t.TPM2ToolsDir != "" || t.AKHandle != "") {
		errs = append(errs, errors.New("tee.gpu_attest_command, tpm2_tools_dir and ak_handle apply to azure-cgpu only"))
	}
	if t.Peer.MeasurementPath == "" {
		errs = append(errs, errors.New("tee.peer.measurement_path required"))
	}
	switch peer, err := t.Peer.ProviderKind(); {
	case err != nil:
		errs = append(errs, fmt.Errorf("tee.peer.provider invalid: %w", err))
	case !slices.Contains(supportedProviders, peer):
		errs = append(errs, fmt.Errorf("tee.peer.provider %q: no verifier this build can run end to end (supported: %v)", peer, supportedProviders))
	case peer == tee.ProviderSimulated:
		if t.Peer.PublicKeyPath == "" {
			errs = append(errs, errors.New("tee.peer.public_key_path required when tee.peer.provider=simulated"))
		}
		if t.Peer.AMDCertChainPath != "" || t.Peer.AMDKDSURL != "" || t.Peer.VCEKCacheDir != "" || t.Peer.MinReportedTCB != 0 {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path, amd_kds_url, vcek_cache_dir and min_reported_tcb apply to a gcp-sev-snp or azure-cgpu peer only"))
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
	case peer == tee.ProviderGCPSEVSNP:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; a SEV-SNP report is signed by the chip's VCEK"))
		}
		if t.Peer.AMDCertChainPath == "" {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path required when tee.peer.provider=gcp-sev-snp (the AMD ASK+ARK chain the VCEK must chain to)"))
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
	case peer == tee.ProviderGCPTDX:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; a TDX quote chains to the Intel SGX Root CA"))
		}
		if t.Peer.AMDCertChainPath != "" || t.Peer.AMDKDSURL != "" || t.Peer.VCEKCacheDir != "" || t.Peer.MinReportedTCB != 0 {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path, amd_kds_url, vcek_cache_dir and min_reported_tcb apply to a gcp-sev-snp or azure-cgpu peer only"))
		}
	case peer == tee.ProviderAzureCGPU:
		if t.Peer.PublicKeyPath != "" {
			errs = append(errs, errors.New("tee.peer.public_key_path applies to a simulated peer only; an Azure confidential GPU VM's report is signed by the chip's VCEK"))
		}
		if t.Peer.AMDCertChainPath == "" {
			errs = append(errs, errors.New("tee.peer.amd_cert_chain_path required when tee.peer.provider=azure-cgpu (the AMD ASK+ARK chain of the chip's product, Genoa for NCC H100 v5)"))
		}
		if t.Peer.PCSURL != "" || t.Peer.PCSCacheDir != "" || len(t.Peer.AcceptableTCBStatuses) > 0 {
			errs = append(errs, errors.New("tee.peer.pcs_url, pcs_cache_dir and acceptable_tcb_statuses apply to a gcp-tdx peer only"))
		}
	}
	if err := t.Peer.GPUPolicy.validate(); err != nil {
		errs = append(errs, fmt.Errorf("tee.peer.%w", err))
	}
	if peer, _ := t.Peer.ProviderKind(); peer != tee.ProviderAzureCGPU && (t.Peer.NRASJWKSURL != "" || t.Peer.NRASCacheDir != "" || t.Peer.GPUPolicy != nil || len(t.Peer.PCRDigests) > 0) {
		errs = append(errs, errors.New("tee.peer.nras_jwks_url, nras_cache_dir, gpu_policy and pcr_digests apply to an azure-cgpu peer only"))
	}
	if _, err := pcrDigests(t.Peer.PCRDigests); err != nil {
		errs = append(errs, fmt.Errorf("tee.peer.%w", err))
	}
	return errs
}

// DefaultConfig returns a Config populated with sensible defaults.
// Callers typically decode a JSON file over this so that operators
// only need to specify fields they want to override.
func DefaultConfig() Config {
	return Config{
		Vault: VaultConfig{
			Address: "127.0.0.1:9443",
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		TEE: TEEConfig{
			WorkloadDescriptor: "acp-compute-worker-v1",
		},
		Runtime: RuntimeConfig{
			JobTimeoutSeconds:       120,
			HandshakeTimeoutSeconds: 10,
			DialBackoffInitialMs:    500,
			DialBackoffMaxMs:        30000,
			IdleBetweenJobsMs:       100,
		},
		Health: HealthConfig{
			ListenAddress: "127.0.0.1:9091",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// LoadConfigFile reads and decodes a JSON configuration file on top
// of DefaultConfig(). Unknown JSON fields are rejected to catch
// typos in operator config during provisioning.
func LoadConfigFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("acp-compute: open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return DecodeConfig(f)
}

// DecodeConfig decodes JSON from r into a Config, applied on top of
// DefaultConfig. Rejects unknown fields.
func DecodeConfig(r io.Reader) (Config, error) {
	c := DefaultConfig()
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("acp-compute: decode config: %w", err)
	}
	return c, nil
}

// Validate performs structural checks that do not require filesystem
// access. Returns a joined error listing every problem so operators
// see the full punch-list in one run.
func (c Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Vault.Address) == "" {
		errs = append(errs, errors.New("vault.address required"))
	} else if _, _, err := net.SplitHostPort(c.Vault.Address); err != nil {
		errs = append(errs, fmt.Errorf("vault.address invalid: %w", err))
	}

	if c.Vault.TLS.Enabled {
		if c.Vault.TLS.ClientCert == "" {
			errs = append(errs, errors.New("vault.tls.client_cert required when TLS enabled"))
		}
		if c.Vault.TLS.ClientKey == "" {
			errs = append(errs, errors.New("vault.tls.client_key required when TLS enabled"))
		}
		if c.Vault.TLS.CABundle == "" {
			errs = append(errs, errors.New("vault.tls.ca_bundle required when TLS enabled"))
		}
		if c.Vault.TLS.ServerName == "" {
			errs = append(errs, errors.New("vault.tls.server_name required when TLS enabled"))
		}
	}

	if strings.TrimSpace(c.TEE.WorkloadDescriptor) == "" {
		errs = append(errs, errors.New("tee.workload_descriptor required"))
	}
	errs = append(errs, validateTEE(c.TEE)...)

	if c.Keys.WorkerSigning.KeyID == "" {
		errs = append(errs, errors.New("keys.worker_signing.kid required"))
	}
	if c.Keys.WorkerSigning.SeedPath == "" {
		errs = append(errs, errors.New("keys.worker_signing.seed_path required"))
	}
	if c.Keys.SessionSealing.KeyID == "" {
		errs = append(errs, errors.New("keys.session_sealing.kid required"))
	}
	if c.Keys.SessionSealing.MaterialPath == "" {
		errs = append(errs, errors.New("keys.session_sealing.material_path required"))
	}

	if len(c.Genome.Door.Command) == 0 || strings.TrimSpace(c.Genome.Door.Command[0]) == "" {
		errs = append(errs, errors.New("genome.door.command required: the worker restores a genome through the vg_genome door (python3 -m vg_genome door --stdin-genome --base BASE_DIR)"))
	}
	for _, kv := range c.Genome.Door.Env {
		if !strings.Contains(kv, "=") {
			errs = append(errs, fmt.Errorf("genome.door.env entry %q must be KEY=VALUE", kv))
		}
	}
	if c.Genome.Door.TimeoutSeconds < 0 {
		errs = append(errs, errors.New("genome.door.timeout_seconds must be >= 0"))
	}

	if c.Runtime.JobTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.job_timeout_seconds must be > 0"))
	}
	if c.Runtime.HandshakeTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.handshake_timeout_seconds must be > 0"))
	}
	if c.Runtime.DialBackoffInitialMs <= 0 {
		errs = append(errs, errors.New("runtime.dial_backoff_initial_ms must be > 0"))
	}
	if c.Runtime.DialBackoffMaxMs < c.Runtime.DialBackoffInitialMs {
		errs = append(errs, errors.New("runtime.dial_backoff_max_ms must be >= dial_backoff_initial_ms"))
	}
	if c.Runtime.IdleBetweenJobsMs < 0 {
		errs = append(errs, errors.New("runtime.idle_between_jobs_ms must be >= 0"))
	}

	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level %q invalid (want debug|info|warn|error)", c.Log.Level))
	}
	switch strings.ToLower(c.Log.Format) {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log.format %q invalid (want json|text)", c.Log.Format))
	}

	return errors.Join(errs...)
}
