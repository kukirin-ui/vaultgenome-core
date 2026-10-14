// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/exposure"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Config is the full on-disk configuration for the sagvd authority
// daemon. Every field is frozen for the Phase-1 investor demo;
// additions are a minor-version change and must update
// `cmd/sagvd/doc.go`.
type Config struct {
	// Vault controls the Return Path TCP listener (where acp-compute
	// workers dial in).
	Vault VaultConfig `json:"vault"`

	// HTTPAPI controls the operator REST API listener (POST /v1/jobs,
	// GET /v1/jobs/{id}).
	HTTPAPI HTTPAPIConfig `json:"http_api"`

	// TEE configures the simulated TEE the vault presents during the
	// Return Path handshake. In Phase 3 this section is replaced by a
	// hardware-backed backend with identical surface.
	TEE TEEConfig `json:"tee"`

	// Keys points at the on-disk material the vault uses to sign
	// authority artifacts and to seal SealedMaterial for JobRequest.
	Keys KeysConfig `json:"keys"`

	// Workers points at the static JSON registry of known worker
	// signing public keys. See workers.go.
	Workers WorkersConfig `json:"workers"`

	// Runtime tunables for the accept / dispatch loop and HTTP timeouts.
	Runtime RuntimeConfig `json:"runtime"`

	// Health controls the local HTTP server that exposes /healthz,
	// /readyz and /metrics. Empty ListenAddress disables the server
	// (useful in tests).
	Health HealthConfig `json:"health"`

	// Log controls structured-logging format and verbosity.
	Log LogConfig `json:"log"`

	// CrossCloud configures cross-cloud key release, run by the
	// `sagvd crosscloud-restore` subcommand (the daemon itself serves
	// no cross-cloud requests). When CrossCloud.Enabled is false (the
	// default) every other field in this section is ignored.
	//
	// See ADR 0006, ADR 0009 and docs/operator/06_cross_cloud_restore.md.
	CrossCloud CrossCloudConfig `json:"crosscloud,omitempty"`

	// Genome configures the gate jobs the REST API accepts: a job names
	// a sealed genome in Genome.BundleDir; sagvd opens it with its key,
	// keeps the genome's reference fixtures, ships the model side to the
	// worker, and holds what the worker computes to the references with
	// the equivalence gate. Without a BundleDir the REST API accepts no
	// jobs (ADR 0013).
	Genome GenomeConfig `json:"genome,omitempty"`

	// Audit is the daemon's Return Path audit log: every decision about
	// a job — accepted, worker admitted or refused, candidate received,
	// judged — on a durable, signed, hash-linked record before it takes
	// effect (ADR 0014). Required when gate jobs are enabled.
	Audit AuditConfig `json:"audit,omitempty"`

	// OperatorStop is the operator's signed stop list (ADR 0010) as Trust
	// Admission consults it for gate jobs (ADR 0015): a stop-all list
	// denies every job, a list revoking the worker's measurement denies
	// that worker, and every denial is a signed, recorded decision. The
	// list is re-read at every admission, so the operator stops the
	// daemon's releases by writing a new list. Optional; when set, all
	// three fields are required.
	OperatorStop OperatorStopConfig `json:"operator_stop,omitempty"`
}

// PolicyProfileGate is the one policy profile the daemon serves: restore
// the named genome in an attested worker and hold it to its sealed
// references under genome.gate. A RecoveryRequest naming another profile
// is denied at Trust Admission.
const PolicyProfileGate = "gate"

// PolicyVersion is the policy every session is pinned to and validation
// checks alignment with (op.policy_alignment): the gate's tolerance, in
// full, so a tolerance changed under a live session is a recorded
// operational failure rather than a silent drift.
func (c Config) PolicyVersion() string {
	g := c.Genome.Gate
	v := fmt.Sprintf("gate-policy/v1;atol=%g;rtol=%g;outliers=%d", g.Atol, g.Rtol, g.MaxNonCriticalOutliers)
	if g.Bfloat16 != nil {
		v += fmt.Sprintf(";bf16-atol=%g;bf16-rtol=%g", g.Bfloat16.Atol, g.Bfloat16.Rtol)
	}
	return v
}

// GateTolerance is a tolerance of the float door: |got - expected| <= atol + rtol*|expected|.
type GateTolerance struct {
	Atol float64 `json:"atol"`
	Rtol float64 `json:"rtol"`
}

// ToleranceFor is the tolerance a genome is held to, by the dtype its
// recipe names: the bfloat16 table when the operator set one and the
// genome computed in bfloat16, the float32 tolerance otherwise.
func (g GateConfig) ToleranceFor(dtype string) equivalence.Tolerance {
	if g.Bfloat16 != nil && dtype == "bfloat16" {
		return equivalence.Tolerance{Atol: g.Bfloat16.Atol, Rtol: g.Bfloat16.Rtol}
	}
	return equivalence.Tolerance{Atol: g.Atol, Rtol: g.Rtol}
}

// OperatorStopEnabled reports whether trust consults a stop list.
func (c Config) OperatorStopEnabled() bool {
	return c.OperatorStop.KeyID != "" || c.OperatorStop.PublicKeyPath != "" || c.OperatorStop.ListPath != ""
}

// GenomeConfig is where the sealed genomes a job may name live, how
// their keys are found, and the tolerance the gate holds a restored model
// to.
type GenomeConfig struct {
	// BundleDir holds the .genome bundles a job may name, with their key
	// files (acpctl genome seal --key-out) or escrow envelopes (--escrow-to,
	// as <bundle>.escrow) beside them. A job names files in it; paths are
	// refused.
	BundleDir string `json:"bundle_dir,omitempty"`

	// KeyEscrowPath is the authority's escrow private key that opens the
	// escrow envelopes in BundleDir: the file `sagvd escrow-provision`
	// writes, sealed to this host's TEE (ADR 0016). Under
	// tee.insecure_simulation a raw 32-byte key (acpctl escrow keygen,
	// mode 0600) is accepted too. Empty falls back to
	// crosscloud.key_escrow_path; without either, jobs must name a key
	// file.
	KeyEscrowPath string `json:"key_escrow_path,omitempty"`

	// Gate is the tolerance every gate job is held to. The byte-exact door
	// is always tried first; this is the tolerance of the native-float
	// door behind it. Declared here, by the operator, in advance — not by
	// the job.
	Gate GateConfig `json:"gate"`
}

// GateConfig is the native-float door's tolerance and outlier policy.
type GateConfig struct {
	Atol                   float64 `json:"atol"`
	Rtol                   float64 `json:"rtol"`
	MaxNonCriticalOutliers int     `json:"max_non_critical_outliers"`
	// Bfloat16, when set, is the tolerance for a genome whose recipe says
	// its base computed in bfloat16: across devices such logits differ by
	// one or two bfloat16 quanta (KNOWN_ISSUES #13), and the float32
	// tolerance above refuses them. The operator sets it knowingly; it is
	// part of the policy every session is pinned to. Absent: bfloat16
	// genomes are held to the float32 tolerance.
	Bfloat16 *GateTolerance `json:"bfloat16,omitempty"`
}

// Enabled reports whether gate jobs can be built.
func (g GenomeConfig) Enabled() bool { return g.BundleDir != "" }

// EscrowKeyPath is the escrow private key that opens envelopes in
// BundleDir: genome.key_escrow_path, or crosscloud.key_escrow_path.
func (c Config) EscrowKeyPath() string {
	if c.Genome.KeyEscrowPath != "" {
		return c.Genome.KeyEscrowPath
	}
	return c.CrossCloud.KeyEscrowPath
}

// VaultConfig aggregates how sagvd accepts Return Path connections.
type VaultConfig struct {
	// ListenAddress is the host:port the vault binds for Return Path
	// inbound sessions. Workers dial this address.
	ListenAddress string `json:"listen_address"`

	// TLS configures mutual TLS for the Return Path listener. When
	// Enabled=false the listener is plain TCP. Validate() refuses a
	// plain-TCP listener on any non-loopback address: workers across a
	// network must authenticate with mTLS.
	TLS TLSConfig `json:"tls"`
}

// HTTPAPIConfig controls the operator REST API.
type HTTPAPIConfig struct {
	// ListenAddress is the host:port the REST API binds. An empty
	// value disables the REST API (tests and loopback-only demos
	// can dispatch jobs in-process through the JobQueue).
	ListenAddress string `json:"listen_address"`

	// BearerToken, if non-empty, is compared (constant-time) against
	// the client-supplied "Authorization: Bearer <token>" header on
	// every endpoint. An unauthenticated REST API is only accepted on a
	// loopback bind; Validate() refuses a non-loopback bind without a
	// token, and requires at least MinNonLoopbackTokenLen characters.
	BearerToken string `json:"bearer_token,omitempty"`

	// BearerTokenFile is the path to a file holding the bearer token
	// (surrounding whitespace is trimmed). Prefer it over BearerToken
	// so the secret lives with the other key material rather than in
	// the config file. Mutually exclusive with BearerToken; resolved at
	// startup by ResolveSecrets().
	BearerTokenFile string `json:"bearer_token_file,omitempty"`
}

// MinNonLoopbackTokenLen is the minimum bearer-token length accepted
// for a REST API reachable beyond the local host.
const MinNonLoopbackTokenLen = exposure.MinBearerTokenLen

// TLSConfig holds server-side mTLS material. All file paths are
// resolved relative to the process working directory.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCAs  string `json:"client_cas"`
}

// TEEConfig names the TEE this vault attests with on the Return Path
// and pins the worker's TEE it will accept.
type TEEConfig struct {
	// Provider is the local TEE backend: "gcp-sev-snp" (AMD SEV-SNP
	// reports through the kernel's configfs-tsm, on any SEV-SNP guest
	// with Linux 6.7 or later — the chip signs) or "simulated" (a key
	// read from SeedPath signs; no hardware isolation; development and
	// tests only). Default "simulated". The cross-cloud release path
	// (sagvd crosscloud-*) does not depend on it.
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

	// SEVGuestDevice is the sev-guest character device the sealer asks
	// for this guest's derived key (default /dev/sev-guest): what seals
	// the escrow key to this host (ADR 0016). gcp-sev-snp only.
	SEVGuestDevice string `json:"sev_guest_device,omitempty"`

	// GPUAttestCommand, TPM2ToolsDir and AKHandle configure the
	// azure-cgpu producer: the command that obtains NVIDIA's signed
	// attestation tokens for a nonce (the nonce is appended; required),
	// where tpm2-tools live (default PATH), and the vTPM handle of the
	// HCL attestation key (default: found by its public key). azure-cgpu
	// only.
	GPUAttestCommand []string `json:"gpu_attest_command,omitempty"`
	TPM2ToolsDir     string   `json:"tpm2_tools_dir,omitempty"`
	AKHandle         string   `json:"ak_handle,omitempty"`

	// VTPMSealPCRs is the PCR selection the escrow key is sealed to on a
	// host whose TEE gives no sealing key of its own — gcp-tdx and
	// azure-cgpu seal to the guest's vTPM (ADR 0022). "sha256:<n>,<n>,...";
	// empty means every PCR the azure-cgpu quote covers (sha256:0-14).
	VTPMSealPCRs string `json:"vtpm_seal_pcrs,omitempty"`

	// Peer holds the trust-anchor material for the worker's TEE side.
	// The vault accepts exactly one worker TEE identity: a Return Path
	// session opens only for a worker whose Evidence verifies under it.
	Peer PeerTEEConfig `json:"peer"`

	// InsecureSimulation must be true to run the simulated provider:
	// its Evidence is signed by a key read from SeedPath, with no
	// hardware isolation. The flag puts that in the config itself.
	// Simulated only.
	InsecureSimulation bool `json:"insecure_simulation,omitempty"`
}

// PeerTEEConfig pins the worker-side TEE the vault will accept.
type PeerTEEConfig struct {
	// Provider is the worker's TEE backend: "simulated" (default) or
	// "gcp-sev-snp". The verifier for it runs here; verification never
	// needs hardware.
	Provider string `json:"provider,omitempty"`

	// PublicKeyPath is the worker's 32-byte raw Ed25519 attestation key.
	// Simulated peers only; a SEV-SNP report is signed by the chip's
	// VCEK, which chains to AMD.
	PublicKeyPath string `json:"public_key_path,omitempty"`

	// MeasurementPath is the worker's launch measurement, raw: 32 bytes
	// for a simulated peer, 48 for SEV-SNP (never truncated, ADR 0007).
	MeasurementPath string `json:"measurement_path"`

	// AMDCertChainPath is the AMD ASK+ARK certificate chain (PEM) the
	// worker's VCEK must chain to. gcp-sev-snp peers only; required.
	AMDCertChainPath string `json:"amd_cert_chain_path,omitempty"`

	// AMDKDSURL overrides the AMD KDS base URL (a mirror). gcp-sev-snp
	// peers only.
	AMDKDSURL string `json:"amd_kds_url,omitempty"`

	// VCEKCacheDir keeps fetched VCEK certificates on disk so each chip
	// is asked of AMD KDS once; a cached certificate is still checked
	// against the pinned chain on every use. gcp-sev-snp peers only.
	VCEKCacheDir string `json:"vcek_cache_dir,omitempty"`

	// MinReportedTCB is the lowest REPORTED_TCB accepted from the
	// worker. gcp-sev-snp peers only.
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
	// Revocation says whether the verifier's own evaluation asks NVIDIA's
	// OCSP responder about the GPU's certificate chain: "ocsp" (the
	// default under both and own; answers cached a day under
	// rim_cache_dir) or "off" (unchecked, on the record). OCSPURL
	// overrides the responder (default http://ocsp.ndis.nvidia.com).
	Revocation string `json:"revocation,omitempty"`
	OCSPURL    string `json:"ocsp_url,omitempty"`
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
	case "", tee.GPUEvaluationNRAS, tee.GPUEvaluationBoth, tee.GPUEvaluationOwn:
	default:
		return fmt.Errorf("gpu_policy.evaluation %q (one of nras, both, own)", g.Evaluation)
	}
	switch g.Revocation {
	case "", tee.GPURevocationOCSP, tee.GPURevocationOff:
	default:
		return fmt.Errorf("gpu_policy.revocation %q (one of ocsp, off)", g.Revocation)
	}
	if (g.Revocation != "" || g.OCSPURL != "") && (g.Evaluation == "" || g.Evaluation == tee.GPUEvaluationNRAS) {
		return errors.New("gpu_policy.revocation and ocsp_url apply to the verifier's own evaluation (evaluation both or own)")
	}
	return nil
}

// apply sets the evaluation fields of a verifier config from the policy,
// reading the root PEM files it names.
func (g *GPUPolicyConfig) apply(cfg *tee.AzureCGPUVerifierConfig) error {
	if g == nil {
		return nil
	}
	cfg.GPUEvaluation, cfg.RIMServiceURL, cfg.RIMCacheDir = g.Evaluation, g.RIMServiceURL, g.RIMCacheDir
	cfg.GPURevocation, cfg.OCSPURL = g.Revocation, g.OCSPURL
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
		if t.SEVGuestDevice != "" {
			errs = append(errs, errors.New("tee.sev_guest_device applies to gcp-sev-snp only"))
		}
		if t.VTPMSealPCRs != "" {
			errs = append(errs, errors.New("tee.vtpm_seal_pcrs applies to gcp-tdx and azure-cgpu only"))
		}
	case provider == tee.ProviderGCPSEVSNP || provider == tee.ProviderGCPTDX:
		if t.SeedPath != "" {
			errs = append(errs, errors.New("tee.seed_path applies to the simulated provider only; a hardware TEE signs with its own key"))
		}
		if t.InsecureSimulation {
			errs = append(errs, errors.New("tee.insecure_simulation applies to the simulated provider only"))
		}
		if provider == tee.ProviderGCPTDX && t.SEVGuestDevice != "" {
			errs = append(errs, errors.New("tee.sev_guest_device applies to gcp-sev-snp only"))
		}
		if provider == tee.ProviderGCPSEVSNP && t.VTPMSealPCRs != "" {
			errs = append(errs, errors.New("tee.vtpm_seal_pcrs applies to gcp-tdx and azure-cgpu only (gcp-sev-snp seals with the chip's derived key)"))
		}
		if provider == tee.ProviderGCPTDX && t.VTPMSealPCRs != "" {
			if err := tee.ValidatePCRSelection(t.VTPMSealPCRs); err != nil {
				errs = append(errs, fmt.Errorf("tee.vtpm_seal_pcrs: %w", err))
			}
		}
	case provider == tee.ProviderAzureCGPU:
		if t.SeedPath != "" || t.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
		}
		if t.TSMReportDir != "" || t.SEVGuestDevice != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir and tee.sev_guest_device do not apply to azure-cgpu (the report comes from the vTPM)"))
		}
		if t.VTPMSealPCRs != "" {
			if err := tee.ValidatePCRSelection(t.VTPMSealPCRs); err != nil {
				errs = append(errs, fmt.Errorf("tee.vtpm_seal_pcrs: %w", err))
			}
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

// KeysConfig bundles the key-material slots sagvd uses.
type KeysConfig struct {
	// AuthoritySigning is the Ed25519 key sagvd uses to sign
	// authority artifacts (ReconstructionJobManifest signatures,
	// ReleaseDecision, AttestationResult). Phase 1 uses it only for
	// provisioning parity with Phase 3; the investor demo does not
	// exercise authority signing on the hot path.
	AuthoritySigning SigningKeyConfig `json:"authority_signing"`

	// SessionSealing is the AES-256 key pre-shared between sagvd and
	// acp-compute. sagvd uses it to Seal SealedMaterial into
	// JobRequest; the worker uses it to Open the SealedMaterialRef
	// and extract the plaintext it will operate on.
	SessionSealing SealingKeyConfig `json:"session_sealing"`

	// AuditSigning is the Ed25519 key that signs the cross-cloud audit
	// log (keys.PurposeSigningAudit). It must stay the same across runs:
	// the log is one hash-linked chain, verified end to end whenever it
	// is opened. Required when crosscloud.enabled=true; its public half
	// (`sagvd identity`) is what auditors verify the log with.
	AuditSigning SigningKeyConfig `json:"audit_signing,omitempty"`
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

// WorkersConfig points at the JSON registry of known worker signing
// public keys. See workers.go for the file schema.
type WorkersConfig struct {
	// RegistryPath is a JSON file listing {kid, signing_pubkey_hex}
	// for every worker this vault will accept a CandidateOutputFrame
	// from. Out-of-band provisioning in Phase 1; attestation-bound
	// in Phase 3.
	RegistryPath string `json:"registry_path"`
}

// RuntimeConfig bounds the accept / dispatch / HTTP timings.
type RuntimeConfig struct {
	// JobTimeoutSeconds caps the total wall-clock duration for a
	// single Return Path session from accept() to close. Guards
	// against a slow or wedged worker holding the dispatcher.
	JobTimeoutSeconds int `json:"job_timeout_seconds"`

	// HandshakeTimeoutSeconds caps the 4-frame handshake phase.
	HandshakeTimeoutSeconds int `json:"handshake_timeout_seconds"`

	// QueuePollMs is how long the dispatcher blocks waiting for the
	// next queued job before re-checking shutdown. Trades demo
	// responsiveness against idle CPU.
	QueuePollMs int `json:"queue_poll_ms"`

	// HTTPReadHeaderTimeoutSeconds bounds HTTP request header read
	// time (guards against slow-loris on the operator REST API).
	HTTPReadHeaderTimeoutSeconds int `json:"http_read_header_timeout_seconds"`

	// HTTPWriteTimeoutSeconds bounds the full response write
	// duration.
	HTTPWriteTimeoutSeconds int `json:"http_write_timeout_seconds"`

	// DefaultJobDeadlineSeconds is the default value when a POST
	// /v1/jobs body omits deadline_seconds_from_now. Also the
	// ceiling: submissions asking for longer are Structurally
	// rejected with 400.
	DefaultJobDeadlineSeconds int `json:"default_job_deadline_seconds"`

	// MaxPayloadBytes caps base64-decoded POST /v1/jobs payload
	// size. Prevents a single client from exhausting vault memory.
	MaxPayloadBytes uint64 `json:"max_payload_bytes"`

	// EvidenceMaxAgeSeconds is how old a worker's Return Path Evidence
	// may be when a job is handed to it. A session whose handshake is
	// older is closed with re_attest and the job stays queued (the worker
	// dials again, attests again). 0 takes the attestation default
	// (5 minutes).
	EvidenceMaxAgeSeconds int `json:"evidence_max_age_seconds,omitempty"`
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

// QueuePoll returns RuntimeConfig.QueuePollMs as a Duration.
func (r RuntimeConfig) QueuePoll() time.Duration {
	return time.Duration(r.QueuePollMs) * time.Millisecond
}

// HTTPReadHeaderTimeout returns the HTTP read-header bound.
func (r RuntimeConfig) HTTPReadHeaderTimeout() time.Duration {
	return time.Duration(r.HTTPReadHeaderTimeoutSeconds) * time.Second
}

// HTTPWriteTimeout returns the HTTP write bound.
func (r RuntimeConfig) HTTPWriteTimeout() time.Duration {
	return time.Duration(r.HTTPWriteTimeoutSeconds) * time.Second
}

// DefaultJobDeadline returns the default per-job deadline.
// EvidenceMaxAge is RuntimeConfig.EvidenceMaxAgeSeconds as a duration,
// the attestation default when unset.
func (r RuntimeConfig) EvidenceMaxAge() time.Duration {
	if r.EvidenceMaxAgeSeconds <= 0 {
		return attestation_result.DefaultTTL
	}
	return time.Duration(r.EvidenceMaxAgeSeconds) * time.Second
}

func (r RuntimeConfig) DefaultJobDeadline() time.Duration {
	return time.Duration(r.DefaultJobDeadlineSeconds) * time.Second
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

// CrossCloudConfig holds the operator-supplied configuration for the
// Phase 4 cross-cloud KMS-mediated restore capability. The whole
// block is optional (Enabled=false skips loading; Phase 1-3 daemons
// behave identically). When Enabled=true, the daemon's startup path
// loads:
//
//   - VerifierRegistryPath into a tee.Registry holding one Verifier
//     per cross-cloud destination this authority may target. Each
//     entry pins the destination's TEE family + attestor pubkey +
//     expected measurement.
//
//   - PolicyAllowListPath into a kms.AllowListPolicy. Entries are
//     (Provider, hex-encoded measurement) pairs. PolicyVersion is
//     recorded in the audit payload of every KEY_RELEASE_AUTHORIZED
//     event so historical decisions can be replayed against the
//     policy snapshot in force at the time.
//
//   - TransportTLS material into the http.Client passed to the
//     HTTPTransport. mTLS is required for production deployments;
//     the no-TLS path is permitted only for loopback/demo tests.
//
// The destination side (acp-bootstrap daemon) is configured
// independently — see cmd/acp-bootstrap/config.go.
type CrossCloudConfig struct {
	// Enabled gates the entire cross-cloud subsystem. When false,
	// every other field is ignored and the daemon behaves exactly
	// as a Phase 1-3 build.
	Enabled bool `json:"enabled"`

	// PolicyVersion is the operator-supplied identifier for the
	// current allow-list snapshot, recorded verbatim in audit
	// payloads. Bump it when the allow-list changes so auditors can
	// correlate decisions to policy state. Required when Enabled.
	PolicyVersion string `json:"policy_version,omitempty"`

	// PolicyAllowListPath is the JSON file describing the
	// (Provider, Measurement) pairs the policy authorises.
	// File schema:
	//
	//   {
	//     "version": "xcc-2026-05-09",
	//     "allowed": {
	//       "aws-nitro":  ["<64-hex>", "<64-hex>"],
	//       "azure-sgx":  ["<64-hex>"],
	//       "gcp-sev-snp": []
	//     }
	//   }
	//
	// Required when Enabled.
	PolicyAllowListPath string `json:"policy_allow_list_path,omitempty"`

	// VerifierRegistryPath is the JSON file describing the verifiers
	// to instantiate at startup, one per cross-cloud destination.
	// File schema:
	//
	//   {
	//     "verifiers": [
	//       {
	//         "provider": "aws-nitro",
	//         "attestor_pubkey_path": "/etc/vg/aws-pca-root.pem",
	//         "expected_measurement_hex": "<64-hex>"
	//       },
	//       {
	//         "provider": "azure-sgx",
	//         "attestor_pubkey_path": "/etc/vg/azure-sgx-pubkey.pem",
	//         "expected_measurement_hex": "<64-hex>"
	//       }
	//     ]
	//   }
	//
	// Required when Enabled.
	VerifierRegistryPath string `json:"verifier_registry_path,omitempty"`

	// TransportBearerToken, if non-empty, is sent as
	// "Authorization: Bearer <token>" on every outbound handshake +
	// token request. Defence-in-depth alongside cryptographic
	// signatures; pair with mTLS in production.
	TransportBearerToken string `json:"transport_bearer_token,omitempty"`

	// RequestTimeoutSeconds caps each individual handshake / token
	// round trip. Zero defers to context cancellation (no per-request
	// timeout). Defaults to 30 when Enabled and unset.
	RequestTimeoutSeconds int `json:"request_timeout_seconds,omitempty"`

	// TransportTLS configures mTLS for the HTTPTransport's
	// http.Client. Strongly recommended for production.
	TransportTLS TLSClientConfig `json:"transport_tls,omitempty"`

	// AuditLogPath is the append-only audit log (a bbolt file) every
	// release decision is written to — handshake, attestation verified,
	// release authorised — before the step it records is taken. The log
	// is verified end to end when it is opened; a log that does not
	// verify stops all releases. Required when enabled. One
	// crosscloud-restore run holds its lock at a time.
	AuditLogPath string `json:"audit_log_path,omitempty"`

	// KeyEscrowPath is the release authority's escrow private key: the
	// file `sagvd escrow-provision` writes, sealed to this host's TEE and
	// opened in memory at start (ADR 0016). Under tee.insecure_simulation
	// a raw 32-byte key (acpctl escrow keygen, mode 0600) is accepted
	// too; on a hardware TEE it is refused. Sealers encapsulate genome
	// keys to its public half, which `sagvd identity` prints;
	// `crosscloud-restore -key-escrow` and `failover` open envelopes with
	// it only to release the key. Optional.
	KeyEscrowPath string `json:"key_escrow_path,omitempty"`

	// InsecureSimulatedDestinations must be true for the verifier
	// registry to hold a "simulated" entry. A simulated destination's
	// Evidence is signed by a key from a file, so releasing keys to it
	// proves the protocol and nothing about hardware; development and
	// tests only.
	InsecureSimulatedDestinations bool `json:"insecure_simulated_destinations,omitempty"`

	// OperatorStop is the operator's signed stop list (ADR 0010):
	// every release is checked against it, and without a valid one
	// nothing is released. Required when enabled.
	OperatorStop OperatorStopConfig `json:"operator_stop,omitempty"`
}

// OperatorStopConfig points at the operator's stop list and the public
// key it must verify under. The matching private key stays with the
// operator (`acpctl stop keygen`), never on this host.
type OperatorStopConfig struct {
	KeyID         string `json:"kid"`
	PublicKeyPath string `json:"public_key_path"`
	ListPath      string `json:"list_path"`
}

// TLSClientConfig holds the source-side outbound mTLS material the
// HTTPTransport uses to authenticate to destination acp-bootstrap
// servers. All file paths are resolved relative to the process
// working directory.
type TLSClientConfig struct {
	Enabled    bool   `json:"enabled"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	CABundle   string `json:"ca_bundle"`
	// ServerName is the name the destination's certificate carries, when
	// it is not the host of the endpoint URL — a destination reached by
	// IP whose certificate names it otherwise. Empty: the endpoint's host.
	ServerName string `json:"server_name,omitempty"`
}

// RequestTimeout returns CrossCloudConfig.RequestTimeoutSeconds as a
// Duration. Returns the documented default (30s) if unset.
func (c CrossCloudConfig) RequestTimeout() time.Duration {
	if c.RequestTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.RequestTimeoutSeconds) * time.Second
}

// DefaultConfig returns a Config populated with sensible defaults.
// Callers typically decode a JSON file over this so that operators
// only need to specify fields they want to override.
func DefaultConfig() Config {
	return Config{
		Vault: VaultConfig{
			ListenAddress: "127.0.0.1:9443",
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		HTTPAPI: HTTPAPIConfig{
			ListenAddress: "127.0.0.1:9080",
		},
		TEE: TEEConfig{
			WorkloadDescriptor: "sagvd-authority-v1",
		},
		Runtime: RuntimeConfig{
			JobTimeoutSeconds:            120,
			HandshakeTimeoutSeconds:      10,
			QueuePollMs:                  250,
			HTTPReadHeaderTimeoutSeconds: 5,
			HTTPWriteTimeoutSeconds:      30,
			DefaultJobDeadlineSeconds:    60,
			MaxPayloadBytes:              4 * 1024 * 1024, // 4 MiB
		},
		Health: HealthConfig{
			ListenAddress: "127.0.0.1:9091",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
		Genome: GenomeConfig{
			// The tolerance the hardware drills declared in advance
			// (VERIFIABLE-CLAIMS C5): measured cross-hardware error is
			// ~50x inside it.
			Gate: GateConfig{Atol: 1e-2, Rtol: 1e-3},
		},
	}
}

// LoadConfigFile reads and decodes a JSON configuration file on top
// of DefaultConfig(). Unknown JSON fields are rejected to catch
// typos in operator config during provisioning.
func LoadConfigFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("sagvd: open config %q: %w", path, err)
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
		return Config{}, fmt.Errorf("sagvd: decode config: %w", err)
	}
	return c, nil
}

// ResolveSecrets loads secret values that the config references by
// path rather than inline. Call it after Validate(). Today that is the
// REST API bearer token (http_api.bearer_token_file): the file is read,
// surrounding whitespace trimmed, and the result must be non-empty — and
// at least MinNonLoopbackTokenLen characters when the REST API is
// reachable beyond the local host.
func (c *Config) ResolveSecrets() error {
	if c.HTTPAPI.BearerTokenFile == "" {
		return nil
	}
	// The file may be sealed to this host (`sagvd seal-keys`, ADR 0023).
	raw, err := readSecret(c.TEE, c.HTTPAPI.BearerTokenFile, 0, "http_api.bearer_token_file")
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("sagvd: http_api.bearer_token_file %q is empty", c.HTTPAPI.BearerTokenFile)
	}
	if c.HTTPAPI.ListenAddress != "" && !exposure.IsLoopback(c.HTTPAPI.ListenAddress) &&
		len(token) < MinNonLoopbackTokenLen {
		return fmt.Errorf("sagvd: token in %q too short for non-loopback listen_address %q (need >= %d characters)",
			c.HTTPAPI.BearerTokenFile, c.HTTPAPI.ListenAddress, MinNonLoopbackTokenLen)
	}
	c.HTTPAPI.BearerToken = token
	return nil
}

// Validate performs structural checks that do not require filesystem
// access. Returns a joined error listing every problem so operators
// see the full punch-list in one run.
func (c Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Vault.ListenAddress) == "" {
		errs = append(errs, errors.New("vault.listen_address required"))
	} else if _, _, err := net.SplitHostPort(c.Vault.ListenAddress); err != nil {
		errs = append(errs, fmt.Errorf("vault.listen_address invalid: %w", err))
	}

	if c.Vault.TLS.Enabled {
		if c.Vault.TLS.ServerCert == "" {
			errs = append(errs, errors.New("vault.tls.server_cert required when TLS enabled"))
		}
		if c.Vault.TLS.ServerKey == "" {
			errs = append(errs, errors.New("vault.tls.server_key required when TLS enabled"))
		}
		if c.Vault.TLS.ClientCAs == "" {
			errs = append(errs, errors.New("vault.tls.client_cas required when TLS enabled"))
		}
	} else if _, _, err := net.SplitHostPort(c.Vault.ListenAddress); err == nil &&
		!exposure.IsLoopback(c.Vault.ListenAddress) {
		// Fail closed: a Return Path listener reachable from the
		// network must authenticate workers with mTLS.
		errs = append(errs, fmt.Errorf(
			"vault.tls.enabled required: listen_address %q is not loopback (workers across a network must use mTLS)",
			c.Vault.ListenAddress))
	}

	// http_api.listen_address is optional (empty → disabled); when
	// present it must parse as host:port.
	if c.HTTPAPI.BearerToken != "" && c.HTTPAPI.BearerTokenFile != "" {
		errs = append(errs, errors.New("http_api: set only one of bearer_token and bearer_token_file"))
	}
	if c.HTTPAPI.ListenAddress != "" {
		if _, _, err := net.SplitHostPort(c.HTTPAPI.ListenAddress); err != nil {
			errs = append(errs, fmt.Errorf("http_api.listen_address invalid: %w", err))
		} else if !exposure.IsLoopback(c.HTTPAPI.ListenAddress) {
			// Fail closed: an operator REST API reachable from the
			// network must require a bearer token.
			switch {
			case c.HTTPAPI.BearerToken == "" && c.HTTPAPI.BearerTokenFile == "":
				errs = append(errs, fmt.Errorf(
					"http_api.bearer_token or bearer_token_file required: listen_address %q is not loopback",
					c.HTTPAPI.ListenAddress))
			case c.HTTPAPI.BearerToken != "" && len(c.HTTPAPI.BearerToken) < MinNonLoopbackTokenLen:
				errs = append(errs, fmt.Errorf(
					"http_api.bearer_token too short for non-loopback listen_address %q (need >= %d characters)",
					c.HTTPAPI.ListenAddress, MinNonLoopbackTokenLen))
			}
		}
	}

	if strings.TrimSpace(c.TEE.WorkloadDescriptor) == "" {
		errs = append(errs, errors.New("tee.workload_descriptor required"))
	}
	errs = append(errs, validateTEE(c.TEE)...)

	if c.Keys.AuthoritySigning.KeyID == "" {
		errs = append(errs, errors.New("keys.authority_signing.kid required"))
	}
	if c.Keys.AuthoritySigning.SeedPath == "" {
		errs = append(errs, errors.New("keys.authority_signing.seed_path required"))
	}
	if c.Keys.SessionSealing.KeyID == "" {
		errs = append(errs, errors.New("keys.session_sealing.kid required"))
	}
	if c.Keys.SessionSealing.MaterialPath == "" {
		errs = append(errs, errors.New("keys.session_sealing.material_path required"))
	}

	if c.Workers.RegistryPath == "" {
		errs = append(errs, errors.New("workers.registry_path required"))
	}

	if c.Runtime.JobTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.job_timeout_seconds must be > 0"))
	}
	if c.Runtime.HandshakeTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.handshake_timeout_seconds must be > 0"))
	}
	if c.Runtime.QueuePollMs <= 0 {
		errs = append(errs, errors.New("runtime.queue_poll_ms must be > 0"))
	}
	if c.Runtime.HTTPReadHeaderTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.http_read_header_timeout_seconds must be > 0"))
	}
	if c.Runtime.HTTPWriteTimeoutSeconds <= 0 {
		errs = append(errs, errors.New("runtime.http_write_timeout_seconds must be > 0"))
	}
	if c.Runtime.DefaultJobDeadlineSeconds <= 0 {
		errs = append(errs, errors.New("runtime.default_job_deadline_seconds must be > 0"))
	}
	if c.Runtime.MaxPayloadBytes == 0 {
		errs = append(errs, errors.New("runtime.max_payload_bytes must be > 0"))
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

	if g := c.Genome.Gate; g.Atol < 0 || g.Rtol < 0 {
		errs = append(errs, errors.New("genome.gate.atol and rtol must be >= 0"))
	}
	if c.Genome.Gate.MaxNonCriticalOutliers < 0 {
		errs = append(errs, errors.New("genome.gate.max_non_critical_outliers must be >= 0"))
	}
	if b := c.Genome.Gate.Bfloat16; b != nil && (b.Atol < 0 || b.Rtol < 0) {
		errs = append(errs, errors.New("genome.gate.bfloat16.atol and rtol must be >= 0"))
	}
	if c.Genome.BundleDir != "" && !filepath.IsAbs(c.Genome.BundleDir) {
		errs = append(errs, fmt.Errorf("genome.bundle_dir %q must be an absolute path", c.Genome.BundleDir))
	}
	if c.Genome.Enabled() && c.Audit.LogPath == "" {
		errs = append(errs, errors.New("audit.log_path required when genome.bundle_dir is set: a gate job is a decision, and no decision is taken off the record"))
	}
	if c.OperatorStopEnabled() {
		if s := c.OperatorStop; s.KeyID == "" || s.PublicKeyPath == "" || s.ListPath == "" {
			errs = append(errs, errors.New("operator_stop.kid, public_key_path and list_path are all required when any is set"))
		}
	}
	if c.Runtime.EvidenceMaxAgeSeconds < 0 {
		errs = append(errs, errors.New("runtime.evidence_max_age_seconds must be >= 0 (0 = the attestation default)"))
	}
	if c.Audit.LogPath != "" {
		if c.Keys.AuditSigning.KeyID == "" || c.Keys.AuditSigning.SeedPath == "" {
			errs = append(errs, errors.New("keys.audit_signing.kid and seed_path required when audit.log_path is set"))
		}
		if c.CrossCloud.AuditLogPath != "" && filepath.Clean(c.CrossCloud.AuditLogPath) == filepath.Clean(c.Audit.LogPath) {
			errs = append(errs, errors.New("audit.log_path and crosscloud.audit_log_path must be different files: the daemon holds its log open, and one process holds a log at a time"))
		}
	}

	// CrossCloud is opt-in; only validate fields when enabled.
	if c.CrossCloud.Enabled {
		if strings.TrimSpace(c.CrossCloud.PolicyVersion) == "" {
			errs = append(errs, errors.New("crosscloud.policy_version required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.PolicyAllowListPath == "" {
			errs = append(errs, errors.New("crosscloud.policy_allow_list_path required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.VerifierRegistryPath == "" {
			errs = append(errs, errors.New("crosscloud.verifier_registry_path required when crosscloud.enabled=true"))
		}
		if c.CrossCloud.AuditLogPath == "" {
			errs = append(errs, errors.New("crosscloud.audit_log_path required when crosscloud.enabled=true (no key is released without a durable audit record)"))
		}
		if c.Keys.AuditSigning.KeyID == "" || c.Keys.AuditSigning.SeedPath == "" {
			errs = append(errs, errors.New("keys.audit_signing.kid and seed_path required when crosscloud.enabled=true"))
		}
		if s := c.CrossCloud.OperatorStop; s.KeyID == "" || s.PublicKeyPath == "" || s.ListPath == "" {
			errs = append(errs, errors.New("crosscloud.operator_stop.kid, public_key_path and list_path required when crosscloud.enabled=true (the operator must be able to stop every release)"))
		}
		if c.CrossCloud.RequestTimeoutSeconds < 0 {
			errs = append(errs, errors.New("crosscloud.request_timeout_seconds must be >= 0 (0 = no per-request timeout)"))
		}
		if c.CrossCloud.TransportTLS.Enabled {
			if c.CrossCloud.TransportTLS.ClientCert == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.client_cert required when transport_tls.enabled=true"))
			}
			if c.CrossCloud.TransportTLS.ClientKey == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.client_key required when transport_tls.enabled=true"))
			}
			if c.CrossCloud.TransportTLS.CABundle == "" {
				errs = append(errs, errors.New("crosscloud.transport_tls.ca_bundle required when transport_tls.enabled=true"))
			}
		}
	}

	return errors.Join(errs...)
}
