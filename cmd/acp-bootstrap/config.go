// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

// Config is the on-disk JSON configuration for acp-bootstrap.
//
// Operators construct one config file per destination deployment.
// Defaults exist for almost every field — only the security-critical
// material paths must be specified.
type Config struct {
	// HTTP controls the cross-cloud listener (handshake + token
	// endpoints). At least ListenAddress is required.
	HTTP HTTPConfig `json:"http"`

	// TEE configures the destination's local TEE producer. This build
	// runs tee.ProviderSimulated with a configured seed file; the
	// hardware producers slot into the same section.
	TEE TEEConfig `json:"tee"`

	// SourceAuthority points at the source authority's signing
	// public key. Loaded once at startup; the receiver verifies
	// every incoming handshake + token signature against it.
	SourceAuthority SourceAuthorityConfig `json:"source_authority"`

	// Genome, when set, makes this destination restore the genomes
	// whose keys are released to it (ADR 0011). Omitted, the daemon only
	// receives keys.
	Genome GenomeConfig `json:"genome,omitempty"`

	// Health controls the /healthz and /readyz listener. Empty
	// disables it. It answers liveness only and exposes nothing else.
	Health HealthConfig `json:"health,omitempty"`

	// Log controls structured-logging format and verbosity.
	Log LogConfig `json:"log"`
}

// HTTPConfig controls the destination's HTTP listener.
type HTTPConfig struct {
	// ListenAddress is the host:port the daemon binds to accept
	// /v1/crosscloud/handshake and /v1/crosscloud/token requests.
	ListenAddress string `json:"listen_address"`

	// BearerToken, if non-empty, is enforced on every incoming
	// request via constant-time compare. Defence-in-depth alongside
	// the source authority's signatures on every payload. On a
	// non-loopback listener without mTLS it is required and must be at
	// least exposure.MinBearerTokenLen characters.
	BearerToken string `json:"bearer_token,omitempty"`

	// BearerTokenFile is the path to a file holding the bearer token
	// (surrounding whitespace is trimmed). Prefer it over BearerToken
	// so the secret lives with the other key material rather than in
	// the config file. Mutually exclusive with BearerToken; resolved at
	// startup by ResolveSecrets().
	BearerTokenFile string `json:"bearer_token_file,omitempty"`

	// TLS configures the inbound TLS / mTLS material. Plain HTTP is
	// accepted only on a loopback listen address; Validate() refuses a
	// non-loopback listener without TLS.
	TLS TLSServerConfig `json:"tls,omitempty"`

	// ReadHeaderTimeoutSeconds bounds HTTP request header reads
	// (slow-loris defense). Defaults to 5s.
	ReadHeaderTimeoutSeconds int `json:"read_header_timeout_seconds,omitempty"`

	// WriteTimeoutSeconds bounds full response write duration.
	// Defaults to 30s.
	WriteTimeoutSeconds int `json:"write_timeout_seconds,omitempty"`
}

// TLSServerConfig holds the inbound TLS material for the HTTP
// listener. The listener speaks TLS 1.3 only. ClientCAs, when set,
// makes it require and verify a client certificate (mTLS).
type TLSServerConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCAs  string `json:"client_cas"`
}

// TEEConfig holds the destination's local TEE producer
// configuration.
type TEEConfig struct {
	// Provider names the TEE backend: "gcp-sev-snp" (AMD SEV-SNP
	// reports through the kernel's configfs-tsm, on any SEV-SNP
	// Confidential VM running Linux 6.7 or later) or "simulated" (a
	// seed-derived stand-in for development and tests). The provider is
	// also the destination_tee_kind every handshake must declare.
	Provider string `json:"provider"`

	// WorkloadDescriptor is hashed into the local measurement for
	// the simulated backend. For real backends, this is
	// informational; the measurement comes from the chip.
	WorkloadDescriptor string `json:"workload_descriptor"`

	// SeedPath is a 32-byte file holding the Ed25519 seed used to
	// derive this destination's attestation key. Simulated backend
	// only. Sensitive — chmod 0600.
	SeedPath string `json:"seed_path,omitempty"`

	// TSMReportDir overrides the configfs-tsm report directory
	// (default /sys/kernel/config/tsm/report). gcp-sev-snp only.
	TSMReportDir string `json:"tsm_report_dir,omitempty"`

	// InsecureSimulation must be true to run the simulated provider,
	// and only then: it says, in the config itself, that this
	// destination has no hardware isolation — its "Evidence" is signed
	// by a key read from a file — and is for development and tests.
	InsecureSimulation bool `json:"insecure_simulation,omitempty"`

	// GPUAttestCommand, TPM2ToolsDir and AKHandle configure the
	// azure-cgpu producer: the command that obtains NVIDIA's signed
	// attestation tokens for a nonce (the nonce is appended; required),
	// where tpm2-tools live (default PATH), and the vTPM handle of the
	// HCL attestation key (default: found by its public key). azure-cgpu
	// only.
	GPUAttestCommand []string `json:"gpu_attest_command,omitempty"`
	TPM2ToolsDir     string   `json:"tpm2_tools_dir,omitempty"`
	AKHandle         string   `json:"ak_handle,omitempty"`

	// SEVGuestDevice is the sev-guest device this host's sealing key is
	// derived through (`acp-bootstrap seal-keys`, ADR 0023; default
	// /dev/sev-guest). gcp-sev-snp only.
	SEVGuestDevice string `json:"sev_guest_device,omitempty"`
	// VTPMSealPCRs is the PCR selection the secret files are sealed to on
	// a gcp-tdx or azure-cgpu host (ADR 0022; default sha256:0-14, the
	// boot the operator pins). Those providers only.
	VTPMSealPCRs string `json:"vtpm_seal_pcrs,omitempty"`
}

// DefaultSEVGuestDevice is where the Linux sev-guest driver appears.
const DefaultSEVGuestDevice = "/dev/sev-guest"

// SEVDevice is the sev-guest device to derive the sealing key through.
func (t TEEConfig) SEVDevice() string {
	if t.SEVGuestDevice != "" {
		return t.SEVGuestDevice
	}
	return DefaultSEVGuestDevice
}

// supportedProviders are the TEE backends this build can run.
var supportedProviders = []tee.Provider{tee.ProviderGCPSEVSNP, tee.ProviderGCPTDX, tee.ProviderAzureCGPU, tee.ProviderSimulated}

// SourceAuthorityConfig points at the source-authority signing
// public key file. Used by the receiver to verify every handshake +
// token signature.
type SourceAuthorityConfig struct {
	// KeyID is the kid the source authority uses when signing.
	// Embedded in every CrossCloudHandshakeRequest and
	// KeyReleaseToken; the receiver looks up the pubkey by this
	// kid.
	KeyID string `json:"kid"`

	// PublicKeyPath holds the source authority's Ed25519 public key.
	// Accepts either:
	//   * a raw 32-byte file, or
	//   * a PEM-encoded SubjectPublicKeyInfo.
	// The format is auto-detected from the leading bytes.
	PublicKeyPath string `json:"public_key_path"`
}

// GenomeConfig points the restorer at its directories.
type GenomeConfig struct {
	// BundleDir holds sealed .genome bundles waiting for their keys.
	// A bundle is opaque without its key, so bundles can be replicated
	// here from anywhere, ahead of any release. Copy them in under
	// another name and rename them to *.genome, so the restorer never
	// reads a half-written bundle.
	BundleDir string `json:"bundle_dir"`

	// RestoreDir receives each restored genome at <restore_dir>/<key
	// id>/ and its signed receipt at <restore_dir>/<key id>.receipt.json.
	RestoreDir string `json:"restore_dir"`

	// RescanSeconds is how often to look again for the bundle of a key
	// that arrived first. Defaults to 5.
	RescanSeconds int `json:"rescan_seconds,omitempty"`

	// Gate, when set, proves each restored model works before the
	// receipt is signed: Command (the vg_genome door) recomputes the
	// genome's sealed fixtures here and the equivalence gate holds the
	// outputs to their references. The verdict goes into the receipt.
	Gate *GateConfig `json:"gate,omitempty"`
}

// GateConfig configures the restored-model gate.
type GateConfig struct {
	// Command runs the gate backend; "{genome}" in an argument is the
	// restored genome's directory. For example:
	// ["python3", "-m", "vg_genome", "door", "--genome", "{genome}",
	//  "--base", "/var/lib/acp/base/qwen2.5-0.5b", "--device", "cuda"]
	Command []string `json:"command"`
	// Env adds KEY=VALUE pairs to the backend's environment.
	Env []string `json:"env,omitempty"`
	// Atol and Rtol bound the float door: |a-e| <= atol + rtol*|e|.
	Atol float64 `json:"atol"`
	Rtol float64 `json:"rtol"`
	// MaxOutliers non-critical fixtures may miss; critical ones never.
	MaxOutliers int `json:"max_outliers,omitempty"`
	// TimeoutSeconds bounds a gate run. Defaults to 1800.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// Required fails a restore that cannot be gated rather than signing
	// for it without a verdict.
	Required bool `json:"required,omitempty"`
}

// Enabled reports whether genome restore is configured.
func (g GenomeConfig) Enabled() bool { return g.BundleDir != "" || g.RestoreDir != "" }

// HealthConfig controls /healthz and /readyz.
type HealthConfig struct {
	ListenAddress string `json:"listen_address"`
}

// LogConfig picks log verbosity and format.
type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// ReadHeaderTimeout returns HTTPConfig.ReadHeaderTimeoutSeconds as a
// Duration with a 5s default.
func (h HTTPConfig) ReadHeaderTimeout() time.Duration {
	if h.ReadHeaderTimeoutSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(h.ReadHeaderTimeoutSeconds) * time.Second
}

// WriteTimeout returns HTTPConfig.WriteTimeoutSeconds as a Duration
// with a 30s default.
func (h HTTPConfig) WriteTimeout() time.Duration {
	if h.WriteTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(h.WriteTimeoutSeconds) * time.Second
}

// DefaultConfig returns sensible defaults that operators can
// override field-by-field via JSON.
func DefaultConfig() Config {
	return Config{
		HTTP: HTTPConfig{
			ListenAddress: "127.0.0.1:8443",
		},
		TEE: TEEConfig{
			WorkloadDescriptor: "acp-bootstrap-destination-v1",
		},
		Health: HealthConfig{
			ListenAddress: "127.0.0.1:8444",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// LoadConfigFile reads and decodes a JSON file on top of
// DefaultConfig(). Unknown fields are rejected to catch operator
// typos at startup.
func LoadConfigFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("acp-bootstrap: open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return DecodeConfig(f)
}

// DecodeConfig decodes JSON from r into a Config on top of
// DefaultConfig.
func DecodeConfig(r io.Reader) (Config, error) {
	c := DefaultConfig()
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("acp-bootstrap: decode config: %w", err)
	}
	return c, nil
}

// ResolveSecrets loads secret values that the config references by
// path rather than inline — today the bearer token
// (http.bearer_token_file). Call it after Validate().
func (c *Config) ResolveSecrets() error {
	if c.HTTP.BearerTokenFile == "" {
		return nil
	}
	// The file may be sealed to this host (`acp-bootstrap seal-keys`, ADR 0023).
	raw, err := readSecret(c.TEE, c.HTTP.BearerTokenFile, 0, "http.bearer_token_file")
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("acp-bootstrap: http.bearer_token_file %q is empty", c.HTTP.BearerTokenFile)
	}
	if !exposure.IsLoopback(c.HTTP.ListenAddress) && len(token) < exposure.MinBearerTokenLen {
		return fmt.Errorf("acp-bootstrap: token in %q too short for non-loopback listen_address %q (need >= %d characters)",
			c.HTTP.BearerTokenFile, c.HTTP.ListenAddress, exposure.MinBearerTokenLen)
	}
	c.HTTP.BearerToken = token
	return nil
}

// Validate enforces structural checks. Returns a joined error so
// operators see the full punch-list per run.
//
// Network exposure fails closed: plain HTTP and unauthenticated
// callers are accepted only on a loopback listen address. Beyond it
// the listener must speak TLS, and callers must present either a
// client certificate (http.tls.client_cas) or a bearer token of at
// least exposure.MinBearerTokenLen characters.
func (c Config) Validate() error {
	var errs []error

	listenOK := false
	if strings.TrimSpace(c.HTTP.ListenAddress) == "" {
		errs = append(errs, errors.New("http.listen_address required"))
	} else if _, _, err := net.SplitHostPort(c.HTTP.ListenAddress); err != nil {
		errs = append(errs, fmt.Errorf("http.listen_address invalid: %w", err))
	} else {
		listenOK = true
	}

	if c.HTTP.TLS.Enabled {
		if c.HTTP.TLS.ServerCert == "" {
			errs = append(errs, errors.New("http.tls.server_cert required when http.tls.enabled=true"))
		}
		if c.HTTP.TLS.ServerKey == "" {
			errs = append(errs, errors.New("http.tls.server_key required when http.tls.enabled=true"))
		}
	} else if c.HTTP.TLS.ClientCAs != "" {
		errs = append(errs, errors.New("http.tls.client_cas set but http.tls.enabled=false"))
	}
	if c.HTTP.BearerToken != "" && c.HTTP.BearerTokenFile != "" {
		errs = append(errs, errors.New("http: set only one of bearer_token and bearer_token_file"))
	}
	if listenOK && !exposure.IsLoopback(c.HTTP.ListenAddress) {
		if !c.HTTP.TLS.Enabled {
			errs = append(errs, fmt.Errorf(
				"http.tls.enabled required: listen_address %q is not loopback (key-release traffic across a network must be encrypted)",
				c.HTTP.ListenAddress))
		}
		hasToken := c.HTTP.BearerToken != "" || c.HTTP.BearerTokenFile != ""
		if c.HTTP.TLS.ClientCAs == "" && !hasToken {
			errs = append(errs, fmt.Errorf(
				"http.tls.client_cas or http.bearer_token(_file) required: listen_address %q is not loopback",
				c.HTTP.ListenAddress))
		}
		if c.HTTP.BearerToken != "" && len(c.HTTP.BearerToken) < exposure.MinBearerTokenLen {
			errs = append(errs, fmt.Errorf(
				"http.bearer_token too short for non-loopback listen_address %q (need >= %d characters)",
				c.HTTP.ListenAddress, exposure.MinBearerTokenLen))
		}
	}

	switch provider, err := tee.ParseProvider(c.TEE.Provider); {
	case strings.TrimSpace(c.TEE.Provider) == "":
		errs = append(errs, errors.New("tee.provider required"))
	case err != nil:
		errs = append(errs, fmt.Errorf("tee.provider invalid: %w", err))
	case !slices.Contains(supportedProviders, provider):
		errs = append(errs, fmt.Errorf("tee.provider %q is not available in this build (supported: %v)", provider, supportedProviders))
	case provider == tee.ProviderSimulated:
		if !c.TEE.InsecureSimulation {
			errs = append(errs, errors.New("tee.provider=simulated has no hardware isolation: set tee.insecure_simulation=true to run it, for development and tests only"))
		}
		if c.TEE.SeedPath == "" {
			errs = append(errs, errors.New("tee.seed_path required when tee.provider=simulated"))
		}
		if c.TEE.TSMReportDir != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir applies to gcp-sev-snp and gcp-tdx only"))
		}
	case provider == tee.ProviderGCPSEVSNP || provider == tee.ProviderGCPTDX:
		if c.TEE.SeedPath != "" {
			errs = append(errs, errors.New("tee.seed_path applies to the simulated provider only; a hardware TEE signs with its own key"))
		}
		if c.TEE.InsecureSimulation {
			errs = append(errs, errors.New("tee.insecure_simulation applies to the simulated provider only"))
		}
	case provider == tee.ProviderAzureCGPU:
		if c.TEE.SeedPath != "" || c.TEE.InsecureSimulation {
			errs = append(errs, errors.New("tee.seed_path and tee.insecure_simulation apply to the simulated provider only"))
		}
		if c.TEE.TSMReportDir != "" {
			errs = append(errs, errors.New("tee.tsm_report_dir does not apply to azure-cgpu (the report comes from the vTPM)"))
		}
		if len(c.TEE.GPUAttestCommand) == 0 {
			errs = append(errs, errors.New("tee.gpu_attest_command required when tee.provider=azure-cgpu (the command that obtains NVIDIA's attestation tokens for a nonce)"))
		}
	}
	if lp, _ := tee.ParseProvider(c.TEE.Provider); lp != tee.ProviderAzureCGPU && (len(c.TEE.GPUAttestCommand) > 0 || c.TEE.TPM2ToolsDir != "" || c.TEE.AKHandle != "") {
		errs = append(errs, errors.New("tee.gpu_attest_command, tpm2_tools_dir and ak_handle apply to azure-cgpu only"))
	}
	if strings.TrimSpace(c.TEE.WorkloadDescriptor) == "" {
		errs = append(errs, errors.New("tee.workload_descriptor required"))
	}

	if c.SourceAuthority.KeyID == "" {
		errs = append(errs, errors.New("source_authority.kid required"))
	}
	if c.SourceAuthority.PublicKeyPath == "" {
		errs = append(errs, errors.New("source_authority.public_key_path required"))
	}

	if c.Genome.Enabled() {
		errs = append(errs, c.Genome.validate()...)
	}

	if c.Health.ListenAddress != "" {
		if _, _, err := net.SplitHostPort(c.Health.ListenAddress); err != nil {
			errs = append(errs, fmt.Errorf("health.listen_address invalid: %w", err))
		}
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

	if provider, err := tee.ParseProvider(c.TEE.Provider); err == nil {
		if c.TEE.SEVGuestDevice != "" && provider != tee.ProviderGCPSEVSNP {
			errs = append(errs, errors.New("tee.sev_guest_device applies to gcp-sev-snp only"))
		}
		if c.TEE.VTPMSealPCRs != "" {
			switch provider {
			case tee.ProviderGCPTDX, tee.ProviderAzureCGPU:
				if err := tee.ValidatePCRSelection(c.TEE.VTPMSealPCRs); err != nil {
					errs = append(errs, fmt.Errorf("tee.vtpm_seal_pcrs: %w", err))
				}
			default:
				errs = append(errs, errors.New("tee.vtpm_seal_pcrs applies to gcp-tdx and azure-cgpu only"))
			}
		}
	}
	return errors.Join(errs...)
}

func (g GenomeConfig) validate() []error {
	var errs []error
	for name, dir := range map[string]string{"genome.bundle_dir": g.BundleDir, "genome.restore_dir": g.RestoreDir} {
		if dir == "" {
			errs = append(errs, fmt.Errorf("%s required when genome restore is configured", name))
		} else if !filepath.IsAbs(dir) {
			errs = append(errs, fmt.Errorf("%s %q must be an absolute path", name, dir))
		}
	}
	if g.BundleDir != "" && g.RestoreDir != "" {
		b, r := filepath.Clean(g.BundleDir), filepath.Clean(g.RestoreDir)
		if b == r || strings.HasPrefix(r+string(filepath.Separator), b+string(filepath.Separator)) || strings.HasPrefix(b+string(filepath.Separator), r+string(filepath.Separator)) {
			errs = append(errs, errors.New("genome.bundle_dir and genome.restore_dir must be separate directories, neither inside the other"))
		}
	}
	if g.RescanSeconds < 0 {
		errs = append(errs, errors.New("genome.rescan_seconds must not be negative"))
	}
	if gate := g.Gate; gate != nil {
		if len(gate.Command) == 0 || strings.TrimSpace(gate.Command[0]) == "" {
			errs = append(errs, errors.New("genome.gate.command required"))
		}
		if gate.Atol < 0 || gate.Rtol < 0 || gate.MaxOutliers < 0 || gate.TimeoutSeconds < 0 {
			errs = append(errs, errors.New("genome.gate: atol, rtol, max_outliers and timeout_seconds must not be negative"))
		}
		for _, kv := range gate.Env {
			if k, _, ok := strings.Cut(kv, "="); !ok || k == "" {
				errs = append(errs, fmt.Errorf("genome.gate.env %q is not KEY=VALUE", kv))
			}
		}
	}
	return errs
}
