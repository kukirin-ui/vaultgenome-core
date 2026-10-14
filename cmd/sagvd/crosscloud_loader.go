// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// CrossCloudAuditSigningKeyID is the kid under which the cross-cloud
// audit-signing key is registered inside crossCloudMaterials. The
// audit-signing key is private to the cross-cloud subsystem and is
// regenerated at every daemon restart for the Phase 4 MVP — chain
// continuity across restart is a Phase 5 enhancement.
const CrossCloudAuditSigningKeyID ids.KeyID = "xcc-audit-1"

// crossCloudMaterials bundles every Phase 4 cross-cloud dependency
// the daemon assembles at startup. Constructed by
// LoadCrossCloudMaterials when CrossCloud.Enabled is true; nil
// otherwise.
//
// The Coordinator itself is NOT part of this bundle — it is wired
// into the Daemon at the call site (daemon.go) because it needs the
// Daemon's source-authority Signer (already loaded by LoadMaterials)
// alongside the cross-cloud-private dependencies bundled here.
type crossCloudMaterials struct {
	// VerifierRegistry holds one tee.Verifier per cross-cloud
	// destination this authority may release keys to.
	VerifierRegistry *tee.Registry

	// Policy is the release policy: the operator's stop list in front
	// of the allow-list. Its PolicyVersion names both, and is written
	// into every release decision on record.
	Policy kms.KeyReleasePolicy

	// StopSerial is the serial of the operator stop list in force.
	StopSerial uint64

	// AllowList and StopList are Policy's parts, for callers that put a
	// narrower policy between them (sagvd failover).
	AllowList kms.KeyReleasePolicy
	StopList  revocation.List

	// Transport is the HTTPTransport configured against
	// CrossCloud.TransportTLS / TransportBearerToken /
	// RequestTimeoutSeconds. Used by the Coordinator to dispatch
	// handshakes and tokens to destination acp-bootstrap endpoints.
	Transport *kms.HTTPTransport

	// AuditChain is the durable, verified audit log the Coordinator's
	// chainAuditEmitter appends to, signed under the configured
	// keys.audit_signing key (keys.PurposeSigningAudit).
	AuditChain chain.Chain

	// AuditEmitter is the kms.AuditEmitter implementation the
	// Coordinator uses. Wraps AuditChain + AuditStore + signing kid.
	AuditEmitter kms.AuditEmitter

	// auditStore holds the audit-signing key. Kept private so the
	// daemon doesn't accidentally use it for non-audit signing.
	auditStore *keys.InMemoryStore

	// auditLog is the durable store behind AuditChain; Close releases it.
	auditLog *store.BBoltStore

	// IDGenerator produces fresh RequestID / DecisionID per
	// cross-cloud invocation, backed by crypto/rand.
	IDGenerator kms.IDGenerator

	// NonceSource produces fresh handshake nonces for the
	// Coordinator, backed by crypto/rand.
	NonceSource kms.NonceSource
}

// Close releases the audit log. Safe on a nil receiver.
func (m *crossCloudMaterials) Close() error {
	if m == nil || m.auditLog == nil {
		return nil
	}
	return m.auditLog.Close()
}

// loadOperatorStop reads the operator's stop list and verifies it under
// the pinned operator key.
func loadOperatorStop(cfg OperatorStopConfig) (revocation.List, error) {
	pub, err := loadAttestorPubKey(cfg.PublicKeyPath)
	if err != nil {
		return revocation.List{}, fmt.Errorf("public_key_path %q: %w", cfg.PublicKeyPath, err)
	}
	raw, err := os.ReadFile(cfg.ListPath)
	if err != nil {
		return revocation.List{}, fmt.Errorf("list_path: %w (without a valid list nothing is released)", err)
	}
	return revocation.Parse(raw, ed25519.PublicKey(pub), cfg.KeyID)
}

// verifierRegistryFile is the on-disk JSON schema for
// CrossCloud.VerifierRegistryPath.
type verifierRegistryFile struct {
	Verifiers []verifierEntry `json:"verifiers"`
}

type verifierEntry struct {
	Provider               string `json:"provider"`
	ExpectedMeasurementHex string `json:"expected_measurement_hex"`

	// AttestorPubKeyPath is the simulated backend's attestation key
	// (raw 32 bytes or PEM, as `acp-bootstrap identity` prints it).
	AttestorPubKeyPath string `json:"attestor_pubkey_path,omitempty"`

	// SEV-SNP (provider "gcp-sev-snp"): the AMD ASK+ARK certificate
	// chain the VCEK must chain to (PEM, as AMD KDS serves it at
	// /vcek/v1/<product>/cert_chain), an optional KDS mirror, and the
	// minimum REPORTED_TCB to accept.
	AMDCertChainPath string `json:"amd_cert_chain_path,omitempty"`
	AMDKDSURL        string `json:"amd_kds_url,omitempty"`
	MinReportedTCB   uint64 `json:"min_reported_tcb,omitempty"`
	// VCEKCacheDir keeps fetched VCEK certificates between runs so each
	// chip's certificate is asked of AMD KDS once (KDS rate-limits).
	VCEKCacheDir string `json:"vcek_cache_dir,omitempty"`

	// TDX (provider "gcp-tdx"): the Intel PCS base URL (a mirror, a
	// PCCS), the directory the TCB info and QE identity documents are
	// kept in between runs, and the Intel TCB statuses accepted (default
	// UpToDate only).
	PCSURL                string   `json:"pcs_url,omitempty"`
	PCSCacheDir           string   `json:"pcs_cache_dir,omitempty"`
	AcceptableTCBStatuses []string `json:"acceptable_tcb_statuses,omitempty"`
	// NRASJWKSURL, NRASCacheDir, GPUPolicy and PCRDigests configure an
	// azure-cgpu verifier, with the AMD fields above (the Genoa chain).
	NRASJWKSURL  string           `json:"nras_jwks_url,omitempty"`
	NRASCacheDir string           `json:"nras_cache_dir,omitempty"`
	GPUPolicy    *GPUPolicyConfig `json:"gpu_policy,omitempty"`
	PCRDigests   []string         `json:"pcr_digests,omitempty"`
}

// allowListFile is the on-disk JSON schema for
// CrossCloud.PolicyAllowListPath.
type allowListFile struct {
	Version string              `json:"version"`
	Allowed map[string][]string `json:"allowed"`
}

// LoadCrossCloudMaterials reads the cross-cloud configuration from
// disk, builds the audit chain + emitter, and returns a fully-wired
// bundle. Returns nil, nil when CrossCloud.Enabled is false.
//
// File formats (all JSON):
//
//   - VerifierRegistryPath: see verifierRegistryFile schema.
//     Each entry's attestor_pubkey is loaded as either:
//
//   - a raw 32-byte file (Ed25519 public key), or
//
//   - a PEM-encoded SubjectPublicKeyInfo.
//     The format is auto-detected by checking the file's leading
//     bytes (the BEGIN PEM marker signals PEM; anything else is
//     treated as raw bytes).
//
//   - PolicyAllowListPath: see allowListFile schema. The version
//     in the file MUST equal CrossCloud.PolicyVersion to defend
//     against operator-mismatch (loading an old allow-list under
//     a new version label).
//
// Returns Structural errors for missing/malformed inputs.
func LoadCrossCloudMaterials(cfg Config, clock shared_time.Clock) (*crossCloudMaterials, error) {
	if !cfg.CrossCloud.Enabled {
		return nil, nil
	}
	if clock == nil {
		return nil, fmt.Errorf("sagvd: LoadCrossCloudMaterials: clock required when crosscloud.enabled=true")
	}

	registry, err := loadVerifierRegistry(cfg.CrossCloud.VerifierRegistryPath, cfg.CrossCloud.InsecureSimulatedDestinations)
	if err != nil {
		return nil, err
	}

	policy, err := loadAllowListPolicy(cfg.CrossCloud.PolicyVersion, cfg.CrossCloud.PolicyAllowListPath)
	if err != nil {
		return nil, err
	}

	transport, err := buildHTTPTransport(cfg.TEE, cfg.CrossCloud)
	if err != nil {
		return nil, err
	}

	// The durable audit log: opened and verified end to end under the
	// stable audit key before anything is appended. A log that does not
	// verify stops every release (fail closed).
	auditSeed, err := readSecret(cfg.TEE, cfg.Keys.AuditSigning.SeedPath, crypto.Ed25519SeedSize, "keys.audit_signing.seed_path")
	if err != nil {
		return nil, err
	}
	auditKID := ids.KeyID(cfg.Keys.AuditSigning.KeyID)
	auditStore := keys.NewInMemoryStore(clock)
	if _, err := auditStore.RegisterSigningFromSeed(auditKID, keys.PurposeSigningAudit, auditSeed); err != nil {
		return nil, fmt.Errorf("sagvd: register audit signing key: %w", err)
	}
	logStore, err := store.Open(cfg.CrossCloud.AuditLogPath)
	if err != nil {
		return nil, fmt.Errorf("sagvd: open crosscloud.audit_log_path: %w", err)
	}
	auditChain, err := chain.OpenPersistentChain(logStore, auditStore)
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: crosscloud.audit_log_path %q: %w", cfg.CrossCloud.AuditLogPath, err)
	}
	emitter, err := newChainAuditEmitter(
		auditChain,
		auditStore,
		auditKID,
		clock,
		"xcc-evt-",
	)
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: build cross-cloud audit emitter: %w", err)
	}
	// Event IDs continue the log rather than restarting with each run.
	emitter.counter = uint64(auditChain.Len())

	// The operator stop: a valid list signed by the operator key is
	// required, and a list older than one already applied (per the
	// verified audit log) is refused, so a stop cannot be rolled back.
	stopList, err := loadOperatorStop(cfg.CrossCloud.OperatorStop)
	if err == nil {
		err = revocation.CheckNotRolledBack(stopList, auditChain.Events())
	}
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("sagvd: crosscloud.operator_stop: %w", err)
	}

	return &crossCloudMaterials{
		VerifierRegistry: registry,
		Policy:           revocation.NewGate(policy, stopList),
		StopSerial:       stopList.Serial,
		AllowList:        policy,
		StopList:         stopList,
		Transport:        transport,
		AuditChain:       auditChain,
		AuditEmitter:     emitter,
		auditStore:       auditStore,
		auditLog:         logStore,
		IDGenerator:      newCryptoRandIDGenerator("xcc-req-", "xcc-dec-"),
		NonceSource:      freshNonceSource(),
	}, nil
}

// loadVerifierRegistry reads the JSON file at path and constructs a
// tee.Registry with one Verifier per entry. A simulated entry is
// accepted only with allowSimulated (crosscloud.insecure_simulated_destinations).
func loadVerifierRegistry(path string, allowSimulated bool) (*tee.Registry, error) {
	specs, err := loadVerifierSpecs(path, allowSimulated)
	if err != nil {
		return nil, err
	}
	return tee.NewRegistry(specs)
}

// loadVerifierSpecs reads the registry file into the specs the registry
// is built from: the anchors of each TEE kind (the AMD chain, the KDS
// mirror, the VCEK cache; a simulated attestor's key), which the failover
// executor also borrows to verify a pinned primary of the same kind.
func loadVerifierSpecs(path string, allowSimulated bool) ([]tee.RegistrySpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read verifier_registry_path %q: %w", path, err)
	}
	var file verifierRegistryFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("sagvd: decode verifier_registry_path %q: %w", path, err)
	}
	if len(file.Verifiers) == 0 {
		return nil, fmt.Errorf("sagvd: verifier_registry_path %q: at least one verifier entry required", path)
	}
	specs := make([]tee.RegistrySpec, 0, len(file.Verifiers))
	for i, e := range file.Verifiers {
		provider, err := tee.ParseProvider(e.Provider)
		if err != nil {
			return nil, fmt.Errorf("sagvd: verifier_registry[%d].provider %q invalid: %w", i, e.Provider, err)
		}
		measurementBytes, err := hex.DecodeString(e.ExpectedMeasurementHex)
		if err != nil {
			return nil, fmt.Errorf("sagvd: verifier_registry[%d].expected_measurement_hex: %w", i, err)
		}
		measurement, err := tee.MeasurementFromBytes(measurementBytes)
		if err != nil {
			return nil, fmt.Errorf("sagvd: verifier_registry[%d].expected_measurement_hex must be a 32-, 48- or 64-byte measurement: %w", i, err)
		}
		spec := tee.VerifierSpec{Provider: provider, ExpectedMeasurement: measurement}
		switch provider {
		case tee.ProviderSimulated:
			if !allowSimulated {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d]: a simulated destination has no hardware isolation; set crosscloud.insecure_simulated_destinations=true to release keys to one, for development and tests only", i)
			}
			pub, err := loadAttestorPubKey(e.AttestorPubKeyPath)
			if err != nil {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d].attestor_pubkey_path %q: %w", i, e.AttestorPubKeyPath, err)
			}
			spec.AttestorPubKey = pub
		case tee.ProviderGCPSEVSNP:
			if e.AMDCertChainPath == "" {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d]: gcp-sev-snp requires amd_cert_chain_path (the AMD ASK+ARK chain the VCEK must chain to)", i)
			}
			chain, err := os.ReadFile(e.AMDCertChainPath)
			if err != nil {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d].amd_cert_chain_path: %w", i, err)
			}
			spec.GCPSEV = tee.GCPSEVVerifierConfig{
				AMDRootPEM:     chain,
				AMDKDSURL:      e.AMDKDSURL,
				MinReportedTCB: e.MinReportedTCB,
				VCEKCacheDir:   e.VCEKCacheDir,
			}
		case tee.ProviderGCPTDX:
			spec.GCPTDX = tee.GCPTDXVerifierConfig{PCSURL: e.PCSURL, PCSCacheDir: e.PCSCacheDir, AcceptableTCBStatuses: e.AcceptableTCBStatuses}
		case tee.ProviderAzureCGPU:
			if e.AMDCertChainPath == "" {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d]: azure-cgpu requires amd_cert_chain_path (the AMD ASK+ARK chain of the chip's product, Genoa for NCC H100 v5)", i)
			}
			chain, err := os.ReadFile(e.AMDCertChainPath)
			if err != nil {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d].amd_cert_chain_path: %w", i, err)
			}
			digests, err := pcrDigests(e.PCRDigests)
			if err != nil {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d].%w", i, err)
			}
			spec.AzureCGPU = tee.AzureCGPUVerifierConfig{AMDRootPEM: chain, AMDKDSURL: e.AMDKDSURL, VCEKCacheDir: e.VCEKCacheDir, MinReportedTCB: e.MinReportedTCB,
				NRASJWKSURL: e.NRASJWKSURL, NRASCacheDir: e.NRASCacheDir, GPU: e.GPUPolicy.policy(), AcceptablePCRDigests: digests}
			if err := e.GPUPolicy.validate(); err != nil {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d].%w", i, err)
			}
			if err := e.GPUPolicy.apply(&spec.AzureCGPU); err != nil {
				return nil, fmt.Errorf("sagvd: verifier_registry[%d].%w", i, err)
			}
		default:
			// Fail closed: a family whose verifier this build cannot run
			// end to end must not be trusted with key releases.
			return nil, fmt.Errorf("sagvd: verifier_registry[%d].provider %q: no verifier this build can run end to end (supported: simulated, gcp-sev-snp, gcp-tdx, azure-cgpu)", i, provider)
		}
		specs = append(specs, tee.RegistrySpec{Provider: provider, Spec: spec})
	}
	return specs, nil
}

// loadAttestorPubKey reads a public key from disk, accepting either a
// raw 32-byte Ed25519 key or a PEM-encoded SubjectPublicKeyInfo.
func loadAttestorPubKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// PEM-encoded SubjectPublicKeyInfo path.
	if strings.Contains(string(data), "-----BEGIN") {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("attestor_pubkey: invalid PEM")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attestor_pubkey: parse PKIX: %w", err)
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("attestor_pubkey: PEM key is %T, want ed25519.PublicKey", key)
		}
		return crypto.PublicKey(ed), nil
	}
	// Raw 32-byte path.
	if len(data) != crypto.Ed25519PublicKeySize {
		return nil, fmt.Errorf("attestor_pubkey: file %d bytes, want %d (raw Ed25519) or PEM-encoded", len(data), crypto.Ed25519PublicKeySize)
	}
	return crypto.PublicKey(data), nil
}

// loadAllowListPolicy parses the JSON allow-list file and constructs
// a kms.AllowListPolicy. The file's version field MUST equal the
// configured policyVersion — a mismatch signals operator drift and is
// rejected before any restore can run.
func loadAllowListPolicy(policyVersion, path string) (*kms.AllowListPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read policy_allow_list_path %q: %w", path, err)
	}
	var file allowListFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("sagvd: decode policy_allow_list_path %q: %w", path, err)
	}
	if file.Version != policyVersion {
		return nil, fmt.Errorf("sagvd: policy_allow_list_path %q version %q does not match crosscloud.policy_version %q (operator drift; refusing to load)",
			path, file.Version, policyVersion)
	}
	allowed := make(map[tee.Provider][][]byte, len(file.Allowed))
	for providerStr, hexList := range file.Allowed {
		provider, err := tee.ParseProvider(providerStr)
		if err != nil {
			return nil, fmt.Errorf("sagvd: policy_allow_list_path %q: provider %q invalid: %w", path, providerStr, err)
		}
		out := make([][]byte, 0, len(hexList))
		for i, h := range hexList {
			b, err := hex.DecodeString(h)
			if err != nil {
				return nil, fmt.Errorf("sagvd: policy_allow_list_path %q: %s[%d] hex decode: %w", path, providerStr, i, err)
			}
			if _, err := tee.MeasurementFromBytes(b); err != nil {
				return nil, fmt.Errorf("sagvd: policy_allow_list_path %q: %s[%d] must be a 32-, 48- or 64-byte measurement; got %d bytes", path, providerStr, i, len(b))
			}
			out = append(out, b)
		}
		allowed[provider] = out
	}
	return kms.NewAllowListPolicy(policyVersion, allowed)
}

// buildHTTPTransport constructs a kms.HTTPTransport configured with
// (optional) mTLS and Bearer auth.
func buildHTTPTransport(teeCfg TEEConfig, cfg CrossCloudConfig) (*kms.HTTPTransport, error) {
	httpClient := &http.Client{}
	if cfg.TransportTLS.Enabled {
		tlsConfig, err := buildClientTLSConfig(teeCfg, cfg.TransportTLS)
		if err != nil {
			return nil, err
		}
		httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
	httpClient.Timeout = cfg.RequestTimeout() + 5*time.Second // outer ceiling > per-request timeout
	return kms.NewHTTPTransport(kms.HTTPTransportConfig{
		HTTPClient:     httpClient,
		BearerToken:    cfg.TransportBearerToken,
		RequestTimeout: cfg.RequestTimeout(),
	}), nil
}

// buildClientTLSConfig assembles a *tls.Config from the operator-
// supplied client certificate, key, and CA bundle.
func buildClientTLSConfig(teeCfg TEEConfig, cfg TLSClientConfig) (*tls.Config, error) {
	certPEM, err := os.ReadFile(cfg.ClientCert)
	if err != nil {
		return nil, fmt.Errorf("sagvd: load mTLS client cert/key: %w", err)
	}
	// The key file may be sealed to this host (`sagvd seal-keys`, ADR 0023).
	keyPEM, err := readSecret(teeCfg, cfg.ClientKey, 0, "crosscloud.transport_tls.client_key")
	if err != nil {
		return nil, fmt.Errorf("sagvd: load mTLS client cert/key: %w", err)
	}
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("sagvd: load mTLS client cert/key: %w", err)
	}
	caRaw, err := os.ReadFile(cfg.CABundle)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read mTLS ca_bundle %q: %w", cfg.CABundle, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return nil, fmt.Errorf("sagvd: ca_bundle %q contained no valid PEM certificates", cfg.CABundle)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      roots,
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS13, // acp-bootstrap accepts nothing older
	}, nil
}
