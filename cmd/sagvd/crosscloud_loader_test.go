// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// writeFile is a t.Helper that writes data to <dir>/<name> with
// 0600 permissions and returns the absolute path. Used to lay down
// fixtures (allow-list JSON, attestor pubkey files, registry JSON)
// in temp directories.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// makeMeasurementHex returns 64 hex chars (32 bytes) where every
// byte equals fillByte. Useful for distinct measurements per test.
func makeMeasurementHex(fillByte byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fillByte
	}
	return hex.EncodeToString(b)
}

// generateEd25519PubRaw returns a fresh 32-byte Ed25519 public key
// (raw, no PEM wrap).
func generateEd25519PubRaw(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub
}

// generateEd25519PubPEM returns a PEM-encoded SubjectPublicKeyInfo
// for a fresh Ed25519 key.
func generateEd25519PubPEM(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// --- LoadCrossCloudMaterials top-level path ------------------------

func TestLoadCrossCloudMaterials_DisabledReturnsNil(t *testing.T) {
	cfg := Config{} // CrossCloud.Enabled defaults to false
	materials, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("LoadCrossCloudMaterials(disabled): %v", err)
	}
	if materials != nil {
		t.Fatal("LoadCrossCloudMaterials(disabled): want nil bundle")
	}
}

// --- loadVerifierRegistry -----------------------------------------

func TestLoadVerifierRegistry_HappyPath_RawPubkey(t *testing.T) {
	dir := t.TempDir()
	pubRaw := generateEd25519PubRaw(t)
	pubPath := writeFile(t, dir, "attestor.pub", pubRaw)

	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + makeMeasurementHex(0x42) + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))

	registry, err := loadVerifierRegistry(regPath, true)
	if err != nil {
		t.Fatalf("loadVerifierRegistry: %v", err)
	}
	if registry.Len() != 1 {
		t.Errorf("registry.Len() = %d; want 1", registry.Len())
	}
	if !registry.Has(tee.ProviderSimulated) {
		t.Error("registry must hold ProviderSimulated entry")
	}
}

// A simulated destination proves the protocol, not hardware: the
// registry refuses one unless the operator says so in the config.
func TestLoadVerifierRegistry_RefusesSimulatedUnlessAcknowledged(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pem", generateEd25519PubPEM(t))
	regPath := writeFile(t, dir, "registry.json", []byte(`{"verifiers":[{"provider":"simulated","attestor_pubkey_path":"`+
		pubPath+`","expected_measurement_hex":"`+makeMeasurementHex(0x42)+`"}]}`))
	_, err := loadVerifierRegistry(regPath, false)
	if err == nil || !strings.Contains(err.Error(), "insecure_simulated_destinations") {
		t.Fatalf("simulated entry without the acknowledgement: err = %v", err)
	}
	if _, err := loadVerifierRegistry(regPath, true); err != nil {
		t.Fatalf("simulated entry with the acknowledgement: %v", err)
	}
}

func TestLoadVerifierRegistry_HappyPath_PEMPubkey(t *testing.T) {
	dir := t.TempDir()
	pubPEM := generateEd25519PubPEM(t)
	pubPath := writeFile(t, dir, "attestor.pem", pubPEM)

	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + makeMeasurementHex(0x42) + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))

	registry, err := loadVerifierRegistry(regPath, true)
	if err != nil {
		t.Fatalf("loadVerifierRegistry(PEM): %v", err)
	}
	if !registry.Has(tee.ProviderSimulated) {
		t.Error("registry must hold the PEM-keyed simulated entry")
	}
}

// Real SEV-SNP: the Evidence is signed by the chip's VCEK, which must
// chain to the AMD root the operator pins; measurements are 48 bytes.
func TestLoadVerifierRegistry_SEVSNP(t *testing.T) {
	dir := t.TempDir()
	chain := writeFile(t, dir, "amd-chain.pem", []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"))
	m48 := strings.Repeat("ab", 48)
	entry := func(extra string) string {
		return `{"verifiers":[{"provider":"gcp-sev-snp","expected_measurement_hex":"` + m48 + `"` + extra + `}]}`
	}

	reg, err := loadVerifierRegistry(writeFile(t, dir, "ok.json", []byte(entry(`,"amd_cert_chain_path":"`+chain+`","min_reported_tcb":7`))), true)
	if err != nil {
		t.Fatalf("loadVerifierRegistry(gcp-sev-snp): %v", err)
	}
	if !reg.Has(tee.ProviderGCPSEVSNP) {
		t.Fatal("registry must hold the gcp-sev-snp entry")
	}
	if _, err := loadVerifierRegistry(writeFile(t, dir, "nochain.json", []byte(entry(""))), true); err == nil || !strings.Contains(err.Error(), "amd_cert_chain_path") {
		t.Fatalf("gcp-sev-snp without an AMD chain: err = %v", err)
	}
	if _, err := loadVerifierRegistry(writeFile(t, dir, "badchain.json", []byte(entry(`,"amd_cert_chain_path":"`+filepath.Join(dir, "absent.pem")+`"`))), true); err == nil {
		t.Fatal("gcp-sev-snp with an unreadable AMD chain was accepted")
	}
}

// Fail closed: a family whose verifier this build cannot run end to end
// is refused when the registry loads, not discovered at release time.
func TestLoadVerifierRegistry_RefusesFamiliesWithoutAWorkingVerifier(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pem", generateEd25519PubPEM(t))
	for _, provider := range []string{"aws-nitro", "azure-sgx", "intel-sgx-dcap"} {
		reg := `{"verifiers":[{"provider":"` + provider + `","attestor_pubkey_path":"` + pubPath + `","expected_measurement_hex":"` + makeMeasurementHex(0x42) + `"}]}`
		_, err := loadVerifierRegistry(writeFile(t, dir, provider+".json", []byte(reg)), true)
		if err == nil || !strings.Contains(err.Error(), "no verifier this build can run end to end") {
			t.Errorf("%s: err = %v, want a fail-closed refusal", provider, err)
		}
	}
}

func TestLoadVerifierRegistry_MissingFile(t *testing.T) {
	_, err := loadVerifierRegistry("/nonexistent/path/registry.json", true)
	if err == nil {
		t.Fatal("loadVerifierRegistry: want error on missing file")
	}
}

func TestLoadVerifierRegistry_EmptyVerifiersRejected(t *testing.T) {
	dir := t.TempDir()
	regPath := writeFile(t, dir, "registry.json", []byte(`{"verifiers":[]}`))
	_, err := loadVerifierRegistry(regPath, true)
	if err == nil || !strings.Contains(err.Error(), "at least one verifier") {
		t.Fatalf("loadVerifierRegistry(empty): err = %v", err)
	}
}

func TestLoadVerifierRegistry_BadProviderRejected(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	registryJSON := `{
		"verifiers": [
			{
				"provider": "vibes-tee",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + makeMeasurementHex(0x42) + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))
	_, err := loadVerifierRegistry(regPath, true)
	if err == nil || !strings.Contains(err.Error(), "vibes-tee") {
		t.Fatalf("loadVerifierRegistry(bad provider): err = %v", err)
	}
}

func TestLoadVerifierRegistry_BadHexRejected(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "not-hex"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))
	_, err := loadVerifierRegistry(regPath, true)
	if err == nil {
		t.Fatal("loadVerifierRegistry(bad hex): want error")
	}
}

func TestLoadVerifierRegistry_WrongMeasurementSizeRejected(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "1234"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))
	_, err := loadVerifierRegistry(regPath, true)
	if err == nil || !strings.Contains(err.Error(), "32-, 48- or 64-byte measurement") {
		t.Fatalf("loadVerifierRegistry(short measurement): err = %v", err)
	}
}

func TestLoadVerifierRegistry_UnknownJSONFieldRejected(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + makeMeasurementHex(0x42) + `",
				"mystery_field": 1
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))
	_, err := loadVerifierRegistry(regPath, true)
	if err == nil || !strings.Contains(err.Error(), "mystery_field") {
		t.Fatalf("loadVerifierRegistry(unknown field): err = %v", err)
	}
}

// --- loadAttestorPubKey -------------------------------------------

func TestLoadAttestorPubKey_RawWrongSize(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "shortkey.pub", []byte{1, 2, 3})
	_, err := loadAttestorPubKey(pubPath)
	if err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Fatalf("loadAttestorPubKey(short raw): err = %v", err)
	}
}

func TestLoadAttestorPubKey_PEMNonEd25519Rejected(t *testing.T) {
	dir := t.TempDir()
	// A valid-looking PEM block but with bogus DER inside.
	bogus := []byte("-----BEGIN PUBLIC KEY-----\nMTIz\n-----END PUBLIC KEY-----\n")
	pubPath := writeFile(t, dir, "bogus.pem", bogus)
	_, err := loadAttestorPubKey(pubPath)
	if err == nil {
		t.Fatal("loadAttestorPubKey(bogus PEM): want error")
	}
}

// --- loadAllowListPolicy -------------------------------------------

func TestLoadAllowListPolicy_HappyPath(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "xcc-test-v1",
		"allowed": {
			"aws-nitro": ["` + makeMeasurementHex(0x10) + `", "` + makeMeasurementHex(0x11) + `"],
			"azure-sgx": ["` + makeMeasurementHex(0x20) + `"]
		}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	policy, err := loadAllowListPolicy("xcc-test-v1", path)
	if err != nil {
		t.Fatalf("loadAllowListPolicy: %v", err)
	}
	if policy.PolicyVersion() != "xcc-test-v1" {
		t.Errorf("PolicyVersion = %q; want xcc-test-v1", policy.PolicyVersion())
	}
}

func TestLoadAllowListPolicy_VersionMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "xcc-test-OLD",
		"allowed": {"aws-nitro": ["` + makeMeasurementHex(0x10) + `"]}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	_, err := loadAllowListPolicy("xcc-test-NEW", path)
	if err == nil || !strings.Contains(err.Error(), "operator drift") {
		t.Fatalf("loadAllowListPolicy(version mismatch): err = %v", err)
	}
}

func TestLoadAllowListPolicy_BadHexRejected(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "v1",
		"allowed": {"aws-nitro": ["not-hex"]}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	_, err := loadAllowListPolicy("v1", path)
	if err == nil {
		t.Fatal("loadAllowListPolicy(bad hex): want error")
	}
}

func TestLoadAllowListPolicy_WrongMeasurementSizeRejected(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "v1",
		"allowed": {"aws-nitro": ["1234"]}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	_, err := loadAllowListPolicy("v1", path)
	if err == nil || !strings.Contains(err.Error(), "32-, 48- or 64-byte measurement") {
		t.Fatalf("loadAllowListPolicy(short measurement): err = %v", err)
	}
}

// A real SEV-SNP or Nitro measurement is 48 bytes and must be pinned
// whole, not rejected or truncated.
func TestLoadAllowListPolicy_AcceptsHardwareMeasurement(t *testing.T) {
	dir := t.TempDir()
	m48 := strings.Repeat("ab", 48)
	path := writeFile(t, dir, "allow.json", []byte(`{"version":"v1","allowed":{"gcp-sev-snp":["`+m48+`"]}}`))
	p, err := loadAllowListPolicy("v1", path)
	if err != nil {
		t.Fatalf("loadAllowListPolicy(48-byte measurement): %v", err)
	}
	m, _ := hex.DecodeString(m48)
	v, err := p.AuthorizeKeyRelease(tee.ProviderGCPSEVSNP, m, "dec-1", []ids.KeyID{"k1"})
	if err != nil || !v.Authorized {
		t.Fatalf("48-byte measurement not authorized: %+v, %v", v, err)
	}
}

func TestLoadAllowListPolicy_BadProviderRejected(t *testing.T) {
	dir := t.TempDir()
	allowJSON := `{
		"version": "v1",
		"allowed": {"vibes-tee": ["` + makeMeasurementHex(0x10) + `"]}
	}`
	path := writeFile(t, dir, "allow.json", []byte(allowJSON))
	_, err := loadAllowListPolicy("v1", path)
	if err == nil || !strings.Contains(err.Error(), "vibes-tee") {
		t.Fatalf("loadAllowListPolicy(bad provider): err = %v", err)
	}
}

// --- buildHTTPTransport -------------------------------------------

func TestBuildHTTPTransport_NoTLS(t *testing.T) {
	cfg := CrossCloudConfig{
		Enabled:               true,
		TransportBearerToken:  "secret",
		RequestTimeoutSeconds: 15,
	}
	tx, err := buildHTTPTransport(TEEConfig{}, cfg)
	if err != nil {
		t.Fatalf("buildHTTPTransport: %v", err)
	}
	if tx == nil {
		t.Fatal("buildHTTPTransport returned nil transport")
	}
}

// --- LoadCrossCloudMaterials end-to-end happy path ----------------

func TestLoadCrossCloudMaterials_HappyPath(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))

	measHex := makeMeasurementHex(0x55)
	registryJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + measHex + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(registryJSON))

	allowJSON := `{
		"version": "xcc-2026-05-09",
		"allowed": {"simulated": ["` + measHex + `"]}
	}`
	allowPath := writeFile(t, dir, "allow.json", []byte(allowJSON))

	cfg := Config{
		CrossCloud: CrossCloudConfig{
			Enabled:               true,
			PolicyVersion:         "xcc-2026-05-09",
			PolicyAllowListPath:   allowPath,
			VerifierRegistryPath:  regPath,
			RequestTimeoutSeconds: 30,
			// The test destinations are simulated.
			InsecureSimulatedDestinations: true,
		},
	}
	withAuditLog(t, dir, &cfg)
	materials, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("LoadCrossCloudMaterials: %v", err)
	}
	if materials == nil {
		t.Fatal("LoadCrossCloudMaterials returned nil bundle (Enabled=true)")
	}
	defer func() { _ = materials.Close() }()
	if materials.VerifierRegistry == nil || materials.Policy == nil || materials.Transport == nil {
		t.Fatal("LoadCrossCloudMaterials: every field must be populated")
	}
	if !materials.VerifierRegistry.Has(tee.ProviderSimulated) {
		t.Error("registry must hold ProviderSimulated")
	}
	if materials.Policy.PolicyVersion() != "xcc-2026-05-09;revocation=1" {
		t.Errorf("policy version = %q; want the allow-list version and the stop-list serial", materials.Policy.PolicyVersion())
	}
}

// withAuditLog provisions the release controls cross-cloud release needs,
// as `keygen` does: a fresh durable audit log with its signing seed, and
// an operator key with a signed stop list (serial 1, nothing stopped).
// It returns the operator key so tests can issue further lists.
func withAuditLog(t *testing.T, dir string, cfg *Config) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "xcc-audit-test", SeedPath: writeFile(t, dir, "audit_signing_seed", seed)}
	cfg.CrossCloud.AuditLogPath = filepath.Join(dir, "xcc-audit.db")

	opPub, opPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CrossCloud.OperatorStop = OperatorStopConfig{
		KeyID:         "operator-test",
		PublicKeyPath: writeFile(t, dir, "operator.pub", opPub),
		ListPath:      filepath.Join(dir, "stop.json"),
	}
	writeStopList(t, cfg.CrossCloud.OperatorStop.ListPath, opPriv, revocation.List{Serial: 1})
	return opPriv
}

func writeStopList(t *testing.T, path string, priv ed25519.PrivateKey, l revocation.List) {
	t.Helper()
	l.IssuedAt = time.Date(2026, 9, 14, 21, 0, 0, 0, time.UTC)
	l.SigningKeyID = "operator-test"
	signed, err := revocation.Sign(l, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// simulatedCrossCloudConfig is a minimal enabled cross-cloud config in dir.
func simulatedCrossCloudConfig(t *testing.T, dir string) Config {
	t.Helper()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	meas := makeMeasurementHex(0x55)
	reg := writeFile(t, dir, "registry.json", []byte(`{"verifiers":[{"provider":"simulated","attestor_pubkey_path":"`+pubPath+`","expected_measurement_hex":"`+meas+`"}]}`))
	allow := writeFile(t, dir, "allow.json", []byte(`{"version":"v1","allowed":{"simulated":["`+meas+`"]}}`))
	cfg := Config{CrossCloud: CrossCloudConfig{Enabled: true, PolicyVersion: "v1", PolicyAllowListPath: allow, VerifierRegistryPath: reg, InsecureSimulatedDestinations: true}}
	withAuditLog(t, dir, &cfg)
	return cfg
}

// The audit log is one chain across runs: a second crosscloud-restore
// sees the first one's events, continues their numbering, and extends
// the same verified chain.
func TestLoadCrossCloudMaterials_AuditLogSpansRuns(t *testing.T) {
	cfg := simulatedCrossCloudConfig(t, t.TempDir())
	emit := func(m *crossCloudMaterials) ids.AuditEventID {
		id, err := m.AuditEmitter.Emit(audit_event.KindCrossCloudHandshakeInitiated, []byte(`{}`), "", "", "req-1")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	first, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatal(err)
	}
	emit(first)
	emit(first)
	tip := first.AuditChain.Tip()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("reopening a verified log: %v", err)
	}
	defer func() { _ = second.Close() }()
	if second.AuditChain.Len() != 2 || string(second.AuditChain.Tip()) != string(tip) {
		t.Fatalf("second run sees %d events; want the first run's 2 with the same tip", second.AuditChain.Len())
	}
	if id := emit(second); id != "xcc-evt-0000000000000003" {
		t.Fatalf("event ID %q does not continue the log", id)
	}
}

// A log signed under a different audit key does not verify, and a log
// that does not verify stops every release.
func TestLoadCrossCloudMaterials_RefusesLogItCannotVerify(t *testing.T) {
	dir := t.TempDir()
	cfg := simulatedCrossCloudConfig(t, dir)
	m, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AuditEmitter.Emit(audit_event.KindCrossCloudHandshakeInitiated, []byte(`{}`), "", "", "req-1"); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()

	other := make([]byte, 32)
	if _, err := rand.Read(other); err != nil {
		t.Fatal(err)
	}
	cfg.Keys.AuditSigning.SeedPath = writeFile(t, dir, "other_seed", other)
	if m, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock()); err == nil {
		_ = m.Close()
		t.Fatal("a log signed under another audit key was accepted")
	} else if !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// The operator's list gates every release: a stop refuses a destination
// the allow-list would admit.
func TestLoadCrossCloudMaterials_OperatorStopGatesReleases(t *testing.T) {
	dir := t.TempDir()
	cfg := simulatedCrossCloudConfig(t, dir)
	opPriv := withAuditLog(t, dir, &cfg)
	writeStopList(t, cfg.CrossCloud.OperatorStop.ListPath, opPriv, revocation.List{Serial: 2, StopAll: true, Reason: "drill"})

	m, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	meas, _ := hex.DecodeString(makeMeasurementHex(0x55))
	v, err := m.Policy.AuthorizeKeyRelease(tee.ProviderSimulated, meas, "dec-1", []ids.KeyID{"k"})
	if err != nil || v.Authorized || !strings.Contains(v.Reason, "operator stop in force") {
		t.Fatalf("verdict under a stop: %+v, %v", v, err)
	}
	if m.StopSerial != 2 {
		t.Fatalf("StopSerial = %d", m.StopSerial)
	}
}

// Without a valid list nothing is released: missing, edited, or signed by
// another key are all refused at load.
func TestLoadCrossCloudMaterials_RequiresAValidStopList(t *testing.T) {
	for name, spoil := range map[string]func(t *testing.T, cfg *Config){
		"missing": func(t *testing.T, cfg *Config) { _ = os.Remove(cfg.CrossCloud.OperatorStop.ListPath) },
		"edited": func(t *testing.T, cfg *Config) {
			raw, _ := os.ReadFile(cfg.CrossCloud.OperatorStop.ListPath)
			_ = os.WriteFile(cfg.CrossCloud.OperatorStop.ListPath, []byte(strings.Replace(string(raw), `"serial":1`, `"serial":9`, 1)), 0o644)
		},
		"other signer": func(t *testing.T, cfg *Config) { cfg.CrossCloud.OperatorStop.KeyID = "someone-else" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := simulatedCrossCloudConfig(t, t.TempDir())
			spoil(t, &cfg)
			if m, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock()); err == nil {
				_ = m.Close()
				t.Fatal("loaded without a valid operator stop list")
			}
		})
	}
}

// Once a decision has been recorded under a list, an older list cannot
// be put back.
func TestLoadCrossCloudMaterials_RefusesStopListRollback(t *testing.T) {
	dir := t.TempDir()
	cfg := simulatedCrossCloudConfig(t, dir)
	opPriv := withAuditLog(t, dir, &cfg)
	writeStopList(t, cfg.CrossCloud.OperatorStop.ListPath, opPriv, revocation.List{Serial: 5})

	m, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"policy_version": m.Policy.PolicyVersion()})
	if _, err := m.AuditEmitter.Emit(audit_event.KindKeyReleaseDenied, payload, "", "", "req-1"); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()

	writeStopList(t, cfg.CrossCloud.OperatorStop.ListPath, opPriv, revocation.List{Serial: 4})
	if m, err := LoadCrossCloudMaterials(cfg, shared_time.NewSystemClock()); err == nil {
		_ = m.Close()
		t.Fatal("an older stop list was accepted after a newer one had been applied")
	} else if !strings.Contains(err.Error(), "rollback refused") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

func TestLoadVerifierSpecs_AzureCGPU(t *testing.T) {
	chain, err := os.ReadFile("../../scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/cert-chain.pem")
	if err != nil {
		t.Skip("azure-cgpu capture not present")
	}
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "genoa.pem")
	require.NoError(t, os.WriteFile(chainPath, chain, 0o600))
	meas := strings.Repeat("ab", 48)
	write := func(entry string) string {
		p := filepath.Join(dir, "verifiers.json")
		require.NoError(t, os.WriteFile(p, []byte(`{"verifiers":[`+entry+`]}`), 0o600))
		return p
	}
	specs, err := loadVerifierSpecs(write(`{"provider":"azure-cgpu","expected_measurement_hex":"`+meas+`","amd_cert_chain_path":"`+chainPath+`",
		"vcek_cache_dir":"`+dir+`","nras_cache_dir":"`+dir+`","gpu_policy":{"hw_models":["GH100"]},"pcr_digests":["`+strings.Repeat("00", 32)+`"]}`), false)
	require.NoError(t, err)
	require.Len(t, specs, 1)
	require.Equal(t, tee.ProviderAzureCGPU, specs[0].Provider)
	require.Equal(t, []string{"GH100"}, specs[0].Spec.AzureCGPU.GPU.AcceptableHWModels)
	require.Len(t, specs[0].Spec.AzureCGPU.AcceptablePCRDigests, 1)
	require.NotEmpty(t, specs[0].Spec.AzureCGPU.AMDRootPEM)
	v, err := tee.BuildVerifier(specs[0].Spec)
	require.NoError(t, err)
	require.NotNil(t, v)

	_, err = loadVerifierSpecs(write(`{"provider":"azure-cgpu","expected_measurement_hex":"`+meas+`"}`), false)
	require.ErrorContains(t, err, "amd_cert_chain_path")
	_, err = loadVerifierSpecs(write(`{"provider":"azure-cgpu","expected_measurement_hex":"`+meas+`","amd_cert_chain_path":"`+chainPath+`","pcr_digests":["zz"]}`), false)
	require.ErrorContains(t, err, "pcr_digests")
}
