// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// testKeyDir lays down a complete set of key material files of the
// right sizes and returns a Config that points at them. Returned
// bytes are deterministic so tests can hash / compare them.
func testKeyDir(t *testing.T) (Config, string) {
	t.Helper()
	dir := t.TempDir()

	writeBytes := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, b, 0o600))
		return path
	}

	teeSeed := bytes.Repeat([]byte{0x11}, crypto.Ed25519SeedSize)
	workerSeed := bytes.Repeat([]byte{0x22}, crypto.Ed25519SeedSize)
	sessionKey := bytes.Repeat([]byte{0x33}, crypto.AES256KeySize)
	peerPub, _, err := crypto.Ed25519FromSeed(bytes.Repeat([]byte{0x44}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	peerMeas := bytes.Repeat([]byte{0x55}, crypto.HashSize)

	cfg := DefaultConfig()
	cfg.TEE.WorkloadDescriptor = "acp-compute-test-worker"
	cfg.TEE.SeedPath = writeBytes("tee.seed", teeSeed)
	cfg.TEE.InsecureSimulation = true
	cfg.TEE.Peer.PublicKeyPath = writeBytes("peer.pub", peerPub)
	cfg.TEE.Peer.MeasurementPath = writeBytes("peer.meas", peerMeas)
	cfg.Keys.WorkerSigning.KeyID = "worker-sign-1"
	cfg.Keys.WorkerSigning.SeedPath = writeBytes("worker.seed", workerSeed)
	cfg.Keys.SessionSealing.KeyID = "session-seal-1"
	cfg.Keys.SessionSealing.MaterialPath = writeBytes("session.key", sessionKey)
	cfg.Genome.Door.Command = []string{"/nonexistent/vg-door"}
	return cfg, dir
}

func testClock(t *testing.T) shared_time.Clock {
	t.Helper()
	return shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
}

func TestLoadMaterials_HappyPath(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	mat, err := LoadMaterials(cfg, testClock(t))
	require.NoError(t, err)
	require.NotNil(t, mat.Store)
	require.NotNil(t, mat.Producer)
	require.NotNil(t, mat.Verifier)
	require.Equal(t, ids.KeyID("worker-sign-1"), mat.SigningKeyID)
	require.Equal(t, ids.KeyID("session-seal-1"), mat.SealingKeyID)
	require.Len(t, mat.SigningPublicKey, crypto.Ed25519PublicKeySize)

	// The signing key must be usable under the declared purpose.
	_, err = mat.Store.Sign(mat.SigningKeyID, keys.PurposeSigningAuthority, []byte("cover"))
	require.NoError(t, err)

	// The sealing key must round-trip under its kid.
	nonce, ct, err := mat.Store.Seal(mat.SealingKeyID, []byte("pt"), []byte("aad"))
	require.NoError(t, err)
	got, err := mat.Store.Open(mat.SealingKeyID, nonce, ct, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("pt"), got)
}

func TestLoadMaterials_Deterministic_SameSeedSamePubkey(t *testing.T) {
	t.Parallel()
	// Two loads of the same files must yield the same signing pubkey —
	// the property the Phase 1 "worker pubkey published out-of-band"
	// affordance depends on.
	cfg, _ := testKeyDir(t)
	a, err := LoadMaterials(cfg, testClock(t))
	require.NoError(t, err)
	b, err := LoadMaterials(cfg, testClock(t))
	require.NoError(t, err)
	require.Equal(t, a.SigningPublicKey, b.SigningPublicKey)
}

func TestLoadMaterials_RejectsShortTEESeed(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	// Overwrite the TEE seed with the wrong length.
	require.NoError(t, os.WriteFile(cfg.TEE.SeedPath, []byte{0x00}, 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "tee.seed_path")
}

func TestLoadMaterials_RejectsShortWorkerSeed(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.WriteFile(cfg.Keys.WorkerSigning.SeedPath, make([]byte, 31), 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.worker_signing.seed_path")
}

func TestLoadMaterials_RejectsShortSealingKey(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.WriteFile(cfg.Keys.SessionSealing.MaterialPath, make([]byte, 33), 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.session_sealing.material_path")
}

func TestLoadMaterials_RejectsWrongPeerPublicKeyLen(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.WriteFile(cfg.TEE.Peer.PublicKeyPath, make([]byte, 31), 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "tee.peer.public_key_path")
}

func TestLoadMaterials_RejectsWrongPeerMeasurementLen(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.WriteFile(cfg.TEE.Peer.MeasurementPath, make([]byte, 33), 0o600))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "tee.peer.measurement_path")
}

func TestLoadMaterials_MissingFileReportsFieldName(t *testing.T) {
	t.Parallel()
	cfg, _ := testKeyDir(t)
	require.NoError(t, os.Remove(cfg.Keys.WorkerSigning.SeedPath))
	_, err := LoadMaterials(cfg, testClock(t))
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.worker_signing.seed_path")
}

// A SEV-SNP peer is pinned by its 48-byte launch measurement and the
// AMD chain its VCEK must chain to; no attestation key file exists for
// it. The verifier is built without hardware.
func TestLoadMaterials_SEVSNPPeerVerifier(t *testing.T) {
	t.Parallel()
	cfg, dir := testKeyDir(t)
	chain := filepath.Join(dir, "amd-chain.pem")
	require.NoError(t, os.WriteFile(chain, []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"), 0o644))
	meas := filepath.Join(dir, "peer.sev.meas")
	require.NoError(t, os.WriteFile(meas, bytes.Repeat([]byte{0x66}, 48), 0o600))
	cfg.TEE.Peer = PeerTEEConfig{Provider: "gcp-sev-snp", MeasurementPath: meas, AMDCertChainPath: chain, VCEKCacheDir: filepath.Join(dir, "vcek")}
	require.NoError(t, cfg.Validate())

	mat, err := LoadMaterials(cfg, testClock(t))
	require.NoError(t, err)
	require.Equal(t, tee.ProviderSimulated, mat.Provider)
	require.Equal(t, tee.ProviderGCPSEVSNP, mat.PeerProvider)
	require.IsType(t, &tee.GCPSEVVerifier{}, mat.Verifier)

	// A 32-byte measurement is not a SEV-SNP launch measurement.
	require.NoError(t, os.WriteFile(meas, bytes.Repeat([]byte{0x66}, 32), 0o600))
	_, err = LoadMaterials(cfg, testClock(t))
	require.ErrorContains(t, err, "48-byte SEV-SNP launch measurement")

	// The chain file must be there.
	require.NoError(t, os.WriteFile(meas, bytes.Repeat([]byte{0x66}, 48), 0o600))
	cfg.TEE.Peer.AMDCertChainPath = filepath.Join(dir, "absent.pem")
	_, err = LoadMaterials(cfg, testClock(t))
	require.ErrorContains(t, err, "amd_cert_chain_path")
}

// Off a Confidential VM the SEV-SNP producer cannot start: there is no
// configfs-tsm to ask for a report, and the daemon says so.
func TestLoadMaterials_SEVSNPProducerNeedsConfigfsTSM(t *testing.T) {
	t.Parallel()
	cfg, dir := testKeyDir(t)
	cfg.TEE.Provider = "gcp-sev-snp"
	cfg.TEE.SeedPath = ""
	cfg.TEE.InsecureSimulation = false
	cfg.TEE.TSMReportDir = filepath.Join(dir, "no-such-tsm")
	require.NoError(t, cfg.Validate())
	_, err := LoadMaterials(cfg, testClock(t))
	require.ErrorContains(t, err, "configfs-tsm")
}

// identity prints what sagvd pins for this worker.
func TestIdentity_PrintsWhatTheVaultPins(t *testing.T) {
	t.Parallel()
	cfg, dir := testKeyDir(t)
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	path := filepath.Join(dir, "acp-compute.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	var out bytes.Buffer
	require.NoError(t, runIdentityCmd([]string{"-config", path}, &out))
	var id workerIdentity
	require.NoError(t, json.Unmarshal(out.Bytes(), &id))
	require.Equal(t, "worker-sign-1", id.SigningKID)
	require.Equal(t, "simulated", id.TEEProvider)
	require.Len(t, id.TEEMeasurementHex, 64)
	require.Contains(t, id.TEEPublicKeyPEM, "BEGIN PUBLIC KEY")
	require.Contains(t, id.SigningPublicKeyPEM, "BEGIN PUBLIC KEY")
	require.Len(t, id.SigningPublicKeyHex, 64)
	require.Error(t, runIdentityCmd(nil, &out), "-config required")
}
