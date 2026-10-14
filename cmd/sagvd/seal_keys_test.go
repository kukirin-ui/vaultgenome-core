// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// `sagvd seal-keys` seals every key file the config names to this host's
// TEE, in place; the daemon reads them back through the same paths, the
// same keys come out, and a file read under another name is refused.
func TestSealKeys_SealsInPlaceAndTheDaemonOpensThem(t *testing.T) {
	f := newMaterialFixture(t)
	cfg := f.cfg
	auditSeed := bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize)
	cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: filepath.Join(f.dir, "audit.seed")}
	require.NoError(t, os.WriteFile(cfg.Keys.AuditSigning.SeedPath, auditSeed, 0o600))
	cfg.Audit.LogPath = filepath.Join(f.dir, "returnpath.db")
	require.NoError(t, cfg.Validate())
	before, err := LoadMaterials(cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	beforePub := append([]byte(nil), before.AuthoritySigningPublicKey...)
	before.Store.Zeroize()

	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	cfgPath := filepath.Join(f.dir, "sagvd.json")
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "SIMULATED TEE")
	var out sealKeysOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.Equal(t, "simulated", out.TEE)
	require.Len(t, out.Sealed, 3)
	require.Empty(t, out.AlreadySealed)
	for _, p := range []string{cfg.Keys.AuthoritySigning.SeedPath, cfg.Keys.SessionSealing.MaterialPath, cfg.Keys.AuditSigning.SeedPath} {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		require.True(t, tee.IsSealedSecret(b), p)
		require.NotContains(t, string(b), string(auditSeed))
		st, err := os.Stat(p)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}

	// The daemon reads the sealed files and has the same keys.
	after, err := LoadMaterials(cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	require.Equal(t, beforePub, []byte(after.AuthoritySigningPublicKey))
	after.Store.Zeroize()
	audit, err := openReturnPathAudit(cfg, shared_time.NewSystemClock(), nil)
	require.NoError(t, err)
	require.NotNil(t, audit)
	require.NoError(t, audit.Close())

	// Sealing again seals nothing and says so.
	stdout.Reset()
	require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.Empty(t, out.Sealed)
	require.Len(t, out.AlreadySealed, 3)

	// A sealed audit seed handed to the daemon as the authority's seed.
	sealedAudit, err := os.ReadFile(cfg.Keys.AuditSigning.SeedPath)
	require.NoError(t, err)
	swapped := cfg
	swapped.Keys.AuthoritySigning.SeedPath = filepath.Join(f.dir, "swapped.seed")
	require.NoError(t, os.WriteFile(swapped.Keys.AuthoritySigning.SeedPath, sealedAudit, 0o600))
	_, err = LoadMaterials(swapped, shared_time.NewSystemClock())
	require.ErrorContains(t, err, `read as "keys.authority_signing.seed_path"`)

	// A bare file of the wrong length, and a missing -config.
	require.NoError(t, os.WriteFile(swapped.Keys.AuthoritySigning.SeedPath, []byte("short"), 0o600))
	_, err = LoadMaterials(swapped, shared_time.NewSystemClock())
	require.ErrorContains(t, err, "must be exactly 32 bytes")
	require.ErrorContains(t, runSealKeysCmd(nil, &stdout, &stderr), "-config required")
}

// `sagvd identity` — the command the operator pins the authority by — reads
// the sealed files too, and prints the same keys as before sealing.
func TestSealKeys_IdentityReadsSealedFiles(t *testing.T) {
	f := newMaterialFixture(t)
	cfg := f.cfg
	cfg.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: filepath.Join(f.dir, "audit.seed")}
	require.NoError(t, os.WriteFile(cfg.Keys.AuditSigning.SeedPath, bytes.Repeat([]byte{0x42}, crypto.Ed25519SeedSize), 0o600))
	cfg.Audit.LogPath = filepath.Join(f.dir, "returnpath.db")
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	cfgPath := filepath.Join(f.dir, "sagvd.json")
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))

	var before, after, stdout, stderr bytes.Buffer
	require.NoError(t, runIdentityCmd([]string{"-config", cfgPath}, &before))
	require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
	require.NoError(t, runIdentityCmd([]string{"-config", cfgPath}, &after))
	require.JSONEq(t, before.String(), after.String(), "the same identity from sealed files")
	require.Contains(t, after.String(), `"audit_public_key_pem"`)
}
