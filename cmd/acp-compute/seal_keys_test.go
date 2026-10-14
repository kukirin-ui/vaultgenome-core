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
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// `acp-compute seal-keys` seals the worker's key files to this host's TEE
// in place; the daemon reads them back through the same paths.
func TestSealKeys_SealsTheWorkersKeyFilesInPlace(t *testing.T) {
	f := newTestFixture(t)
	before, err := LoadMaterials(f.cfg, f.clock)
	require.NoError(t, err)
	beforePub := append([]byte(nil), before.SigningPublicKey...)
	before.Store.Zeroize()

	raw, err := json.Marshal(f.cfg)
	require.NoError(t, err)
	cfgPath := filepath.Join(f.dir, "acp-compute.json")
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
	var out sealKeysOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.Equal(t, "simulated", out.TEE)
	require.Len(t, out.Sealed, 2)
	for _, p := range []string{f.cfg.Keys.WorkerSigning.SeedPath, f.cfg.Keys.SessionSealing.MaterialPath} {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		require.True(t, tee.IsSealedSecret(b), p)
		require.NotContains(t, string(b), string(f.workerSeed))
	}

	after, err := LoadMaterials(f.cfg, f.clock)
	require.NoError(t, err)
	require.Equal(t, beforePub, []byte(after.SigningPublicKey))
	after.Store.Zeroize()

	stdout.Reset()
	require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.Empty(t, out.Sealed)
	require.Len(t, out.AlreadySealed, 2)

	// The sealing key handed to the daemon as the signing seed: refused by name.
	sealedSealing, err := os.ReadFile(f.cfg.Keys.SessionSealing.MaterialPath)
	require.NoError(t, err)
	swapped := f.cfg
	swapped.Keys.WorkerSigning.SeedPath = filepath.Join(f.dir, "swapped.seed")
	require.NoError(t, os.WriteFile(swapped.Keys.WorkerSigning.SeedPath, sealedSealing, 0o600))
	_, err = LoadMaterials(swapped, f.clock)
	require.ErrorContains(t, err, `read as "keys.worker_signing.seed_path"`)
	require.ErrorContains(t, runSealKeysCmd(nil, &stdout, &stderr), "-config required")
}

func TestSealKeys_IdentityReadsSealedFiles(t *testing.T) {
	f := newTestFixture(t)
	raw, err := json.Marshal(f.cfg)
	require.NoError(t, err)
	cfgPath := filepath.Join(f.dir, "acp-compute.json")
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))
	var before, after, stdout, stderr bytes.Buffer
	require.NoError(t, runIdentityCmd([]string{"-config", cfgPath}, &before))
	require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
	require.NoError(t, runIdentityCmd([]string{"-config", cfgPath}, &after))
	require.JSONEq(t, before.String(), after.String(), "the same identity from sealed files")
}
