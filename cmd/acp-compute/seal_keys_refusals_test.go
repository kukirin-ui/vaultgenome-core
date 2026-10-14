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

// seal-keys stops, with nothing printed, on a bad flag, a config it
// cannot read or that does not validate, material it cannot load, a key
// file it cannot read or that is not the length its field wants, and a
// directory it cannot write the sealed file into. Key files it sealed
// before it stopped stay sealed, and still open.
func TestSealKeys_Refusals(t *testing.T) {
	f := newTestFixture(t)
	writeConfig := func(name string, c Config) string {
		raw, err := json.Marshal(c)
		require.NoError(t, err)
		p := filepath.Join(f.dir, name)
		require.NoError(t, os.WriteFile(p, raw, 0o600))
		return p
	}
	// ownKeys gives a config its own copies of the two key files, so what
	// one case seals in place is not what another reads.
	ownKeys := func(name string) Config {
		dir := filepath.Join(f.dir, name)
		require.NoError(t, os.Mkdir(dir, 0o700))
		c := f.cfg
		c.Keys.WorkerSigning.SeedPath = filepath.Join(dir, "worker.seed")
		c.Keys.SessionSealing.MaterialPath = filepath.Join(dir, "session.key")
		require.NoError(t, os.WriteFile(c.Keys.WorkerSigning.SeedPath, f.workerSeed, 0o600))
		require.NoError(t, os.WriteFile(c.Keys.SessionSealing.MaterialPath, f.sealingKey, 0o600))
		return c
	}
	invalid := f.cfg
	invalid.Vault.Address = ""
	noSeed := f.cfg
	noSeed.TEE.SeedPath = filepath.Join(f.dir, "absent.seed")
	noKey := f.cfg
	noKey.Keys.SessionSealing.MaterialPath = filepath.Join(f.dir, "absent.key")
	shortKey := f.cfg
	shortKey.Keys.SessionSealing.MaterialPath = filepath.Join(f.dir, "short.key")
	require.NoError(t, os.WriteFile(shortKey.Keys.SessionSealing.MaterialPath, make([]byte, 31), 0o600))
	// The TLS client key is not loaded with the other material, so it is
	// seal-keys itself that finds it missing or empty — after the two key
	// files before it in the config's order have been sealed.
	tls := TLSConfig{Enabled: true, ClientCert: filepath.Join(f.dir, "client.crt"), CABundle: filepath.Join(f.dir, "ca.pem"), ServerName: "127.0.0.1"}
	noTLSKey := ownKeys("no-tls-key")
	noTLSKey.Vault.TLS = tls
	noTLSKey.Vault.TLS.ClientKey = filepath.Join(f.dir, "absent-client.key")
	emptyTLSKey := ownKeys("empty-tls-key")
	emptyTLSKey.Vault.TLS = tls
	emptyTLSKey.Vault.TLS.ClientKey = filepath.Join(f.dir, "empty-client.key")
	require.NoError(t, os.WriteFile(emptyTLSKey.Vault.TLS.ClientKey, nil, 0o600))

	type refusal struct {
		args []string
		want string
	}
	cases := map[string]refusal{
		"unknown flag":                  {[]string{"-bogus"}, "flag provided but not defined"},
		"missing config file":           {[]string{"-config", filepath.Join(f.dir, "absent.json")}, "open config"},
		"config that does not validate": {[]string{"-config", writeConfig("invalid.json", invalid)}, "seal-keys: config validation"},
		"material that does not load":   {[]string{"-config", writeConfig("no-seed.json", noSeed)}, "read tee.seed_path"},
		"key file that is missing":      {[]string{"-config", writeConfig("no-key.json", noKey)}, "read keys.session_sealing.material_path"},
		"key file of the wrong length":  {[]string{"-config", writeConfig("short-key.json", shortKey)}, "must be exactly 32 bytes (got 31)"},
		"TLS key that is missing":       {[]string{"-config", writeConfig("no-tls-key.json", noTLSKey)}, "seal-keys: read vault.tls.client_key"},
		"TLS key that is empty":         {[]string{"-config", writeConfig("empty-tls-key.json", emptyTLSKey)}, "seal-keys: vault.tls.client_key"},
	}
	readOnly := ownKeys("read-only")
	if os.Geteuid() != 0 {
		// Root writes anywhere; everyone else is refused by the directory.
		cases["directory that cannot be written"] = refusal{[]string{"-config", writeConfig("read-only.json", readOnly)}, "seal-keys: write keys.worker_signing.seed_path"}
		ro := filepath.Dir(readOnly.Keys.WorkerSigning.SeedPath)
		require.NoError(t, os.Chmod(ro, 0o500))
		t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			require.ErrorContains(t, runSealKeysCmd(tc.args, &stdout, &stderr), tc.want)
			require.Empty(t, stdout.String(), "nothing is printed on refusal")
		})
	}

	// The flag set reports to the stderr the command was given.
	var stdout, stderr bytes.Buffer
	require.Error(t, runSealKeysCmd([]string{"-bogus"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "-config")

	// Nothing was sealed where the refusal came before the first key file.
	for _, p := range []string{f.cfg.Keys.WorkerSigning.SeedPath, readOnly.Keys.WorkerSigning.SeedPath} {
		raw, err := os.ReadFile(p)
		require.NoError(t, err)
		require.Equal(t, f.workerSeed, raw, p)
	}
	raw, err := os.ReadFile(f.cfg.Keys.SessionSealing.MaterialPath)
	require.NoError(t, err)
	require.Equal(t, f.sealingKey, raw)

	// Where the refusal came at the TLS key, the two key files before it
	// are sealed in place and still open on this host.
	for _, c := range []Config{noTLSKey, emptyTLSKey} {
		for _, p := range []string{c.Keys.WorkerSigning.SeedPath, c.Keys.SessionSealing.MaterialPath} {
			raw, err := os.ReadFile(p)
			require.NoError(t, err)
			require.True(t, tee.IsSealedSecret(raw), p)
		}
		mat, err := LoadMaterials(c, f.clock)
		require.NoError(t, err)
		mat.Store.Zeroize()
	}
}
