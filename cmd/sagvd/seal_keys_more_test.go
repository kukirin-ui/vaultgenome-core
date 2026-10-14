// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// seal-keys seals the key files the config names and no others: the
// cross-cloud transport key only when that transport is on.
func TestKeyFiles_FollowTheConfig(t *testing.T) {
	cfg := minimalValidConfig()
	names := func(c Config) []string {
		var out []string
		for _, f := range keyFiles(c) {
			out = append(out, f.name)
		}
		return out
	}
	require.Equal(t, []string{"keys.authority_signing.seed_path", "keys.session_sealing.material_path"}, names(cfg))
	cfg.CrossCloud.TransportTLS = TLSClientConfig{ClientKey: "/xcc.key"}
	require.NotContains(t, names(cfg), "crosscloud.transport_tls.client_key", "configured but not enabled")
	cfg.CrossCloud.TransportTLS.Enabled = true
	require.Contains(t, names(cfg), "crosscloud.transport_tls.client_key")
	for _, f := range keyFiles(cfg) {
		if f.name == "crosscloud.transport_tls.client_key" {
			require.Equal(t, "/xcc.key", f.path)
			require.Equal(t, 0, f.n, "a PEM key has no fixed length")
		}
	}
}

// seal-keys writes nothing when the config does not validate, the
// materials do not load, or a key file is not what the config says.
func TestSealKeys_RefusesBeforeSealing(t *testing.T) {
	f := newMaterialFixture(t)
	writeCfg := func(name string, cfg Config) string {
		raw, err := json.Marshal(cfg)
		require.NoError(t, err)
		p := filepath.Join(f.dir, name)
		require.NoError(t, os.WriteFile(p, raw, 0o600))
		return p
	}
	invalid := f.cfg
	invalid.TEE.Provider = "vmware"
	noPeer := f.cfg
	noPeer.TEE.Peer.MeasurementPath = filepath.Join(f.dir, "absent")
	noAudit := f.cfg
	noAudit.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: filepath.Join(f.dir, "absent.seed")}
	noAudit.Audit.LogPath = filepath.Join(f.dir, "rp.db")
	shortAudit := f.cfg
	shortAudit.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: filepath.Join(f.dir, "short.seed")}
	shortAudit.Audit.LogPath = filepath.Join(f.dir, "rp.db")
	require.NoError(t, os.WriteFile(shortAudit.Keys.AuditSigning.SeedPath, bytes.Repeat([]byte{1}, 31), 0o600))
	authBefore, err := os.ReadFile(f.cfg.Keys.AuthoritySigning.SeedPath)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"undefined flag":    {[]string{"-nope"}, "flag provided but not defined"},
		"missing config":    {[]string{"-config", filepath.Join(f.dir, "absent.json")}, "absent.json"},
		"invalid config":    {[]string{"-config", writeCfg("invalid.json", invalid)}, "seal-keys: config validation"},
		"materials missing": {[]string{"-config", writeCfg("nopeer.json", noPeer)}, "tee.peer.measurement_path"},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, runSealKeysCmd(tc.args, io.Discard, io.Discard), tc.want)
		})
	}
	authAfter, err := os.ReadFile(f.cfg.Keys.AuthoritySigning.SeedPath)
	require.NoError(t, err)
	require.Equal(t, authBefore, authAfter, "every refusal left the key files as they were")

	// Files are sealed one by one, in config order: a key file that is not
	// there, or not what the config says, stops the run where it is found,
	// with the files before it sealed in place and that one untouched.
	require.ErrorContains(t, runSealKeysCmd([]string{"-config", writeCfg("noaudit.json", noAudit)}, io.Discard, io.Discard), "seal-keys: read keys.audit_signing.seed_path")
	sealedAuth, err := os.ReadFile(f.cfg.Keys.AuthoritySigning.SeedPath)
	require.NoError(t, err)
	require.True(t, tee.IsSealedSecret(sealedAuth))
	require.ErrorContains(t, runSealKeysCmd([]string{"-config", writeCfg("short.json", shortAudit)}, io.Discard, io.Discard), "keys.audit_signing.seed_path")
	short, err := os.ReadFile(shortAudit.Keys.AuditSigning.SeedPath)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{1}, 31), short)

	require.ErrorContains(t, replaceFile(filepath.Join(f.dir, "missing-dir", "x"), []byte("sealed")), "no such file")
}
