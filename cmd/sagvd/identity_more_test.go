// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// identity refuses before it prints: a config that does not validate, key
// material it cannot read, an escrow file that is not there; and with gate
// jobs enabled it prints the policy every session is pinned to.
func TestIdentity_RefusalsAndPolicy(t *testing.T) {
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
	noPeerKey := f.cfg
	noPeerKey.TEE.Peer.PublicKeyPath = filepath.Join(f.dir, "absent.pub")
	noEscrow := f.cfg
	noEscrow.Genome.KeyEscrowPath = filepath.Join(f.dir, "absent.escrow")
	noAuditSeed := f.cfg
	noAuditSeed.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: filepath.Join(f.dir, "absent.seed")}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"undefined flag":     {[]string{"-nope"}, "flag provided but not defined"},
		"invalid config":     {[]string{"-config", writeCfg("invalid.json", invalid)}, "identity: config validation"},
		"peer key missing":   {[]string{"-config", writeCfg("nopeer.json", noPeerKey)}, "tee.peer.public_key_path"},
		"escrow missing":     {[]string{"-config", writeCfg("noescrow.json", noEscrow)}, "identity: key_escrow_path"},
		"audit seed missing": {[]string{"-config", writeCfg("noaudit.json", noAuditSeed)}, "keys.audit_signing.seed_path"},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, runIdentityCmd(tc.args, io.Discard), tc.want)
		})
	}

	gate := f.cfg
	gate.Genome.BundleDir = f.dir
	gate.Audit.LogPath = filepath.Join(f.dir, "rp.db")
	gate.Keys.AuditSigning = SigningKeyConfig{KeyID: "audit-1", SeedPath: f.cfg.Keys.AuthoritySigning.SeedPath}
	gate.Genome.Gate.MaxNonCriticalOutliers = 2
	require.NoError(t, gate.Validate())
	var out bytes.Buffer
	require.NoError(t, runIdentityCmd([]string{"-config", writeCfg("gate.json", gate)}, &out))
	var id authorityIdentity
	require.NoError(t, json.Unmarshal(out.Bytes(), &id))
	require.Equal(t, gate.PolicyVersion(), id.PolicyVersion)
	require.True(t, strings.Contains(id.PolicyVersion, "outliers=2"))
	require.Equal(t, []string{PolicyProfileGate}, id.PolicyProfiles)
	require.Equal(t, "audit-1", id.AuditKID)
	require.Nil(t, id.TDX)
	require.Nil(t, id.VTPM)
	require.Empty(t, id.KeyEscrowTag)
}

// What a TDX measurement is made of is printed with it: the MRTD and the
// four RTMRs, each a SHA-384; other producers have no such breakdown.
func TestTDXIdentityOf(t *testing.T) {
	sim, err := tee.NewSimulated([]byte("not-tdx"), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	require.Nil(t, tdxIdentityOf(sim))
	require.Nil(t, vtpmIdentityOf(sim))

	id := tdxIdentityOf(&tee.GCPTDXProducer{})
	require.NotNil(t, id)
	require.Equal(t, strings.Repeat("00", 48), id.MRTDHex, "a producer that read nothing yet reports the zero registers")
	require.Len(t, id.RTMRHex, 4)
	for _, r := range id.RTMRHex {
		require.Len(t, r, 96)
	}
}
