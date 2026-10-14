// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// identity refuses what it cannot print from — a bad flag, a config it
// cannot read or that does not validate, key material it cannot load —
// and prints nothing then.
func TestIdentity_Refusals(t *testing.T) {
	t.Parallel()
	cfg, dir := testKeyDir(t)
	writeConfig := func(name string, c Config) string {
		raw, err := json.Marshal(c)
		require.NoError(t, err)
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, raw, 0o600))
		return p
	}
	invalid := cfg
	invalid.Vault.Address = ""
	noSeed := cfg
	noSeed.TEE.SeedPath = filepath.Join(dir, "absent.seed")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"unknown flag":                  {[]string{"-bogus"}, "flag provided but not defined"},
		"missing config file":           {[]string{"-config", filepath.Join(dir, "absent.json")}, "open config"},
		"config that does not validate": {[]string{"-config", writeConfig("invalid.json", invalid)}, "identity: config validation"},
		"material that does not load":   {[]string{"-config", writeConfig("no-seed.json", noSeed)}, "read tee.seed_path"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			require.ErrorContains(t, runIdentityCmd(tc.args, &out), tc.want)
			require.Empty(t, out.String(), "nothing is printed on refusal")
		})
	}
}

// A TDX producer's identity is what its measurement is made of — MRTD and
// the four RTMRs, hex, 48 bytes each — and every other producer has none.
func TestTDXIdentityOf(t *testing.T) {
	t.Parallel()
	sim, err := tee.NewSimulated([]byte("w"), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	require.Nil(t, tdxIdentityOf(sim))
	require.Nil(t, tdxIdentityOf(nil))

	id := tdxIdentityOf(&tee.GCPTDXProducer{})
	require.NotNil(t, id)
	require.Equal(t, strings.Repeat("00", 48), id.MRTDHex)
	require.Len(t, id.RTMRHex, 4)
	for _, r := range id.RTMRHex {
		require.Equal(t, strings.Repeat("00", 48), r)
	}
}

// Only an Azure confidential GPU producer has a vTPM boot to report.
func TestVTPMIdentityOf_OtherProducersHaveNone(t *testing.T) {
	t.Parallel()
	sim, err := tee.NewSimulated([]byte("w"), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	require.Nil(t, vtpmIdentityOf(sim))
	require.Nil(t, vtpmIdentityOf(&tee.GCPTDXProducer{}))
	require.Nil(t, vtpmIdentityOf(nil))
}
