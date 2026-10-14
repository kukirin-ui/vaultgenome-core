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
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

func runStop(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := stopCmd(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// The operator's whole flow: create a key, sign a stop, check it.
func TestStop_KeygenIssueVerify(t *testing.T) {
	dir := t.TempDir()
	seed, pub := filepath.Join(dir, "operator.seed"), filepath.Join(dir, "operator.pem")
	list := filepath.Join(dir, "stop.json")
	measurement := strings.Repeat("ab", 48)

	code, _, stderr := runStop("keygen", "-out", seed, "-pub", pub)
	require.Equal(t, 0, code, stderr)
	info, err := os.Stat(seed)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the operator seed is private")

	code, _, stderr = runStop("keygen", "-out", seed, "-pub", pub)
	require.NotEqual(t, 0, code, "an existing operator key is never overwritten")
	require.Contains(t, stderr, "exists")

	code, _, stderr = runStop("issue", "-key", seed, "-kid", "operator-1", "-serial", "7", "-all",
		"-revoke", "gcp-sev-snp:"+strings.ToUpper(measurement), "-reason", "drill", "-out", list)
	require.Equal(t, 0, code, stderr)

	code, stdout, stderr := runStop("verify", "-in", list, "-pubkey", pub, "-kid", "operator-1")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "serial 7")
	require.Contains(t, stdout, "ALL RELEASES STOPPED")
	require.Contains(t, stdout, "revoked gcp-sev-snp "+measurement)
	require.Contains(t, stdout, "reason: drill")

	code, stdout, _ = runStop("verify", "-in", list, "-pubkey", pub, "-kid", "operator-1", "-json")
	require.Equal(t, 0, code)
	var l revocation.List
	require.NoError(t, json.Unmarshal([]byte(stdout), &l))
	require.True(t, l.StopAll)
	require.Equal(t, uint64(7), l.Serial)
}

// A list that was edited, or checked against another operator's key or
// ID, fails verification with exit code 4.
func TestStop_VerifyRefusesWhatTheOperatorDidNotSign(t *testing.T) {
	dir := t.TempDir()
	seed, pub := filepath.Join(dir, "op.seed"), filepath.Join(dir, "op.pem")
	otherSeed, otherPub := filepath.Join(dir, "other.seed"), filepath.Join(dir, "other.pem")
	list := filepath.Join(dir, "stop.json")
	for _, kp := range [][2]string{{seed, pub}, {otherSeed, otherPub}} {
		code, _, stderr := runStop("keygen", "-out", kp[0], "-pub", kp[1])
		require.Equal(t, 0, code, stderr)
	}
	code, _, stderr := runStop("issue", "-key", seed, "-kid", "operator-1", "-serial", "2", "-all", "-out", list)
	require.Equal(t, 0, code, stderr)

	raw, err := os.ReadFile(list)
	require.NoError(t, err)
	lifted := filepath.Join(dir, "lifted.json")
	require.NoError(t, os.WriteFile(lifted, bytes.Replace(raw, []byte(`"stop_all": true`), []byte(`"stop_all": false`), 1), 0o644))

	for name, args := range map[string][]string{
		"edited":    {"verify", "-in", lifted, "-pubkey", pub, "-kid", "operator-1"},
		"other key": {"verify", "-in", list, "-pubkey", otherPub, "-kid", "operator-1"},
		"other kid": {"verify", "-in", list, "-pubkey", pub, "-kid", "operator-2"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, _ := runStop(args...)
			require.Equal(t, 4, code)
		})
	}
}

func TestStop_UsageErrors(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "op.seed")
	code, _, _ := runStop("keygen", "-out", seed, "-pub", filepath.Join(dir, "op.pem"))
	require.Equal(t, 0, code)

	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"no subcommand":      {nil, 2},
		"unknown subcommand": {[]string{"lift"}, 2},
		"help":               {[]string{"help"}, 0},
		"keygen needs paths": {[]string{"keygen"}, 2},
		"issue needs serial": {[]string{"issue", "-key", seed, "-kid", "k", "-out", filepath.Join(dir, "x.json")}, 2},
		"bad revoke":         {[]string{"issue", "-key", seed, "-kid", "k", "-serial", "1", "-revoke", "nocolon", "-out", filepath.Join(dir, "x.json")}, 2},
		"bad measurement":    {[]string{"issue", "-key", seed, "-kid", "k", "-serial", "1", "-revoke", "gcp-sev-snp:zz", "-out", filepath.Join(dir, "x.json")}, 1},
		"short seed":         {[]string{"issue", "-key", filepath.Join(dir, "op.pem"), "-kid", "k", "-serial", "1", "-out", filepath.Join(dir, "x.json")}, 1},
		"verify needs input": {[]string{"verify"}, 2},
		"verify missing":     {[]string{"verify", "-in", filepath.Join(dir, "absent"), "-pubkey", seed, "-kid", "k"}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, _ := runStop(tc.args...)
			require.Equal(t, tc.code, code)
		})
	}
}
