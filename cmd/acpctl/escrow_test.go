// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
)

// The operator's side of the recovery ceremony: a recovery key made off
// the release host; an envelope (as sagvd escrow-provision writes it)
// opened with it; the escrow key on stdout, raw, for the pipe.
func TestEscrowRecoveryCommands(t *testing.T) {
	work := t.TempDir()
	recoverySeed, recoveryPub := filepath.Join(work, "recovery.seed"), filepath.Join(work, "recovery.pem")
	var out, errOut bytes.Buffer
	require.Equal(t, 0, escrowCmd([]string{"recovery-keygen", "--out", recoverySeed, "--pub", recoveryPub}, &out, &errOut), errOut.String())
	require.Contains(t, out.String(), "keep it off the release host")
	info, err := os.Stat(recoverySeed)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.Equal(t, 1, escrowCmd([]string{"recovery-keygen", "--out", recoverySeed, "--pub", recoveryPub}, &out, &errOut), "never overwritten")

	// The release host wraps its escrow key to the recovery public key.
	pemBytes, err := os.ReadFile(recoveryPub)
	require.NoError(t, err)
	rpub, err := escrow.ParsePublicPEM(pemBytes)
	require.NoError(t, err)
	escrowKey, err := escrow.GenerateKey()
	require.NoError(t, err)
	env, err := escrow.WrapRecovery(escrowKey, rpub)
	require.NoError(t, err)
	raw, err := env.Marshal()
	require.NoError(t, err)
	envelope := filepath.Join(work, "escrow.recovery")
	require.NoError(t, os.WriteFile(envelope, raw, 0o600))

	out.Reset()
	errOut.Reset()
	require.Equal(t, 0, escrowCmd([]string{"recover", "--in", envelope, "--key", recoverySeed}, &out, &errOut), errOut.String())
	require.Equal(t, escrowKey.Bytes(), out.Bytes(), "the raw key, for the pipe")
	require.Contains(t, errOut.String(), env.EscrowKey)

	// The wrong recovery key, a damaged envelope, a readable seed: refused.
	other := filepath.Join(work, "other.seed")
	require.Equal(t, 0, escrowCmd([]string{"recovery-keygen", "--out", other, "--pub", filepath.Join(work, "other.pem")}, &out, &errOut))
	require.Equal(t, 1, escrowCmd([]string{"recover", "--in", envelope, "--key", other}, &out, &errOut))
	require.NoError(t, os.WriteFile(filepath.Join(work, "bad.recovery"), []byte("{"), 0o600))
	require.Equal(t, 2, escrowCmd([]string{"recover", "--in", filepath.Join(work, "bad.recovery"), "--key", recoverySeed}, &out, &errOut))
	require.NoError(t, os.Chmod(recoverySeed, 0o644))
	require.Equal(t, 2, escrowCmd([]string{"recover", "--in", envelope, "--key", recoverySeed}, &out, &errOut))
	require.Equal(t, 2, escrowCmd([]string{"recover"}, &out, &errOut))
	require.Equal(t, 2, escrowCmd([]string{"recovery-keygen"}, &out, &errOut))
	require.Equal(t, 2, escrowCmd([]string{"nonsense"}, &out, &errOut))
	require.Equal(t, 0, escrowCmd([]string{"--help"}, &out, &errOut))
}
