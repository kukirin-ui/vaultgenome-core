// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

type sealKeyOutput struct {
	TEE            string `json:"tee"`
	MeasurementHex string `json:"measurement_hex"`
	Key            string `json:"key"`
	Sealed         bool   `json:"sealed"`
	AlreadySealed  bool   `json:"already_sealed"`
}

// The seed file sealed in place to the primary's TEE: the same key
// afterwards for identity and for the watch, opened with --tee; sealed
// once only; no seed for another host or without the TEE.
func TestSentinel_SealKeySealsTheSeedToThePrimarysTEE(t *testing.T) {
	dir := t.TempDir()
	seed, pub, escrowPEM := sentinelKeys(t, dir)
	teeSeed := filepath.Join(dir, "tee.seed")
	require.NoError(t, os.WriteFile(teeSeed, bytes.Repeat([]byte{0x31}, 32), 0o600))
	teeArgs := []string{"--tee", "simulated", "--tee-seed", teeSeed, "--workload-descriptor", "primary-drill"}
	bare, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.Len(t, bare, ed25519.SeedSize)

	code, stdout, stderr := runCmd(sentinelRun, append([]string{"identity", "--key", seed}, teeArgs...)...)
	require.Equal(t, 0, code, stderr)
	var before sentinelIdentity
	require.NoError(t, json.Unmarshal([]byte(stdout), &before))

	code, stdout, stderr = runCmd(sentinelRun, append([]string{"seal-key", "--key", seed}, teeArgs...)...)
	require.Equal(t, 0, code, stderr)
	var out sealKeyOutput
	require.NoError(t, json.Unmarshal([]byte(stdout), &out))
	require.True(t, out.Sealed)
	require.False(t, out.AlreadySealed)
	require.Equal(t, "simulated", out.TEE)
	require.Equal(t, before.MeasurementHex, out.MeasurementHex)

	sealed, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.True(t, tee.IsSealedSecret(sealed), "the file is a sealed secret now")
	require.NotContains(t, string(sealed), string(bare))
	info, err := os.Stat(seed)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.Contains(t, string(sealed), `"name": "sentinel.seed"`)

	// The same key, from the sealed file.
	code, stdout, stderr = runCmd(sentinelRun, append([]string{"identity", "--key", seed}, teeArgs...)...)
	require.Equal(t, 0, code, stderr)
	var after sentinelIdentity
	require.NoError(t, json.Unmarshal([]byte(stdout), &after))
	require.Equal(t, before.SentinelKeyID, after.SentinelKeyID)
	require.Equal(t, before.SentinelPublicKeyPEM, after.SentinelPublicKeyPEM)

	// Sealing again seals nothing: the file is proven to open and left.
	code, stdout, stderr = runCmd(sentinelRun, append([]string{"seal-key", "--key", seed}, teeArgs...)...)
	require.Equal(t, 0, code, stderr)
	require.NoError(t, json.Unmarshal([]byte(stdout), &out))
	require.False(t, out.Sealed)
	require.True(t, out.AlreadySealed)
	again, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.Equal(t, sealed, again)

	// On another host (the simulated TEE's measurement is its descriptor's)
	// the sealed file is no seed; without the TEE neither.
	code, _, stderr = runCmd(sentinelRun, "identity", "--tee", "simulated", "--tee-seed", teeSeed, "--workload-descriptor", "another-host", "--key", seed)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "--key")
	require.Contains(t, stderr, "sentinel.seed")
	code, _, stderr = runCmd(sentinelRun, "watch", "--content-dir", dir, "--outbox", filepath.Join(dir, "ob"), "--escrow-to", escrowPEM, "--key", seed)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "pass --tee to open it")

	// The watch runs from the sealed file: one generation sealed, the
	// records signed by the same sentinel key.
	state, outbox := filepath.Join(dir, "state"), filepath.Join(dir, "outbox")
	require.NoError(t, os.MkdirAll(state, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(state, "adapter.safetensors"), []byte("weights"), 0o644))
	canary := filepath.Join(dir, "canary")
	require.NoError(t, os.WriteFile(canary, []byte("quiet"), 0o600))
	go func() {
		for {
			if m, _ := filepath.Glob(filepath.Join(outbox, "gen-*.seal.json")); len(m) > 0 {
				_ = os.WriteFile(canary, []byte("touched"), 0o600)
				return
			}
		}
	}()
	code, _, stderr = runCmd(sentinelRun, append([]string{"watch", "--content-dir", state, "--outbox", outbox, "--escrow-to", escrowPEM, "--key", seed,
		"--tripwire", canary, "--interval", "20ms", "--settle", "0s"}, teeArgs...)...)
	require.Equal(t, 3, code, stderr)
	pk, err := readEd25519PublicKey(pub)
	require.NoError(t, err)
	chain, _, err := sentinel.ReadChain(outbox, ed25519.PublicKey(pk))
	require.NoError(t, err)
	require.Len(t, chain, 1)
}

func TestSentinel_SealKeyRefusesBadArguments(t *testing.T) {
	dir := t.TempDir()
	seed, _, _ := sentinelKeys(t, dir)
	teeSeed := filepath.Join(dir, "tee.seed")
	require.NoError(t, os.WriteFile(teeSeed, bytes.Repeat([]byte{0x31}, 32), 0o600))

	code, _, stderr := runCmd(sentinelRun, "seal-key", "--key", seed)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "--key and --tee are required")

	short := filepath.Join(dir, "short.seed")
	require.NoError(t, os.WriteFile(short, []byte("short"), 0o600))
	code, _, stderr = runCmd(sentinelRun, "seal-key", "--key", short, "--tee", "simulated", "--tee-seed", teeSeed)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "not a 32-byte seed")

	require.NoError(t, os.Chmod(seed, 0o644))
	code, _, stderr = runCmd(sentinelRun, "seal-key", "--key", seed, "--tee", "simulated", "--tee-seed", teeSeed)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "open to other users")
	bare, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.False(t, tee.IsSealedSecret(bare), "nothing was sealed")
}
