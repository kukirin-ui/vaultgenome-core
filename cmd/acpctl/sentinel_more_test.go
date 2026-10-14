// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// parsedTEEFlags parses args into the TEE flags the sentinel commands share.
func parsedTEEFlags(t *testing.T, args ...string) teeFlags {
	t.Helper()
	fs := flag.NewFlagSet("tee", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	tf := addTEEFlags(fs)
	require.NoError(t, fs.Parse(args))
	return tf
}

// --tee names a producer this build can run on this host, or says why not;
// unset, there is no producer and no error.
func TestTEEFlags_Producer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seed := filepath.Join(dir, "tee.seed")
	require.NoError(t, os.WriteFile(seed, bytes.Repeat([]byte{0x31}, 32), 0o600))
	short := filepath.Join(dir, "short.seed")
	require.NoError(t, os.WriteFile(short, []byte("short"), 0o600))

	provider, p, err := parsedTEEFlags(t).producer()
	require.NoError(t, err)
	require.Empty(t, provider)
	require.Nil(t, p)

	provider, p, err = parsedTEEFlags(t, "--tee", "simulated", "--tee-seed", seed, "--workload-descriptor", "drill").producer()
	require.NoError(t, err)
	require.Equal(t, tee.ProviderSimulated, provider)
	require.Equal(t, tee.MeasurementOf([]byte("drill")), p.Measurement())

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"unknown kind":           {[]string{"--tee", "quantum"}, `--tee: structural[field_value_invalid]: tee: unknown provider "quantum"`},
		"no producer for tdx":    {[]string{"--tee", "gcp-tdx"}, "--tee gcp-tdx: no producer this build can run (supported: gcp-sev-snp, simulated)"},
		"sev-snp off a cvm":      {[]string{"--tee", "gcp-sev-snp", "--tsm-report-dir", filepath.Join(dir, "absent")}, "--tee gcp-sev-snp: "},
		"simulated without seed": {[]string{"--tee", "simulated"}, "--tee simulated needs --tee-seed"},
		"simulated short seed":   {[]string{"--tee", "simulated", "--tee-seed", short}, "--tee-seed: " + short + " holds 5 bytes, not a 32-byte seed"},
		"simulated absent seed":  {[]string{"--tee", "simulated", "--tee-seed", filepath.Join(dir, "absent")}, "--tee-seed: "},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			provider, p, err := parsedTEEFlags(t, tc.args...).producer()
			require.ErrorContains(t, err, tc.want)
			require.Empty(t, provider)
			require.Nil(t, p)
		})
	}
}

// keygen writes the seed before the public key, and reports either
// failing; identity needs a producer it can build.
func TestSentinel_KeygenAndIdentityFailures(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent")

	code, _, stderr := runCmd(sentinelRun, "keygen", "--out", filepath.Join(absent, "s.seed"), "--pub", filepath.Join(dir, "s.pem"))
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl sentinel keygen:")
	_, err := os.Stat(filepath.Join(dir, "s.pem"))
	require.True(t, os.IsNotExist(err), "no public key without its seed")

	seed := filepath.Join(dir, "s.seed")
	code, _, stderr = runCmd(sentinelRun, "keygen", "--out", seed, "--pub", filepath.Join(absent, "s.pem"))
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl sentinel keygen:")
	info, err := os.Stat(seed)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	code, _, stderr = runCmd(sentinelRun, "keygen", "--nope")
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "flag provided but not defined")

	code, _, stderr = runCmd(sentinelRun, "identity", "--tee", "gcp-sev-snp", "--tsm-report-dir", absent)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl sentinel identity: --tee gcp-sev-snp:")

	code, _, stderr = runCmd(sentinelRun, "identity", "--nope")
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "flag provided but not defined")
}

// seal-key refuses before writing: no producer, no key file, a sealed file
// this host does not open, and a directory it cannot replace the file in.
func TestSentinel_SealKeyRefusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seed, _, _ := sentinelKeys(t, dir)
	teeSeed := filepath.Join(dir, "tee.seed")
	require.NoError(t, os.WriteFile(teeSeed, bytes.Repeat([]byte{0x31}, 32), 0o600))
	absent := filepath.Join(dir, "absent")

	code, _, stderr := runCmd(sentinelRun, "seal-key", "--key", seed, "--tee", "gcp-sev-snp", "--tsm-report-dir", absent)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl sentinel seal-key: --tee gcp-sev-snp:")

	code, _, stderr = runCmd(sentinelRun, "seal-key", "--key", filepath.Join(dir, "absent.seed"), "--tee", "simulated", "--tee-seed", teeSeed)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "acpctl sentinel seal-key: --key:")

	code, _, stderr = runCmd(sentinelRun, "seal-key", "--nope")
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "flag provided but not defined")

	// Sealed on one primary, the file is no seed on another, and seal-key
	// there says so rather than sealing the sealed file again.
	code, _, stderr = runCmd(sentinelRun, "seal-key", "--key", seed, "--tee", "simulated", "--tee-seed", teeSeed, "--workload-descriptor", "primary-one")
	require.Equal(t, 0, code, stderr)
	sealedBytes, err := os.ReadFile(seed)
	require.NoError(t, err)
	code, _, stderr = runCmd(sentinelRun, "seal-key", "--key", seed, "--tee", "simulated", "--tee-seed", teeSeed, "--workload-descriptor", "primary-two")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, seed+" is sealed, and this host cannot open it")
	again, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.Equal(t, sealedBytes, again, "the file is left as it was")
}

// A seed file in a directory that takes no new file is not replaced, and
// the bare seed stays as it was.
func TestSentinel_SealKeyCannotReplaceInReadOnlyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	t.Parallel()
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keyDir, 0o755))
	seed, _, _ := sentinelKeys(t, keyDir)
	teeSeed := filepath.Join(dir, "tee.seed")
	require.NoError(t, os.WriteFile(teeSeed, bytes.Repeat([]byte{0x31}, 32), 0o600))
	bare, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(keyDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(keyDir, 0o755) })

	code, _, stderr := runCmd(sentinelRun, "seal-key", "--key", seed, "--tee", "simulated", "--tee-seed", teeSeed)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl sentinel seal-key:")
	got, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.Equal(t, bare, got)
	entries, err := os.ReadDir(keyDir)
	require.NoError(t, err)
	require.Len(t, entries, 3, "the seed, its public key and the escrow key: no temporary file is left behind")
}

// A sealed file is read as the sentinel's seed only when it is one: the
// right name, and 32 bytes once open.
func TestReadSentinelSeed_RefusesWhatIsNotASeed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	teeSeedBytes := bytes.Repeat([]byte{0x31}, 32)
	teeSeed := filepath.Join(dir, "tee.seed")
	require.NoError(t, os.WriteFile(teeSeed, teeSeedBytes, 0o600))
	sim, err := tee.NewSimulated([]byte("sentinel"), teeSeedBytes)
	require.NoError(t, err)
	tf := parsedTEEFlags(t, "--tee", "simulated", "--tee-seed", teeSeed)

	sealAs := func(file, name string, plain []byte) string {
		blob, err := tee.SealSecret(plain, sim, tee.ProviderSimulated, sim.Measurement(), name)
		require.NoError(t, err)
		p := filepath.Join(dir, file)
		require.NoError(t, os.WriteFile(p, blob, 0o600))
		return p
	}
	shortSealed := sealAs("short.sealed", sentinelSeedName, []byte("short"))
	otherName := sealAs("other.sealed", "other.seed", bytes.Repeat([]byte{7}, 32))
	good := sealAs("good.sealed", sentinelSeedName, bytes.Repeat([]byte{7}, 32))

	key, err := readSentinelSeed(good, tf, tee.ProviderSimulated, sim)
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{7}, 32), key.Seed())

	_, err = readSentinelSeed(shortSealed, tf, tee.ProviderSimulated, sim)
	require.ErrorContains(t, err, shortSealed+": the sealed seed is 5 bytes, want 32")

	_, err = readSentinelSeed(otherName, tf, tee.ProviderSimulated, sim)
	require.ErrorContains(t, err, `the file is "other.seed", read as "sentinel.seed"`)

	_, err = readSentinelSeed(good, tf, "", nil)
	require.ErrorContains(t, err, "pass --tee to open it")

	// Through the command: identity refuses the short one with exit 2.
	code, _, stderr := runCmd(sentinelRun, "identity", "--tee", "simulated", "--tee-seed", teeSeed, "--key", shortSealed)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "acpctl sentinel identity: --key: "+shortSealed+": the sealed seed is 5 bytes, want 32")

	// And seal-key proves a sealed file opens here without touching it.
	code, stdout, stderr := runCmd(sentinelRun, "seal-key", "--key", good, "--tee", "simulated", "--tee-seed", teeSeed)
	require.Equal(t, 0, code, stderr)
	var out sealKeyOutput
	require.NoError(t, json.Unmarshal([]byte(stdout), &out))
	require.True(t, out.AlreadySealed)
	require.Equal(t, hex.EncodeToString(sim.Measurement()), out.MeasurementHex)
}

// readPrivateFile refuses a file other users can read, or none at all.
func TestReadPrivateFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	private := filepath.Join(dir, "private")
	require.NoError(t, os.WriteFile(private, []byte("secret"), 0o600))
	open := filepath.Join(dir, "open")
	require.NoError(t, os.WriteFile(open, []byte("secret"), 0o640))

	got, err := readPrivateFile(private)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), got)

	_, err = readPrivateFile(open)
	require.ErrorContains(t, err, open+" is open to other users (mode 0640); chmod 600 it")

	_, err = readPrivateFile(filepath.Join(dir, "absent"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

// replaceFile swaps the file's bytes whole, private, leaving no temporary
// file, and writes nothing where it cannot.
func TestReplaceFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "seed")
	require.NoError(t, os.WriteFile(p, []byte("old"), 0o644))
	require.NoError(t, replaceFile(p, []byte("new")))
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, []byte("new"), got)
	info, err := os.Stat(p)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	require.Error(t, replaceFile(filepath.Join(dir, "absent", "seed"), []byte("x")))
}

func TestPrintJSONAndZero(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printJSON(&buf, map[string]any{"b": 1, "a": "x"})
	require.Equal(t, "{\n  \"a\": \"x\",\n  \"b\": 1\n}\n", buf.String())

	b := []byte{1, 2, 3}
	zero(b)
	require.Equal(t, []byte{0, 0, 0}, b)
	zero(nil)
}
