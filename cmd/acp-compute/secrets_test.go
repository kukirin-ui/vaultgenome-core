// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// sealedToSimulatedHost seals plain as the secret called name to the
// simulated TEE cfg describes, the way `acp-compute seal-keys` does.
func sealedToSimulatedHost(t *testing.T, cfg TEEConfig, plain []byte, name string) []byte {
	t.Helper()
	provider, producer, err := buildTEEProducer(cfg)
	require.NoError(t, err)
	require.Equal(t, tee.ProviderSimulated, provider)
	sealer, closer, err := tee.SealerFor(producer, tee.SealerOptions{})
	require.NoError(t, err)
	require.Nil(t, closer)
	raw, err := tee.SealSecret(plain, sealer, provider, producer.Measurement(), name)
	require.NoError(t, err)
	require.True(t, tee.IsSealedSecret(raw))
	return raw
}

// The host's sealer follows its TEE: the simulated TEE seals with its own
// weak key; a TDX guest or an Azure confidential GPU VM seals to its vTPM,
// built from the PCR selection alone with nothing opened; a SEV-SNP host
// off the chip has no producer and so no sealer; a bad PCR selection and
// an unknown provider are refused by name.
func TestHostSealer_PerProvider(t *testing.T) {
	t.Parallel()
	cfg, dir := testKeyDir(t)

	s, closer, provider, err := hostSealer(cfg.TEE)
	require.NoError(t, err)
	require.IsType(t, &tee.Simulated{}, s)
	require.Nil(t, closer)
	require.Equal(t, tee.ProviderSimulated, provider)

	for _, p := range []tee.Provider{tee.ProviderGCPTDX, tee.ProviderAzureCGPU} {
		s, closer, provider, err := hostSealer(TEEConfig{Provider: string(p), VTPMSealPCRs: "sha256:0,1,2"})
		require.NoError(t, err, p)
		require.Nil(t, closer)
		require.Equal(t, p, provider)
		vtpm, ok := s.(*tee.VTPMSealer)
		require.True(t, ok, "%s host: sealer %T", p, s)
		require.Equal(t, "sha256:0,1,2", vtpm.PCRs())
	}

	for name, tc := range map[string]struct {
		cfg  TEEConfig
		want string
	}{
		"bad PCR selection":    {TEEConfig{Provider: "gcp-tdx", VTPMSealPCRs: "sha1:0"}, "tee.vtpm_seal_pcrs"},
		"unknown provider":     {TEEConfig{Provider: "nope"}, "unknown provider"},
		"sev-snp off the chip": {TEEConfig{Provider: "gcp-sev-snp", TSMReportDir: filepath.Join(dir, "no-such-tsm")}, "configfs-tsm"},
	} {
		s, closer, provider, err := hostSealer(tc.cfg)
		require.ErrorContains(t, err, tc.want, name)
		require.Nil(t, s, name)
		require.Nil(t, closer, name)
		require.Empty(t, provider, name)
	}
}

// A key file is read bare — exactly the length wanted, any length when
// none is — or sealed to this host, in which case it opens here under its
// own name at the length wanted. Another length, another name, another
// host, a host with no sealer and a file sealed to another TEE are each
// refused by name, with nothing handed back.
func TestReadSecret_BareAndSealed(t *testing.T) {
	t.Parallel()
	cfg, dir := testKeyDir(t)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	const field = "keys.session_sealing.material_path"
	key32 := bytes.Repeat([]byte{0x43}, 32)
	bare := write("bare.key", key32)
	short := write("short.key", []byte{1, 2, 3})
	empty := write("empty.key", nil)
	sealed32 := write("sealed32.key", sealedToSimulatedHost(t, cfg.TEE, key32, field))
	sealed16 := write("sealed16.key", sealedToSimulatedHost(t, cfg.TEE, bytes.Repeat([]byte{0x44}, 16), field))
	asTLSKey := write("tls.key", sealedToSimulatedHost(t, cfg.TEE, key32, "vault.tls.client_key"))

	got, err := readSecret(cfg.TEE, bare, 32, field)
	require.NoError(t, err)
	require.Equal(t, key32, got)
	got, err = readSecret(cfg.TEE, bare, 0, field)
	require.NoError(t, err, "any length when none is wanted")
	require.Equal(t, key32, got)
	got, err = readSecret(cfg.TEE, sealed32, 32, field)
	require.NoError(t, err)
	require.Equal(t, key32, got, "the sealed file opens to the key")

	elsewhere := cfg.TEE
	elsewhere.WorkloadDescriptor += "-elsewhere"
	for name, tc := range map[string]struct {
		cfg     TEEConfig
		path    string
		wantLen int
		want    string
	}{
		"bare of the wrong length":  {cfg.TEE, short, 32, "must be exactly 32 bytes (got 3)"},
		"bare but empty":            {cfg.TEE, empty, 0, "is empty"},
		"missing":                   {cfg.TEE, filepath.Join(dir, "absent.key"), 32, "read " + field},
		"sealed at another length":  {cfg.TEE, sealed16, 32, "the sealed key is 16 bytes, want 32"},
		"sealed under another name": {cfg.TEE, asTLSKey, 32, `is "vault.tls.client_key", read as "` + field + `"`},
		"sealed on another host":    {elsewhere, sealed32, 32, "this host does not open it"},
		"host without a sealer": {TEEConfig{Provider: "gcp-sev-snp", TSMReportDir: filepath.Join(dir, "no-such-tsm")}, sealed32, 32,
			"is sealed and this host cannot open it"},
		"sealed to another TEE": {TEEConfig{Provider: "gcp-tdx", TPM2ToolsDir: dir}, sealed32, 32, "sealed to simulated, this host is gcp-tdx"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := readSecret(tc.cfg, tc.path, tc.wantLen, field)
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, got)
		})
	}
}

// replaceFile puts the new bytes in place of the old in one rename, mode
// 0600, and leaves no temporary file beside the key; a path whose
// directory is missing, or that is a directory itself, is refused and
// nothing is written over.
func TestReplaceFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))
	require.NoError(t, replaceFile(path, []byte("new")))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("new"), got)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file is left beside the key")

	fresh := filepath.Join(dir, "fresh")
	require.NoError(t, replaceFile(fresh, []byte("x")))
	info, err = os.Stat(fresh)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	require.Error(t, replaceFile(filepath.Join(dir, "no-such-dir", "key"), []byte("x")))

	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o700))
	require.Error(t, replaceFile(sub, []byte("x")))
	info, err = os.Stat(sub)
	require.NoError(t, err)
	require.True(t, info.IsDir(), "the directory is still a directory")
}
