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

// The host's sealer comes from the TEE config alone: a vTPM sealer for the
// providers that seal through the vTPM, the producer's own sealer for the
// rest; a provider that is not there, or a bad PCR selection, is refused.
func TestHostSealer_PerProvider(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  TEEConfig
		want string
	}{
		"invalid provider":     {TEEConfig{Provider: "vmware"}, "unknown provider"},
		"tdx bad pcrs":         {TEEConfig{Provider: "gcp-tdx", VTPMSealPCRs: "sha1:0"}, "tee.vtpm_seal_pcrs"},
		"sev-snp off the chip": {TEEConfig{Provider: "gcp-sev-snp", TSMReportDir: filepath.Join(t.TempDir(), "no-tsm")}, "configfs-tsm"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := hostSealer(tc.cfg)
			require.ErrorContains(t, err, tc.want)
		})
	}
	for _, provider := range []string{"gcp-tdx", "azure-cgpu"} {
		s, closer, got, err := hostSealer(TEEConfig{Provider: provider, VTPMSealPCRs: "sha256:0,1,2", TPM2ToolsDir: "/opt/tpm2"})
		require.NoError(t, err)
		require.Nil(t, closer, "a vTPM sealer holds nothing open")
		require.Equal(t, tee.Provider(provider), got)
		v, ok := s.(*tee.VTPMSealer)
		require.True(t, ok, "%T", s)
		require.Equal(t, "sha256:0,1,2", v.PCRs())
	}
	seed := filepath.Join(t.TempDir(), "seed")
	require.NoError(t, os.WriteFile(seed, bytes.Repeat([]byte{1}, 32), 0o600))
	s, closer, got, err := hostSealer(TEEConfig{WorkloadDescriptor: "w", SeedPath: seed})
	require.NoError(t, err)
	require.Nil(t, closer)
	require.Equal(t, tee.ProviderSimulated, got)
	require.IsType(t, &tee.Simulated{}, s, "the simulated TEE seals with its own key")
}

// readSecret takes bare bytes of the expected length, or a file sealed by
// seal-keys that this host can open; every other shape is named.
func TestReadSecret_Shapes(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	seedPath := write("seed", bytes.Repeat([]byte{1}, 32))
	host := TEEConfig{WorkloadDescriptor: "sealing-host", SeedPath: seedPath}
	sealer, _, provider, err := hostSealer(host)
	require.NoError(t, err)
	_, producer, err := buildTEEProducer(host)
	require.NoError(t, err)
	seal := func(plain []byte, name string) []byte {
		raw, err := tee.SealSecret(plain, sealer, provider, producer.Measurement(), name)
		require.NoError(t, err)
		return raw
	}
	empty := write("empty", nil)
	short := write("short", []byte("short"))
	token := write("token", []byte("any-length-token\n"))
	sealed32 := write("sealed32", seal(bytes.Repeat([]byte{7}, 32), "keys.session_sealing.material_path"))
	sealed16 := write("sealed16", seal(bytes.Repeat([]byte{7}, 16), "keys.x"))

	got, err := readSecret(host, token, 0, "http_api.bearer_token_file")
	require.NoError(t, err)
	require.Equal(t, []byte("any-length-token\n"), got, "any length when none is required")
	got, err = readSecret(host, sealed32, 32, "keys.session_sealing.material_path")
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{7}, 32), got, "opened on the host that sealed it")

	for name, tc := range map[string]struct {
		cfg     TEEConfig
		path    string
		wantLen int
		want    string
	}{
		"missing":                         {host, filepath.Join(dir, "absent"), 32, "read keys.x"},
		"empty":                           {host, empty, 0, "is empty"},
		"wrong length":                    {host, short, 32, "must be exactly 32 bytes"},
		"sealed, host cannot open":        {TEEConfig{Provider: "vmware"}, sealed32, 32, "is sealed and this host cannot open it"},
		"sealed under another name":       {host, write("other", seal(bytes.Repeat([]byte{7}, 32), "keys.audit_signing.seed_path")), 32, `read as "keys.x"`},
		"sealed, wrong length":            {host, sealed16, 32, "the sealed key is 16 bytes, want 32"},
		"sealed, vtpm host without tools": {TEEConfig{Provider: "gcp-tdx", TPM2ToolsDir: filepath.Join(dir, "no-tools")}, sealed32, 32, "keys.x"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readSecret(tc.cfg, tc.path, tc.wantLen, "keys.x")
			require.ErrorContains(t, err, tc.want)
		})
	}
}
