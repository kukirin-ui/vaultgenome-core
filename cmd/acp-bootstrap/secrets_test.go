// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// sealedToSimulatedHost seals plain as the secret called name to the
// simulated TEE cfg describes, the way `acp-bootstrap seal-keys` does.
func sealedToSimulatedHost(t *testing.T, cfg TEEConfig, plain []byte, name string) []byte {
	t.Helper()
	producer, err := buildTEEProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sealer, closer, err := tee.SealerFor(producer, tee.SealerOptions{})
	if err != nil || closer != nil {
		t.Fatalf("SealerFor: err=%v closer=%v", err, closer)
	}
	raw, err := tee.SealSecret(plain, sealer, tee.ProviderSimulated, producer.Measurement(), name)
	if err != nil {
		t.Fatal(err)
	}
	if !tee.IsSealedSecret(raw) {
		t.Fatal("SealSecret did not produce a sealed secret file")
	}
	return raw
}

// The host's sealer follows its TEE: the simulated TEE seals with its own
// weak key; a TDX guest or an Azure confidential GPU VM seals to its vTPM,
// built from the PCR selection alone with nothing opened; a SEV-SNP host
// off the chip has no producer and so no sealer; a bad PCR selection and
// an unknown provider are refused by name.
func TestHostSealer_PerProvider(t *testing.T) {
	dst := newDestination(t)
	cfg := dst.config()

	s, closer, provider, err := hostSealer(cfg.TEE)
	if err != nil || closer != nil || provider != tee.ProviderSimulated {
		t.Fatalf("simulated host: closer=%v provider=%q err=%v", closer, provider, err)
	}
	if _, ok := s.(*tee.Simulated); !ok {
		t.Fatalf("the simulated host seals with its own TEE, got %T", s)
	}
	for _, p := range []tee.Provider{tee.ProviderGCPTDX, tee.ProviderAzureCGPU} {
		s, closer, provider, err := hostSealer(TEEConfig{Provider: string(p), VTPMSealPCRs: "sha256:0,1,2"})
		if err != nil || closer != nil || provider != p {
			t.Fatalf("%s host: closer=%v provider=%q err=%v", p, closer, provider, err)
		}
		vtpm, ok := s.(*tee.VTPMSealer)
		if !ok || vtpm.PCRs() != "sha256:0,1,2" {
			t.Fatalf("%s host: sealer %T, want the vTPM sealer bound to the configured PCRs", p, s)
		}
	}
	for name, tc := range map[string]struct {
		cfg  TEEConfig
		want string
	}{
		"bad PCR selection":    {TEEConfig{Provider: "gcp-tdx", VTPMSealPCRs: "sha1:0"}, "tee.vtpm_seal_pcrs"},
		"unknown provider":     {TEEConfig{Provider: "nope"}, "acp-bootstrap: tee.provider"},
		"sev-snp off the chip": {TEEConfig{Provider: "gcp-sev-snp", TSMReportDir: filepath.Join(dst.dir, "no-such-tsm")}, "configfs-tsm"},
	} {
		s, closer, provider, err := hostSealer(tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) || s != nil || closer != nil || provider != "" {
			t.Fatalf("%s: sealer=%v closer=%v provider=%q err=%v, want an error mentioning %q", name, s, closer, provider, err, tc.want)
		}
	}
}

// A secret file is read bare — exactly the length wanted, any length when
// none is — or sealed to this host, in which case it opens here under its
// own name at the length wanted. Another length, another name, another
// host, a host with no sealer and a file sealed to another TEE are each
// refused by name, with nothing handed back.
func TestReadSecret_BareAndSealed(t *testing.T) {
	dst := newDestination(t)
	cfg := dst.config()
	write := func(name string, b []byte) string {
		p := filepath.Join(dst.dir, name)
		writeFile(t, p, b)
		return p
	}
	const field = "http.bearer_token_file"
	token := []byte(strongToken())
	key32 := bytes.Repeat([]byte{0x43}, 32)
	sealed := write("sealed", sealedToSimulatedHost(t, cfg.TEE, token, field))

	for name, tc := range map[string]struct {
		path    string
		wantLen int
		want    []byte
	}{
		"bare, any length":     {write("bare", token), 0, token},
		"bare, exact length":   {write("bare32", key32), 32, key32},
		"sealed, any length":   {sealed, 0, token},
		"sealed, exact length": {write("sealed32", sealedToSimulatedHost(t, cfg.TEE, key32, field)), 32, key32},
	} {
		got, err := readSecret(cfg.TEE, tc.path, tc.wantLen, field)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("%s: got %q, err=%v", name, got, err)
		}
	}

	elsewhere := cfg.TEE
	elsewhere.WorkloadDescriptor += "-elsewhere"
	for name, tc := range map[string]struct {
		cfg     TEEConfig
		path    string
		wantLen int
		want    string
	}{
		"bare of the wrong length": {cfg.TEE, write("short", []byte{1, 2, 3}), 32, "must be exactly 32 bytes (got 3)"},
		"bare but empty":           {cfg.TEE, write("empty", nil), 0, "is empty"},
		"missing":                  {cfg.TEE, filepath.Join(dst.dir, "absent"), 0, "read " + field},
		"sealed at another length": {cfg.TEE, write("sealed16", sealedToSimulatedHost(t, cfg.TEE, key32[:16], field)), 32,
			"the sealed secret is 16 bytes, want 32"},
		"sealed under another name": {cfg.TEE, write("server.key", sealedToSimulatedHost(t, cfg.TEE, token, "http.tls.server_key")), 0,
			`is "http.tls.server_key", read as "` + field + `"`},
		"sealed on another host": {elsewhere, sealed, 0, "this host does not open it"},
		"host without a sealer": {TEEConfig{Provider: "gcp-sev-snp", TSMReportDir: filepath.Join(dst.dir, "no-such-tsm")}, sealed, 0,
			"is sealed and this host cannot open it"},
		"sealed to another TEE": {TEEConfig{Provider: "gcp-tdx", TPM2ToolsDir: dst.dir}, sealed, 0, "sealed to simulated, this host is gcp-tdx"},
	} {
		got, err := readSecret(tc.cfg, tc.path, tc.wantLen, field)
		if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
			t.Fatalf("%s: got %q, err=%v, want an error mentioning %q", name, got, err, tc.want)
		}
	}
}

// replaceFile puts the new bytes in place of the old in one rename, mode
// 0600, and leaves no temporary file beside the secret; a path whose
// directory is missing, or that is a directory itself, is refused and
// nothing is written over.
func TestReplaceFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("after replaceFile: %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode after replaceFile: %v, %v", info.Mode(), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("a temporary file is left beside the secret: %v, %v", entries, err)
	}

	fresh := filepath.Join(dir, "fresh")
	if err := replaceFile(fresh, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(fresh); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("a new file: %v, %v", info, err)
	}

	if err := replaceFile(filepath.Join(dir, "no-such-dir", "secret"), []byte("x")); err == nil {
		t.Fatal("a path in a missing directory was accepted")
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(sub, []byte("x")); err == nil {
		t.Fatal("a directory was replaced by a file")
	}
	if info, err := os.Stat(sub); err != nil || !info.IsDir() {
		t.Fatalf("the directory is gone: %v, %v", info, err)
	}
}
