// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func writeConfigFile(t *testing.T, dir string, cfg Config) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.json")
	writeFile(t, p, b)
	return p
}

// The destination's secret files sealed in place to its TEE: the TLS
// server key and the bearer token; the daemon then starts from the
// sealed files and serves mTLS with the token as before; sealed once
// only; another host does not open them.
func TestSealKeys_SealsTheTLSKeyAndTheTokenAndTheDaemonOpensThem(t *testing.T) {
	dst := newDestination(t)
	pki := newPKI(t, dst.dir)
	token := strongToken()
	cfg := dst.config()
	cfg.HTTP.TLS = TLSServerConfig{Enabled: true, ServerCert: pki.serverCert, ServerKey: pki.serverKey, ClientCAs: pki.caCert}
	cfg.HTTP.BearerTokenFile = filepath.Join(dst.dir, "api_token")
	writeFile(t, cfg.HTTP.BearerTokenFile, []byte(token+"\n"))
	keyPEM, err := os.ReadFile(pki.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	configPath := writeConfigFile(t, dst.dir, cfg)

	var stdout, stderr bytes.Buffer
	if err := runSealKeys([]string{"-config", configPath}, &stdout, &stderr); err != nil {
		t.Fatalf("seal-keys: %v\n%s", err, stderr.String())
	}
	var out sealKeysOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.TEE != "simulated" || len(out.MeasurementHex) != 64 || len(out.Sealed) != 2 || len(out.AlreadySealed) != 0 {
		t.Fatalf("seal-keys output: %+v", out)
	}
	if out.Sealed[0].Name != "http.tls.server_key" || out.Sealed[1].Name != "http.bearer_token_file" {
		t.Fatalf("sealed names: %+v", out.Sealed)
	}
	if !strings.Contains(stderr.String(), "SIMULATED TEE") {
		t.Fatalf("no simulated warning: %s", stderr.String())
	}
	for _, p := range []string{pki.serverKey, cfg.HTTP.BearerTokenFile} {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !tee.IsSealedSecret(raw) || bytes.Contains(raw, keyPEM) || bytes.Contains(raw, []byte(token)) {
			t.Fatalf("%s is not sealed (or holds the plaintext)", p)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %04o", p, info.Mode().Perm())
		}
	}

	// Sealing again seals nothing: the files are proven to open and left.
	stdout.Reset()
	if err := runSealKeys([]string{"-config", configPath}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sealed) != 0 || len(out.AlreadySealed) != 2 {
		t.Fatalf("second seal-keys: %+v", out)
	}

	// The daemon reads the token and the key from the sealed files.
	if err := cfg.ResolveSecrets(); err != nil {
		t.Fatalf("ResolveSecrets on the sealed token: %v", err)
	}
	if cfg.HTTP.BearerToken != token {
		t.Fatalf("token from the sealed file: %q", cfg.HTTP.BearerToken)
	}
	r := start(t, cfg)
	dek := []byte("fedcba9876543210fedcba9876543210")
	if _, err := restore(t, dst, r.url, pki.client(t, true, tls.VersionTLS13), token, dek); err != nil {
		t.Fatalf("restore with client certificate and token against the sealed material: %v", err)
	}
	if _, err := restore(t, dst, r.url, pki.client(t, true, tls.VersionTLS13), "", dek); err == nil {
		t.Fatal("a caller without the bearer token completed a restore")
	}
	requireRegistered(t, r.d, "dek-1")

	// Another host (another simulated descriptor) opens neither.
	other := cfg
	other.TEE.WorkloadDescriptor = cfg.TEE.WorkloadDescriptor + "-elsewhere"
	if err := other.ResolveSecrets(); err == nil || !strings.Contains(err.Error(), "http.bearer_token_file") {
		t.Fatalf("the sealed token opened on another host: %v", err)
	}
	if _, _, err := buildHTTPServer(other.TEE, other.HTTP, nil, quietLog); err == nil || !strings.Contains(err.Error(), "http.tls.server_key") {
		t.Fatalf("the sealed TLS key opened on another host: %v", err)
	}
}

// Nothing to seal is not an error; a bad config, an unreadable file and
// an empty file are.
func TestSealKeys_Refusals(t *testing.T) {
	dst := newDestination(t)
	cfg := dst.config()
	configPath := writeConfigFile(t, dst.dir, cfg)
	var stdout, stderr bytes.Buffer
	if err := runSealKeys([]string{"-config", configPath}, &stdout, &stderr); err != nil {
		t.Fatalf("nothing to seal: %v", err)
	}
	var out sealKeysOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil || len(out.Sealed) != 0 {
		t.Fatalf("nothing to seal: %v %+v", err, out)
	}

	if err := runSealKeys(nil, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "-config is required") {
		t.Fatalf("no -config: %v", err)
	}
	if err := runSealKeys([]string{"-config", filepath.Join(dst.dir, "absent.json")}, &stdout, &stderr); err == nil {
		t.Fatal("a missing config file was accepted")
	}

	cfg.HTTP.BearerTokenFile = filepath.Join(dst.dir, "empty_token")
	writeFile(t, cfg.HTTP.BearerTokenFile, nil)
	configPath = writeConfigFile(t, dst.dir, cfg)
	if err := runSealKeys([]string{"-config", configPath}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("an empty token file was sealed: %v", err)
	}
	cfg.HTTP.BearerTokenFile = filepath.Join(dst.dir, "absent_token")
	configPath = writeConfigFile(t, dst.dir, cfg)
	if err := runSealKeys([]string{"-config", configPath}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "http.bearer_token_file") {
		t.Fatalf("a missing token file was sealed: %v", err)
	}
}
