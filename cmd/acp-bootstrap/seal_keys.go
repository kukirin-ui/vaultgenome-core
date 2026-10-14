// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

type sealKeysOutput struct {
	TEE            string           `json:"tee"`
	MeasurementHex string           `json:"measurement_hex"`
	Sealed         []sealedKeyEntry `json:"sealed"`
	AlreadySealed  []sealedKeyEntry `json:"already_sealed,omitempty"`
}

type sealedKeyEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// secretFiles are the secret files the config names: the TLS server key
// when TLS is on, and the bearer token file when one is set. Each is
// sealed under its config name, so a file sealed as one does not open as
// the other.
func secretFiles(cfg Config) []sealedKeyEntry {
	var files []sealedKeyEntry
	if cfg.HTTP.TLS.Enabled && cfg.HTTP.TLS.ServerKey != "" {
		files = append(files, sealedKeyEntry{Name: "http.tls.server_key", Path: cfg.HTTP.TLS.ServerKey})
	}
	if cfg.HTTP.BearerTokenFile != "" {
		files = append(files, sealedKeyEntry{Name: "http.bearer_token_file", Path: cfg.HTTP.BearerTokenFile})
	}
	return files
}

// runSealKeys implements `acp-bootstrap seal-keys -config <path>`: every
// secret file the config names — the TLS server key, the bearer token —
// is sealed in place to this host's TEE (ADR 0023), each under its name,
// after being opened once from the sealed form; the daemon then reads
// them sealed. A file already sealed is left as it is. Run it once the
// config is final and before the daemon's first start; a new chip, image
// or boot of a vTPM host needs new files.
func runSealKeys(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("acp-bootstrap seal-keys", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("acp-bootstrap seal-keys: -config is required")
	}
	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("acp-bootstrap seal-keys: config validation: %w", err)
	}
	producer, err := buildTEEProducer(cfg.TEE)
	if err != nil {
		return err
	}
	sealer, closer, provider, err := hostSealer(cfg.TEE)
	if err != nil {
		return err
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	if provider == tee.ProviderSimulated {
		fmt.Fprintln(stderr, "acp-bootstrap seal-keys: SIMULATED TEE: the files are sealed under a key derived from the simulated measurement, with no hardware behind it; development and tests only")
	}
	measurement := producer.Measurement()
	out := sealKeysOutput{TEE: string(provider), MeasurementHex: hex.EncodeToString(measurement)}
	for _, f := range secretFiles(cfg) {
		raw, err := os.ReadFile(f.Path)
		if err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: read %s (%q): %w", f.Name, f.Path, err)
		}
		if tee.IsSealedSecret(raw) {
			if _, err := readSecret(cfg.TEE, f.Path, 0, f.Name); err != nil {
				return fmt.Errorf("acp-bootstrap seal-keys: %s is sealed, and this host cannot open it: %w", f.Name, err)
			}
			out.AlreadySealed = append(out.AlreadySealed, f)
			continue
		}
		if len(raw) == 0 {
			return fmt.Errorf("acp-bootstrap seal-keys: %s (%q) is empty", f.Name, f.Path)
		}
		sealed, err := tee.SealSecret(raw, sealer, provider, measurement, f.Name)
		zero(raw)
		if err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: %s: %w", f.Name, err)
		}
		back, err := tee.OpenSecret(sealed, sealer, provider, f.Name)
		zero(back)
		if err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: %s: the sealed file does not open on this host: %w", f.Name, err)
		}
		if err := replaceFile(f.Path, sealed); err != nil {
			return fmt.Errorf("acp-bootstrap seal-keys: write %s (%q): %w", f.Name, f.Path, err)
		}
		out.Sealed = append(out.Sealed, f)
	}
	if out.Sealed == nil {
		out.Sealed = []sealedKeyEntry{}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// replaceFile writes data beside path, mode 0600, and renames it over
// path: the old bytes are never half-replaced.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".seal-keys-*")
	if err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
