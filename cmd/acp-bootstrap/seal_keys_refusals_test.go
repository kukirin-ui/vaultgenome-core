// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// identity refuses what it cannot print from — a bad flag, a config it
// cannot read, a TEE it cannot build — and prints nothing then.
func TestIdentity_Refusals(t *testing.T) {
	dst := newDestination(t)
	noSeed := dst.config()
	noSeed.TEE.SeedPath = filepath.Join(dst.dir, "absent_seed")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"unknown flag":                {[]string{"-bogus"}, "flag provided but not defined"},
		"missing config file":         {[]string{"-config", filepath.Join(dst.dir, "absent.json")}, "open config"},
		"material that does not load": {[]string{"-config", writeConfigFile(t, dst.dir, noSeed)}, "read tee.seed_path"},
	} {
		var out strings.Builder
		err := runIdentity(tc.args, &out)
		if err == nil || !strings.Contains(err.Error(), tc.want) || out.Len() != 0 {
			t.Fatalf("%s: err=%v out=%q, want an error mentioning %q and no output", name, err, out.String(), tc.want)
		}
	}
}

// seal-keys stops, with nothing printed and nothing sealed, on a bad
// flag, a config that does not validate, a TEE it cannot build, a file
// sealed on another host, and a directory it cannot write into.
func TestSealKeys_StopsBeforeSealing(t *testing.T) {
	dst := newDestination(t)
	cfg := dst.config()
	var stdout, stderr bytes.Buffer

	// The flag set reports to the stderr it was given.
	if err := runSealKeys([]string{"-bogus"}, &stdout, &stderr); err == nil || !strings.Contains(stderr.String(), "-config") {
		t.Fatalf("unknown flag: err=%v stderr=%q", err, stderr.String())
	}

	invalid := cfg
	invalid.TEE.Provider = "nope"
	if err := runSealKeys([]string{"-config", writeConfigFile(t, dst.dir, invalid)}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "config validation") {
		t.Fatalf("invalid config: %v", err)
	}

	noSeed := cfg
	noSeed.TEE.SeedPath = filepath.Join(dst.dir, "absent_seed")
	if err := runSealKeys([]string{"-config", writeConfigFile(t, dst.dir, noSeed)}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "read tee.seed_path") {
		t.Fatalf("missing seed: %v", err)
	}

	// A token sealed on another host is neither re-sealed nor accepted.
	elsewhere := cfg.TEE
	elsewhere.WorkloadDescriptor += "-elsewhere"
	token := []byte(strongToken())
	foreign := cfg
	foreign.HTTP.BearerTokenFile = filepath.Join(dst.dir, "foreign_token")
	sealedElsewhere := sealedToSimulatedHost(t, elsewhere, token, "http.bearer_token_file")
	writeFile(t, foreign.HTTP.BearerTokenFile, sealedElsewhere)
	err := runSealKeys([]string{"-config", writeConfigFile(t, dst.dir, foreign)}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "http.bearer_token_file is sealed, and this host cannot open it") {
		t.Fatalf("token sealed elsewhere: %v", err)
	}
	if raw, err := os.ReadFile(foreign.HTTP.BearerTokenFile); err != nil || !bytes.Equal(raw, sealedElsewhere) {
		t.Fatalf("the foreign file was touched: %v", err)
	}

	if os.Geteuid() != 0 {
		// Root writes anywhere; everyone else is refused by the directory.
		ro := filepath.Join(dst.dir, "ro")
		if err := os.Mkdir(ro, 0o700); err != nil {
			t.Fatal(err)
		}
		readOnly := cfg
		readOnly.HTTP.BearerTokenFile = filepath.Join(ro, "api_token")
		writeFile(t, readOnly.HTTP.BearerTokenFile, token)
		configPath := writeConfigFile(t, dst.dir, readOnly)
		if err := os.Chmod(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
		err := runSealKeys([]string{"-config", configPath}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "write http.bearer_token_file") {
			t.Fatalf("read-only directory: %v", err)
		}
		if raw, err := os.ReadFile(readOnly.HTTP.BearerTokenFile); err != nil || !bytes.Equal(raw, token) {
			t.Fatalf("the token is no longer the bare token: %q, %v", raw, err)
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("a refusal printed %q", stdout.String())
	}
}
