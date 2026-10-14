// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package exposure

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:9443":       true,
		"127.10.20.30:1":       true,
		"[::1]:9443":           true,
		"localhost:9080":       true,
		"0.0.0.0:9443":         false, // every interface
		":9443":                false, // every interface
		"[::]:9443":            false, // every interface
		"10.66.0.2:9443":       false,
		"sagvd:9443":           false, // hostname may resolve anywhere
		"not-a-host-port":      false,
		"example.com:9080":     false,
		"[::ffff:127.0.0.1]:1": true, // IPv4-mapped loopback
	}
	for addr, want := range cases {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "127.0.0.1": true, "::1": true,
		"": false, "0.0.0.0": false, "10.0.0.1": false, "acp-bootstrap": false,
	} {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	got, err := ReadTokenFile(write("token", "  s3cret-token\n"))
	if err != nil || got != "s3cret-token" {
		t.Fatalf("ReadTokenFile = %q, %v; want the trimmed token", got, err)
	}
	if _, err := ReadTokenFile(write("blank", " \n\t")); err == nil {
		t.Fatal("a whitespace-only token file was accepted")
	}
	if _, err := ReadTokenFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing token file was accepted")
	}
}
