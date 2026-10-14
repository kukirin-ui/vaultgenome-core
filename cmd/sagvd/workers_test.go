// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// writeWorkerRegistry helper builds a JSON file on disk for the
// LoadWorkerRegistry tests. Uses the same schema the production
// caller hands us.
func writeWorkerRegistry(t *testing.T, path string, entries []WorkerEntry) {
	t.Helper()
	body, err := json.Marshal(WorkerRegistryFile{Workers: entries})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// randomWorker returns one WorkerEntry with a freshly-generated
// Ed25519 key. Note: ids.KeyID's string form is used as-is, so the
// test exercises the realistic case where operators pick their own
// identifiers.
func randomWorker(t *testing.T, kid string) (WorkerEntry, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return WorkerEntry{
		KeyID:               kid,
		SigningPublicKeyHex: hex.EncodeToString(pub),
	}, pub
}

func TestLoadWorkerRegistry_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workers.json")
	e1, pub1 := randomWorker(t, "worker-alpha")
	e2, pub2 := randomWorker(t, "worker-beta")
	writeWorkerRegistry(t, path, []WorkerEntry{e1, e2})

	resolver, entries, err := LoadWorkerRegistry(path)
	if err != nil {
		t.Fatalf("LoadWorkerRegistry: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries len = %d want 2", len(entries))
	}

	// Resolver must hand back the same public key we wrote.
	vk, err := resolver.Resolve(ids.KeyID("worker-alpha"), keys.PurposeSigningAuthority)
	if err != nil {
		t.Fatalf("Resolve worker-alpha: %v", err)
	}
	if string(vk.PublicKey) != string(pub1) {
		t.Fatal("worker-alpha public key round-trip mismatch")
	}
	vk2, err := resolver.Resolve(ids.KeyID("worker-beta"), keys.PurposeSigningAuthority)
	if err != nil {
		t.Fatalf("Resolve worker-beta: %v", err)
	}
	if string(vk2.PublicKey) != string(pub2) {
		t.Fatal("worker-beta public key round-trip mismatch")
	}
}

func TestLoadWorkerRegistry_EmptyPath(t *testing.T) {
	_, _, err := LoadWorkerRegistry("")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadWorkerRegistry_FileMissing(t *testing.T) {
	_, _, err := LoadWorkerRegistry(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("err = nil")
	}
}

func TestLoadWorkerRegistry_EmptyList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workers.json")
	writeWorkerRegistry(t, path, nil)
	_, _, err := LoadWorkerRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "no entries") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadWorkerRegistry_DuplicateKID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workers.json")
	e, _ := randomWorker(t, "dup")
	writeWorkerRegistry(t, path, []WorkerEntry{e, e})
	_, _, err := LoadWorkerRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate kid") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadWorkerRegistry_BadHex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workers.json")
	writeWorkerRegistry(t, path, []WorkerEntry{{
		KeyID: "bad", SigningPublicKeyHex: "not-hex!",
	}})
	_, _, err := LoadWorkerRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "invalid hex") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadWorkerRegistry_WrongLenHex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workers.json")
	writeWorkerRegistry(t, path, []WorkerEntry{{
		KeyID: "short", SigningPublicKeyHex: "aa",
	}})
	_, _, err := LoadWorkerRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "decode to") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadWorkerRegistry_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workers.json")
	body := `{"workers":[], "typo_field": "x"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := LoadWorkerRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "typo_field") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadWorkerRegistry_MissingKID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workers.json")
	e, _ := randomWorker(t, "")
	writeWorkerRegistry(t, path, []WorkerEntry{e})
	_, _, err := LoadWorkerRegistry(path)
	if err == nil || !strings.Contains(err.Error(), "kid required") {
		t.Fatalf("err = %v", err)
	}
}
