// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// TestEncodeDecodeVault — envelope round-trip + malformed-input handling.
func TestEncodeDecodeVault_RoundTrip(t *testing.T) {
	t.Parallel()
	env := VaultEnvelope{
		Format:                      "vault-genome-v1",
		TEEProvider:                 "simulated",
		AAD:                         []byte("session=alpha"),
		SimulatedWorkloadDescriptor: []byte("test-workload"),
	}
	sealed := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	blob, err := EncodeVault(env, sealed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	gotEnv, gotSealed, err := DecodeVault(blob)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotEnv.TEEProvider != "simulated" {
		t.Errorf("provider mismatch: got %q want %q", gotEnv.TEEProvider, "simulated")
	}
	if !bytes.Equal(gotSealed, sealed) {
		t.Errorf("sealed bytes mismatch")
	}
	if gotEnv.SealedAt == 0 {
		t.Errorf("expected SealedAt to be auto-populated")
	}
}

func TestDecodeVault_RejectsBadMagic(t *testing.T) {
	t.Parallel()
	bogus := append([]byte("NOT-A-VAULT-AT-ALL"), make([]byte, 100)...)
	_, _, err := DecodeVault(bogus)
	if err == nil || !strings.Contains(err.Error(), "magic mismatch") {
		t.Errorf("expected magic mismatch error, got %v", err)
	}
}

func TestDecodeVault_RejectsTruncated(t *testing.T) {
	t.Parallel()
	_, _, err := DecodeVault([]byte("VG-VAULT-01"))
	if err == nil {
		t.Errorf("expected too-short error")
	}
}

// TestRecoverCmd_SimulatedFullCycle — seal a payload using the simulated
// backend, write the envelope to disk, run `acpctl recover`, and check
// the recovered plaintext matches the original.
func TestRecoverCmd_SimulatedFullCycle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")
	outPath := filepath.Join(dir, "recovered.bin")

	plaintext := []byte("vault genome integration payload — secret material")
	aad := []byte("session=alpha;manifest=M;component=C")
	descriptor := []byte("acpctl-recover-test-workload-v1")
	seed := bytes.Repeat([]byte{0xAA}, shared_crypto.Ed25519SeedSize)

	// Seal using the simulated TEE.
	sim, err := tee.NewSimulated(descriptor, seed)
	if err != nil {
		t.Fatalf("NewSimulated: %v", err)
	}
	sealed, err := sim.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	env := VaultEnvelope{
		TEEProvider:                 "simulated",
		AAD:                         aad,
		SimulatedWorkloadDescriptor: descriptor,
		SimulatedSeed:               seed,
	}
	blob, err := EncodeVault(env, sealed)
	if err != nil {
		t.Fatalf("EncodeVault: %v", err)
	}
	if err := os.WriteFile(vaultPath, blob, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	rc := recoverCmd([]string{"--vault", vaultPath, "--output", outPath}, stdout, stderr)
	if rc != 0 {
		t.Fatalf("recoverCmd rc=%d stderr=%q stdout=%q", rc, stderr.String(), stdout.String())
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch:\n got=%q\nwant=%q", got, plaintext)
	}

	// Output file mode must be 0600 (operator secret).
	st, _ := os.Stat(outPath)
	if mode := st.Mode().Perm(); mode != 0600 {
		t.Errorf("output mode %o, want 0600", mode)
	}
}

func TestRecoverCmd_DryRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")

	descriptor := []byte("dry-run-workload")
	seed := bytes.Repeat([]byte{0xBB}, shared_crypto.Ed25519SeedSize)
	sim, _ := tee.NewSimulated(descriptor, seed)
	sealed, _ := sim.Seal([]byte("payload"), []byte("aad"))

	env := VaultEnvelope{
		TEEProvider:                 "simulated",
		AAD:                         []byte("aad"),
		SimulatedWorkloadDescriptor: descriptor,
		SimulatedSeed:               seed,
	}
	blob, _ := EncodeVault(env, sealed)
	_ = os.WriteFile(vaultPath, blob, 0600)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	rc := recoverCmd([]string{"--vault", vaultPath, "--dry-run", "--json"}, stdout, stderr)
	if rc != 0 {
		t.Fatalf("dry-run rc=%d stderr=%q", rc, stderr.String())
	}

	var result dryRunResult
	if err := json.NewDecoder(stdout).Decode(&result); err != nil {
		t.Fatalf("decode JSON output: %v\noutput: %q", err, stdout.String())
	}
	if !result.OK || result.Provider != "simulated" || !result.Available {
		t.Errorf("dry-run JSON: %+v", result)
	}
	if result.SealedBytes < 1 {
		t.Errorf("dry-run JSON: sealed_bytes=%d", result.SealedBytes)
	}
}

func TestRecoverCmd_RefusesOverwriteWithoutForce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")
	outPath := filepath.Join(dir, "existing.bin")

	descriptor := []byte("overwrite-workload")
	seed := bytes.Repeat([]byte{0xCC}, shared_crypto.Ed25519SeedSize)
	sim, _ := tee.NewSimulated(descriptor, seed)
	sealed, _ := sim.Seal([]byte("payload"), nil)

	env := VaultEnvelope{
		TEEProvider:                 "simulated",
		SimulatedWorkloadDescriptor: descriptor,
		SimulatedSeed:               seed,
	}
	blob, _ := EncodeVault(env, sealed)
	_ = os.WriteFile(vaultPath, blob, 0600)
	_ = os.WriteFile(outPath, []byte("existing"), 0600)

	stderr := &bytes.Buffer{}
	rc := recoverCmd([]string{"--vault", vaultPath, "--output", outPath}, &bytes.Buffer{}, stderr)
	if rc == 0 {
		t.Fatal("expected non-zero rc when output exists without --force")
	}
	if !strings.Contains(stderr.String(), "refusing to overwrite") {
		t.Errorf("stderr should educate about --force; got %q", stderr.String())
	}

	// With --force, the same recover succeeds.
	rc = recoverCmd([]string{"--vault", vaultPath, "--output", outPath, "--force"}, &bytes.Buffer{}, stderr)
	if rc != 0 {
		t.Errorf("--force did not allow overwrite: rc=%d stderr=%q", rc, stderr.String())
	}
}

func TestRecoverCmd_TamperedAADRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")
	outPath := filepath.Join(dir, "out.bin")

	descriptor := []byte("aad-test-workload")
	seed := bytes.Repeat([]byte{0xDD}, shared_crypto.Ed25519SeedSize)
	sim, _ := tee.NewSimulated(descriptor, seed)
	sealed, _ := sim.Seal([]byte("payload"), []byte("aad-correct"))

	env := VaultEnvelope{
		TEEProvider:                 "simulated",
		AAD:                         []byte("aad-WRONG"), // <- tampered envelope AAD
		SimulatedWorkloadDescriptor: descriptor,
		SimulatedSeed:               seed,
	}
	blob, _ := EncodeVault(env, sealed)
	_ = os.WriteFile(vaultPath, blob, 0600)

	stderr := &bytes.Buffer{}
	rc := recoverCmd([]string{"--vault", vaultPath, "--output", outPath}, &bytes.Buffer{}, stderr)
	if rc == 0 {
		t.Fatal("expected unseal failure with mismatched AAD")
	}
	if rc != 4 {
		t.Errorf("expected exit code 4 (unseal failure); got %d", rc)
	}
	if !strings.Contains(stderr.String(), "unseal") {
		t.Errorf("stderr should mention unseal; got %q", stderr.String())
	}
}

func TestRecoverCmd_RejectsUnknownProvider(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")

	env := VaultEnvelope{TEEProvider: "fictional-tee"}
	blob, _ := EncodeVault(env, []byte("doesnt-matter"))
	_ = os.WriteFile(vaultPath, blob, 0600)

	stderr := &bytes.Buffer{}
	rc := recoverCmd([]string{"--vault", vaultPath, "--output", "/tmp/out"}, &bytes.Buffer{}, stderr)
	if rc == 0 {
		t.Fatal("expected non-zero rc for unknown provider")
	}
	if !strings.Contains(stderr.String(), "unknown provider") {
		t.Errorf("stderr should mention unknown provider; got %q", stderr.String())
	}
}

func TestRecoverCmd_RejectsMissingVaultFlag(t *testing.T) {
	t.Parallel()
	stderr := &bytes.Buffer{}
	rc := recoverCmd([]string{"--output", "/tmp/out"}, &bytes.Buffer{}, stderr)
	if rc != 2 {
		t.Errorf("expected exit 2 for missing --vault; got %d", rc)
	}
	if !strings.Contains(stderr.String(), "--vault is required") {
		t.Errorf("stderr should educate about missing flag; got %q", stderr.String())
	}
}

func TestRecoverCmd_RejectsMissingOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")
	_ = os.WriteFile(vaultPath, []byte("fake"), 0600)

	stderr := &bytes.Buffer{}
	rc := recoverCmd([]string{"--vault", vaultPath}, &bytes.Buffer{}, stderr)
	if rc != 2 {
		t.Errorf("expected exit 2 for missing --output; got %d", rc)
	}
}

func TestRecoverCmd_DryRunNonexistentVault(t *testing.T) {
	t.Parallel()
	stderr := &bytes.Buffer{}
	rc := recoverCmd([]string{"--vault", "/nonexistent/path", "--dry-run"}, &bytes.Buffer{}, stderr)
	if rc == 0 {
		t.Fatal("expected error for nonexistent vault")
	}
	if !strings.Contains(stderr.String(), "read vault") {
		t.Errorf("stderr should explain failure; got %q", stderr.String())
	}
}

func TestRecoverCmd_JSONOutputOnSuccess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.vault")
	outPath := filepath.Join(dir, "out.bin")

	descriptor := []byte("json-output-workload")
	seed := bytes.Repeat([]byte{0xEE}, shared_crypto.Ed25519SeedSize)
	sim, _ := tee.NewSimulated(descriptor, seed)
	plaintext := []byte("json-test-payload")
	sealed, _ := sim.Seal(plaintext, nil)

	env := VaultEnvelope{
		TEEProvider:                 "simulated",
		SimulatedWorkloadDescriptor: descriptor,
		SimulatedSeed:               seed,
	}
	blob, _ := EncodeVault(env, sealed)
	_ = os.WriteFile(vaultPath, blob, 0600)

	stdout := &bytes.Buffer{}
	rc := recoverCmd([]string{"--vault", vaultPath, "--output", outPath, "--json"}, stdout, &bytes.Buffer{})
	if rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	var result recoverResult
	if err := json.NewDecoder(stdout).Decode(&result); err != nil {
		t.Fatalf("decode: %v\nstdout=%q", err, stdout.String())
	}
	if !result.OK || result.PlaintextBytes != len(plaintext) || result.Output != outPath {
		t.Errorf("JSON result: %+v", result)
	}
}
