//go:build integration

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Continuity Drill in miniature, with the shipping binaries: a genome
// sealed on the source (acpctl) sits on the destination as an opaque
// bundle; the operator's policy releases its key to the attested
// destination (sagvd crosscloud-restore); the destination restores it by
// itself (acp-bootstrap); the source confirms the restore from the
// destination's TEE-signed receipt (sagvd crosscloud-confirm). Every step
// is on the audit record, and the restored tree is the sealed tree, byte
// for byte.

// confirmResult is what `sagvd crosscloud-confirm` prints.
type confirmResult struct {
	Status string `json:"status"`
	Error  *struct {
		Category string `json:"category"`
		Message  string `json:"message"`
	} `json:"error"`
	KeyID                  string  `json:"key_id"`
	DestinationMeasurement string  `json:"destination_measurement_hex"`
	BundleSHA256           string  `json:"bundle_sha256"`
	PayloadSHA256          string  `json:"payload_sha256"`
	TreeSHA256             string  `json:"tree_sha256"`
	Files                  int     `json:"files"`
	Bytes                  int64   `json:"bytes"`
	RestoreSeconds         float64 `json:"restore_seconds"`
	KeyToRestoredSeconds   float64 `json:"key_to_restored_seconds"`
	MatchedOperatorBundle  bool    `json:"matched_operator_bundle"`
	AuditID                string  `json:"audit_id"`
	AuditChainLength       int     `json:"audit_chain_length"`
	AuditTip               string  `json:"audit_tip"`
}

// fineTuneOutput writes what a LoRA fine-tune leaves behind; the weights
// are random, so nothing about them compresses or repeats, and large
// enough to span several bundle segments.
func fineTuneOutput(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	weights := make([]byte, 3<<20+12345)
	if _, err := rand.Read(weights); err != nil {
		t.Fatal(err)
	}
	for rel, data := range map[string][]byte{
		"adapter_config.json":             []byte(`{"base_model_name_or_path":"Qwen/Qwen2.5-0.5B","r":16,"lora_alpha":32,"target_modules":["q_proj","v_proj"]}`),
		"adapter_model.safetensors":       weights,
		"tokenizer/tokenizer_config.json": []byte(`{"eos_token":"<|im_end|>"}`),
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func treeOf(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// replicate copies a bundle into dir the way an operator's sync should:
// under a temporary name, then renamed, so no half-written bundle is
// ever visible as *.genome.
func replicate(t *testing.T, bundle, dir string) {
	t.Helper()
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".incoming-"+filepath.Base(bundle))
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, filepath.Base(bundle))); err != nil {
		t.Fatal(err)
	}
}

func (x *xcc) confirm(t *testing.T, config string, args ...string) (confirmResult, string, error) {
	t.Helper()
	var res confirmResult
	out, err := runJSON(t, &res, bins.sagvd, append([]string{"crosscloud-confirm", "-config", config}, args...)...)
	return res, out, err
}

// destinationGET calls the destination API as the source does: mTLS and
// the bearer token.
func (x *xcc) destinationGET(t *testing.T, path string) (int, []byte) {
	t.Helper()
	sec := func(p ...string) string { return filepath.Join(append([]string{x.secrets}, p...)...) }
	cert, err := tls.LoadX509KeyPair(sec("acp-compute", "tls", "client.crt"), sec("acp-compute", "tls", "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(sec("shared", "tls", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool,
	}}}
	req, err := http.NewRequest(http.MethodGet, x.endpoint+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+x.token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func TestLiveGenomeDrill_SealReleaseRestoreConfirm(t *testing.T) {
	x := newXCC(t)

	// 1. Seal the fine-tune output. The key goes to a 0600 file; the
	// bundle holds no key.
	adapter := fineTuneOutput(t)
	vault := t.TempDir()
	bundlePath, keyPath := filepath.Join(vault, "gen-0.genome"), filepath.Join(vault, "gen-0.key")
	var sealed struct {
		KeyID         string `json:"key_id"`
		PayloadSHA256 string `json:"payload_sha256"`
		BundleBytes   int64  `json:"bundle_bytes"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "genome", "seal", "--content-dir", adapter,
		"--output", bundlePath, "--key-out", keyPath, "--json")), &sealed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed.KeyID, "genome-") {
		t.Fatalf("seal: key id %q", sealed.KeyID)
	}

	// 2. The destination holds the bundle before any release: opaque
	// without its key.
	root := t.TempDir()
	bundles, restored := filepath.Join(root, "bundles"), filepath.Join(root, "restored")
	if err := os.MkdirAll(bundles, 0o755); err != nil {
		t.Fatal(err)
	}
	replicate(t, bundlePath, bundles)
	destCfg := x.destinationConfig(t, "destination", map[string]any{
		"genome": map[string]any{"bundle_dir": bundles, "restore_dir": restored, "rescan_seconds": 1},
	})
	id := identityOf(t, bins.bootstrap, destCfg)
	x.startDestination(t, destCfg)
	srcCfg := x.sourceConfig(t, id, id["measurement_hex"])

	// Nothing to confirm before a release.
	if res, _, err := x.confirm(t, srcCfg, "-decision-id", "drill-genome-1",
		"-destination-endpoint", x.endpoint, "-bundle", bundlePath); err == nil || res.Error == nil || res.Error.Category != "authority" {
		t.Fatalf("confirm before any release: err=%v result=%+v", err, res)
	}

	// 3. The operator's policy releases the genome key.
	rel, out, err := x.release(t, srcCfg, x.endpoint, "drill-genome-1", sealed.KeyID+":"+keyPath)
	if err != nil || rel.Status != "ok" {
		t.Fatalf("release: %v\n%s", err, out)
	}

	// 4. The destination restores by itself; the source confirms from its
	// signed receipt, checked against the bundle it holds.
	conf, out, err := x.confirm(t, srcCfg, "-decision-id", "drill-genome-1",
		"-destination-endpoint", x.endpoint, "-bundle", bundlePath, "-wait", "30s")
	if err != nil || conf.Status != "ok" {
		t.Fatalf("confirm: %v\n%s", err, out)
	}
	if !conf.MatchedOperatorBundle || conf.KeyID != sealed.KeyID || conf.PayloadSHA256 != sealed.PayloadSHA256 ||
		conf.DestinationMeasurement != id["measurement_hex"] || conf.Files != 3 {
		t.Fatalf("confirmation: %+v", conf)
	}
	t.Logf("drill: %d files, %d bytes restored in %.3fs (key to restored %.3fs); tree %s",
		conf.Files, conf.Bytes, conf.RestoreSeconds, conf.KeyToRestoredSeconds, conf.TreeSHA256)

	// 5. The restored tree is the sealed tree, and acpctl agrees with the
	// key the operator holds.
	target := filepath.Join(restored, sealed.KeyID)
	want, got := treeOf(t, adapter), treeOf(t, target)
	if len(want) != len(got) {
		t.Fatalf("restored %d files, sealed %d", len(got), len(want))
	}
	for p, data := range want {
		if !bytes.Equal(got[p], data) {
			t.Fatalf("restored %s differs from the sealed file", p)
		}
	}
	var verified struct {
		OK            bool   `json:"ok"`
		Authenticated bool   `json:"authenticated"`
		TreeSHA256    string `json:"tree_sha256"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "genome", "verify", "--bundle", bundlePath,
		"--key-file", keyPath, "--restored", target, "--json")), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.OK || !verified.Authenticated || verified.TreeSHA256 != conf.TreeSHA256 {
		t.Fatalf("acpctl genome verify: %+v, confirmed tree %s", verified, conf.TreeSHA256)
	}

	// 6. On record: handshake, attestation, release, restore confirmed —
	// and the log verifies to the tip the confirmation reported.
	if ok, events, tip := x.auditVerify(t); !ok || events != 4 || tip != conf.AuditTip {
		t.Fatalf("audit log: ok=%v events=%d tip=%s, confirm tip %s", ok, events, tip, conf.AuditTip)
	}

	// 7. The destination's own account, over its authenticated API.
	code, body := x.destinationGET(t, "/v1/genome/restores")
	if code != http.StatusOK || !strings.Contains(string(body), `"state":"restored"`) || !strings.Contains(string(body), sealed.KeyID) {
		t.Fatalf("GET /v1/genome/restores: %d %s", code, body)
	}
	if n := len(x.destLog("genome restored")); n != 1 {
		t.Fatalf("destination logged %d restores, want 1", n)
	}
	if n := len(x.destLog("genome key erased after restore")); n != 1 {
		t.Fatalf("destination erased %d keys after the restore, want 1", n)
	}

	// 8. A confirmation cannot be claimed for a genome the operator does
	// not hold: a different bundle is refused, and nothing is recorded.
	other := filepath.Join(vault, "other.genome")
	acpctl(t, "genome", "seal", "--content-dir", fineTuneOutput(t), "--output", other, "--key-out", filepath.Join(vault, "other.key"))
	res, _, err := x.confirm(t, srcCfg, "-decision-id", "drill-genome-1", "-destination-endpoint", x.endpoint, "-bundle", other)
	if err == nil || res.Error == nil || res.Error.Category != "authority" {
		t.Fatalf("confirm with a genome that was not released: err=%v result=%+v", err, res)
	}
	if ok, events, _ := x.auditVerify(t); !ok || events != 4 {
		t.Fatalf("a refused confirmation changed the audit log: ok=%v events=%d", ok, events)
	}
}

// modelGenomeDir writes a model genome as the vg_genome worker does —
// genome.json, fixtures fx-000/fx-001 with float32 references, an
// adapter — and returns it with the gate response a model that came back
// right would give.
func modelGenomeDir(t *testing.T, fx0, fx1 string) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	fixtures, err := json.Marshal(map[string]any{"schema": "vault-genome/lora-fixtures/v1", "fixtures": []map[string]any{
		{"id": "fx-000", "critical": true, "expected": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": fx0}},
		{"id": "fx-001", "expected": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": fx1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(fixtures)
	genome, err := json.Marshal(map[string]any{
		"schema": "vault-genome/lora-genome/v1",
		"base": map[string]any{"name": "Qwen/Qwen2.5-0.5B-Instruct", "manifest": map[string]any{
			"files": map[string]string{"model.safetensors": "sha256:00"}, "digest": "sha256:base"}},
		"adapter":  map[string]any{"dir": "adapter", "weights_sha256": "sha256:cd"},
		"fixtures": map[string]any{"file": "fixtures.json", "sha256": "sha256:" + hex.EncodeToString(sum[:])},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"genome.json": genome, "fixtures.json": fixtures, "adapter/adapter_model.safetensors": []byte("lora weights"),
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := json.Marshal(map[string]any{"outputs": map[string]any{
		"fx-000": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": fx0},
		"fx-001": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": fx1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return dir, resp
}

// The destination proves the restored model works before it signs: its
// gate recomputes the sealed fixtures and the verdict is in the receipt.
// The source can require a passing verdict, and a model that misses its
// references is refused on the record's terms.
func TestLiveGenomeDrill_GatedModel(t *testing.T) {
	x := newXCC(t)
	vault := t.TempDir()
	good, _ := modelGenomeDir(t, "AADAPwAAAMA=", "AACAPgAAQEA=") // [1.5, -2], [0.25, 3]
	acpctl(t, "genome", "seal", "--content-dir", good, "--output", filepath.Join(vault, "good.genome"), "--key-out", filepath.Join(vault, "good.key"))
	var goodID struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "genome", "inspect", "--bundle", filepath.Join(vault, "good.genome"), "--json")), &goodID); err != nil {
		t.Fatal(err)
	}

	// The gate backend answers as a restored model on this hardware
	// would: the references for the good genome, far off for any other.
	_, rightResp := modelGenomeDir(t, "AADAPwAAAMA=", "AACAPgAAQEA=")
	right := filepath.Join(vault, "right.json")
	wrong := filepath.Join(vault, "wrong.json")
	if err := os.WriteFile(right, rightResp, 0o644); err != nil {
		t.Fatal(err)
	}
	_, wrongResp := modelGenomeDir(t, "AAAQQQAAAMA=", "AACAPgAAQEA=") // fx-000 = [9, -2]
	if err := os.WriteFile(wrong, wrongResp, 0o644); err != nil {
		t.Fatal(err)
	}
	door := filepath.Join(vault, "door.sh")
	script := "#!/bin/sh\ncat >/dev/null\nif grep -q '" + goodID.KeyID + "' <<EOF\n$1\nEOF\nthen cat " + right + "\nelse cat " + wrong + "\nfi\n"
	if err := os.WriteFile(door, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	bundles, restored := filepath.Join(root, "bundles"), filepath.Join(root, "restored")
	if err := os.MkdirAll(bundles, 0o755); err != nil {
		t.Fatal(err)
	}
	replicate(t, filepath.Join(vault, "good.genome"), bundles)
	destCfg := x.destinationConfig(t, "destination", map[string]any{
		"genome": map[string]any{"bundle_dir": bundles, "restore_dir": restored, "rescan_seconds": 1,
			"gate": map[string]any{"command": []string{door, "{genome}"}, "atol": 1e-3, "rtol": 1e-3, "required": true}},
	})
	id := identityOf(t, bins.bootstrap, destCfg)
	x.startDestination(t, destCfg)
	srcCfg := x.sourceConfig(t, id, id["measurement_hex"])

	if rel, out, err := x.release(t, srcCfg, x.endpoint, "gated-1", goodID.KeyID+":"+filepath.Join(vault, "good.key")); err != nil || rel.Status != "ok" {
		t.Fatalf("release: %v\n%s", err, out)
	}
	var conf struct {
		confirmResult
		Gate *struct {
			Level    string `json:"level"`
			Door     string `json:"door"`
			Fixtures int    `json:"fixtures"`
		} `json:"gate"`
	}
	out, err := runJSON(t, &conf, bins.sagvd, "crosscloud-confirm", "-config", srcCfg, "-decision-id", "gated-1",
		"-destination-endpoint", x.endpoint, "-bundle", filepath.Join(vault, "good.genome"), "-require-gate", "EQUIVALENT", "-wait", "30s")
	if err != nil || conf.Status != "ok" || conf.Gate == nil || conf.Gate.Level != "EXACT" || conf.Gate.Fixtures != 2 {
		t.Fatalf("confirm with a required gate: %v\n%s", err, out)
	}
	if n := len(x.destLog("genome gated")); n != 1 {
		t.Fatalf("destination logged %d gate runs, want 1", n)
	}

	// A second genome whose restored model misses its references: signed
	// for as FAIL, and a source that requires a passing gate refuses it.
	bad, _ := modelGenomeDir(t, "AADAPwAAAMA=", "AACAPgAAQEA=")
	if err := os.WriteFile(filepath.Join(bad, "data.txt"), []byte("another fine-tune"), 0o644); err != nil {
		t.Fatal(err)
	}
	acpctl(t, "genome", "seal", "--content-dir", bad, "--output", filepath.Join(vault, "bad.genome"), "--key-out", filepath.Join(vault, "bad.key"))
	var badID struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "genome", "inspect", "--bundle", filepath.Join(vault, "bad.genome"), "--json")), &badID); err != nil {
		t.Fatal(err)
	}
	replicate(t, filepath.Join(vault, "bad.genome"), bundles)
	if rel, out, err := x.release(t, srcCfg, x.endpoint, "gated-2", badID.KeyID+":"+filepath.Join(vault, "bad.key")); err != nil || rel.Status != "ok" {
		t.Fatalf("release: %v\n%s", err, out)
	}
	res, _, err := x.confirm(t, srcCfg, "-decision-id", "gated-2", "-destination-endpoint", x.endpoint,
		"-bundle", filepath.Join(vault, "bad.genome"), "-require-gate", "EQUIVALENT", "-wait", "30s")
	if err == nil || res.Error == nil || !strings.Contains(res.Error.Message, "gate verdict FAIL") {
		t.Fatalf("confirm of a model that failed its gate: err=%v result=%+v", err, res)
	}
	code, body := x.destinationGET(t, "/v1/genome/restores")
	if code != http.StatusOK || !strings.Contains(string(body), `"state":"gate_failed"`) {
		t.Fatalf("destination does not report the failed gate: %d %s", code, body)
	}
	// On record: two releases (3 events each) and one confirmation.
	if ok, events, _ := x.auditVerify(t); !ok || events != 7 {
		t.Fatalf("audit log: ok=%v events=%d, want 7", ok, events)
	}
}

// Key escrow: the sealing machine keeps nothing that opens the bundle. It
// encapsulates the key to the release authority's escrow key (published by
// `sagvd identity`); only the authority opens the envelope, and only to
// release the key to an attested destination.
func TestLiveGenomeDrill_EscrowedKey(t *testing.T) {
	x := newXCC(t)
	escrowKey := filepath.Join(x.dir, "escrow.key")
	acpctl(t, "escrow", "keygen", "--out", escrowKey, "--pub", filepath.Join(x.dir, "escrow-local.pem"))

	root := t.TempDir()
	bundles, restored := filepath.Join(root, "bundles"), filepath.Join(root, "restored")
	if err := os.MkdirAll(bundles, 0o755); err != nil {
		t.Fatal(err)
	}
	destCfg := x.destinationConfig(t, "destination", map[string]any{
		"genome": map[string]any{"bundle_dir": bundles, "restore_dir": restored, "rescan_seconds": 1},
	})
	id := identityOf(t, bins.bootstrap, destCfg)
	x.startDestination(t, destCfg)
	srcCfg := x.sourceConfig(t, id, id["measurement_hex"])
	raw, err := os.ReadFile(srcCfg)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c["crosscloud"].(map[string]any)["key_escrow_path"] = escrowKey
	srcCfg = writeJSON(t, "sagvd-escrow.json", c)

	// The sealer pins the escrow key the authority publishes.
	authority := identityOf(t, bins.sagvd, srcCfg)
	if authority["key_escrow_public_key_pem"] == "" {
		t.Fatalf("sagvd identity does not publish the escrow key: %v", authority)
	}
	pinned := filepath.Join(t.TempDir(), "escrow.pem")
	if err := os.WriteFile(pinned, []byte(authority["key_escrow_public_key_pem"]), 0o644); err != nil {
		t.Fatal(err)
	}

	adapter := fineTuneOutput(t)
	vault := t.TempDir()
	bundlePath := filepath.Join(vault, "gen-0.genome")
	var sealed struct {
		KeyID      string `json:"key_id"`
		EscrowFile string `json:"escrow_file"`
		EscrowKey  string `json:"escrow_key"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "genome", "seal", "--content-dir", adapter, "--output", bundlePath,
		"--escrow-to", pinned, "--json")), &sealed); err != nil {
		t.Fatal(err)
	}
	if sealed.EscrowKey != authority["key_escrow_tag"] {
		t.Fatalf("sealed to escrow key %s, the authority publishes %s", sealed.EscrowKey, authority["key_escrow_tag"])
	}
	entries, err := os.ReadDir(vault)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("the sealer kept %d files; want only the bundle and its escrow envelope", len(entries))
	}
	replicate(t, bundlePath, bundles)

	rel, out, err := runRelease(t, srcCfg, x.endpoint, "escrow-1", "-key-escrow", sealed.EscrowFile)
	if err != nil || rel.Status != "ok" {
		t.Fatalf("release from escrow: %v\n%s", err, out)
	}
	conf, out, err := x.confirm(t, srcCfg, "-decision-id", "escrow-1", "-destination-endpoint", x.endpoint, "-bundle", bundlePath, "-wait", "30s")
	if err != nil || conf.Status != "ok" || !conf.MatchedOperatorBundle {
		t.Fatalf("confirm: %v\n%s", err, out)
	}
	want, got := treeOf(t, adapter), treeOf(t, filepath.Join(restored, sealed.KeyID))
	for p, data := range want {
		if !bytes.Equal(got[p], data) {
			t.Fatalf("restored %s differs", p)
		}
	}
}

// runRelease runs `sagvd crosscloud-restore` with explicit key arguments.
func runRelease(t *testing.T, config, endpoint, decision string, keyArgs ...string) (restoreResult, string, error) {
	t.Helper()
	args := append([]string{"crosscloud-restore", "-config", config, "-decision-id", decision,
		"-destination-kind", "simulated", "-destination-endpoint", endpoint}, keyArgs...)
	var res restoreResult
	out, err := runJSON(t, &res, bins.sagvd, args...)
	return res, out, err
}
