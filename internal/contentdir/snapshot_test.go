// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package contentdir

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTree creates files (relative path → contents) under a new dir.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// readTree returns every regular file under dir as relative path → contents.
func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// craftTar builds a tar with the given entries, for hostile-input tests.
func craftTar(t *testing.T, entries ...tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		h := h
		body := []byte("payload")
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var sample = map[string]string{
	"adapter_config.json":         `{"r":8,"alpha":16}`,
	"adapters.safetensors":        strings.Repeat("\x00\x01\x02weights", 512),
	"tokenizer/tokenizer.json":    `{"vocab":{}}`,
	"tokenizer/special/eos.txt":   "</s>",
	"checkpoints/step-100/opt.pt": strings.Repeat("o", 3000),
}

func TestCaptureRestore_RoundTripIsByteExact(t *testing.T) {
	src := writeTree(t, sample)
	snap, payload, err := CapturePayload(src)
	if err != nil {
		t.Fatalf("CapturePayload: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "restored")
	n, err := Restore(payload, dst)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != snap.TotalBytes {
		t.Fatalf("Restore wrote %d bytes, snapshot says %d", n, snap.TotalBytes)
	}
	got := readTree(t, dst)
	if len(got) != len(sample) {
		t.Fatalf("restored %d files, want %d", len(got), len(sample))
	}
	for rel, want := range sample {
		if got[rel] != want {
			t.Fatalf("restored %s differs from the original", rel)
		}
	}
}

// The payload must not depend on where the directory lives, when its
// files were written, or their permission bits — only on content and
// relative paths — so the sealed address is reproducible across hosts.
func TestCapture_DeterministicAcrossPathsClocksAndModes(t *testing.T) {
	a := writeTree(t, sample)
	b := writeTree(t, sample)
	past := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := filepath.WalkDir(b, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if err := os.Chmod(p, 0o755); err != nil {
			return err
		}
		return os.Chtimes(p, past, past)
	}); err != nil {
		t.Fatal(err)
	}

	snapA, payloadA, err := CapturePayload(a)
	if err != nil {
		t.Fatal(err)
	}
	snapB, payloadB, err := CapturePayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payloadA, payloadB) || snapA.PayloadSHA256 != snapB.PayloadSHA256 {
		t.Fatalf("same content, different payload: %s vs %s", snapA.PayloadSHA256, snapB.PayloadSHA256)
	}
	_, again, err := CapturePayload(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payloadA, again) {
		t.Fatal("capturing the same directory twice produced different payloads")
	}
	sum := sha256.Sum256(payloadA)
	if snapA.PayloadSHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("PayloadSHA256 %s does not hash the returned payload", snapA.PayloadSHA256)
	}
}

func TestCapture_ComponentsAreSortedWithCorrectDigests(t *testing.T) {
	src := writeTree(t, sample)
	snap, _, err := CapturePayload(src)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for i, c := range snap.Components {
		if i > 0 && snap.Components[i-1].Path >= c.Path {
			t.Fatalf("components not strictly sorted at %d: %q then %q", i, snap.Components[i-1].Path, c.Path)
		}
		body, ok := sample[c.Path]
		if !ok {
			t.Fatalf("unexpected component %q", c.Path)
		}
		sum := sha256.Sum256([]byte(body))
		if c.Digest != "sha256:"+hex.EncodeToString(sum[:]) || c.Size != int64(len(body)) {
			t.Fatalf("component %s: digest %s size %d do not match its content", c.Path, c.Digest, c.Size)
		}
		total += c.Size
	}
	if len(snap.Components) != len(sample) || snap.TotalBytes != total {
		t.Fatalf("got %d components / %d bytes, want %d / %d", len(snap.Components), snap.TotalBytes, len(sample), total)
	}
	if snap.SourceDir != src {
		abs, _ := filepath.Abs(src)
		if snap.SourceDir != abs {
			t.Fatalf("SourceDir %q, want %q", snap.SourceDir, abs)
		}
	}
}

// Only regular files are captured: a symlink in the source — which could
// point anywhere on the host — is not followed and not recorded.
func TestCapture_IgnoresSymlinks(t *testing.T) {
	src := writeTree(t, map[string]string{"model.bin": "weights"})
	secret := writeTree(t, map[string]string{"secret.txt": "host secret"})
	if err := os.Symlink(filepath.Join(secret, "secret.txt"), filepath.Join(src, "link-to-file")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(src, "link-to-dir")); err != nil {
		t.Fatal(err)
	}
	snap, payload, err := CapturePayload(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Components) != 1 || snap.Components[0].Path != "model.bin" {
		t.Fatalf("components %+v, want only model.bin", snap.Components)
	}
	if bytes.Contains(payload, []byte("host secret")) {
		t.Fatal("payload contains data reached through a symlink")
	}
}

func TestCapture_RejectsUnusableSources(t *testing.T) {
	file := filepath.Join(writeTree(t, map[string]string{"f": "x"}), "f")
	for name, src := range map[string]string{
		"empty directory": t.TempDir(),
		"regular file":    file,
		"missing path":    filepath.Join(t.TempDir(), "nope"),
	} {
		if _, _, err := CapturePayload(src); err == nil {
			t.Errorf("CapturePayload(%s) = nil error, want refusal", name)
		}
	}
}

// A hostile payload must not write outside the target directory, whether
// by relative traversal or an absolute path.
func TestRestore_RefusesPathTraversal(t *testing.T) {
	for _, name := range []string{"../escape.txt", "a/../../escape.txt", "/tmp/escape.txt"} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dst := filepath.Join(parent, "target")
			payload := craftTar(t, tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644})
			if _, err := Restore(payload, dst); err == nil {
				t.Fatalf("Restore accepted entry %q", name)
			}
			if _, err := os.Stat(filepath.Join(parent, "escape.txt")); err == nil {
				t.Fatal("a file was written outside the target directory")
			}
		})
	}
}

// A symlink already present in the target directory must not become a
// way out of it: an entry "link/pwned" where target/link points elsewhere
// has to be refused, and nothing may appear at the link's destination.
func TestRestore_RefusesSymlinkEscape(t *testing.T) {
	dst := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dst, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	payload := craftTar(t, tar.Header{Name: "link/pwned.txt", Typeflag: tar.TypeReg, Mode: 0o644})
	if _, err := Restore(payload, dst); err == nil {
		t.Fatal("Restore wrote through a symlink in the target directory")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); err == nil {
		t.Fatal("a file was written outside the target directory via a symlink")
	}
}

// Non-regular tar entries (symlinks, hard links, devices) are never
// materialised.
func TestRestore_SkipsNonRegularEntries(t *testing.T) {
	dst := t.TempDir()
	payload := craftTar(t,
		tar.Header{Name: "evil-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777},
		tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"},
		tar.Header{Name: "ok.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	)
	n, err := Restore(payload, dst)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != int64(len("payload")) {
		t.Fatalf("Restore wrote %d bytes, want %d", n, len("payload"))
	}
	for _, name := range []string{"evil-link", "hard"} {
		if _, err := os.Lstat(filepath.Join(dst, name)); err == nil {
			t.Fatalf("non-regular entry %q was materialised", name)
		}
	}
	if got := readTree(t, dst); got["ok.txt"] != "payload" || len(got) != 1 {
		t.Fatalf("restored tree %v, want only ok.txt", got)
	}
}

func TestRestore_RejectsCorruptPayload(t *testing.T) {
	_, good, err := CapturePayload(writeTree(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{
		"truncated": good[:len(good)/3],
		"garbage":   bytes.Repeat([]byte{0xFF}, 1024),
	} {
		if _, err := Restore(payload, t.TempDir()); err == nil {
			t.Errorf("Restore(%s payload) = nil error, want failure", name)
		}
	}
}
