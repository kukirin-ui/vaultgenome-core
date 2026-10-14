// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package safetar

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

type entry struct {
	hdr  tar.Header
	body string
}

func regular(name, body string) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644}, body: body}
}

func build(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.hdr
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtract_WritesNestedRegularFiles(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "new", "target") // created by Extract
	payload := build(t,
		regular("a.txt", "alpha"),
		regular("dir/b.txt", "bravo"),
		regular("dir/deeper/c.bin", "\x00\x01charlie"),
		regular("..leading-dots-is-a-legal-name", "delta"),
	)
	n, err := Extract(payload, dst)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	want := map[string]string{
		"a.txt":                          "alpha",
		"dir/b.txt":                      "bravo",
		"dir/deeper/c.bin":               "\x00\x01charlie",
		"..leading-dots-is-a-legal-name": "delta",
	}
	var total int64
	for rel, body := range want {
		got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel)))
		if err != nil || string(got) != body {
			t.Fatalf("%s: got %q (%v), want %q", rel, got, err, body)
		}
		total += int64(len(body))
	}
	if n != total {
		t.Fatalf("Extract reported %d bytes, want %d", n, total)
	}
}

func TestExtract_OverwritesExistingFile(t *testing.T) {
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, "f"), []byte("a much longer previous body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(build(t, regular("f", "new")), dst); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "f")); string(got) != "new" {
		t.Fatalf("existing file not truncated: %q", got)
	}
}

func TestExtract_RefusesNonLocalNames(t *testing.T) {
	for _, name := range []string{"../escape", "a/../../escape", "/tmp/escape", "", "."} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dst := filepath.Join(parent, "target")
			if _, err := Extract(build(t, regular(name, "x")), dst); err == nil {
				t.Fatalf("Extract accepted entry name %q", name)
			}
			if _, err := os.Stat(filepath.Join(parent, "escape")); err == nil {
				t.Fatal("a file was written outside the target")
			}
		})
	}
}

// A symlink already inside the target must not become a way out of it,
// whether the entry writes through it directly or creates directories
// beneath it.
func TestExtract_RefusesSymlinkEscape(t *testing.T) {
	for _, name := range []string{"link/pwned", "link/deeper/pwned"} {
		t.Run(name, func(t *testing.T) {
			dst, outside := t.TempDir(), t.TempDir()
			if err := os.Symlink(outside, filepath.Join(dst, "link")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if _, err := Extract(build(t, regular(name, "x")), dst); err == nil {
				t.Fatalf("Extract wrote %q through a symlink in the target", name)
			}
			entries, _ := os.ReadDir(outside)
			if len(entries) != 0 {
				t.Fatalf("files appeared outside the target: %v", entries)
			}
		})
	}
}

// A symlink inside the target that stays inside the target is ordinary
// structure and may be written through.
func TestExtract_AllowsSymlinkThatStaysInside(t *testing.T) {
	dst := t.TempDir()
	if err := os.Mkdir(filepath.Join(dst, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dst, "alias")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Extract(build(t, regular("alias/f", "inside")), dst); err != nil {
		t.Fatalf("Extract through an in-root symlink: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "real", "f")); string(got) != "inside" {
		t.Fatalf("got %q, want %q", got, "inside")
	}
}

func TestExtract_SkipsNonRegularEntries(t *testing.T) {
	dst := t.TempDir()
	payload := build(t,
		entry{hdr: tar.Header{Name: "sym", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}},
		entry{hdr: tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"}},
		entry{hdr: tar.Header{Name: "dir", Typeflag: tar.TypeDir, Mode: 0o777}},
		entry{hdr: tar.Header{Name: "fifo", Typeflag: tar.TypeFifo, Mode: 0o644}},
		regular("ok", "fine"),
	)
	n, err := Extract(payload, dst)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if n != int64(len("fine")) {
		t.Fatalf("Extract wrote %d bytes, want %d", n, len("fine"))
	}
	for _, name := range []string{"sym", "hard", "dir", "fifo"} {
		if _, err := os.Lstat(filepath.Join(dst, name)); err == nil {
			t.Fatalf("non-regular entry %q was materialised", name)
		}
	}
}

func TestExtract_RejectsCorruptArchive(t *testing.T) {
	good := build(t, regular("a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), regular("b", "bbbb"))
	for name, payload := range map[string][]byte{
		"truncated body": good[:512+10],
		"garbage":        bytes.Repeat([]byte{0xFF}, 1024),
	} {
		if _, err := Extract(payload, t.TempDir()); err == nil {
			t.Errorf("Extract(%s) = nil error, want failure", name)
		}
	}
}

func TestExtract_FailsWhenTargetIsAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(build(t, regular("a", "x")), file); err == nil {
		t.Fatal("Extract into a regular file succeeded")
	}
}

func TestLocalName(t *testing.T) {
	for name, wantOK := range map[string]bool{
		"a":            true,
		"a/b/c":        true,
		"a/./b":        true,
		"..dots":       true,
		"a/b/../c":     true, // stays inside
		"../a":         false,
		"a/../../b":    false,
		"/abs":         false,
		"":             false,
		".":            false,
		"a/b/../../..": false,
	} {
		_, err := LocalName(name)
		if (err == nil) != wantOK {
			t.Errorf("LocalName(%q) err=%v, want ok=%v", name, err, wantOK)
		}
	}
}
