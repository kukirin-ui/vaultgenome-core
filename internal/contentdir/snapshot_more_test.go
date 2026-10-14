// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package contentdir

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var errSinkDown = errors.New("sink unavailable")

// hookWriter is a payload sink a test can make fail on a chosen write,
// or act on a write before it lands: the tar header of an entry is one
// write and its content the next, so a test can place a failure, or a
// change on disk, at an exact point of the capture.
type hookWriter struct {
	fail    func(p []byte) bool
	onWrite func(p []byte)
}

func (h *hookWriter) Write(p []byte) (int, error) {
	if h.onWrite != nil {
		h.onWrite(p)
	}
	if h.fail != nil && h.fail(p) {
		return 0, errSinkDown
	}
	return len(p), nil
}

// isHeaderOf reports whether a write is the tar header of the entry
// named name (a header block starts with the entry name).
func isHeaderOf(p []byte, name string) bool {
	return len(p) == 512 && bytes.HasPrefix(p, []byte(name))
}

// isTrailer reports whether a write is a block of the tar end-of-archive
// marker: a whole zero block. Padding is always shorter than a block.
func isTrailer(p []byte) bool {
	return len(p) == 512 && bytes.Equal(p, make([]byte, 512))
}

// afterHeaderOf fails the first write that follows the header of name:
// the entry's content.
func afterHeaderOf(name string) func(p []byte) bool {
	armed := false
	return func(p []byte) bool {
		if armed {
			return true
		}
		armed = isHeaderOf(p, name)
		return false
	}
}

// A capture whose sink fails is reported at the step that failed: a
// file's header, a file's content, or the archive's trailer. No capture
// is reported complete over a sink that lost bytes.
func TestCapture_ReportsASinkFailureAtEveryStep(t *testing.T) {
	src := writeTree(t, map[string]string{"a.bin": "alpha", "b.bin": "beta"})
	cases := map[string]struct {
		fail func(p []byte) bool
		want string
	}{
		"file header":  {func(p []byte) bool { return isHeaderOf(p, "a.bin") }, "contentdir: a.bin: tar header"},
		"file content": {afterHeaderOf("b.bin"), "contentdir: b.bin: read"},
		"trailer":      {isTrailer, "contentdir: close tar"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, n, err := Capture(src, &hookWriter{fail: tc.fail})
			if err == nil {
				t.Fatalf("capture over a failing sink reported success after %d bytes", n)
			}
			if !errors.Is(err, errSinkDown) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the sink's error reported at %q", err, tc.want)
			}
		})
	}
}

// A file that shrinks while it is read is refused: the snapshot would
// otherwise describe bytes that were not written.
func TestCapture_RefusesAFileThatChangesWhileRead(t *testing.T) {
	src := writeTree(t, map[string]string{"shrink.bin": strings.Repeat("x", 4096)})
	sink := &hookWriter{onWrite: func(p []byte) {
		if isHeaderOf(p, "shrink.bin") {
			if err := os.Truncate(filepath.Join(src, "shrink.bin"), 1024); err != nil {
				t.Error(err)
			}
		}
	}}
	_, _, err := Capture(src, sink)
	if err == nil || !strings.Contains(err.Error(), "changed size while it was read (1024 of 4096 bytes)") {
		t.Fatalf("err = %v, want a size-change refusal", err)
	}
}

// An entry that is no longer a regular file when it is opened is refused
// rather than archived as something else.
func TestWriteFile_RefusesWhatIsNotARegularFile(t *testing.T) {
	src := writeTree(t, map[string]string{"sub/inner.txt": "x"})
	root, err := os.OpenRoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	_, err = writeFile(tar.NewWriter(io.Discard), root, "sub")
	if err == nil || !strings.Contains(err.Error(), "no longer a regular file") {
		t.Fatalf("err = %v, want a refusal of the directory", err)
	}
}

// What the process may not read is reported, not silently left out of
// the payload: an unreadable file, an unreadable subdirectory, and, for
// the fingerprint, a directory whose entries cannot be inspected.
func TestCaptureAndFingerprint_ReportUnreadableEntries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything regardless of mode")
	}
	t.Run("unreadable file", func(t *testing.T) {
		src := writeTree(t, map[string]string{"open.bin": "x", "locked.bin": "y"})
		locked := filepath.Join(src, "locked.bin")
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
		_, _, err := CapturePayload(src)
		if err == nil || !strings.Contains(err.Error(), "contentdir: locked.bin:") || !errors.Is(err, os.ErrPermission) {
			t.Fatalf("err = %v, want a permission refusal naming locked.bin", err)
		}
	})
	t.Run("unreadable subdirectory", func(t *testing.T) {
		src := writeTree(t, map[string]string{"open.bin": "x", "vault/secret.bin": "y"})
		dir := filepath.Join(src, "vault")
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		_, _, err := CapturePayload(src)
		if err == nil || !strings.Contains(err.Error(), "contentdir: walk:") || !errors.Is(err, os.ErrPermission) {
			t.Fatalf("err = %v, want a walk refusal", err)
		}
		if _, err := Fingerprint(src); err == nil || !strings.Contains(err.Error(), "contentdir: walk:") {
			t.Fatalf("fingerprint err = %v, want a walk refusal", err)
		}
	})
	t.Run("directory whose entries cannot be inspected", func(t *testing.T) {
		src := writeTree(t, map[string]string{"a.bin": "x"})
		if err := os.Chmod(src, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(src, 0o700) })
		if _, err := Fingerprint(src); err == nil || !strings.Contains(err.Error(), "contentdir: walk:") || !errors.Is(err, os.ErrPermission) {
			t.Fatalf("fingerprint err = %v, want a walk refusal", err)
		}
	})
}

// A relative source path is resolved against the working directory; a
// process whose working directory is gone cannot say what it would seal
// and is told so.
func TestCaptureAndFingerprint_RefuseWhenTheWorkingDirectoryIsGone(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("this platform still reports a working directory after it was removed")
	}
	if _, err := Fingerprint("relative"); err == nil || !strings.Contains(err.Error(), "contentdir: abs relative") {
		t.Fatalf("fingerprint err = %v, want an abs refusal", err)
	}
	if _, _, err := Capture("relative", io.Discard); err == nil || !strings.Contains(err.Error(), "contentdir: abs relative") {
		t.Fatalf("capture err = %v, want an abs refusal", err)
	}
}
