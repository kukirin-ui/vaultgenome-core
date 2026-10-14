// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package ollama

import (
	"bytes"
	"errors"
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

// A capture whose sink fails is reported at the step that failed:
// the manifest entry, a blob's header, a blob's content, or the
// archive's trailer. No capture is reported complete over a sink that
// lost bytes.
func TestCapture_ReportsASinkFailureAtEveryStep(t *testing.T) {
	home, mf := fakeStore(t, "llama3.2:3b", config, weights, template)
	configEntry := "models/blobs/" + blobFilename(mf.Config.Digest)
	cases := map[string]struct {
		fail func(p []byte) bool
		want string
	}{
		"manifest header": {func([]byte) bool { return true }, "tar manifest"},
		"blob header":     {func(p []byte) bool { return isHeaderOf(p, configEntry) }, "ollama snapshot: " + errSinkDown.Error()},
		"blob content":    {afterHeaderOf(configEntry), "read blob " + blobFilename(mf.Config.Digest)},
		"trailer":         {isTrailer, "close tar"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, n, err := Capture("llama3.2:3b", home, &hookWriter{fail: tc.fail})
			if err == nil {
				t.Fatalf("capture over a failing sink reported success after %d bytes", n)
			}
			if !errors.Is(err, errSinkDown) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want the sink's error reported at %q", err, tc.want)
			}
		})
	}
}

// A blob that shrinks while it is read is refused: the snapshot would
// otherwise describe bytes that were not written.
func TestCapture_RefusesABlobThatChangesWhileRead(t *testing.T) {
	home, mf := fakeStore(t, "llama3.2:3b", config, weights)
	blob := filepath.Join(home, "models", "blobs", blobFilename(mf.Layers[0].Digest))
	entry := "models/blobs/" + blobFilename(mf.Layers[0].Digest)
	sink := &hookWriter{onWrite: func(p []byte) {
		if isHeaderOf(p, entry) {
			if err := os.Truncate(blob, int64(len(weights)/2)); err != nil {
				t.Error(err)
			}
		}
	}}
	_, _, err := Capture("llama3.2:3b", home, sink)
	if err == nil || !strings.Contains(err.Error(), "changed size while it was read") {
		t.Fatalf("err = %v, want a size-change refusal", err)
	}
}

// A store whose manifest or blobs are not what a model store holds is
// refused before anything is sealed: an invalid ref, a manifest that
// does not parse, a config digest that is not a digest, a missing blob
// store, a missing config blob, and a blob that is a directory.
func TestCapture_RefusesABrokenStore(t *testing.T) {
	cases := map[string]struct {
		setup func(t *testing.T) (ref, home string)
		want  string
	}{
		"invalid model ref": {
			setup: func(t *testing.T) (string, string) { return "../escape:1", t.TempDir() },
			want:  "invalid model ref",
		},
		"manifest does not parse": {
			setup: func(t *testing.T) (string, string) {
				home := t.TempDir()
				rel, err := manifestPathFor("broken:1")
				if err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(home, "models", rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("{not json"), 0o644); err != nil {
					t.Fatal(err)
				}
				return "broken:1", home
			},
			want: "parse manifest",
		},
		"config digest is not a digest": {
			setup: func(t *testing.T) (string, string) {
				home := t.TempDir()
				writeManifest(t, home, "broken:1", ManifestRef{SchemaVersion: 2, Config: Layer{Digest: "sha256:short"}})
				return "broken:1", home
			},
			want: "manifest config: invalid digest",
		},
		"no blob store": {
			setup: func(t *testing.T) (string, string) {
				home := t.TempDir()
				writeManifest(t, home, "broken:1", ManifestRef{SchemaVersion: 2, Config: Layer{Digest: digestOf(config)}})
				return "broken:1", home
			},
			want: "open blob store",
		},
		"config blob missing": {
			setup: func(t *testing.T) (string, string) {
				home, mf := fakeStore(t, "broken:1", config, weights)
				if err := os.Remove(filepath.Join(home, "models", "blobs", blobFilename(mf.Config.Digest))); err != nil {
					t.Fatal(err)
				}
				return "broken:1", home
			},
			want: "read blob",
		},
		"blob is a directory": {
			setup: func(t *testing.T) (string, string) {
				home, mf := fakeStore(t, "broken:1", config, weights)
				blob := filepath.Join(home, "models", "blobs", blobFilename(mf.Layers[0].Digest))
				if err := os.Remove(blob); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(blob, 0o755); err != nil {
					t.Fatal(err)
				}
				return "broken:1", home
			},
			want: "is not a regular file",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ref, home := tc.setup(t)
			_, _, err := CapturePayload(ref, home)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A blob referenced twice by the manifest is written once: the payload
// stays content-addressed, the total counts it once, and the restore
// still verifies both references.
func TestCapture_WritesASharedBlobOnce(t *testing.T) {
	home, mf := fakeStore(t, "shared:1", config, weights, weights)
	if mf.Layers[0].Digest != mf.Layers[1].Digest {
		t.Fatal("the fixture must reference one blob twice")
	}
	snap, payload, err := CapturePayload("shared:1", home)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(home, "models", snap.ManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(len(manifestBytes) + len(config) + len(weights)); snap.TotalBytes != want {
		t.Fatalf("TotalBytes %d, want %d (the shared blob counted once)", snap.TotalBytes, want)
	}
	if got := bytes.Count(payload, []byte("models/blobs/"+blobFilename(mf.Layers[0].Digest))); got != 1 {
		t.Fatalf("the shared blob appears %d times in the payload, want once", got)
	}
	if len(snap.Components) != 4 {
		t.Fatalf("%d components, want 4 (both references are described)", len(snap.Components))
	}
	restored := t.TempDir()
	if _, err := Restore(payload, restored); err != nil {
		t.Fatal(err)
	}
	if err := VerifyComponents(snap, restored); err != nil {
		t.Fatal(err)
	}
}

// A restore cannot begin where its directories cannot be made.
func TestRestore_RefusesATargetItCannotCreate(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := Restore([]byte{}, filepath.Join(file, "home"))
	if err == nil || !strings.Contains(err.Error(), "ollama restore: mkdir") {
		t.Fatalf("err = %v, want a mkdir refusal", err)
	}
	if n != 0 {
		t.Fatalf("wrote %d bytes before refusing", n)
	}
}

// Verification of a restore fails on a blob or a manifest that is not
// there, naming the file.
func TestVerifyComponents_ReportsWhatIsMissing(t *testing.T) {
	home, mf := fakeStore(t, "llama3.2:3b", config, weights)
	snap, payload, err := CapturePayload("llama3.2:3b", home)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		remove func(restored string) string
		want   string
	}{
		"blob": {
			remove: func(restored string) string {
				return filepath.Join(restored, "models", "blobs", blobFilename(mf.Layers[0].Digest))
			},
			want: "verify: read ",
		},
		"manifest": {
			remove: func(restored string) string { return filepath.Join(restored, "models", snap.ManifestPath) },
			want:   "verify: read manifest",
		},
	} {
		t.Run(name, func(t *testing.T) {
			restored := t.TempDir()
			if _, err := Restore(payload, restored); err != nil {
				t.Fatal(err)
			}
			path := tc.remove(restored)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			err := VerifyComponents(snap, restored)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), path) {
				t.Fatalf("err = %v, want %q naming %s", err, tc.want, path)
			}
		})
	}
}
