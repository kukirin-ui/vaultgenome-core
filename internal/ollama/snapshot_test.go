// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package ollama

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeStore lays out an Ollama model store for ref under a new home:
// models/manifests/<registry>/<ns>/<name>/<tag> plus content-addressed
// blobs. It returns the home directory and the manifest it wrote.
func fakeStore(t *testing.T, ref string, config []byte, layers ...[]byte) (string, ManifestRef) {
	t.Helper()
	home := t.TempDir()
	blobs := filepath.Join(home, "models", "blobs")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBlob := func(data []byte, mediaType string) Layer {
		d := digestOf(data)
		if err := os.WriteFile(filepath.Join(blobs, blobFilename(d)), data, 0o644); err != nil {
			t.Fatal(err)
		}
		return Layer{MediaType: mediaType, Digest: d, Size: int64(len(data))}
	}
	mf := ManifestRef{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
		Config:        writeBlob(config, "application/vnd.docker.container.image.v1+json"),
	}
	for i, l := range layers {
		mt := "application/vnd.ollama.image.model"
		if i > 0 {
			mt = "application/vnd.ollama.image.template"
		}
		mf.Layers = append(mf.Layers, writeBlob(l, mt))
	}
	writeManifest(t, home, ref, mf)
	return home, mf
}

func writeManifest(t *testing.T, home, ref string, mf ManifestRef) {
	t.Helper()
	rel, err := manifestPathFor(ref)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, "models", rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

var (
	weights  = bytes.Repeat([]byte("GGUF\x00\x01weights-"), 4096)
	template = []byte("{{ .Prompt }}")
	config   = []byte(`{"model_format":"gguf","model_family":"llama"}`)
)

func TestCaptureRestoreVerify_RoundTripIsByteExact(t *testing.T) {
	home, mf := fakeStore(t, "llama3.2:3b", config, weights, template)
	snap, payload, err := CapturePayload("llama3.2:3b", home)
	if err != nil {
		t.Fatalf("CapturePayload: %v", err)
	}
	if snap.Model != "llama3.2:3b" || len(snap.Components) != 4 {
		t.Fatalf("snapshot %+v: want model llama3.2:3b with 4 components", snap)
	}
	wantTotal := int64(len(weights) + len(template) + len(config))
	manifestBytes, _ := os.ReadFile(filepath.Join(home, "models", snap.ManifestPath))
	if snap.TotalBytes != wantTotal+int64(len(manifestBytes)) {
		t.Fatalf("TotalBytes %d, want %d", snap.TotalBytes, wantTotal+int64(len(manifestBytes)))
	}

	restored := filepath.Join(t.TempDir(), "restored-home")
	if _, err := Restore(payload, restored); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := VerifyComponents(snap, restored); err != nil {
		t.Fatalf("VerifyComponents: %v", err)
	}
	for _, l := range append([]Layer{mf.Config}, mf.Layers...) {
		src, _ := os.ReadFile(filepath.Join(home, "models", "blobs", blobFilename(l.Digest)))
		dst, err := os.ReadFile(filepath.Join(restored, "models", "blobs", blobFilename(l.Digest)))
		if err != nil || !bytes.Equal(src, dst) {
			t.Fatalf("blob %s not restored byte-exact (%v)", l.Digest, err)
		}
	}
}

func TestCapture_IsDeterministic(t *testing.T) {
	home, _ := fakeStore(t, "qwen:0.5b", config, weights, template)
	s1, p1, err := CapturePayload("qwen:0.5b", home)
	if err != nil {
		t.Fatal(err)
	}
	s2, p2, err := CapturePayload("qwen:0.5b", home)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1, p2) || s1.PayloadSHA256 != s2.PayloadSHA256 {
		t.Fatal("capturing the same model twice produced different payloads")
	}
	if s1.PayloadSHA256 != digestOf(p1) {
		t.Fatalf("PayloadSHA256 %s does not hash the payload", s1.PayloadSHA256)
	}
	for i := 1; i < len(s1.Components); i++ {
		if s1.Components[i-1].Digest > s1.Components[i].Digest {
			t.Fatal("components are not sorted by digest")
		}
	}
}

// A blob that no longer hashes to its manifest digest is refused at
// capture: a corrupted local store must not be sealed as a genome.
func TestCapture_RefusesBlobThatDoesNotMatchItsDigest(t *testing.T) {
	home, mf := fakeStore(t, "llama3.2:3b", config, weights)
	blob := filepath.Join(home, "models", "blobs", blobFilename(mf.Layers[0].Digest))
	if err := os.WriteFile(blob, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CapturePayload("llama3.2:3b", home); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("CapturePayload with a tampered blob: err = %v, want digest mismatch", err)
	}
}

// A manifest whose digests are not plain sha256 hex is refused before any
// blob path is built from them. The /dev/zero case would otherwise read
// forever; the test fails rather than hangs if validation ever regresses.
func TestCapture_RefusesMaliciousManifestDigests(t *testing.T) {
	for name, digest := range map[string]string{
		"traversal to /etc/passwd": "sha256:../../../../../../etc/passwd",
		"traversal to /dev/zero":   "sha256:../../../../../../dev/zero",
		"uppercase hex":            "sha256:" + strings.Repeat("A", 64),
		"short":                    "sha256:abcd",
		"other algorithm":          "md5:" + strings.Repeat("0", 32),
		"empty":                    "",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			mf := ManifestRef{SchemaVersion: 2, Config: Layer{Digest: digestOf(config)}, Layers: []Layer{{Digest: digest}}}
			writeManifest(t, home, "evil:latest", mf)
			done := make(chan error, 1)
			go func() {
				_, _, err := CapturePayload("evil:latest", home)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "invalid digest") {
					t.Fatalf("err = %v, want an invalid digest refusal", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("CapturePayload did not return: digest was used as a path before validation")
			}
		})
	}
}

func TestManifestPathFor(t *testing.T) {
	ok := map[string]string{
		"llama3.2:3b":                  "manifests/registry.ollama.ai/library/llama3.2/3b",
		"qwen":                         "manifests/registry.ollama.ai/library/qwen/latest",
		"acme/phi-3:mini_q4":           "manifests/registry.ollama.ai/acme/phi-3/mini_q4",
		"registry.example.com/ns/m:v1": "manifests/registry.example.com/ns/m/v1",
	}
	for ref, want := range ok {
		got, err := manifestPathFor(ref)
		if err != nil || got != filepath.FromSlash(want) {
			t.Errorf("manifestPathFor(%q) = %q, %v; want %q", ref, got, err, want)
		}
	}
	for _, ref := range []string{
		"", "../../etc:passwd", "a/../b:c", "model:../../x", "model:", ":tag",
		"/abs:tag", "a/b/c/d:e", ".hidden:tag", "model:tag/extra", "a//b:c",
	} {
		if got, err := manifestPathFor(ref); err == nil {
			t.Errorf("manifestPathFor(%q) = %q, want refusal", ref, got)
		}
	}
}

func TestVerifyComponents_DetectsTamperedRestore(t *testing.T) {
	home, mf := fakeStore(t, "llama3.2:3b", config, weights)
	snap, payload, err := CapturePayload("llama3.2:3b", home)
	if err != nil {
		t.Fatal(err)
	}
	restored := t.TempDir()
	if _, err := Restore(payload, restored); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(restored, "models", "blobs", blobFilename(mf.Layers[0].Digest))
	if err := os.WriteFile(blob, []byte("flipped"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyComponents(snap, restored); err == nil {
		t.Fatal("VerifyComponents accepted a tampered blob")
	}

	if _, err := Restore(payload, restored); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(restored, "models", snap.ManifestPath)
	if err := os.WriteFile(manifest, []byte(`{"schemaVersion":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyComponents(snap, restored); err == nil || !strings.Contains(err.Error(), "manifest digest mismatch") {
		t.Fatalf("VerifyComponents with a tampered manifest: err = %v", err)
	}
}

// The snapshot is decoded from a bundle, so VerifyComponents treats it as
// untrusted: malformed input is an error, never a panic or a read outside
// the restored home.
func TestVerifyComponents_RejectsMalformedSnapshots(t *testing.T) {
	home, _ := fakeStore(t, "llama3.2:3b", config, weights)
	good, payload, err := CapturePayload("llama3.2:3b", home)
	if err != nil {
		t.Fatal(err)
	}
	restored := t.TempDir()
	if _, err := Restore(payload, restored); err != nil {
		t.Fatal(err)
	}
	noManifest := good
	noManifest.Components = nil
	for _, c := range good.Components {
		if c.Role != "manifest" {
			noManifest.Components = append(noManifest.Components, c)
		}
	}
	badDigest := good
	badDigest.Components = append([]Component{{Role: "layer", Digest: "sha256:../../../../etc/passwd"}}, good.Components...)
	badPath := good
	badPath.ManifestPath = "../../../../etc/passwd"

	for name, snap := range map[string]Snapshot{
		"empty snapshot":     {},
		"no manifest":        noManifest,
		"traversal digest":   badDigest,
		"traversal manifest": badPath,
		"absolute manifest":  func() Snapshot { s := good; s.ManifestPath = "/etc/passwd"; return s }(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyComponents(snap, restored); err == nil {
				t.Fatal("VerifyComponents accepted a malformed snapshot")
			}
		})
	}
}

func TestRestore_IsConfinedToTargetHome(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTarEntry(tw, "../escape", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if _, err := Restore(buf.Bytes(), filepath.Join(parent, "home")); err == nil {
		t.Fatal("Restore accepted an entry outside the target home")
	}
	if _, err := os.Stat(filepath.Join(parent, "escape")); err == nil {
		t.Fatal("a file was written outside the target home")
	}
}

func TestCapture_MissingModel(t *testing.T) {
	if _, _, err := CapturePayload("absent:latest", t.TempDir()); err == nil {
		t.Fatal("CapturePayload of a model that is not in the store succeeded")
	}
}
