// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ollama bridges a running Ollama installation into Vault Genome's
// seal/unseal pipeline. It treats Ollama's on-disk model store
// (manifest + content-addressed blobs) as the payload that gets sealed
// inside a TEE Sealer, and provides the inverse operation that materialises
// the same bytes back into a fresh OLLAMA_MODELS directory.
//
// Why this exists: every claim on vaultgenome.com about "model continuity"
// historically resolved to mock byte buffers. This package makes those
// claims resolve to a real Llama 3.2 / Qwen / Mistral model instead, which
// turns the demo into a downloadable artifact a buyer can verify.
package ollama

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/safetar"
)

// ManifestRef mirrors Ollama's on-disk manifest schema (Docker v2-style).
// We only decode the fields we need to enumerate referenced blobs.
type ManifestRef struct {
	SchemaVersion int     `json:"schemaVersion"`
	MediaType     string  `json:"mediaType"`
	Config        Layer   `json:"config"`
	Layers        []Layer `json:"layers"`
}

// Layer is one entry in a manifest — pointer to a content-addressed blob.
type Layer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"` // "sha256:<hex>"
	Size      int64  `json:"size"`
}

// Component is the in-snapshot record for a single blob (manifest or layer).
// Carried in the genome envelope so an inspector can list the bundle's
// contents without unsealing the payload.
type Component struct {
	Role      string `json:"role"`       // "manifest" | "config" | "layer"
	MediaType string `json:"media_type"` // copied from manifest
	Digest    string `json:"digest"`     // "sha256:<hex>"
	Size      int64  `json:"size"`
}

// Snapshot is the metadata side of a captured Ollama model: enough info to
// describe the bundle (model ref, components, total bytes, payload digest)
// without including the bytes themselves.
type Snapshot struct {
	Model         string      `json:"model"`         // "llama3.2:3b"
	ManifestPath  string      `json:"manifest_path"` // relative to OLLAMA_MODELS
	Manifest      ManifestRef `json:"manifest"`
	Components    []Component `json:"components"` // sorted by digest for determinism
	TotalBytes    int64       `json:"total_bytes"`
	PayloadSHA256 string      `json:"payload_sha256"` // sha256 of the tarball bytes
}

// CapturePayload reads the model identified by modelRef from ollamaHome
// (typically ~/.ollama) and returns:
//
//   - Snapshot: structured metadata describing what's inside the bundle
//   - []byte:   a deterministic uncompressed tar stream containing the
//     manifest and every referenced blob, laid out so Restore
//     can drop it back into a fresh OLLAMA_MODELS directory
//
// Determinism matters here: the same model on the same machine must produce
// byte-identical tar output across runs, so the payload SHA-256 (which gets
// signed into the genome envelope) is reproducible. We achieve this by
// sorting tar entries lexicographically and zeroing per-entry timestamps.
func CapturePayload(modelRef, ollamaHome string) (Snapshot, []byte, error) {
	var buf bytes.Buffer
	snap, _, err := Capture(modelRef, ollamaHome, &buf)
	if err != nil {
		return Snapshot{}, nil, err
	}
	return snap, buf.Bytes(), nil
}

// Capture writes the payload CapturePayload returns to w instead, blob by
// blob, so a model of any size is captured in bounded memory. It returns
// the snapshot and the number of payload bytes written. Every blob is
// hashed as it is written and must match its manifest digest; if one does
// not, the error comes after its bytes were written, and whatever w
// received must be discarded.
func Capture(modelRef, ollamaHome string, w io.Writer) (Snapshot, int64, error) {
	manifestRel, err := manifestPathFor(modelRef)
	if err != nil {
		return Snapshot{}, 0, err
	}
	manifestAbs := filepath.Join(ollamaHome, "models", manifestRel)

	manifestBytes, err := os.ReadFile(manifestAbs)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("ollama snapshot: read manifest %s: %w", manifestAbs, err)
	}

	var mf ManifestRef
	if err := json.Unmarshal(manifestBytes, &mf); err != nil {
		return Snapshot{}, 0, fmt.Errorf("ollama snapshot: parse manifest: %w", err)
	}
	// Digests become file names under models/blobs, so validate every one
	// before touching the filesystem: a crafted "sha256:../../dev/zero"
	// would otherwise read outside the store (or never finish reading).
	if err := validateDigest(mf.Config.Digest); err != nil {
		return Snapshot{}, 0, fmt.Errorf("ollama snapshot: manifest config: %w", err)
	}
	for i, l := range mf.Layers {
		if err := validateDigest(l.Digest); err != nil {
			return Snapshot{}, 0, fmt.Errorf("ollama snapshot: manifest layer %d: %w", i, err)
		}
	}

	components := []Component{
		{Role: "manifest", MediaType: "application/vnd.ollama.manifest", Digest: digestOf(manifestBytes), Size: int64(len(manifestBytes))},
		{Role: "config", MediaType: mf.Config.MediaType, Digest: mf.Config.Digest, Size: mf.Config.Size},
	}
	for _, l := range mf.Layers {
		components = append(components, Component{
			Role:      "layer",
			MediaType: l.MediaType,
			Digest:    l.Digest,
			Size:      l.Size,
		})
	}

	// Deterministic order so payload bytes are reproducible.
	sort.Slice(components, func(i, j int) bool { return components[i].Digest < components[j].Digest })

	blobs, err := os.OpenRoot(filepath.Join(ollamaHome, "models", "blobs"))
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("ollama snapshot: open blob store: %w", err)
	}
	defer func() { _ = blobs.Close() }()

	counted := &countingWriter{w: w}
	payloadHash := sha256.New()
	tw := tar.NewWriter(io.MultiWriter(counted, payloadHash))

	// 1. The manifest, written under its source-relative path so Restore
	//    can drop it back where Ollama expects to find it.
	if err := writeTarEntry(tw, "models/"+manifestRel, manifestBytes); err != nil {
		return Snapshot{}, 0, fmt.Errorf("ollama snapshot: tar manifest: %w", err)
	}

	// 2. Every referenced blob, named by digest (Ollama's on-disk
	//    convention: ~/.ollama/models/blobs/sha256-<hex>).
	seen := map[string]bool{}
	totalBytes := int64(len(manifestBytes))
	addBlob := func(digest string) error {
		if seen[digest] {
			return nil
		}
		seen[digest] = true
		n, err := writeBlob(tw, blobs, digest)
		totalBytes += n
		return err
	}

	if err := addBlob(mf.Config.Digest); err != nil {
		return Snapshot{}, 0, fmt.Errorf("ollama snapshot: %w", err)
	}
	for _, l := range mf.Layers {
		if err := addBlob(l.Digest); err != nil {
			return Snapshot{}, 0, fmt.Errorf("ollama snapshot: %w", err)
		}
	}

	if err := tw.Close(); err != nil {
		return Snapshot{}, 0, fmt.Errorf("ollama snapshot: close tar: %w", err)
	}

	return Snapshot{
		Model:         modelRef,
		ManifestPath:  manifestRel,
		Manifest:      mf,
		Components:    components,
		TotalBytes:    totalBytes,
		PayloadSHA256: "sha256:" + hex.EncodeToString(payloadHash.Sum(nil)),
	}, counted.n, nil
}

// writeBlob streams one content-addressed blob into the tar and checks it
// hashes to the digest that names it.
func writeBlob(tw *tar.Writer, blobs *os.Root, digest string) (int64, error) {
	name := blobFilename(digest)
	f, err := blobs.Open(name)
	if err != nil {
		return 0, fmt.Errorf("read blob %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("read blob %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("blob %s is not a regular file", name)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     "models/blobs/" + name,
		Mode:     0o644,
		Size:     info.Size(),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}); err != nil {
		return 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), f)
	if err != nil {
		return n, fmt.Errorf("read blob %s: %w", name, err)
	}
	if n != info.Size() {
		return n, fmt.Errorf("blob %s changed size while it was read", name)
	}
	if actual := "sha256:" + hex.EncodeToString(h.Sum(nil)); actual != digest {
		return n, fmt.Errorf("blob %s: digest mismatch (manifest says %s, on disk %s)", name, digest, actual)
	}
	return n, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Restore extracts a payload produced by CapturePayload into targetHome,
// reproducing the OLLAMA_MODELS layout under targetHome/models/, and
// returns the number of bytes written. Callers point Ollama at the result
// with OLLAMA_MODELS. Extraction is confined to targetHome by safetar.
func Restore(payload []byte, targetHome string) (int64, error) {
	for _, dir := range []string{
		filepath.Join(targetHome, "models", "blobs"),
		filepath.Join(targetHome, "models", "manifests"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, fmt.Errorf("ollama restore: mkdir %s: %w", dir, err)
		}
	}
	n, err := safetar.Extract(payload, targetHome)
	if err != nil {
		return n, fmt.Errorf("ollama restore: %w", err)
	}
	return n, nil
}

// VerifyComponents re-hashes the manifest and every blob of a restored
// OLLAMA_MODELS layout and fails on any divergence from the snapshot. Used
// by `acpctl genome verify` after a restore to prove that what came out of
// the seal is bit-identical to what went in. The snapshot is untrusted
// input (it is decoded from a bundle), so its digests and manifest path
// are validated before they are used to build file paths.
func VerifyComponents(snap Snapshot, restoredHome string) error {
	var manifestDigest string
	for _, c := range snap.Components {
		if err := validateDigest(c.Digest); err != nil {
			return fmt.Errorf("verify: %s component: %w", c.Role, err)
		}
		if c.Role == "manifest" {
			manifestDigest = c.Digest
			continue
		}
		path := filepath.Join(restoredHome, "models", "blobs", blobFilename(c.Digest))
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("verify: read %s: %w", path, err)
		}
		if got := digestOf(data); got != c.Digest {
			return fmt.Errorf("verify: blob digest mismatch (snapshot %s, on-disk %s)", c.Digest, got)
		}
	}
	if manifestDigest == "" {
		return errors.New("verify: snapshot records no manifest component")
	}
	if !filepath.IsLocal(snap.ManifestPath) {
		return fmt.Errorf("verify: snapshot manifest path %q is not local", snap.ManifestPath)
	}
	manifestPath := filepath.Join(restoredHome, "models", snap.ManifestPath)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("verify: read manifest %s: %w", manifestPath, err)
	}
	if got := digestOf(data); got != manifestDigest {
		return fmt.Errorf("verify: manifest digest mismatch (snapshot %s, on-disk %s)", manifestDigest, got)
	}
	return nil
}

// digestPattern is the only digest form accepted: it doubles as a blob
// file name, so it must be exactly "sha256:" and 64 lowercase hex digits.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validateDigest(d string) error {
	if !digestPattern.MatchString(d) {
		return fmt.Errorf("invalid digest %q (want sha256:<64 lowercase hex>)", d)
	}
	return nil
}

// refPart is one component of a model reference (registry host,
// namespace, model name, or tag). It must start with a letter or digit, so
// "." and ".." — and hidden names — can never become path elements.
var refPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// manifestPathFor turns "llama3.2:3b" into the relative on-disk path
// "manifests/registry.ollama.ai/library/llama3.2/3b". Any explicit
// registry/namespace prefix is honoured; the bare-name shortcut assumes
// the canonical Ollama registry. Every component is validated, so a
// reference can never address a path outside models/manifests.
func manifestPathFor(modelRef string) (string, error) {
	if modelRef == "" {
		return "", errors.New("ollama snapshot: model ref must not be empty")
	}
	name, tag, ok := strings.Cut(modelRef, ":")
	if !ok {
		tag = "latest"
		name = modelRef
	}
	parts := strings.Split(name, "/")
	for _, p := range append(append([]string(nil), parts...), tag) {
		if !refPart.MatchString(p) {
			return "", fmt.Errorf("ollama snapshot: invalid model ref %q", modelRef)
		}
	}
	// Normalise the registry/namespace prefix.
	switch len(parts) {
	case 1:
		return filepath.Join("manifests", "registry.ollama.ai", "library", parts[0], tag), nil
	case 2:
		return filepath.Join("manifests", "registry.ollama.ai", parts[0], parts[1], tag), nil
	case 3:
		return filepath.Join("manifests", parts[0], parts[1], parts[2], tag), nil
	default:
		return "", fmt.Errorf("ollama snapshot: cannot parse model ref %q", modelRef)
	}
}

func blobFilename(digest string) string {
	// "sha256:abcd..." → "sha256-abcd..." (Ollama's on-disk convention)
	return strings.Replace(digest, ":", "-", 1)
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeTarEntry writes a single regular file with deterministic header
// fields (mtime=0, uid/gid=0, mode=0644) so the tar bytes are reproducible
// across hosts and clocks.
func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
