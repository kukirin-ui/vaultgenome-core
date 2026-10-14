// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package contentdir is a generic directory-sealing payload source for
// Vault Genome bundles. It complements internal/ollama (which knows about
// Ollama's manifest+blob layout) by handling the case where the workload
// is "an arbitrary directory of files" — for example, a LoRA adapter
// produced by mlx_lm.lora, a fine-tune checkpoint, a RAG corpus, or any
// other on-disk artefact a TEE-aware operator wants under continuity.
//
// Determinism: the tar layout is sorted by path, mtime is zeroed, and
// uid/gid/mode are normalised so the payload SHA-256 is reproducible
// across hosts and clocks.
package contentdir

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/vault-genome/vaultgenome-core/internal/shared/safetar"
)

// Component is the in-snapshot record for one file inside a sealed dir.
// Carried in the genome envelope so an inspector can list contents
// without unsealing.
type Component struct {
	Path   string `json:"path"`   // forward-slash, relative to the sealed root
	Digest string `json:"digest"` // "sha256:<hex>"
	Size   int64  `json:"size"`
}

// Snapshot describes a sealed directory: the source path, the per-file
// components, total bytes, and the payload SHA-256. The bundle envelope
// embeds this verbatim.
type Snapshot struct {
	SourceDir     string      `json:"source_dir"`     // absolute path the snapshot came from
	Components    []Component `json:"components"`     // sorted by path (deterministic)
	TotalBytes    int64       `json:"total_bytes"`    // sum of every component's size
	PayloadSHA256 string      `json:"payload_sha256"` // sha256 of the tar bytes
}

// CapturePayload reads every regular file under sourceDir (recursively),
// packs them into a deterministic uncompressed tar, and returns the
// snapshot metadata + the tar bytes. Symlinks, devices, and other
// non-regular entries are ignored.
//
// The tar entry name for each file is its path relative to sourceDir
// using forward slashes — so a file at sourceDir/adapters.safetensors
// is stored as "adapters.safetensors" in the tar (not under any prefix).
func CapturePayload(sourceDir string) (Snapshot, []byte, error) {
	var buf bytes.Buffer
	snap, _, err := Capture(sourceDir, &buf)
	if err != nil {
		return Snapshot{}, nil, err
	}
	return snap, buf.Bytes(), nil
}

// Capture writes the payload CapturePayload returns to w instead, file by
// file, so a directory of any size is captured in bounded memory. It
// returns the snapshot and the number of payload bytes written. Files are
// read through an os.Root on sourceDir, and a file that changes size
// while it is read is an error: the snapshot always describes exactly
// the bytes written.
func Capture(sourceDir string, w io.Writer) (Snapshot, int64, error) {
	abs, err := filepath.Abs(sourceDir)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("contentdir: abs %s: %w", sourceDir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("contentdir: stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return Snapshot{}, 0, fmt.Errorf("contentdir: %s is not a directory", abs)
	}

	var rels []string
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(abs, path)
		if err != nil {
			return fmt.Errorf("rel %s: %w", path, err)
		}
		// Forward-slash for tar portability.
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("contentdir: walk: %w", err)
	}
	if len(rels) == 0 {
		return Snapshot{}, 0, fmt.Errorf("contentdir: %s contains no regular files", abs)
	}
	// Deterministic tar order.
	sort.Strings(rels)

	root, err := os.OpenRoot(abs)
	if err != nil {
		return Snapshot{}, 0, fmt.Errorf("contentdir: open %s: %w", abs, err)
	}
	defer func() { _ = root.Close() }()

	counted := &countingWriter{w: w}
	payloadHash := sha256.New()
	tw := tar.NewWriter(io.MultiWriter(counted, payloadHash))
	components := make([]Component, 0, len(rels))
	var total int64
	for _, rel := range rels {
		c, err := writeFile(tw, root, rel)
		if err != nil {
			return Snapshot{}, 0, fmt.Errorf("contentdir: %s: %w", rel, err)
		}
		components = append(components, c)
		total += c.Size
	}
	if err := tw.Close(); err != nil {
		return Snapshot{}, 0, fmt.Errorf("contentdir: close tar: %w", err)
	}
	return Snapshot{
		SourceDir:     abs,
		Components:    components,
		TotalBytes:    total,
		PayloadSHA256: "sha256:" + hex.EncodeToString(payloadHash.Sum(nil)),
	}, counted.n, nil
}

// writeFile streams one file into the tar with deterministic header
// fields and returns its component record.
func writeFile(tw *tar.Writer, root *os.Root, rel string) (Component, error) {
	f, err := root.Open(filepath.FromSlash(rel))
	if err != nil {
		return Component{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return Component{}, err
	}
	if !info.Mode().IsRegular() {
		return Component{}, errors.New("no longer a regular file")
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     rel,
		Mode:     0o644,
		Size:     info.Size(),
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}); err != nil {
		return Component{}, fmt.Errorf("tar header: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), f)
	if err != nil {
		return Component{}, fmt.Errorf("read: %w (did it change while it was read?)", err)
	}
	if n != info.Size() {
		return Component{}, fmt.Errorf("changed size while it was read (%d of %d bytes)", n, info.Size())
	}
	return Component{Path: rel, Digest: "sha256:" + hex.EncodeToString(h.Sum(nil)), Size: n}, nil
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

// Restore extracts a payload produced by CapturePayload into targetDir,
// recreating the original directory structure, and returns the number of
// bytes written. Extraction is confined to targetDir by safetar: no entry
// can land outside it, whether by "..", an absolute name, or a symlink
// already inside targetDir.
func Restore(payload []byte, targetDir string) (int64, error) {
	n, err := safetar.Extract(payload, targetDir)
	if err != nil {
		return n, fmt.Errorf("contentdir restore: %w", err)
	}
	return n, nil
}
