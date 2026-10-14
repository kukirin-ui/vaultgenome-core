// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package safetar extracts the deterministic tar payloads that
// internal/contentdir and internal/ollama seal into genome bundles.
//
// Extraction is the step where a hostile or corrupted payload could reach
// the host filesystem, so it lives in one place and is confined by
// construction: every write goes through an os.Root opened on the target
// directory. No entry can land outside the target — not by "..", not by
// an absolute name, and not through a symlink that already exists inside
// the target. Only regular files are materialised.
package safetar

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Extract writes every regular-file entry of payload under targetDir,
// creating targetDir and intermediate directories as needed (mode 0755;
// files 0644). It returns the number of file bytes written.
//
// Non-regular entries (symlinks, hard links, devices, directories) are
// skipped. A name that is not lexically local is an error, as is any
// write the os.Root refuses. A failure to close a written file is
// reported: an unflushed file is a failed extraction. On error the target
// may hold a partial extraction; callers verify content digests
// afterwards, so a partial tree is never mistaken for a restore.
func Extract(payload []byte, targetDir string) (int64, error) {
	return ExtractReader(bytes.NewReader(payload), targetDir)
}

// ExtractReader is Extract over a stream: the tar is read from r entry by
// entry, so a payload of any size extracts in bounded memory. It stops at
// the tar's end-of-archive marker and does not read r past it.
func ExtractReader(r io.Reader, targetDir string) (int64, error) {
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return 0, fmt.Errorf("safetar: create target: %w", err)
	}
	root, err := os.OpenRoot(targetDir)
	if err != nil {
		return 0, fmt.Errorf("safetar: open target: %w", err)
	}
	defer func() { _ = root.Close() }()

	tr := tar.NewReader(r)
	var written int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return written, nil
		}
		if err != nil {
			return written, fmt.Errorf("safetar: read entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name, err := LocalName(hdr.Name)
		if err != nil {
			return written, err
		}
		n, err := writeEntry(root, name, tr)
		written += n
		if err != nil {
			return written, err
		}
	}
}

func writeEntry(root *os.Root, name string, r io.Reader) (int64, error) {
	if dir := filepath.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return 0, fmt.Errorf("safetar: create directory for %s: %w", name, err)
		}
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("safetar: create %s: %w", name, err)
	}
	n, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		return n, fmt.Errorf("safetar: write %s: %w", name, copyErr)
	}
	if closeErr != nil {
		return n, fmt.Errorf("safetar: close %s: %w", name, closeErr)
	}
	return n, nil
}

// LocalName converts a tar entry name to a clean OS path, refusing any
// name that is not lexically local — empty, absolute, or escaping its root
// with ".." — or that names the root itself. os.Root enforces confinement
// regardless; this check turns an obviously hostile name into a clear
// error before any filesystem call.
func LocalName(name string) (string, error) {
	local := filepath.FromSlash(name)
	clean := filepath.Clean(local)
	if !filepath.IsLocal(local) || clean == "." {
		return "", fmt.Errorf("safetar: refusing non-local entry name %q", name)
	}
	return clean, nil
}
