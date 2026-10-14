// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package restore puts an opened genome on disk, all or nothing.
//
// The payload is extracted into a staging directory inside the target,
// read to its authenticated end, and the staged tree is checked against
// the bundle header's snapshot: exactly the files it lists, each with the
// digest it records. Only then are the files moved into the target. A
// payload that fails to open or does not match leaves the target as it
// was. Every filesystem step goes through an os.Root on the target, so
// nothing a payload names can land outside it.
package restore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/tree"
	"github.com/vault-genome/vaultgenome-core/internal/shared/safetar"
)

// StagingPrefix names the staging directories Restore creates inside a
// target. One that outlives its restore was left by a crash; it is never
// part of a restored tree.
const StagingPrefix = tree.StagingPrefix

// Result describes a completed restore.
type Result struct {
	Target        string `json:"target"`
	Files         int    `json:"files"`
	BytesWritten  int64  `json:"bytes_written"`
	PayloadSHA256 string `json:"payload_sha256"`
	// TreeSHA256 is tree.Digest of the restored files: the same genome
	// restored anywhere has the same tree digest.
	TreeSHA256 string `json:"tree_sha256"`
}

// Restore extracts payload — the stream bundle.Reader.Payload returns, or
// any stream that ends in io.EOF only when it is complete and authentic —
// into target, which is created if it does not exist. Files the genome
// holds replace same-named files in target; nothing else in target is
// touched. On error, target is left as it was (and removed again if
// Restore created it), except when moving verified files into place
// fails midway, which the error then says.
func Restore(h bundle.Header, payload io.Reader, target string) (Result, error) {
	files, err := tree.Files(h)
	if err != nil {
		return Result{}, err
	}
	created := false
	if _, err := os.Stat(target); errors.Is(err, fs.ErrNotExist) {
		created = true
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return Result{}, fmt.Errorf("restore: create target: %w", err)
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		return Result{}, fmt.Errorf("restore: open target: %w", err)
	}
	defer func() { _ = root.Close() }()

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return Result{}, fmt.Errorf("restore: staging name: %w", err)
	}
	staging := StagingPrefix + hex.EncodeToString(suffix[:])
	if err := root.Mkdir(staging, 0o700); err != nil {
		return Result{}, fmt.Errorf("restore: create staging: %w", err)
	}
	moved := false
	defer func() {
		_ = root.RemoveAll(staging)
		if created && !moved {
			_ = os.Remove(target)
		}
	}()

	written, err := safetar.ExtractReader(payload, filepath.Join(target, staging))
	if err != nil {
		return Result{}, fmt.Errorf("restore: %w", err)
	}
	// The tar reader stops at its end marker; the payload is proven whole
	// and authentic only at its own end.
	if _, err := io.Copy(io.Discard, payload); err != nil {
		return Result{}, fmt.Errorf("restore: %w", err)
	}
	if err := checkTree(root, staging, files, true); err != nil {
		return Result{}, err
	}

	moved = true
	for _, p := range tree.Paths(files) {
		if dir := path.Dir(p); dir != "." {
			if err := root.MkdirAll(filepath.FromSlash(dir), 0o755); err != nil {
				return Result{}, fmt.Errorf("restore: moving verified files into place failed at %s, target holds part of the genome: %w", p, err)
			}
		}
		if err := root.Rename(filepath.FromSlash(staging+"/"+p), filepath.FromSlash(p)); err != nil {
			return Result{}, fmt.Errorf("restore: moving verified files into place failed at %s, target holds part of the genome: %w", p, err)
		}
	}
	return Result{
		Target:        target,
		Files:         len(files),
		BytesWritten:  written,
		PayloadSHA256: h.PayloadSHA256,
		TreeSHA256:    tree.Digest(files),
	}, nil
}

// Verify checks that dir holds every file a restore of h holds, each with
// its recorded digest. Other files in dir are allowed (a model restored
// into a live Ollama store sits beside other models). It returns the tree
// digest.
func Verify(h bundle.Header, dir string) (string, error) {
	files, err := tree.Files(h)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("restore: open %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	if err := checkTree(root, ".", files, false); err != nil {
		return "", err
	}
	return tree.Digest(files), nil
}

// checkTree re-hashes each expected file under base; with exact, it also
// refuses any regular file under base that is not expected.
func checkTree(root *os.Root, base string, files map[string]string, exact bool) error {
	for _, p := range tree.Paths(files) {
		got, err := digestFile(root, filepath.FromSlash(path.Join(base, p)))
		if err != nil {
			return fmt.Errorf("restore: %s: %w", p, err)
		}
		if got != files[p] {
			return fmt.Errorf("restore: %s: digest mismatch (snapshot %s, restored %s)", p, files[p], got)
		}
	}
	if !exact {
		return nil
	}
	return fs.WalkDir(root.FS(), base, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(name, base+"/")
		if _, ok := files[rel]; !ok || !d.Type().IsRegular() {
			return fmt.Errorf("restore: the payload holds %s, which the snapshot does not list", rel)
		}
		return nil
	})
}

func digestFile(root *os.Root, name string) (string, error) {
	f, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
