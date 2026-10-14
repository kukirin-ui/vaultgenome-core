// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tree says what a genome restores to — every file and its
// digest — from the bundle header alone, and digests that tree.
//
// It reads and writes nothing, so the release authority can compute the
// tree a destination must have restored (to check its receipt) without
// linking any code that materialises a genome.
package tree

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
)

// StagingPrefix is reserved for the staging directories a restore
// creates inside its target; no genome file may live under it.
const StagingPrefix = ".vg-staging-"

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// The snapshot fields a tree needs. They mirror contentdir.Snapshot and
// ollama.Snapshot, which this package does not import.
type dirSnapshot struct {
	Components []struct {
		Path   string `json:"path"`
		Digest string `json:"digest"`
	} `json:"components"`
}

type ollamaSnapshot struct {
	ManifestPath string `json:"manifest_path"`
	Components   []struct {
		Role   string `json:"role"`
		Digest string `json:"digest"`
	} `json:"components"`
}

// Files maps every file a restore of h holds — a forward-slash path under
// the restore target — to its "sha256:<hex>" digest. The snapshot comes
// from a bundle, so every path is checked to stay inside the target and
// every digest to be a digest before either is used.
func Files(h bundle.Header) (map[string]string, error) {
	files := map[string]string{}
	switch h.ContentKind {
	case bundle.ContentDir:
		var snap dirSnapshot
		if err := json.Unmarshal(h.ContentSnapshot, &snap); err != nil {
			return nil, fmt.Errorf("tree: dir snapshot: %w", err)
		}
		for _, c := range snap.Components {
			if !filepath.IsLocal(filepath.FromSlash(c.Path)) {
				return nil, fmt.Errorf("tree: component path %q is not inside the restored directory", c.Path)
			}
			if !digestRE.MatchString(c.Digest) {
				return nil, fmt.Errorf("tree: %s: digest %q is not sha256:<64 hex>", c.Path, c.Digest)
			}
			files[c.Path] = c.Digest
		}
	case bundle.ContentOllama:
		var snap ollamaSnapshot
		if err := json.Unmarshal(h.ContentSnapshot, &snap); err != nil {
			return nil, fmt.Errorf("tree: ollama snapshot: %w", err)
		}
		if !filepath.IsLocal(snap.ManifestPath) {
			return nil, fmt.Errorf("tree: manifest path %q is not local", snap.ManifestPath)
		}
		manifest := "models/" + filepath.ToSlash(snap.ManifestPath)
		for _, c := range snap.Components {
			if !digestRE.MatchString(c.Digest) {
				return nil, fmt.Errorf("tree: %s component digest %q is not sha256:<64 hex>", c.Role, c.Digest)
			}
			if c.Role == "manifest" {
				files[manifest] = c.Digest
				continue
			}
			files["models/blobs/"+strings.Replace(c.Digest, ":", "-", 1)] = c.Digest
		}
		if _, ok := files[manifest]; !ok {
			return nil, errors.New("tree: the ollama snapshot has no manifest component")
		}
	default:
		return nil, fmt.Errorf("tree: unknown content kind %q", h.ContentKind)
	}
	if len(files) == 0 {
		return nil, errors.New("tree: the snapshot lists no files")
	}
	for p := range files {
		if strings.HasPrefix(p, StagingPrefix) {
			return nil, fmt.Errorf("tree: snapshot path %q is reserved", p)
		}
	}
	return files, nil
}

// Digest is the tree digest of a set of files: SHA-256 over the sorted
// lines "<path> <sha256 hex>\n". It measures the files, not how they
// were packed, so the same genome restored anywhere has the same digest.
func Digest(files map[string]string) string {
	h := sha256.New()
	for _, p := range Paths(files) {
		fmt.Fprintf(h, "%s %s\n", p, strings.TrimPrefix(files[p], "sha256:"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Paths returns the paths of files in sorted order.
func Paths(files map[string]string) []string {
	out := make([]string, 0, len(files))
	for p := range files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
