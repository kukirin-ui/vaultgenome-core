// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package contentdir

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
)

// Fingerprint is a cheap digest of what Capture would read from sourceDir:
// every regular file's path, size, modification time and mode, without
// reading any content. It changes whenever the payload may have changed,
// so a watcher can poll it and capture only when it moves. (It can also
// change when the payload did not — a file touched but not modified — so
// it decides when to look, never what was sealed.)
func Fingerprint(sourceDir string) (string, error) {
	abs, err := filepath.Abs(sourceDir)
	if err != nil {
		return "", fmt.Errorf("contentdir: abs %s: %w", sourceDir, err)
	}
	var lines []string
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(abs, path)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s\x00%d\x00%d\x00%o\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano(), info.Mode()))
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("contentdir: walk: %w", err)
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
