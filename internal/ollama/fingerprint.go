// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package ollama

import (
	"fmt"
	"os"
	"path/filepath"
)

// Fingerprint is a cheap digest of the model modelRef names: the SHA-256
// of its manifest. Blobs are content-addressed and the manifest lists
// them by digest, so a model whose content changed has a new manifest; a
// watcher can poll this and capture only when it moves.
func Fingerprint(modelRef, ollamaHome string) (string, error) {
	manifestRel, err := manifestPathFor(modelRef)
	if err != nil {
		return "", err
	}
	manifest, err := os.ReadFile(filepath.Join(ollamaHome, "models", manifestRel))
	if err != nil {
		return "", fmt.Errorf("ollama fingerprint: %w", err)
	}
	return digestOf(manifest), nil
}
