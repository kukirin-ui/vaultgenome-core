// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tree

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
)

var (
	dA = "sha256:" + strings.Repeat("a", 64)
	dB = "sha256:" + strings.Repeat("b", 64)
	dC = "sha256:" + strings.Repeat("c", 64)
)

func header(kind, snapshot string) bundle.Header {
	return bundle.Header{ContentKind: kind, ContentSnapshot: json.RawMessage(snapshot)}
}

func TestFiles_Directory(t *testing.T) {
	files, err := Files(header(bundle.ContentDir, `{"components":[{"path":"adapter.safetensors","digest":"`+dA+`"},{"path":"tok/cfg.json","digest":"`+dB+`"}]}`))
	require.NoError(t, err)
	require.Equal(t, map[string]string{"adapter.safetensors": dA, "tok/cfg.json": dB}, files)
	require.Equal(t, []string{"adapter.safetensors", "tok/cfg.json"}, Paths(files))
}

func TestFiles_Ollama(t *testing.T) {
	files, err := Files(header(bundle.ContentOllama, `{"manifest_path":"manifests/registry.ollama.ai/library/qwen/0.5b","components":[
		{"role":"manifest","digest":"`+dA+`"},{"role":"config","digest":"`+dB+`"},{"role":"layer","digest":"`+dC+`"}]}`))
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"models/manifests/registry.ollama.ai/library/qwen/0.5b": dA,
		"models/blobs/sha256-" + strings.Repeat("b", 64):        dB,
		"models/blobs/sha256-" + strings.Repeat("c", 64):        dC,
	}, files)
}

// A snapshot comes from a bundle: nothing in it may name a path outside
// the target, or pass a non-digest off as a digest.
func TestFiles_RefusesWhatCouldEscapeOrMislead(t *testing.T) {
	for name, h := range map[string]bundle.Header{
		"unknown kind":         header("exe", `{}`),
		"bad json":             header(bundle.ContentDir, `[`),
		"dir parent":           header(bundle.ContentDir, `{"components":[{"path":"../x","digest":"`+dA+`"}]}`),
		"dir absolute":         header(bundle.ContentDir, `{"components":[{"path":"/etc/x","digest":"`+dA+`"}]}`),
		"dir bad digest":       header(bundle.ContentDir, `{"components":[{"path":"x","digest":"md5:1"}]}`),
		"dir reserved":         header(bundle.ContentDir, `{"components":[{"path":"`+StagingPrefix+`1/x","digest":"`+dA+`"}]}`),
		"dir empty":            header(bundle.ContentDir, `{"components":[]}`),
		"ollama bad json":      header(bundle.ContentOllama, `[`),
		"ollama escape":        header(bundle.ContentOllama, `{"manifest_path":"../../m","components":[{"role":"manifest","digest":"`+dA+`"}]}`),
		"ollama digest path":   header(bundle.ContentOllama, `{"manifest_path":"m","components":[{"role":"layer","digest":"sha256:../../x"}]}`),
		"ollama no manifest":   header(bundle.ContentOllama, `{"manifest_path":"m","components":[{"role":"layer","digest":"`+dA+`"}]}`),
		"ollama no components": header(bundle.ContentOllama, `{"manifest_path":"m","components":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Files(h)
			require.Error(t, err)
		})
	}
}

// The digest measures the files, not their order or packing.
func TestDigest(t *testing.T) {
	a := map[string]string{"x": dA, "y/z": dB}
	b := map[string]string{"y/z": dB, "x": dA}
	require.Equal(t, Digest(a), Digest(b))
	require.Len(t, Digest(a), 64)
	require.NotEqual(t, Digest(a), Digest(map[string]string{"x": dB, "y/z": dA}))
	require.NotEqual(t, Digest(a), Digest(map[string]string{"x": dA}))
}
