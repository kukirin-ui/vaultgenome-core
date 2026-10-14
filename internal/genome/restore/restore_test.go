// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restore

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contentdir"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/tree"
	"github.com/vault-genome/vaultgenome-core/internal/ollama"
)

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
}

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = string(data)
		return err
	}))
	return out
}

var adapter = map[string]string{
	"adapter_config.json":       `{"r":16}`,
	"adapter_model.safetensors": strings.Repeat("delta", 5000),
	"tokenizer/special.json":    `{"eos":"</s>"}`,
}

// sealDir seals a directory the way acpctl does and returns the bundle
// and its key.
func sealDir(t *testing.T, files map[string]string) ([]byte, []byte) {
	t.Helper()
	src := t.TempDir()
	writeTree(t, src, files)
	snap, payload, err := contentdir.CapturePayload(src)
	require.NoError(t, err)
	raw, err := json.Marshal(snap)
	require.NoError(t, err)
	blob, dek, err := bundle.SealBytes(bundle.Header{
		ContentKind: bundle.ContentDir, ContentRef: src, ContentSnapshot: raw, SegmentBytes: bundle.MinSegmentBytes,
	}, payload)
	require.NoError(t, err)
	return blob, dek
}

func openStream(t *testing.T, blob, dek []byte) (bundle.Header, io.Reader) {
	t.Helper()
	r, err := bundle.NewReader(bytes.NewReader(blob))
	require.NoError(t, err)
	payload, err := r.PayloadWithKey(dek)
	require.NoError(t, err)
	return r.Header, payload
}

func requireNoStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), StagingPrefix), "staging %s left behind", e.Name())
	}
}

func TestRestore_DirectoryIsExactAndMeasured(t *testing.T) {
	blob, dek := sealDir(t, adapter)
	h, payload := openStream(t, blob, dek)
	target := filepath.Join(t.TempDir(), "restored")

	res, err := Restore(h, payload, target)
	require.NoError(t, err)
	require.Equal(t, adapter, readTree(t, target))
	require.Equal(t, 3, res.Files)
	require.Equal(t, h.PayloadSHA256, res.PayloadSHA256)
	require.EqualValues(t, len(adapter["adapter_config.json"])+len(adapter["adapter_model.safetensors"])+len(adapter["tokenizer/special.json"]), res.BytesWritten)

	files, err := tree.Files(h)
	require.NoError(t, err)
	require.Equal(t, tree.Digest(files), res.TreeSHA256)
	digest, err := Verify(h, target)
	require.NoError(t, err)
	require.Equal(t, res.TreeSHA256, digest)

	// The same genome sealed again (new key, new bundle) restores to the
	// same tree digest: it measures the files, not the packing.
	blob2, dek2 := sealDir(t, adapter)
	h2, payload2 := openStream(t, blob2, dek2)
	res2, err := Restore(h2, payload2, filepath.Join(t.TempDir(), "again"))
	require.NoError(t, err)
	require.Equal(t, res.TreeSHA256, res2.TreeSHA256)
	requireNoStaging(t, target)
}

// Restoring into a directory that already holds files replaces the
// genome's files and leaves the others alone.
func TestRestore_MergesIntoAnExistingTarget(t *testing.T) {
	blob, dek := sealDir(t, adapter)
	h, payload := openStream(t, blob, dek)
	target := t.TempDir()
	writeTree(t, target, map[string]string{"adapter_config.json": "stale", "notes.txt": "keep me"})

	_, err := Restore(h, payload, target)
	require.NoError(t, err)
	got := readTree(t, target)
	require.Equal(t, adapter["adapter_config.json"], got["adapter_config.json"])
	require.Equal(t, "keep me", got["notes.txt"])
	requireNoStaging(t, target)

	_, err = Verify(h, target)
	require.NoError(t, err, "extra files do not fail Verify")
}

// A payload that does not open — wrong bytes anywhere — leaves the target
// exactly as it was, and a target Restore created is removed again.
func TestRestore_FailureLeavesTheTargetUntouched(t *testing.T) {
	blob, dek := sealDir(t, adapter)
	// Corrupt the last segment: the tar extracts fully from the earlier
	// segments' bytes only if the stream is not checked to its end.
	corrupt := append([]byte(nil), blob...)
	corrupt[len(corrupt)-5] ^= 0x10

	existing := t.TempDir()
	writeTree(t, existing, map[string]string{"notes.txt": "keep me", "adapter_config.json": "old"})
	h, payload := openStream(t, corrupt, dek)
	_, err := Restore(h, payload, existing)
	require.Error(t, err)
	require.Equal(t, map[string]string{"notes.txt": "keep me", "adapter_config.json": "old"}, readTree(t, existing))
	requireNoStaging(t, existing)

	fresh := filepath.Join(t.TempDir(), "fresh")
	h, payload = openStream(t, corrupt, dek)
	_, err = Restore(h, payload, fresh)
	require.Error(t, err)
	_, err = os.Stat(fresh)
	require.True(t, os.IsNotExist(err), "a target Restore created is removed on failure")
}

// A complete tar is not a complete payload: a stream that ends in an
// error after the tar's end marker fails the restore.
func TestRestore_ReadsToTheAuthenticatedEnd(t *testing.T) {
	blob, dek := sealDir(t, adapter)
	h, payload := openStream(t, blob, dek)
	whole, err := io.ReadAll(payload)
	require.NoError(t, err)
	stream := io.MultiReader(bytes.NewReader(whole), errReader{errors.New("bundle: data after the last segment")})
	target := filepath.Join(t.TempDir(), "t")
	_, err = Restore(h, stream, target)
	require.ErrorContains(t, err, "data after the last segment")
	_, err = os.Stat(target)
	require.True(t, os.IsNotExist(err))
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func tarOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range []string{"a.txt", "b.txt", "../escape.txt", "c.txt"} {
		data, ok := files[name]
		if !ok {
			continue
		}
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(data))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

// sealCrafted seals an arbitrary tar under an arbitrary snapshot — what
// a key holder who wanted to mislead a destination could produce.
func sealCrafted(t *testing.T, snap contentdir.Snapshot, payload []byte) (bundle.Header, io.Reader) {
	t.Helper()
	raw, err := json.Marshal(snap)
	require.NoError(t, err)
	blob, dek, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentDir, ContentRef: "/x", ContentSnapshot: raw}, payload)
	require.NoError(t, err)
	return openStream(t, blob, dek)
}

func digest(s string) string { return bundle.PayloadDigest([]byte(s)) }

// The restored tree must be exactly the tree the snapshot lists.
func TestRestore_RefusesATreeTheSnapshotDoesNotDescribe(t *testing.T) {
	a := contentdir.Component{Path: "a.txt", Digest: digest("A"), Size: 1}
	for name, tc := range map[string]struct {
		snap    contentdir.Snapshot
		payload map[string]string
		want    string
	}{
		"extra file":       {contentdir.Snapshot{Components: []contentdir.Component{a}}, map[string]string{"a.txt": "A", "b.txt": "B"}, "does not list"},
		"missing file":     {contentdir.Snapshot{Components: []contentdir.Component{a, {Path: "c.txt", Digest: digest("C")}}}, map[string]string{"a.txt": "A"}, "c.txt"},
		"other content":    {contentdir.Snapshot{Components: []contentdir.Component{a}}, map[string]string{"a.txt": "Z"}, "digest mismatch"},
		"escaping entry":   {contentdir.Snapshot{Components: []contentdir.Component{a}}, map[string]string{"a.txt": "A", "../escape.txt": "E"}, "non-local"},
		"escaping path":    {contentdir.Snapshot{Components: []contentdir.Component{{Path: "../a.txt", Digest: digest("A")}}}, map[string]string{"a.txt": "A"}, "not inside"},
		"reserved path":    {contentdir.Snapshot{Components: []contentdir.Component{{Path: StagingPrefix + "x/a.txt", Digest: digest("A")}}}, map[string]string{"a.txt": "A"}, "reserved"},
		"empty snapshot":   {contentdir.Snapshot{}, map[string]string{"a.txt": "A"}, "no files"},
		"absolute path":    {contentdir.Snapshot{Components: []contentdir.Component{{Path: "/etc/passwd", Digest: digest("A")}}}, map[string]string{"a.txt": "A"}, "not inside"},
		"digest is a path": {contentdir.Snapshot{Components: []contentdir.Component{{Path: "a.txt", Digest: "sha256:../../x"}}}, map[string]string{"a.txt": "A"}, "not sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			h, payload := sealCrafted(t, tc.snap, tarOf(t, tc.payload))
			parent := t.TempDir()
			target := filepath.Join(parent, "t")
			_, err := Restore(h, payload, target)
			require.ErrorContains(t, err, tc.want)
			_, statErr := os.Stat(target)
			require.True(t, os.IsNotExist(statErr), "nothing restored")
			entries, err := os.ReadDir(parent)
			require.NoError(t, err)
			require.Empty(t, entries, "nothing written beside the target")
		})
	}
}

func TestFiles_RefusesUnknownOrBrokenSnapshots(t *testing.T) {
	for name, h := range map[string]bundle.Header{
		"unknown kind":    {ContentKind: "exe"},
		"bad dir json":    {ContentKind: bundle.ContentDir, ContentSnapshot: json.RawMessage(`[`)},
		"bad ollama json": {ContentKind: bundle.ContentOllama, ContentSnapshot: json.RawMessage(`[`)},
		"ollama escape":   {ContentKind: bundle.ContentOllama, ContentSnapshot: json.RawMessage(`{"manifest_path":"../../x","components":[]}`)},
		"ollama bad blob": {ContentKind: bundle.ContentOllama, ContentSnapshot: json.RawMessage(`{"manifest_path":"manifests/m","components":[{"role":"layer","digest":"sha256:../x"}]}`)},
		"ollama no manifest": {ContentKind: bundle.ContentOllama, ContentSnapshot: json.RawMessage(
			`{"manifest_path":"manifests/m","components":[{"role":"layer","digest":"sha256:` + strings.Repeat("a", 64) + `"}]}`)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tree.Files(h)
			require.Error(t, err)
			_, err = Restore(h, bytes.NewReader(nil), filepath.Join(t.TempDir(), "t"))
			require.Error(t, err)
			_, err = Verify(h, t.TempDir())
			require.Error(t, err)
		})
	}
}

// An Ollama model restores into a fresh store, blob by blob verified.
func TestRestore_OllamaModel(t *testing.T) {
	home := t.TempDir()
	blobs := filepath.Join(home, "models", "blobs")
	require.NoError(t, os.MkdirAll(blobs, 0o755))
	layer := func(data, mediaType string) ollama.Layer {
		d := digest(data)
		require.NoError(t, os.WriteFile(filepath.Join(blobs, strings.Replace(d, ":", "-", 1)), []byte(data), 0o644))
		return ollama.Layer{MediaType: mediaType, Digest: d, Size: int64(len(data))}
	}
	mf := ollama.ManifestRef{
		SchemaVersion: 2,
		Config:        layer(`{"model_family":"llama"}`, "application/vnd.docker.container.image.v1+json"),
		Layers:        []ollama.Layer{layer(strings.Repeat("GGUF", 9000), "application/vnd.ollama.image.model")},
	}
	raw, err := json.Marshal(mf)
	require.NoError(t, err)
	mp := filepath.Join(home, "models", "manifests", "registry.ollama.ai", "library", "tiny", "1b")
	require.NoError(t, os.MkdirAll(filepath.Dir(mp), 0o755))
	require.NoError(t, os.WriteFile(mp, raw, 0o644))

	var payload bytes.Buffer
	snap, n, err := ollama.Capture("tiny:1b", home, &payload)
	require.NoError(t, err)
	require.EqualValues(t, payload.Len(), n)
	snapJSON, err := json.Marshal(snap)
	require.NoError(t, err)
	blob, dek, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentOllama, ContentRef: "tiny:1b", ContentSnapshot: snapJSON}, payload.Bytes())
	require.NoError(t, err)

	h, stream := openStream(t, blob, dek)
	target := filepath.Join(t.TempDir(), "ollama")
	res, err := Restore(h, stream, target)
	require.NoError(t, err)
	require.Equal(t, 3, res.Files)
	require.Equal(t, readTree(t, home), readTree(t, target))
	require.NoError(t, ollama.VerifyComponents(snap, target))
	_, err = Verify(h, target)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(target, "models", "blobs", strings.Replace(mf.Layers[0].Digest, ":", "-", 1)), []byte("tampered"), 0o644))
	_, err = Verify(h, target)
	require.ErrorContains(t, err, "digest mismatch")
	require.NoError(t, os.Remove(filepath.Join(target, "models", "blobs", strings.Replace(mf.Layers[0].Digest, ":", "-", 1))))
	_, err = Verify(h, target)
	require.Error(t, err)
	_, err = Verify(h, filepath.Join(target, "absent"))
	require.Error(t, err)
}
