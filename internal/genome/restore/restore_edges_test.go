// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restore

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contentdir"
)

// skipIfRoot skips a permission-based case when the test runs with
// privileges that ignore file modes.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not restrict root")
	}
}

// Restore refuses a target it cannot prepare — a path under a file, a
// directory it cannot open, a directory it cannot write a staging area
// into — before reading a byte of the payload, and names the step.
func TestRestore_RefusesATargetItCannotPrepare(t *testing.T) {
	blob, dek := sealDir(t, adapter)

	t.Run("target under a file", func(t *testing.T) {
		parent := t.TempDir()
		file := filepath.Join(parent, "file")
		require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
		h, payload := openStream(t, blob, dek)
		_, err := Restore(h, payload, filepath.Join(file, "target"))
		require.ErrorContains(t, err, "restore: create target")
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		require.Equal(t, "x", string(data), "the file in the way is untouched")
	})

	t.Run("target cannot be opened", func(t *testing.T) {
		skipIfRoot(t)
		target := filepath.Join(t.TempDir(), "sealed")
		require.NoError(t, os.Mkdir(target, 0o000))
		t.Cleanup(func() { _ = os.Chmod(target, 0o700) })
		h, payload := openStream(t, blob, dek)
		_, err := Restore(h, payload, target)
		require.ErrorContains(t, err, "restore: open target")
	})

	t.Run("target is read-only", func(t *testing.T) {
		skipIfRoot(t)
		target := filepath.Join(t.TempDir(), "readonly")
		require.NoError(t, os.Mkdir(target, 0o500))
		t.Cleanup(func() { _ = os.Chmod(target, 0o700) })
		h, payload := openStream(t, blob, dek)
		_, err := Restore(h, payload, target)
		require.ErrorContains(t, err, "restore: create staging")
		entries, err := os.ReadDir(target)
		require.NoError(t, err)
		require.Empty(t, entries, "nothing is written into a read-only target")
	})
}

// Moving verified files into place can collide with what the target
// already holds under a genome path: a file where the genome needs a
// directory, or a directory where it needs a file. The error says the
// target holds part of the genome, and the verified files stay in place
// up to the collision.
func TestRestore_MoveCollisionsAreReported(t *testing.T) {
	cases := map[string]struct {
		prepare func(t *testing.T, target string)
		at      string
	}{
		"file where a directory is needed": {
			prepare: func(t *testing.T, target string) {
				require.NoError(t, os.WriteFile(filepath.Join(target, "tokenizer"), []byte("not a dir"), 0o644))
			},
			at: "tokenizer/special.json",
		},
		"directory where a file is needed": {
			prepare: func(t *testing.T, target string) {
				require.NoError(t, os.Mkdir(filepath.Join(target, "adapter_config.json"), 0o755))
			},
			at: "adapter_config.json",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			blob, dek := sealDir(t, adapter)
			h, payload := openStream(t, blob, dek)
			target := t.TempDir()
			tc.prepare(t, target)
			_, err := Restore(h, payload, target)
			require.ErrorContains(t, err, "moving verified files into place failed at "+tc.at)
			require.ErrorContains(t, err, "target holds part of the genome")
			requireNoStaging(t, target)
		})
	}
}

// tarWith writes a tar of regular files in the given order.
func tarWith(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: e[0], Mode: 0o644, Size: int64(len(e[1])), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(e[1]))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

// A snapshot path that the payload fills with a directory is refused: a
// directory has no digest to match, whichever side it is checked on.
func TestRestore_RefusesADirectoryWhereAFileIsListed(t *testing.T) {
	snap := contentdir.Snapshot{Components: []contentdir.Component{{Path: "a.txt", Digest: digest("A"), Size: 1}}}
	h, payload := sealCrafted(t, snap, tarWith(t, [][2]string{{"a.txt/inner", "A"}}))
	target := filepath.Join(t.TempDir(), "t")
	_, err := Restore(h, payload, target)
	require.ErrorContains(t, err, "restore: a.txt: not a regular file")
	_, statErr := os.Stat(target)
	require.True(t, os.IsNotExist(statErr), "nothing restored")

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a.txt"), 0o755))
	_, err = Verify(h, dir)
	require.ErrorContains(t, err, "restore: a.txt: not a regular file")
}

// drainChmod serves a tar and, once the tar has been consumed and the
// restore drains the stream to its end, makes a directory inside the
// staging area unreadable — the state a restore meets when the host
// changes permissions under it between extraction and verification.
type drainChmod struct {
	t      *testing.T
	data   []byte
	off    int
	target string
	sub    string
	done   bool
}

func (d *drainChmod) Read(p []byte) (int, error) {
	if d.off < len(d.data) {
		n := copy(p, d.data[d.off:])
		d.off += n
		return n, nil
	}
	if !d.done {
		d.done = true
		entries, err := os.ReadDir(d.target)
		require.NoError(d.t, err)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), StagingPrefix) {
				dir := filepath.Join(d.target, e.Name(), d.sub)
				require.NoError(d.t, os.Chmod(dir, 0o000))
				d.t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			}
		}
	}
	return 0, io.EOF
}

// The exactness walk over the staged tree surfaces a directory it cannot
// read instead of passing a tree it could not fully inspect.
func TestRestore_UnreadableStagedDirectoryFailsTheWalk(t *testing.T) {
	skipIfRoot(t)
	snap := contentdir.Snapshot{Components: []contentdir.Component{{Path: "a.txt", Digest: digest("A"), Size: 1}}}
	raw := tarWith(t, [][2]string{{"a.txt", "A"}, {"extra/b.txt", "B"}})
	target := filepath.Join(t.TempDir(), "t")
	h, _ := sealCrafted(t, snap, raw)
	_, err := Restore(h, &drainChmod{t: t, data: raw, target: target, sub: "extra"}, target)
	require.Error(t, err)
	require.ErrorContains(t, err, "permission denied")
	require.NotContains(t, err.Error(), "does not list", "the walk stops at the unreadable directory, not at its contents")
}
