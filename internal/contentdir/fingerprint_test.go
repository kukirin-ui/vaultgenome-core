// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package contentdir

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The fingerprint moves with anything Capture would see differently, and
// stays put otherwise.
func TestFingerprint_MovesWithTheTree(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "a.bin"), []byte("one"), 0o644))
	fp := func() string {
		t.Helper()
		f, err := Fingerprint(dir)
		must(err)
		return f
	}
	first := fp()
	if fp() != first {
		t.Fatal("fingerprint moved without a change")
	}
	for name, change := range map[string]func(){
		"content": func() { must(os.WriteFile(filepath.Join(dir, "a.bin"), []byte("two!"), 0o644)) },
		"mtime": func() {
			at := time.Now().Add(time.Hour)
			must(os.Chtimes(filepath.Join(dir, "a.bin"), at, at))
		},
		"mode":     func() { must(os.Chmod(filepath.Join(dir, "a.bin"), 0o600)) },
		"new file": func() { must(os.WriteFile(filepath.Join(dir, "sub.bin"), []byte("x"), 0o644)) },
	} {
		before := fp()
		change()
		if fp() == before {
			t.Errorf("%s: fingerprint did not move", name)
		}
	}
	if _, err := Fingerprint(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("fingerprint of a missing directory")
	}
}
