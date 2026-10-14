// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// A file sealed at the origin does not come back on a destination of
// another identity: the narration says so and reports no byte-exact
// restore, instead of pretending.
func TestSealRealFile_AnotherDestinationCannotRestore(t *testing.T) {
	seed := sha256.Sum256([]byte("vaultgenome-demo-workload"))
	origin, err := tee.NewSimulated([]byte("vaultgenome-origin"), seed[:])
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := tee.NewSimulated([]byte("vaultgenome-stranger"), seed[:])
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "model.bin")
	if err := os.WriteFile(path, []byte("weights"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if (printer{&buf}).sealRealFile(origin, stranger, path) {
		t.Fatal("a destination of another identity reported a byte-exact restore")
	}
	if !strings.Contains(buf.String(), "restore mismatch") {
		t.Fatalf("narration lacks the mismatch:\n%s", buf.String())
	}

	buf.Reset()
	if !(printer{&buf}).sealRealFile(origin, origin, path) {
		t.Fatal("the origin could not restore its own sealed file")
	}
	if !strings.Contains(buf.String(), "sealed and restored BYTE-EXACT") {
		t.Fatalf("narration lacks the byte-exact report:\n%s", buf.String())
	}
}
