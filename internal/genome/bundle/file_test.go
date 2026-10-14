// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// memCapture captures payload with a snapshot naming its digest.
func memCapture(payload []byte) Capture {
	return func(w io.Writer) (json.RawMessage, int64, error) {
		n, err := w.Write(payload)
		snap := fmt.Sprintf(`{"payload_sha256":%q}`, PayloadDigest(payload))
		return json.RawMessage(snap), int64(n), err
	}
}

func TestDescribeThenSealFile(t *testing.T) {
	payload := bytes.Repeat([]byte("adapter weights "), 5000)
	h, err := Describe(ContentDir, "/models/adapter", memCapture(payload))
	if err != nil {
		t.Fatal(err)
	}
	if h.PayloadSHA256 != PayloadDigest(payload) || h.PayloadBytes != int64(len(payload)) || h.ContentKind != ContentDir {
		t.Fatalf("header %+v", h)
	}
	path := filepath.Join(t.TempDir(), "g.genome.partial")
	out, err := SealFile(path, h, memCapture(payload))
	if err != nil {
		t.Fatal(err)
	}
	id, err := Identify(path)
	if err != nil {
		t.Fatal(err)
	}
	if id.SHA256 != out.SHA256 || id.Size != out.Size || id.Header.KeyID != out.Header.KeyID {
		t.Fatalf("SealFile says %s/%d, the file is %s/%d", out.SHA256, out.Size, id.SHA256, id.Size)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := OpenBytes(blob, out.DEK)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("open: %v", err)
	}
}

func TestSealFileRefusesAChangedSource(t *testing.T) {
	h, err := Describe(ContentDir, "/models/adapter", memCapture([]byte("first pass")))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "g.genome.partial")
	if _, err := SealFile(path, h, memCapture([]byte("FIRST PASS"))); err == nil || !strings.Contains(err.Error(), "change") {
		t.Fatalf("a source that changed between passes: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the partial bundle was left behind")
	}
	failing := func(io.Writer) (json.RawMessage, int64, error) { return nil, 0, errors.New("disk gone") }
	if _, err := SealFile(path, h, failing); err == nil {
		t.Fatal("a failing capture sealed")
	}
	if _, err := SealFile(filepath.Join(t.TempDir(), "absent", "g.genome"), h, memCapture([]byte("first pass"))); err == nil {
		t.Fatal("sealed into a missing directory")
	}
}

func TestDescribeRefusesWhatIsNotASnapshot(t *testing.T) {
	for name, c := range map[string]Capture{
		"capture fails": func(io.Writer) (json.RawMessage, int64, error) { return nil, 0, errors.New("unreadable") },
		"not json":      func(io.Writer) (json.RawMessage, int64, error) { return json.RawMessage("{"), 0, nil },
		"no digest":     func(io.Writer) (json.RawMessage, int64, error) { return json.RawMessage(`{"files":1}`), 0, nil },
	} {
		if _, err := Describe(ContentDir, "x", c); err == nil {
			t.Errorf("%s: described", name)
		}
	}
}
