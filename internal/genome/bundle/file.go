// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Capture streams a payload to w and describes it: the content kind's
// snapshot (which carries the payload's "payload_sha256") and the number
// of bytes written. Run twice over unchanged content, it must write the
// same bytes — sealing is two passes over the source (Describe, then
// SealFile), and a source that changed between them is refused.
type Capture func(w io.Writer) (snapshot json.RawMessage, n int64, err error)

// Describe runs capture once, keeping nothing of the payload, and returns a
// header describing it: kind, ref, snapshot, digest and size. The caller
// adds the chain-of-custody fields before sealing.
func Describe(kind, ref string, capture Capture) (Header, error) {
	snapshot, n, err := capture(io.Discard)
	if err != nil {
		return Header{}, err
	}
	var probe struct {
		PayloadSHA256 string `json:"payload_sha256"`
	}
	if err := json.Unmarshal(snapshot, &probe); err != nil {
		return Header{}, fmt.Errorf("bundle: snapshot: %w", err)
	}
	if !payloadDigestRE.MatchString(probe.PayloadSHA256) {
		return Header{}, errors.New("bundle: the snapshot names no payload_sha256")
	}
	return Header{
		ContentKind:     kind,
		ContentRef:      ref,
		ContentSnapshot: snapshot,
		PayloadSHA256:   probe.PayloadSHA256,
		PayloadBytes:    n,
	}, nil
}

// Sealed is a bundle SealFile wrote: its header, its key, and the file's
// size and SHA-256 (hex).
type Sealed struct {
	Header Header
	DEK    []byte
	Size   int64
	SHA256 string
}

// SealFile streams the payload capture produces through Seal into the file
// at path (created or truncated, mode 0644) and syncs it. h must describe
// the payload (Describe); Seal refuses a stream that is not that payload.
// On error the file is removed. The caller moves the file into place only
// once the key is stored, so a bundle is never left whose key was lost.
func SealFile(path string, h Header, capture Capture) (Sealed, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return Sealed{}, err
	}
	pr, pw := io.Pipe()
	go func() {
		_, _, err := capture(pw)
		_ = pw.CloseWithError(err)
	}()
	sum := sha256.New()
	counted := &countingWriter{w: io.MultiWriter(f, sum)}
	sealed, dek, err := Seal(counted, h, pr)
	_ = pr.CloseWithError(errors.New("sealing stopped"))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return Sealed{}, err
	}
	return Sealed{Header: sealed, DEK: dek, Size: counted.n, SHA256: hex.EncodeToString(sum.Sum(nil))}, nil
}
