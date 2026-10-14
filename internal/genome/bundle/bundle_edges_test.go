// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// Seal refuses a header it cannot encode or that would not fit a reader's
// header bound, before any key or byte of output exists.
func TestSeal_RefusesUnencodableOrOversizedHeader(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		snapshot json.RawMessage
		want     string
	}{
		"snapshot is not json":    {json.RawMessage(`{"components":`), "bundle: encode header"},
		"header over the maximum": {json.RawMessage(`"` + strings.Repeat("a", MaxHeaderBytes) + `"`), "bundle: header is"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := header()
			h.ContentSnapshot = tc.snapshot
			h.PayloadSHA256 = PayloadDigest(payload)
			h.PayloadBytes = int64(len(payload))
			var out bytes.Buffer
			_, dek, err := Seal(&out, h, bytes.NewReader(payload))
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, dek)
			require.Zero(t, out.Len(), "nothing is written for a refused header")
		})
	}
}

// Seal surfaces the destination's write error, whether it strikes while
// the header is going out (a header larger than the write buffer) or
// while the segments are (a payload larger than the write buffer).
func TestSeal_SurfacesWriteErrors(t *testing.T) {
	t.Parallel()
	bigSnapshot := json.RawMessage(`"` + strings.Repeat("s", 1<<17) + `"`)
	cases := map[string]struct {
		mutate  func(h *Header)
		payload []byte
	}{
		"while writing the header":   {func(h *Header) { h.ContentSnapshot = bigSnapshot }, []byte("tiny")},
		"while writing the segments": {func(h *Header) { h.SegmentBytes = MinSegmentBytes }, bytes.Repeat([]byte("w"), 40*MinSegmentBytes)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := header()
			tc.mutate(&h)
			h.PayloadSHA256 = PayloadDigest(tc.payload)
			h.PayloadBytes = int64(len(tc.payload))
			_, dek, err := Seal(failingWriter{}, h, bytes.NewReader(tc.payload))
			require.ErrorContains(t, err, "bundle: write: disk full")
			require.Nil(t, dek)
		})
	}
}

// OpenBytes reports a bundle that is not a bundle, and a bundle whose
// segments do not open, without returning any payload.
func TestOpenBytes_RefusesWhatItCannotOpen(t *testing.T) {
	t.Parallel()
	b, dek := seal(t, small(), payload)
	edited := append([]byte(nil), b...)
	edited[len(edited)-1] ^= 0x01

	cases := map[string]struct {
		blob []byte
		dek  []byte
		want string
	}{
		"not a bundle":          {[]byte("plain text"), dek, "not a v3 Vault Genome bundle"},
		"last segment edited":   {edited, dek, "does not open under key"},
		"key of another bundle": {b, bytes.Repeat([]byte{7}, crypto.AES256KeySize), "this key is not"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, h, err := OpenBytes(tc.blob, tc.dek)
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, got)
			require.Equal(t, Header{}, h)
		})
	}
}

// craft writes a bundle under a caller-chosen DEK from a header taken as
// given, so a test can produce what Seal never would: a header, fully
// authenticated by every segment, that describes a payload other than the
// one the segments carry.
func craft(t *testing.T, h Header, dek, p []byte) []byte {
	t.Helper()
	h.Format = Format
	h.KeyID = NewKeyID(h.PayloadSHA256, h.Generation, dek)
	if h.SegmentBytes == 0 {
		h.SegmentBytes = DefaultSegmentBytes
	}
	require.NoError(t, h.validate())
	hb, err := json.Marshal(h)
	require.NoError(t, err)
	prefix := make([]byte, noncePrefixSize)
	_, err = io.ReadFull(rand.Reader, prefix)
	require.NoError(t, err)
	aead, err := crypto.NewGCM(dek)
	require.NoError(t, err)

	var out bytes.Buffer
	out.WriteString(Magic)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(hb)))
	out.Write(n[:])
	out.Write(hb)
	out.Write(prefix)
	aad := segmentAAD(hb)
	count := segmentCount(h.PayloadBytes, h.SegmentBytes)
	for i := range count {
		size := min(h.SegmentBytes, h.PayloadBytes-i*h.SegmentBytes)
		seg := p[i*h.SegmentBytes : i*h.SegmentBytes+size]
		out.Write(aead.Seal(nil, segmentNonce(prefix, i, i == count-1), seg, aad))
	}
	return out.Bytes()
}

// A header that lies about its payload's digest is caught at the end of
// the stream even though every segment authenticates under it: the
// reader releases the segments (they are authentic under the key) but
// refuses to end the stream with io.EOF, so a consumer that reads to the
// end never trusts a payload the header does not describe.
func TestOpen_RefusesAHeaderThatMisdescribesItsPayload(t *testing.T) {
	t.Parallel()
	dek := make([]byte, crypto.AES256KeySize)
	_, err := io.ReadFull(rand.Reader, dek)
	require.NoError(t, err)

	h := small()
	h.PayloadSHA256 = PayloadDigest([]byte("the payload the header claims"))
	h.PayloadBytes = int64(len(payload))
	blob := craft(t, h, dek, payload)

	honest := small()
	honest.PayloadSHA256 = PayloadDigest(payload)
	honest.PayloadBytes = int64(len(payload))
	got, _, err := OpenBytes(craft(t, honest, dek, payload), dek)
	require.NoError(t, err, "the same crafting with an honest header opens")
	require.Equal(t, payload, got)

	r, err := NewReader(bytes.NewReader(blob))
	require.NoError(t, err)
	stream, err := r.PayloadWithKey(dek)
	require.NoError(t, err)
	got, err = io.ReadAll(stream)
	require.ErrorContains(t, err, "opened payload is not the payload the header describes")
	require.Equal(t, payload, got, "the segments themselves were authentic under the key")

	_, _, err = OpenBytes(blob, dek)
	require.ErrorContains(t, err, "opened payload is not the payload the header describes")
}

// A second read of a Reader's payload is refused: the stream can be
// consumed once, and a repeat attempt yields the sticky error rather than
// a re-opened stream.
func TestReader_PayloadStreamsOnce(t *testing.T) {
	t.Parallel()
	b, dek := seal(t, small(), payload)
	r, err := NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	first, err := r.PayloadWithKey(dek)
	require.NoError(t, err)
	got, err := io.ReadAll(first)
	require.NoError(t, err)
	require.Equal(t, payload, got)

	second, err := r.PayloadWithKey(dek)
	require.NoError(t, err, "the key check passes; the stream itself is spent")
	got, err = io.ReadAll(second)
	require.ErrorContains(t, err, "payload already read")
	require.Empty(t, got)
}
