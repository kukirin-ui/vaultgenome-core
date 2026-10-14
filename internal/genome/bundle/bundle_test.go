// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

var payload = bytes.Repeat([]byte("model weights "), 1000)

func header() Header {
	return Header{
		ContentKind:     ContentDir,
		ContentRef:      "/models/adapter",
		ContentSnapshot: json.RawMessage(`{"components":[]}`),
		SealedAt:        time.Date(2026, 9, 14, 22, 0, 0, 0, time.UTC),
	}
}

func seal(t *testing.T, h Header, p []byte) ([]byte, []byte) {
	t.Helper()
	b, dek, err := SealBytes(h, p)
	require.NoError(t, err)
	return b, dek
}

// small returns a header with the smallest segments, so a modest payload
// spans many of them.
func small() Header {
	h := header()
	h.SegmentBytes = MinSegmentBytes
	return h
}

func open(t *testing.T, blob, dek []byte) ([]byte, error) {
	t.Helper()
	p, _, err := OpenBytes(blob, dek)
	return p, err
}

// segments splits a sealed bundle into its prefix (through the nonce
// prefix) and its sealed segments.
func segments(t *testing.T, blob []byte) ([]byte, [][]byte) {
	t.Helper()
	r, err := NewReader(bytes.NewReader(blob))
	require.NoError(t, err)
	start := len(Magic) + 4 + len(r.HeaderBytes) + noncePrefixSize
	var segs [][]byte
	rest := blob[start:]
	step := int(r.Header.SegmentBytes) + 16
	for len(rest) > step {
		segs = append(segs, rest[:step])
		rest = rest[step:]
	}
	segs = append(segs, rest)
	return blob[:start], segs
}

func join(prefix []byte, segs ...[]byte) []byte {
	out := append([]byte(nil), prefix...)
	for _, s := range segs {
		out = append(out, s...)
	}
	return out
}

func TestSealOpen_RoundTrip(t *testing.T) {
	t.Parallel()
	b, dek := seal(t, header(), payload)
	require.True(t, IsV3(b))
	require.Len(t, dek, 32)
	require.False(t, bytes.Contains(b, dek), "the key is not in the bundle")
	require.False(t, bytes.Contains(b, payload[:64]), "the payload is not in the clear")

	got, h, err := OpenBytes(b, dek)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.Equal(t, Format, h.Format)
	require.Equal(t, PayloadDigest(payload), h.PayloadSHA256)
	require.EqualValues(t, len(payload), h.PayloadBytes)
	require.EqualValues(t, DefaultSegmentBytes, h.SegmentBytes)
	require.Regexp(t, `^genome-[0-9a-f]{12}-g0-[0-9a-f]{12}$`, h.KeyID)
	require.True(t, IsKeyID(h.KeyID))
	require.NoError(t, CheckKey(h.KeyID, dek))
}

// Payloads that fill segments exactly, spill one byte over, or are empty
// all round-trip, and the segment count is what the format says.
func TestSealOpen_SegmentBoundaries(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		size, segs int
	}{
		"empty":         {0, 1},
		"one byte":      {1, 1},
		"one segment":   {MinSegmentBytes, 1},
		"one byte over": {MinSegmentBytes + 1, 2},
		"many":          {10*MinSegmentBytes + 17, 11},
	} {
		t.Run(name, func(t *testing.T) {
			p := bytes.Repeat([]byte{0xA5}, tc.size)
			b, dek := seal(t, small(), p)
			_, segs := segments(t, b)
			require.Len(t, segs, tc.segs)
			got, err := open(t, b, dek)
			require.NoError(t, err)
			require.Equal(t, p, got)
		})
	}
}

// The payload streams out through any reader shape, and opening works in
// bounded memory: the reader hands out one segment at a time.
func TestOpen_Streams(t *testing.T) {
	t.Parallel()
	p := bytes.Repeat([]byte("0123456789abcdef"), 5000) // 80 000 bytes, 20 segments
	b, dek := seal(t, small(), p)
	r, err := NewReader(iotest.OneByteReader(bytes.NewReader(b)))
	require.NoError(t, err)
	stream, err := r.PayloadWithKey(dek)
	require.NoError(t, err)
	got, err := io.ReadAll(iotest.OneByteReader(stream))
	require.NoError(t, err)
	require.Equal(t, p, got)

	_, err = io.ReadAll(r.Payload(nil))
	require.ErrorContains(t, err, "already read")
}

// A destination opens the bundle with a released DEK that never leaves
// its keystore.
func TestOpen_ThroughAKeystore(t *testing.T) {
	t.Parallel()
	b, dek := seal(t, small(), payload)
	store := keys.NewInMemoryStore(shared_time.NewSystemClock())

	r, err := NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	_, err = io.ReadAll(r.Payload(store))
	require.Error(t, err, "no key registered under the bundle's key id")

	require.NoError(t, store.RegisterSealing(ids.KeyID(r.Header.KeyID), dek))
	r, err = NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	got, err := io.ReadAll(r.Payload(store))
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

// Each seal draws a fresh key: the same payload sealed twice yields two
// different keys, key IDs and ciphertexts, and neither key opens the
// other bundle.
func TestSeal_FreshKeyEachTime(t *testing.T) {
	t.Parallel()
	b1, k1 := seal(t, header(), payload)
	b2, k2 := seal(t, header(), payload)
	require.NotEqual(t, k1, k2)
	r1, err := NewReader(bytes.NewReader(b1))
	require.NoError(t, err)
	r2, err := NewReader(bytes.NewReader(b2))
	require.NoError(t, err)
	require.NotEqual(t, r1.Header.KeyID, r2.Header.KeyID)
	require.NotEqual(t, b1, b2)
	_, err = open(t, b1, k2)
	require.ErrorContains(t, err, "this key is not")
	require.ErrorContains(t, CheckKey(r1.Header.KeyID, k2), "this key is not")
	require.ErrorContains(t, CheckKey(r1.Header.KeyID, k1[:16]), "32 bytes")
	require.ErrorContains(t, CheckKey("genome-dek-1", k1), "not a genome key id")
}

// Nothing in a bundle can change — header, segment content, segment
// order, segment count, trailing bytes — without it failing to open. And
// no byte of a segment is released before that segment authenticates.
func TestOpen_RefusesEditedBundles(t *testing.T) {
	t.Parallel()
	p := bytes.Repeat([]byte("weights!"), 3*MinSegmentBytes/8) // 3 full segments
	b, dek := seal(t, small(), p)
	prefix, segs := segments(t, b)
	require.Len(t, segs, 3)

	flipped := func(seg []byte) []byte {
		out := append([]byte(nil), seg...)
		out[len(out)/2] ^= 0x01
		return out
	}
	lastAsMiddle := append([]byte(nil), segs[2]...)

	for name, tc := range map[string]struct {
		blob     []byte
		released int // bytes a reader may see before the error
	}{
		"header":             {bytes.Replace(b, []byte("/models/adapter"), []byte("/models/ADAPTER"), 1), 0},
		"first segment":      {join(prefix, flipped(segs[0]), segs[1], segs[2]), 0},
		"middle segment":     {join(prefix, segs[0], flipped(segs[1]), segs[2]), MinSegmentBytes},
		"swapped segments":   {join(prefix, segs[1], segs[0], segs[2]), 0},
		"last dropped":       {join(prefix, segs[0], segs[1]), 2 * MinSegmentBytes},
		"last repeated":      {join(prefix, segs[0], segs[1], segs[2], segs[2]), 3 * MinSegmentBytes},
		"last moved earlier": {join(prefix, segs[0], lastAsMiddle, segs[2]), MinSegmentBytes},
		"trailing byte":      {append(append([]byte(nil), b...), 0), 3 * MinSegmentBytes},
		"cut mid-segment":    {b[:len(b)-100], 2 * MinSegmentBytes},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := NewReader(bytes.NewReader(tc.blob))
			require.NoError(t, err, "the header itself still parses")
			stream, err := r.PayloadWithKey(dek)
			require.NoError(t, err)
			got, err := io.ReadAll(stream)
			require.Error(t, err)
			require.Len(t, got, tc.released)
			require.Equal(t, p[:tc.released], got, "what was released is authentic")
		})
	}
}

func TestNewReader_RefusesMalformedBundles(t *testing.T) {
	t.Parallel()
	b, _ := seal(t, header(), payload)
	r, err := NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	body := b[len(Magic)+4+len(r.HeaderBytes):]
	withHeader := func(mutate func(h map[string]any)) []byte {
		var h map[string]any
		require.NoError(t, json.Unmarshal(r.HeaderBytes, &h))
		mutate(h)
		hb, err := json.Marshal(h)
		require.NoError(t, err)
		var out bytes.Buffer
		out.WriteString(Magic)
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(hb)))
		out.Write(n[:])
		out.Write(hb)
		out.Write(body)
		return out.Bytes()
	}

	for name, blob := range map[string][]byte{
		"not a bundle":     []byte("hello"),
		"empty":            nil,
		"v2 magic":         []byte("VG-GENOME-01\x00\x00\x00\x00\x00\x00\x00\x02{}"),
		"no header length": []byte(Magic),
		"header overruns":  append([]byte(Magic), 0x00, 0x00, 0xff, 0xff),
		"header too large": append([]byte(Magic), 0xff, 0xff, 0xff, 0xff),
		"no nonce prefix":  b[:len(Magic)+4+len(r.HeaderBytes)+3],
		"trailing json":    withHeaderBytes(r.HeaderBytes, append(append([]byte(nil), r.HeaderBytes...), []byte(" {}")...), body),
		"unknown field":    withHeader(func(h map[string]any) { h["unwrapped_key"] = "x" }),
		"other format":     withHeader(func(h map[string]any) { h["format"] = "vault-genome-v2" }),
		"unknown kind":     withHeader(func(h map[string]any) { h["content_kind"] = "exe" }),
		"bad digest":       withHeader(func(h map[string]any) { h["payload_sha256"] = "md5:00" }),
		"foreign key id":   withHeader(func(h map[string]any) { h["key_id"] = "genome-000000000000-g0-000000000000" }),
		"orphan gen":       withHeader(func(h map[string]any) { h["generation"] = 3 }),
		"negative size":    withHeader(func(h map[string]any) { h["payload_bytes"] = -1 }),
		"tiny segments":    withHeader(func(h map[string]any) { h["segment_bytes"] = 16 }),
		"huge segments":    withHeader(func(h map[string]any) { h["segment_bytes"] = MaxSegmentBytes + 1 }),
		"no seal time":     withHeader(func(h map[string]any) { delete(h, "sealed_at") }),
		"too many segs": withHeader(func(h map[string]any) {
			h["payload_bytes"] = int64(MinSegmentBytes) << 33
			h["segment_bytes"] = MinSegmentBytes
		}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewReader(bytes.NewReader(blob))
			require.Error(t, err)
		})
	}
}

func withHeaderBytes(_ []byte, hb, body []byte) []byte {
	var out bytes.Buffer
	out.WriteString(Magic)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(hb)))
	out.Write(n[:])
	out.Write(hb)
	out.Write(body)
	return out.Bytes()
}

// Seal checks the payload stream against the header's description, so a
// source that changes between the describing pass and the sealing pass
// cannot produce a bundle.
func TestSeal_RefusesAPayloadThatIsNotTheOneDescribed(t *testing.T) {
	t.Parallel()
	described := func(p []byte) Header {
		h := small()
		h.PayloadSHA256 = PayloadDigest(p)
		h.PayloadBytes = int64(len(p))
		return h
	}
	p := bytes.Repeat([]byte("abcd"), 3000)

	_, _, err := Seal(io.Discard, described(p), bytes.NewReader(p[:len(p)-1]))
	require.ErrorContains(t, err, "ended before")
	_, _, err = Seal(io.Discard, described(p), bytes.NewReader(append(append([]byte(nil), p...), 'x')))
	require.ErrorContains(t, err, "longer than")
	changed := append([]byte(nil), p...)
	changed[5000] = 'Z'
	_, _, err = Seal(io.Discard, described(p), bytes.NewReader(changed))
	require.ErrorContains(t, err, "did it change while it was sealed")
	_, _, err = Seal(io.Discard, small(), bytes.NewReader(p))
	require.ErrorContains(t, err, "must describe the payload")
	_, _, err = Seal(io.Discard, described(p), iotest.ErrReader(errors.New("disk gone")))
	require.ErrorContains(t, err, "disk gone")
	_, _, err = Seal(failingWriter{}, described(p), bytes.NewReader(p))
	require.ErrorContains(t, err, "write")

	h, dek, err := Seal(io.Discard, described(p), bytes.NewReader(p))
	require.NoError(t, err)
	require.NoError(t, CheckKey(h.KeyID, dek))
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// A later generation names its parent; genesis names none.
func TestSeal_ChainOfCustody(t *testing.T) {
	t.Parallel()
	h := header()
	h.Generation = 2
	_, _, err := SealBytes(h, payload)
	require.ErrorContains(t, err, "generation 0 has no parent")

	h.ParentBundleSHA256 = strings.Repeat("ab", 32)
	h.ParentGeneration = 1
	b, dek, err := SealBytes(h, payload)
	require.NoError(t, err)
	_, got, err := OpenBytes(b, dek)
	require.NoError(t, err)
	require.Contains(t, got.KeyID, "-g2-")

	h = header()
	h.ContentKind = "exe"
	_, _, err = SealBytes(h, payload)
	require.Error(t, err)
}

func TestIdentify(t *testing.T) {
	t.Parallel()
	b, _ := seal(t, small(), payload)
	path := t.TempDir() + "/g.genome"
	require.NoError(t, os.WriteFile(path, b, 0o644))
	id, err := Identify(path)
	require.NoError(t, err)
	require.EqualValues(t, len(b), id.Size)
	sum := sha256.Sum256(b)
	require.Equal(t, hex.EncodeToString(sum[:]), id.SHA256)
	require.Equal(t, PayloadDigest(payload), id.Header.PayloadSHA256)

	_, err = Identify(path + ".absent")
	require.Error(t, err)
	require.NoError(t, os.WriteFile(path, []byte("not a bundle"), 0o644))
	_, err = Identify(path)
	require.Error(t, err)
}
