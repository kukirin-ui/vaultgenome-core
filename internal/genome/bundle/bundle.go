// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bundle is the Vault Genome v3 on-disk format: a model, or any
// directory, sealed under a data-encryption key (DEK) that is not in the
// file.
//
// A v3 bundle can be kept anywhere — object storage, another cloud, a
// removable disk — because it is useless without its DEK, and the
// platform hands that DEK only to a destination the operator's policy
// admits (cross-cloud key release, ADR 0009 and 0010) or to an operator
// holding the key file. The v2 format stored the key that sealed it
// inside the bundle (KNOWN_ISSUES #7); v3 replaces it.
//
// Layout:
//
//	magic(16) ‖ u32 BE header length ‖ header JSON ‖ nonce prefix(7) ‖ segment 0 ‖ … ‖ segment n-1
//
// The payload is cut into segments of the header's segment_bytes (the last
// may be shorter, and an empty payload is one empty segment). Segment i is
// AES-256-GCM under the DEK with nonce prefix ‖ u32 BE i ‖ last-flag and
// additional data SHA-256(label ‖ header). So every segment is bound to
// this header, to its position, and to whether it ends the payload: a
// reader authenticates each segment before releasing a byte of it, and an
// edited, reordered, truncated or extended bundle fails — the online
// authenticated-encryption construction of Hoang, Reyhanitabar, Rogaway
// and Vizár (CRYPTO 2015) that streaming AEADs such as Tink's use. Sealing
// and opening run in bounded memory whatever the payload's size.
package bundle

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Magic starts every v3 bundle. It differs from the v2 magic, so no v2
// reader mistakes a v3 bundle for its own and vice versa.
const Magic = "VG-GENOME-03\x00\x00\x00\x00"

// Format is the header's format string.
const Format = "vault-genome-v3"

// MaxHeaderBytes bounds the header a reader will accept.
const MaxHeaderBytes = 4 << 20

// Segment sizes. The default keeps the per-segment overhead (a 16-byte
// tag) under 0.002%.
const (
	DefaultSegmentBytes = 1 << 20
	MinSegmentBytes     = 4 << 10
	MaxSegmentBytes     = 64 << 20
)

// noncePrefixSize leaves 5 of GCM's 12 nonce bytes for the segment index
// and the last-segment flag.
const noncePrefixSize = 7

const segmentAADLabel = "vault-genome bundle segment v3\x00"

// Content kinds a v3 bundle can carry.
const (
	ContentOllama = "ollama" // an Ollama model store snapshot
	ContentDir    = "dir"    // a directory tree (LoRA adapter, checkpoint, corpus, ...)
)

// Header is the bundle's public metadata. Nothing in it is secret, and
// all of it is authenticated by every segment's GCM tag.
type Header struct {
	Format string `json:"format"`
	// KeyID names the DEK; it is how a keystore that holds the DEK finds
	// it. It reads genome-<payload prefix>-g<generation>-<key tag>: the
	// tag is derived from the DEK (KeyTag), so two seals of the same
	// payload never share an ID, and it reveals nothing about the key.
	KeyID    string    `json:"key_id"`
	SealedAt time.Time `json:"sealed_at"`

	// Chain of custody: Generation 0 is genesis; later generations name
	// their parent bundle (by file SHA-256) and its payload.
	Generation          uint64 `json:"generation"`
	ParentBundleSHA256  string `json:"parent_bundle_sha256,omitempty"`
	ParentPayloadSHA256 string `json:"parent_payload_sha256,omitempty"`
	ParentGeneration    uint64 `json:"parent_generation,omitempty"`

	ContentKind string `json:"content_kind"`
	ContentRef  string `json:"content_ref"`
	// ContentSnapshot is the kind's snapshot (ollama.Snapshot or
	// contentdir.Snapshot): what each file or blob should hash to.
	ContentSnapshot json.RawMessage `json:"content_snapshot"`

	// PayloadSHA256 ("sha256:<hex>") and PayloadBytes describe the
	// plaintext payload; opening checks both.
	PayloadSHA256 string `json:"payload_sha256"`
	PayloadBytes  int64  `json:"payload_bytes"`
	SegmentBytes  int64  `json:"segment_bytes"`
}

var (
	payloadDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	keyIDRE         = regexp.MustCompile(`^genome-([0-9a-f]{12})-g([0-9]+)-([0-9a-f]{12})$`)
)

// KeyTag is the short, one-way tag of a DEK that ends its key ID.
func KeyTag(dek []byte) string {
	sum := sha256.Sum256(append([]byte("vault-genome key tag v1\x00"), dek...))
	return hex.EncodeToString(sum[:6])
}

// NewKeyID names a DEK sealing a payload at a generation.
func NewKeyID(payloadSHA256 string, generation uint64, dek []byte) string {
	return fmt.Sprintf("genome-%s-g%d-%s", payloadSHA256[len("sha256:"):][:12], generation, KeyTag(dek))
}

// IsKeyID reports whether kid has the form NewKeyID gives a genome DEK.
func IsKeyID(kid string) bool { return keyIDRE.MatchString(kid) }

// CheckKey refuses a DEK that is not the one kid names. The key ID
// carries the key's tag, so a wrong key file is caught before it opens,
// releases or registers anything.
func CheckKey(kid string, dek []byte) error {
	m := keyIDRE.FindStringSubmatch(kid)
	if m == nil {
		return fmt.Errorf("bundle: %q is not a genome key id", kid)
	}
	if len(dek) != crypto.AES256KeySize {
		return fmt.Errorf("bundle: a genome key is %d bytes, this one is %d", crypto.AES256KeySize, len(dek))
	}
	if m[3] != KeyTag(dek) {
		return fmt.Errorf("bundle: this key is not %s", kid)
	}
	return nil
}

// PayloadDigest returns the "sha256:<hex>" digest of payload.
func PayloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// segmentCount is how many segments carry a payload: at least one, so an
// empty payload still ends in an authenticated last segment.
func segmentCount(payloadBytes, segmentBytes int64) int64 {
	if payloadBytes == 0 {
		return 1
	}
	return (payloadBytes + segmentBytes - 1) / segmentBytes
}

func (h Header) validate() error {
	if h.Format != Format {
		return fmt.Errorf("bundle: format %q, want %q", h.Format, Format)
	}
	if h.ContentKind != ContentOllama && h.ContentKind != ContentDir {
		return fmt.Errorf("bundle: content kind %q", h.ContentKind)
	}
	if !payloadDigestRE.MatchString(h.PayloadSHA256) {
		return fmt.Errorf("bundle: payload digest %q is not sha256:<64 hex>", h.PayloadSHA256)
	}
	if h.PayloadBytes < 0 {
		return errors.New("bundle: negative payload size")
	}
	if h.SegmentBytes < MinSegmentBytes || h.SegmentBytes > MaxSegmentBytes {
		return fmt.Errorf("bundle: segment size %d outside [%d, %d]", h.SegmentBytes, MinSegmentBytes, MaxSegmentBytes)
	}
	if segmentCount(h.PayloadBytes, h.SegmentBytes) > 1<<32 {
		return errors.New("bundle: payload needs more than 2^32 segments")
	}
	m := keyIDRE.FindStringSubmatch(h.KeyID)
	if m == nil || m[1] != h.PayloadSHA256[len("sha256:"):][:12] || m[2] != strconv.FormatUint(h.Generation, 10) {
		return fmt.Errorf("bundle: key id %q does not name this payload and generation", h.KeyID)
	}
	if h.SealedAt.IsZero() {
		return errors.New("bundle: sealed_at required")
	}
	if (h.Generation == 0) != (h.ParentBundleSHA256 == "") {
		return errors.New("bundle: generation 0 has no parent, and every later generation names one")
	}
	return nil
}

func segmentAAD(headerBytes []byte) []byte {
	h := sha256.New()
	h.Write([]byte(segmentAADLabel))
	h.Write(headerBytes)
	return h.Sum(nil)
}

func segmentNonce(prefix []byte, i int64, last bool) []byte {
	nonce := make([]byte, crypto.GCMNonceSize)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[noncePrefixSize:], uint32(i))
	if last {
		nonce[crypto.GCMNonceSize-1] = 1
	}
	return nonce
}

// Seal writes a bundle of payload to w under a fresh random DEK and
// returns the completed header and the DEK — which the caller must keep,
// because nothing else opens the bundle.
//
// h must already describe the payload: PayloadSHA256 and PayloadBytes,
// from a first pass over it. Seal reads payload once, in segments, and
// checks it yields exactly those bytes; if it does not — the source
// changed between the passes — Seal fails and what it wrote to w must be
// discarded. Seal fills in the format, key ID, segment size (if unset)
// and seal time (if unset).
func Seal(w io.Writer, h Header, payload io.Reader) (Header, []byte, error) {
	if !payloadDigestRE.MatchString(h.PayloadSHA256) || h.PayloadBytes < 0 {
		return Header{}, nil, errors.New("bundle: the header must describe the payload (payload_sha256, payload_bytes)")
	}
	dek := make([]byte, crypto.AES256KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Header{}, nil, fmt.Errorf("bundle: generate key: %w", err)
	}
	h.Format = Format
	h.KeyID = NewKeyID(h.PayloadSHA256, h.Generation, dek)
	if h.SegmentBytes == 0 {
		h.SegmentBytes = DefaultSegmentBytes
	}
	if h.SealedAt.IsZero() {
		h.SealedAt = time.Now().UTC()
	}
	if err := h.validate(); err != nil {
		return Header{}, nil, err
	}
	headerBytes, err := json.Marshal(h)
	if err != nil {
		return Header{}, nil, fmt.Errorf("bundle: encode header: %w", err)
	}
	if len(headerBytes) > MaxHeaderBytes {
		return Header{}, nil, fmt.Errorf("bundle: header is %d bytes, over %d", len(headerBytes), MaxHeaderBytes)
	}
	prefix := make([]byte, noncePrefixSize)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return Header{}, nil, fmt.Errorf("bundle: generate nonce prefix: %w", err)
	}
	aead, err := crypto.NewGCM(dek)
	if err != nil {
		return Header{}, nil, err
	}

	bw := bufio.NewWriterSize(w, 1<<16)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(headerBytes)))
	for _, part := range [][]byte{[]byte(Magic), n[:], headerBytes, prefix} {
		if _, err := bw.Write(part); err != nil {
			return Header{}, nil, fmt.Errorf("bundle: write: %w", err)
		}
	}

	aad := segmentAAD(headerBytes)
	digest := sha256.New()
	plain := make([]byte, h.SegmentBytes)
	sealed := make([]byte, 0, h.SegmentBytes+int64(aead.Overhead()))
	count := segmentCount(h.PayloadBytes, h.SegmentBytes)
	for i := range count {
		size := min(h.SegmentBytes, h.PayloadBytes-i*h.SegmentBytes)
		if _, err := io.ReadFull(payload, plain[:size]); err != nil {
			return Header{}, nil, fmt.Errorf("bundle: payload ended before the %d bytes its header describes: %w", h.PayloadBytes, err)
		}
		digest.Write(plain[:size])
		sealed = aead.Seal(sealed[:0], segmentNonce(prefix, i, i == count-1), plain[:size], aad)
		if _, err := bw.Write(sealed); err != nil {
			return Header{}, nil, fmt.Errorf("bundle: write: %w", err)
		}
	}
	if k, _ := io.ReadFull(payload, plain[:1]); k > 0 {
		return Header{}, nil, fmt.Errorf("bundle: payload is longer than the %d bytes its header describes", h.PayloadBytes)
	}
	if got := "sha256:" + hex.EncodeToString(digest.Sum(nil)); got != h.PayloadSHA256 {
		return Header{}, nil, fmt.Errorf("bundle: payload hashes to %s, not the %s its header describes (did it change while it was sealed?)", got, h.PayloadSHA256)
	}
	if err := bw.Flush(); err != nil {
		return Header{}, nil, fmt.Errorf("bundle: write: %w", err)
	}
	return h, dek, nil
}

// SealBytes seals an in-memory payload, filling in its description.
func SealBytes(h Header, payload []byte) (blob, dek []byte, err error) {
	h.PayloadSHA256 = PayloadDigest(payload)
	h.PayloadBytes = int64(len(payload))
	var buf bytes.Buffer
	if _, dek, err = Seal(&buf, h, bytes.NewReader(payload)); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), dek, nil
}

// IsV3 reports whether blob starts like a v3 bundle.
func IsV3(blob []byte) bool {
	return len(blob) >= len(Magic) && string(blob[:len(Magic)]) == Magic
}

// Reader is a bundle whose header has been read and validated; the
// payload is still sealed, positioned after the header.
type Reader struct {
	Header      Header
	HeaderBytes []byte // the header exactly as sealed

	r      io.Reader
	prefix []byte
	opened bool
}

// NewReader reads and validates a bundle's header from r. It needs no key
// and reads nothing past the header, so a bundle of any size is
// identified cheaply.
func NewReader(r io.Reader) (*Reader, error) {
	prefix := make([]byte, len(Magic)+4)
	if _, err := io.ReadFull(r, prefix); err != nil {
		if IsV3(prefix) {
			return nil, errors.New("bundle: truncated before the header")
		}
		return nil, errors.New("bundle: not a v3 Vault Genome bundle")
	}
	if !IsV3(prefix) {
		return nil, errors.New("bundle: not a v3 Vault Genome bundle")
	}
	n := binary.BigEndian.Uint32(prefix[len(Magic):])
	if n > MaxHeaderBytes {
		return nil, fmt.Errorf("bundle: header length %d over %d", n, MaxHeaderBytes)
	}
	headerBytes := make([]byte, n)
	if _, err := io.ReadFull(r, headerBytes); err != nil {
		return nil, fmt.Errorf("bundle: header length %d does not fit: %w", n, err)
	}
	var h Header
	dec := json.NewDecoder(bytes.NewReader(headerBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("bundle: header: %w", err)
	}
	if dec.More() {
		return nil, errors.New("bundle: header: trailing data")
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	noncePrefix := make([]byte, noncePrefixSize)
	if _, err := io.ReadFull(r, noncePrefix); err != nil {
		return nil, errors.New("bundle: truncated payload")
	}
	return &Reader{Header: h, HeaderBytes: headerBytes, r: r, prefix: noncePrefix}, nil
}

// Opener opens AES-256-GCM ciphertext under a key it holds by ID.
// keys.InMemoryStore implements it, so a destination opens a genome with
// a released DEK without the key ever leaving its keystore.
type Opener interface {
	Open(kid ids.KeyID, nonce, ciphertext, aad []byte) ([]byte, error)
}

// Payload returns the payload as a stream, opened with the key o holds
// under the header's key ID.
//
// Every byte the stream yields belongs to a segment whose tag has been
// checked. It ends with io.EOF only after the last segment, the payload
// size and the payload digest have all checked out, and nothing follows
// the last segment; a wrong key or an edited, reordered, truncated or
// extended bundle ends it with an error instead. A consumer that stops
// before io.EOF — a tar reader stops at its end marker — has not yet seen
// that proof and must read on to io.EOF before trusting what it read.
// A Reader's payload can be streamed once.
func (b *Reader) Payload(o Opener) io.Reader {
	kid := ids.KeyID(b.Header.KeyID)
	return b.payload(func(nonce, ct, aad []byte) ([]byte, error) {
		return o.Open(kid, nonce, ct, aad)
	})
}

// PayloadWithKey is Payload with the DEK itself (an operator's key file).
// A key that is not the one the header names is refused at once.
func (b *Reader) PayloadWithKey(dek []byte) (io.Reader, error) {
	if err := CheckKey(b.Header.KeyID, dek); err != nil {
		return nil, err
	}
	aead, err := crypto.NewGCM(dek)
	if err != nil {
		return nil, err
	}
	return b.payload(func(nonce, ct, aad []byte) ([]byte, error) {
		return aead.Open(nil, nonce, ct, aad)
	}), nil
}

func (b *Reader) payload(open func(nonce, ct, aad []byte) ([]byte, error)) io.Reader {
	if b.opened {
		return &payloadReader{err: errors.New("bundle: payload already read")}
	}
	b.opened = true
	return &payloadReader{
		b:      b,
		open:   open,
		aad:    segmentAAD(b.HeaderBytes),
		count:  segmentCount(b.Header.PayloadBytes, b.Header.SegmentBytes),
		sealed: make([]byte, b.Header.SegmentBytes+16),
		digest: sha256.New(),
	}
}

type payloadReader struct {
	b      *Reader
	open   func(nonce, ct, aad []byte) ([]byte, error)
	aad    []byte
	next   int64 // index of the next segment to open
	count  int64
	sealed []byte
	plain  []byte // unread part of the current segment
	digest hash.Hash
	total  int64
	err    error // sticky: io.EOF once the whole payload checked out
}

func (p *payloadReader) Read(out []byte) (int, error) {
	for len(p.plain) == 0 {
		if p.err != nil {
			return 0, p.err
		}
		p.err = p.advance()
	}
	n := copy(out, p.plain)
	p.plain = p.plain[n:]
	return n, nil
}

// advance opens the next segment into p.plain, or — after the last —
// returns io.EOF if everything checks out.
func (p *payloadReader) advance() error {
	h := p.b.Header
	if p.next == p.count {
		var probe [1]byte
		if k, _ := io.ReadFull(p.b.r, probe[:]); k > 0 {
			return errors.New("bundle: data after the last segment")
		}
		if p.total != h.PayloadBytes || "sha256:"+hex.EncodeToString(p.digest.Sum(nil)) != h.PayloadSHA256 {
			return errors.New("bundle: opened payload is not the payload the header describes")
		}
		return io.EOF
	}
	size := min(h.SegmentBytes, h.PayloadBytes-p.next*h.SegmentBytes)
	ct := p.sealed[:size+16]
	if _, err := io.ReadFull(p.b.r, ct); err != nil {
		return fmt.Errorf("bundle: truncated in segment %d of %d", p.next+1, p.count)
	}
	pt, err := p.open(segmentNonce(p.b.prefix, p.next, p.next == p.count-1), ct, p.aad)
	if err != nil {
		return fmt.Errorf("bundle: segment %d of %d does not open under key %s: %w", p.next+1, p.count, h.KeyID, err)
	}
	p.digest.Write(pt)
	p.total += int64(len(pt))
	p.plain = pt
	p.next++
	return nil
}

// OpenBytes opens an in-memory bundle with its DEK and returns the
// payload and header.
func OpenBytes(blob, dek []byte) ([]byte, Header, error) {
	r, err := NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, Header{}, err
	}
	payload, err := r.PayloadWithKey(dek)
	if err != nil {
		return nil, Header{}, err
	}
	out, err := io.ReadAll(payload)
	if err != nil {
		return nil, Header{}, err
	}
	return out, r.Header, nil
}

// Identity is what anyone holding a bundle can know without its key: the
// header, and the file's size and SHA-256.
type Identity struct {
	Header Header
	SHA256 string // hex, of the whole file
	Size   int64
}

// Identify reads the header of the bundle file at path and hashes the
// whole file as a stream.
func Identify(path string) (Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	counted := &countingWriter{w: h}
	br := bufio.NewReader(f)
	r, err := NewReader(io.TeeReader(br, counted))
	if err != nil {
		return Identity{}, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := io.Copy(counted, br); err != nil {
		return Identity{}, fmt.Errorf("%s: %w", path, err)
	}
	return Identity{Header: r.Header, SHA256: hex.EncodeToString(h.Sum(nil)), Size: counted.n}, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
