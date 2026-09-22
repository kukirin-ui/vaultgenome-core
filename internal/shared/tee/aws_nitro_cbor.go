// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// A small CBOR codec (RFC 8949) for the AWS Nitro attestation document.
//
// The document, and the COSE_Sign1 envelope around it, use a narrow
// subset of CBOR: unsigned and negative integers, byte and text strings,
// arrays, maps with integer or text keys, the null value and one tag (18,
// COSE_Sign1). Lengths are definite or indefinite (RFC 8949 §3.2.2 and
// §3.2.3) — the hypervisor writes the document's map with an indefinite
// length, as the four production captures of May 2026 show. This file
// decodes exactly that subset and refuses everything else — floating-point
// numbers, the other simple values, reserved additional-information
// values, a break code outside an indefinite-length item — so the parser
// has no branch the hypervisor's encoder never takes. It is written from
// the RFC rather than taken from a library because a CBOR library would be
// the first third-party parser on the path an unauthenticated peer's bytes
// take before any signature is checked (see docs/dependencies/ for the
// policy).
//
// The encoder writes definite lengths only. The verifier needs it for the
// Sig_structure of RFC 9052 §4.4, which is rebuilt from the envelope's
// parts and hashed; the tests need it to build documents to sign.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// cborKind names the CBOR items the decoder produces.
type cborKind uint8

const (
	cborUint  cborKind = iota // major type 0
	cborNInt                  // major type 1: the value is -1 - u
	cborBytes                 // major type 2
	cborText                  // major type 3
	cborArray                 // major type 4
	cborMap                   // major type 5, kept as key/value pairs
	cborTag                   // major type 6, u is the tag number
	cborNull                  // major type 7, simple value 22
)

// cborItem is one decoded item. Which fields are set depends on kind:
// u for integers and tags, b for strings, items for arrays (the elements)
// and maps (key, value, key, value, …), tagged for the tag's content.
type cborItem struct {
	kind   cborKind
	u      uint64
	b      []byte
	items  []cborItem
	tagged *cborItem
}

// Limits on what the decoder will take. An attestation document is about
// 4.5 KB with a five-certificate chain and up to 32 PCRs; these bounds
// leave room for that many times over and stop a hostile input from
// asking for more.
const (
	cborMaxDepth = 8
	cborMaxItems = 4096
	cborMaxInput = 64 * 1024
)

var (
	errCBORTrailing  = errors.New("cbor: bytes after the top-level item")
	errCBORTruncated = errors.New("cbor: truncated")
	errCBORDepth     = errors.New("cbor: nesting deeper than allowed")
	errCBORItems     = errors.New("cbor: more items than allowed")
	errCBORBreak     = errors.New("cbor: break code outside an indefinite-length item")
)

// cborDecode decodes one item that must span the whole input.
func cborDecode(in []byte) (*cborItem, error) {
	if len(in) > cborMaxInput {
		return nil, fmt.Errorf("cbor: input of %d bytes exceeds the %d-byte limit", len(in), cborMaxInput)
	}
	d := &cborDecoder{in: in}
	item, err := d.item(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(in) {
		return nil, errCBORTrailing
	}
	return item, nil
}

type cborDecoder struct {
	in    []byte
	pos   int
	count int
}

// head reads the initial byte and its argument (RFC 8949 §3). indefinite
// reports additional information 31: an indefinite length for strings,
// arrays and maps, the break code for major type 7.
func (d *cborDecoder) head() (major byte, arg uint64, indefinite bool, err error) {
	if d.pos >= len(d.in) {
		return 0, 0, false, errCBORTruncated
	}
	ib := d.in[d.pos]
	d.pos++
	major = ib >> 5
	ai := ib & 0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), false, nil
	case ai == 24, ai == 25, ai == 26, ai == 27:
		n := 1 << (ai - 24)
		if d.pos+n > len(d.in) {
			return 0, 0, false, errCBORTruncated
		}
		raw := d.in[d.pos : d.pos+n]
		d.pos += n
		switch n {
		case 1:
			arg = uint64(raw[0])
		case 2:
			arg = uint64(binary.BigEndian.Uint16(raw))
		case 4:
			arg = uint64(binary.BigEndian.Uint32(raw))
		default:
			arg = binary.BigEndian.Uint64(raw)
		}
		return major, arg, false, nil
	case ai == 31:
		return major, 0, true, nil
	default:
		return 0, 0, false, fmt.Errorf("cbor: reserved additional information %d", ai)
	}
}

// take returns the next n bytes of a string.
func (d *cborDecoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.in)-d.pos) {
		return nil, errCBORTruncated
	}
	out := d.in[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return out, nil
}

// item decodes one item at the given nesting depth.
func (d *cborDecoder) item(depth int) (*cborItem, error) {
	if depth > cborMaxDepth {
		return nil, errCBORDepth
	}
	d.count++
	if d.count > cborMaxItems {
		return nil, errCBORItems
	}
	major, arg, indefinite, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0, 1:
		if indefinite {
			return nil, errors.New("cbor: an integer has no indefinite form")
		}
		if major == 0 {
			return &cborItem{kind: cborUint, u: arg}, nil
		}
		return &cborItem{kind: cborNInt, u: arg}, nil
	case 2, 3:
		kind := cborBytes
		if major == 3 {
			kind = cborText
		}
		if indefinite {
			return d.indefiniteString(major, kind)
		}
		b, err := d.take(arg)
		if err != nil {
			return nil, err
		}
		return &cborItem{kind: kind, b: b}, nil
	case 4:
		it := &cborItem{kind: cborArray}
		if indefinite {
			for {
				e, done, err := d.member(depth + 1)
				if err != nil {
					return nil, err
				}
				if done {
					return it, nil
				}
				it.items = append(it.items, *e)
			}
		}
		if arg > uint64(len(d.in)-d.pos) { // every element takes at least one byte
			return nil, errCBORTruncated
		}
		it.items = make([]cborItem, 0, arg)
		for i := uint64(0); i < arg; i++ {
			e, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			it.items = append(it.items, *e)
		}
		return it, nil
	case 5:
		it := &cborItem{kind: cborMap}
		if indefinite {
			for {
				k, done, err := d.member(depth + 1)
				if err != nil {
					return nil, err
				}
				if done {
					return it, nil
				}
				v, err := d.mapValue(k, depth+1)
				if err != nil {
					return nil, err
				}
				it.items = append(it.items, *k, *v)
			}
		}
		if arg > uint64(len(d.in)-d.pos)/2 { // every pair takes at least two bytes
			return nil, errCBORTruncated
		}
		it.items = make([]cborItem, 0, 2*arg)
		for i := uint64(0); i < arg; i++ {
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			v, err := d.mapValue(k, depth+1)
			if err != nil {
				return nil, err
			}
			it.items = append(it.items, *k, *v)
		}
		return it, nil
	case 6:
		if indefinite {
			return nil, errors.New("cbor: a tag has no indefinite form")
		}
		content, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		return &cborItem{kind: cborTag, u: arg, tagged: content}, nil
	default: // 7
		if indefinite {
			return nil, errCBORBreak
		}
		if arg == 22 && d.in[d.pos-1] == 0xf6 {
			return &cborItem{kind: cborNull}, nil
		}
		return nil, fmt.Errorf("cbor: unsupported simple or floating-point value (additional information %d)", arg)
	}
}

// member decodes the next element of an indefinite-length array or map,
// or reports the break code (0xff) that ends it.
func (d *cborDecoder) member(depth int) (it *cborItem, done bool, err error) {
	if d.pos >= len(d.in) {
		return nil, false, errCBORTruncated
	}
	if d.in[d.pos] == 0xff {
		d.pos++
		return nil, true, nil
	}
	it, err = d.item(depth)
	return it, false, err
}

// mapValue checks a map key and decodes its value.
func (d *cborDecoder) mapValue(key *cborItem, depth int) (*cborItem, error) {
	if key.kind != cborUint && key.kind != cborNInt && key.kind != cborText {
		return nil, errors.New("cbor: map keys must be integers or text")
	}
	return d.item(depth)
}

// indefiniteString concatenates the definite-length chunks of an
// indefinite-length byte or text string (RFC 8949 §3.2.3): each chunk
// must be of the same major type and definite, and the break code ends
// the string.
func (d *cborDecoder) indefiniteString(major byte, kind cborKind) (*cborItem, error) {
	var out []byte
	for {
		if d.pos >= len(d.in) {
			return nil, errCBORTruncated
		}
		if d.in[d.pos] == 0xff {
			d.pos++
			return &cborItem{kind: kind, b: out}, nil
		}
		m, n, indefinite, err := d.head()
		if err != nil {
			return nil, err
		}
		if m != major || indefinite {
			return nil, errors.New("cbor: an indefinite-length string may hold only definite chunks of its own type")
		}
		chunk, err := d.take(n)
		if err != nil {
			return nil, err
		}
		d.count++
		if d.count > cborMaxItems {
			return nil, errCBORItems
		}
		out = append(out, chunk...)
	}
}

// mapLookup returns the value under a text key of a map, or nil. The
// second result says whether the key occurred more than once, which the
// callers refuse: RFC 8949 §5.6 leaves duplicate keys to the application,
// and a document that names a field twice is not one the hypervisor wrote.
func (it *cborItem) mapLookup(key string) (val *cborItem, dup bool) {
	for i := 0; i+1 < len(it.items); i += 2 {
		k := it.items[i]
		if k.kind == cborText && string(k.b) == key {
			if val != nil {
				return val, true
			}
			val = &it.items[i+1]
		}
	}
	return val, false
}

// mapLookupInt is mapLookup for a small non-negative integer key.
func (it *cborItem) mapLookupInt(key uint64) (val *cborItem, dup bool) {
	for i := 0; i+1 < len(it.items); i += 2 {
		k := it.items[i]
		if k.kind == cborUint && k.u == key {
			if val != nil {
				return val, true
			}
			val = &it.items[i+1]
		}
	}
	return val, false
}

// cborEncoder writes the subset the decoder reads, in the preferred
// (shortest) serialization of RFC 8949 §4.1.
type cborEncoder struct {
	buf []byte
}

func (e *cborEncoder) head(major byte, arg uint64) {
	mt := major << 5
	switch {
	case arg < 24:
		e.buf = append(e.buf, mt|byte(arg))
	case arg <= math.MaxUint8:
		e.buf = append(e.buf, mt|24, byte(arg))
	case arg <= math.MaxUint16:
		e.buf = append(e.buf, mt|25)
		e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(arg))
	case arg <= math.MaxUint32:
		e.buf = append(e.buf, mt|26)
		e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(arg))
	default:
		e.buf = append(e.buf, mt|27)
		e.buf = binary.BigEndian.AppendUint64(e.buf, arg)
	}
}

func (e *cborEncoder) uint(v uint64)  { e.head(0, v) }
func (e *cborEncoder) nint(v int64)   { e.head(1, uint64(-1-v)) } // v < 0
func (e *cborEncoder) bytes(b []byte) { e.head(2, uint64(len(b))); e.buf = append(e.buf, b...) }
func (e *cborEncoder) text(s string)  { e.head(3, uint64(len(s))); e.buf = append(e.buf, s...) }
func (e *cborEncoder) array(n int)    { e.head(4, uint64(n)) }
func (e *cborEncoder) mapping(n int)  { e.head(5, uint64(n)) }
func (e *cborEncoder) tag(n uint64)   { e.head(6, n) }
func (e *cborEncoder) null()          { e.buf = append(e.buf, 0xf6) }
