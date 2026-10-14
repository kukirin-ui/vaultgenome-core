// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strconv"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// CanonicalJSON returns a deterministic byte-form of v suitable as the
// cover-bytes of a signature or the pre-image of a hash.
//
// # Doctrinal role
//
// Every Signature field in every contract covers the output of CanonicalJSON
// applied to the contract value with its Signature field zeroed out. Every
// AuditEvent.Hash is the SHA-256 of CanonicalJSON applied to the event with
// Hash and Signature zeroed out. The contract-layer CanonicalBytes() methods
// delegate here.
//
// # MVP profile
//
// This implementation is a pragmatic subset of RFC 8785 (JCS):
//
//   - Object keys are sorted by UTF-8 code-point (Go sort.Strings behavior,
//     which is byte-lex over well-formed UTF-8).
//   - Arrays preserve input order.
//   - Strings use Go's standard encoding/json escaping.
//   - Integers are emitted as decimal digits with no exponent.
//   - Floats are emitted via strconv.FormatFloat(x, 'g', -1, 64) and
//     MUST NOT be NaN or +/-Inf — those inputs are rejected.
//   - Booleans and null are verbatim.
//
// This is NOT full RFC 8785 (which has specific float-shortest-round-trip
// rules). It is deterministic for every contract value used in this
// project. Stage D can replace the implementation with a full JCS library
// without changing the public signature of this function.
func CanonicalJSON(v any) ([]byte, error) {
	// Round-trip through encoding/json to normalize the value shape.
	// After this step we have a tree of (map[string]any | []any | string |
	// float64 | json.Number | bool | nil).
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: canonical: intermediate marshal failed",
			err,
		)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: canonical: intermediate decode failed",
			err,
		)
	}

	var buf bytes.Buffer
	if err := canonicalEncode(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalEncode(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		// encoding/json handles escape rules correctly; reuse it.
		b, err := json.Marshal(x)
		if err != nil {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"crypto: canonical: string encode failed",
				err,
			)
		}
		buf.Write(b)
	case json.Number:
		// json.Number is the original textual representation preserved by
		// the UseNumber decoder. For integers we keep it verbatim; for
		// floats we normalize to guarantee cross-run stability.
		if _, err := x.Int64(); err == nil {
			buf.WriteString(x.String())
			return nil
		}
		f, err := x.Float64()
		if err != nil {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"crypto: canonical: unparseable number",
				err,
			)
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"crypto: canonical: NaN/Inf disallowed",
				nil,
			)
		}
		buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"crypto: canonical: NaN/Inf disallowed",
				nil,
			)
		}
		buf.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
	case []any:
		buf.WriteByte('[')
		for i, el := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalEncode(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return shared_errors.Structural(
					shared_errors.CodeFieldValueInvalid,
					"crypto: canonical: key encode failed",
					err,
				)
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := canonicalEncode(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crypto: canonical: unsupported type in tree",
			nil,
		)
	}
	return nil
}
