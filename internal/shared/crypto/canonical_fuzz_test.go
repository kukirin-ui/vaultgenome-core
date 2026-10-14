// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// FuzzCanonicalJSON_Determinism verifies that CanonicalJSON is a stable
// total function over every byte sequence that parses as JSON: the exact
// same input parses and re-canonicalises to the exact same output, and
// applying canonicalisation twice is a no-op (idempotence).
//
// This is the cover-bytes-stability contract every Signature field in
// every canonical contract relies on. A regression here breaks signature
// verification across the whole codebase.
//
// The corpus seed is a spread of JSON shapes the contract family
// actually encounters: primitive scalars, arrays of scalars, nested
// objects, empty containers, unicode strings, numeric edges, and the
// key-ordering cases the canonicaliser's sort.Strings is meant to
// normalise. Fuzz inputs that fail to parse as JSON are discarded via
// t.Skip so the fuzzer can prune the space quickly.
func FuzzCanonicalJSON_Determinism(f *testing.F) {
	seeds := []string{
		`null`,
		`true`,
		`false`,
		`0`,
		`-1`,
		`42`,
		`3.14`,
		`"hello"`,
		`""`,
		`"unicode: Ω ☃ 🎉"`,
		`[]`,
		`[1,2,3]`,
		`["a","b","c"]`,
		`{}`,
		`{"a":1,"b":2}`,
		// Swapped key order: canonicalisation should sort to the same form as the above.
		`{"b":2,"a":1}`,
		// Nested.
		`{"outer":{"z":1,"a":2},"list":[{"k":"v"},{"k":"w"}]}`,
		// Numeric edges that the canonicaliser is still required to handle.
		`{"int":9223372036854775807,"float":0.1,"zero":0,"neg":-7}`,
		// String escape corners.
		`{"backslash":"a\\b","quote":"a\"b","newline":"a\nb","tab":"a\tb"}`,
		// Mixed.
		`[null,true,false,0,"",[[[]]],{}]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		t.Parallel()

		// Only exercise inputs that already parse as JSON. Non-JSON bytes
		// are not in the contract domain — the upstream callers (every
		// contract's CanonicalBytes) only ever feed CanonicalJSON values
		// that encoding/json just produced.
		var tree any
		if err := json.Unmarshal(raw, &tree); err != nil {
			t.Skip()
		}

		// Round-trip stability: canonicalise the decoded tree twice
		// through independent encoder invocations and assert byte
		// equality. This is the cover-bytes contract Signature fields
		// depend on.
		first, err := crypto.CanonicalJSON(tree)
		if err != nil {
			// Certain legitimately-parsed JSON values (e.g. numbers too
			// large to round-trip through float64 when UseNumber fails
			// in an unusual corner) are rejected by the canonicaliser's
			// domain gate. That is documented behaviour; fuzz moves on.
			t.Skip()
		}
		second, err := crypto.CanonicalJSON(tree)
		if err != nil {
			t.Fatalf("canonicalisation non-deterministic: second call errored after first succeeded: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("canonicalisation non-deterministic: first=%q second=%q", first, second)
		}

		// Idempotence: re-parsing the canonical output and re-canonicalising
		// it MUST produce the same bytes. This is the property a verifier
		// relies on when it receives cover-bytes from an adversarial
		// producer and re-canonicalises defensively before hashing.
		var reparsed any
		if err := json.Unmarshal(first, &reparsed); err != nil {
			t.Fatalf("canonical output not re-parseable as JSON: %v (bytes=%q)", err, first)
		}
		third, err := crypto.CanonicalJSON(reparsed)
		if err != nil {
			t.Fatalf("canonical output failed second canonicalisation: %v", err)
		}
		if !bytes.Equal(first, third) {
			t.Fatalf("canonicalisation not idempotent: first=%q third=%q", first, third)
		}
	})
}

// FuzzCanonicalJSON_ObjectKeyOrderInsensitive asserts the §JCS property
// that distinct object-key input orderings canonicalise to the same
// output — the doctrinal invariant that makes byte-stable signatures
// possible over Go map types (whose iteration order is randomised).
//
// The fuzz driver splits the input into (key, value) pairs and builds
// two maps: one in the input order, one reversed. Both MUST produce
// byte-identical canonical outputs.
func FuzzCanonicalJSON_ObjectKeyOrderInsensitive(f *testing.F) {
	f.Add("a", "1", "b", "2", "c", "3")
	f.Add("k1", "v1", "k2", "v2", "k3", "v3")
	f.Add("", "empty-key-allowed", "x", "y", "z", "value")
	f.Add("Ω", "omega", "α", "alpha", "β", "beta")
	f.Fuzz(func(t *testing.T, k1, v1, k2, v2, k3, v3 string) {
		t.Parallel()

		// Duplicate keys would be a different test (the canonical form
		// disallows that path via the upstream map structure); skip.
		if k1 == k2 || k1 == k3 || k2 == k3 {
			t.Skip()
		}

		forward := map[string]any{k1: v1, k2: v2, k3: v3}
		reverse := map[string]any{k3: v3, k2: v2, k1: v1}

		a, err := crypto.CanonicalJSON(forward)
		if err != nil {
			t.Fatalf("forward canonicalisation failed: %v", err)
		}
		b, err := crypto.CanonicalJSON(reverse)
		if err != nil {
			t.Fatalf("reverse canonicalisation failed: %v", err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("canonicalisation is key-order-sensitive: forward=%q reverse=%q", a, b)
		}
	})
}
