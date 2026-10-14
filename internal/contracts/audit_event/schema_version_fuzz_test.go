// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_event

import (
	"testing"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// FuzzAuditEvent_SchemaVersionRangeGate pins the AuditEvent.Validate
// schema-version admission rule:
//
//   - SchemaVersion in [SchemaVersionMin, SchemaVersionMax] → accepted.
//   - SchemaVersion outside that closed range → rejected with a
//     Structural error under CodeSchemaVersionUnsupported.
//
// This gate is doctrinally load-bearing: it is the explicit forward
// /backward-compatibility boundary (see the SchemaVersionMin doctrine
// comment — a v1 reader MUST refuse a v2 event because the new Kind
// values are uninterpretable). The fuzz driver sweeps every uint16
// value the range can take and asserts the gate behaves as a total
// function.
//
// Note on test placement: this file lives in `package audit_event`
// (not the _test shim) so it can import the unexported `validFixture`
// helper defined in audit_event_test.go.
func FuzzAuditEvent_SchemaVersionRangeGate(f *testing.F) {
	// Seed the corners the fuzz engine should explore first: the two
	// boundary values, one below the floor, one above the ceiling, and
	// the unsigned-integer extremes.
	f.Add(uint16(0))            // below floor (rejected)
	f.Add(SchemaVersionMin - 1) // == 0 today; same as above
	f.Add(SchemaVersionMin)     // floor (accepted)
	f.Add(SchemaVersionCurrent) // current (accepted)
	f.Add(SchemaVersionMax)     // ceiling (accepted)
	f.Add(SchemaVersionMax + 1) // above ceiling (rejected)
	f.Add(uint16(100))          // distant future (rejected)
	f.Add(uint16(65535))        // uint16 ceiling (rejected)

	f.Fuzz(func(t *testing.T, sv uint16) {
		t.Parallel()

		e := validFixture()
		e.SchemaVersion = sv
		err := e.Validate()

		inRange := sv >= SchemaVersionMin && sv <= SchemaVersionMax
		if inRange {
			if err != nil {
				t.Fatalf("in-range SchemaVersion %d was rejected: %v", sv, err)
			}
			return
		}

		// Out-of-range: MUST be rejected with the specific classified
		// code the range gate surfaces. A rejection with a different
		// code would suggest a later validation step is catching the
		// problem and would indicate the gate itself is bypassable
		// in some code path.
		if err == nil {
			t.Fatalf("out-of-range SchemaVersion %d (min=%d max=%d) was accepted",
				sv, SchemaVersionMin, SchemaVersionMax)
		}
		if got := shared_errors.CodeOf(err); got != shared_errors.CodeSchemaVersionUnsupported {
			t.Fatalf("out-of-range SchemaVersion %d: expected code %q, got %q (err=%v)",
				sv, shared_errors.CodeSchemaVersionUnsupported, got, err)
		}
		if got := shared_errors.CategoryOf(err); got != shared_errors.CategoryStructural {
			t.Fatalf("out-of-range SchemaVersion %d: expected category Structural, got %v (err=%v)",
				sv, got, err)
		}
	})
}

// FuzzAuditEvent_SchemaVersionRangeGate_ExplicitTable is a table-driven
// companion that runs the exact boundary values as explicit unit tests.
// The fuzz test above drives random coverage; this test documents the
// doctrinal boundary points as named cases auditors can read without
// invoking the fuzz corpus.
func TestAuditEvent_SchemaVersionRangeGate_ExplicitBoundaries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		sv        uint16
		wantError bool
	}{
		{"zero (below floor)", 0, true},
		{"floor", SchemaVersionMin, false},
		{"current", SchemaVersionCurrent, false},
		{"ceiling", SchemaVersionMax, false},
		{"one above ceiling", SchemaVersionMax + 1, true},
		{"uint16 max", 65535, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := validFixture()
			e.SchemaVersion = tc.sv
			err := e.Validate()
			if tc.wantError {
				if err == nil {
					t.Fatalf("sv=%d: expected error, got nil", tc.sv)
				}
				if got := shared_errors.CodeOf(err); got != shared_errors.CodeSchemaVersionUnsupported {
					t.Fatalf("sv=%d: got code %q, want %q", tc.sv, got,
						shared_errors.CodeSchemaVersionUnsupported)
				}
			} else if err != nil {
				t.Fatalf("sv=%d: unexpected error: %v", tc.sv, err)
			}
		})
	}
}
