// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// fakeBackend returns an ExternalBackend whose process emits the given tensor as
// the protocol response for any fixture id (a stand-in for a real RepDL runner).
func fakeBackend(tsr equivalence.Tensor) ExternalBackend {
	b64 := base64.StdEncoding.EncodeToString(tsr.Raw)
	shape, _ := json.Marshal(tsr.Shape)
	resp := fmt.Sprintf(`{"dtype":"%s","shape":%s,"raw_b64":"%s"}`, tsr.DType, string(shape), b64)
	// consume stdin, then print the fixed JSON response. resp has no single quotes.
	return ExternalBackend{Argv: []string{"sh", "-c", "cat >/dev/null; printf '%s' '" + resp + "'"}}
}

func TestExternalBackend_ServesDoor(t *testing.T) {
	exp := f64Tensor([]int{3}, []float64{1, 2, 3})
	be := fakeBackend(exp)

	got, err := be.Recompute("a")
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if got.DType != exp.DType || string(got.Raw) != string(exp.Raw) {
		t.Fatalf("adapter did not round-trip the tensor: got %+v", got)
	}

	// As a ladder door it must open and be recorded as the reproducible-float kind.
	fx := []equivalence.Fixture{{ID: "a", Expected: exp}}
	res, err := Regenerate("g", fx,
		[]Strategy{be.Door(2, "repdl-ref", equivalence.Tolerance{}, equivalence.StrictPolicy())})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if !res.Opened || res.Kind != KindReproducibleFloat {
		t.Fatalf("external door should open as reproducible-float, got %+v", res)
	}
	if res.Verdict.Level != equivalence.LevelExact {
		t.Fatalf("matching output should be EXACT, got %s", res.Verdict.Level)
	}
}

func TestExternalBackend_BrokenBackendFallsThrough(t *testing.T) {
	exp := f64Tensor([]int{1}, []float64{5})
	broken := ExternalBackend{Argv: []string{"sh", "-c", "exit 3"}} // non-zero exit
	good := fakeBackend(exp)

	fx := []equivalence.Fixture{{ID: "a", Expected: exp}}
	res, err := Regenerate("g", fx, []Strategy{
		broken.Door(2, "broken-repdl", equivalence.Tolerance{}, equivalence.StrictPolicy()),
		good.Door(3, "backup", equivalence.Tolerance{}, equivalence.StrictPolicy()),
	})
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if !res.Opened || res.Name != "backup" {
		t.Fatalf("descent should fall through the broken backend to the backup door, got %+v", res)
	}
	if len(res.Attempts) != 2 || res.Attempts[0].Level != attemptError {
		t.Fatalf("broken backend must be recorded as an ERROR attempt, got %+v", res.Attempts)
	}
	if res.Attempts[0].Err == "" {
		t.Fatal("errored door should carry an error message for the audit trail")
	}
}

func TestExternalBackend_EmptyArgvRejected(t *testing.T) {
	be := ExternalBackend{}
	if _, err := be.Recompute("a"); err == nil {
		t.Fatal("empty argv must be rejected")
	}
}
