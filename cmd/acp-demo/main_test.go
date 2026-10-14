// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
)

// The demo is a reviewer's first contact with the platform, so what it
// prints must be what actually happened. This pins each claim to the real
// ladder result rather than to the narration.
func TestRun_EveryPrintedClaimHolds(t *testing.T) {
	var buf bytes.Buffer
	out, err := run(&buf, "")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, buf.String())
	}

	// ③ same runtime → the pinned door opens with an EXACT verdict.
	if !out.Same.Opened || out.Same.Name != "pinned-f64-replay" || out.Same.Verdict.Level != equivalence.LevelExact {
		t.Fatalf("③ same runtime: opened=%v door=%q level=%s, want pinned-f64-replay EXACT",
			out.Same.Opened, out.Same.Name, out.Same.Verdict.Level)
	}

	// ④ one ULP of float drift → the pinned door fails, the integer door
	// opens EQUIVALENT.
	if !out.Drift.Opened || out.Drift.Name != "integer-portable" || out.Drift.Verdict.Level != equivalence.LevelEquivalent {
		t.Fatalf("④ drift: opened=%v door=%q level=%s, want integer-portable EQUIVALENT",
			out.Drift.Opened, out.Drift.Name, out.Drift.Verdict.Level)
	}
	if len(out.Drift.Attempts) != 2 || out.Drift.Attempts[0].Level != equivalence.LevelFail {
		t.Fatalf("④ drift: attempts %+v, want the pinned door to FAIL first", out.Drift.Attempts)
	}

	// ⑤ corrupted weights → no door opens → fail-closed.
	if out.Corrupt.Opened {
		t.Fatalf("⑤ corrupted genome opened door %q", out.Corrupt.Name)
	}
	if got := reconstruction.Reason(out.Corrupt.Verdict); got != reconstitution_decision.ReasonValidationFailed {
		t.Fatalf("⑤ reason %s, want %s", got, reconstitution_decision.ReasonValidationFailed)
	}

	if !out.SignaturesVerified {
		t.Fatal("a signed verdict failed to verify")
	}
	if out.FileByteExact {
		t.Fatal("FileByteExact set although no -model file was given")
	}

	text := buf.String()
	for _, want := range []string{
		"① ORIGIN NODE", "② DESTINATION NODE", "③ REGENERATION", "④ CROSS-HARDWARE", "⑤ SAFETY",
		`door opened: "pinned-f64-replay"`, "verdict EXACT",
		`door opened: "integer-portable"`, "verdict EQUIVALENT",
		"signature verifies: true",
		"model is NOT brought up (fail-closed)",
		"nothing here rebuilds a model from a recipe alone: the delta is sealed",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("narration lacks %q", want)
		}
	}
}

func TestRun_SealsAGivenFileByteExact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.safetensors")
	if err := os.WriteFile(path, bytes.Repeat([]byte("\x00weights\xff"), 10_000), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	out, err := run(&buf, path)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !out.FileByteExact || !strings.Contains(buf.String(), "sealed and restored BYTE-EXACT") {
		t.Fatalf("file not reported byte-exact:\n%s", buf.String())
	}
}

// An unreadable -model file is narrated, not fatal: the rest of the
// demonstration still stands.
func TestRun_UnreadableFileIsReportedNotFatal(t *testing.T) {
	var buf bytes.Buffer
	out, err := run(&buf, filepath.Join(t.TempDir(), "missing.bin"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.FileByteExact || !strings.Contains(buf.String(), "could not read") {
		t.Fatalf("missing file not reported:\n%s", buf.String())
	}
	if !out.Same.Opened || !out.Drift.Opened || out.Corrupt.Opened {
		t.Fatal("the demonstration changed because of an unrelated file problem")
	}
}

// The integrity step the demo narrates is real: a sealed genome with one
// flipped byte, or unsealed under the wrong address, does not open.
func TestSealedGenome_TamperIsRejected(t *testing.T) {
	seed := sha256.Sum256([]byte("vaultgenome-demo-workload"))
	origin, err := tee.NewSimulated([]byte("vaultgenome-origin"), seed[:])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeGenome(buildGenome(1, 4))
	if err != nil {
		t.Fatal(err)
	}
	addr := sha256.Sum256(raw)
	sealed, err := origin.Seal(raw, addr[:])
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := origin.Unseal(tampered, addr[:]); err == nil {
		t.Fatal("a sealed genome with a flipped byte unsealed")
	}
	wrong := sha256.Sum256([]byte("another genome"))
	if _, err := origin.Unseal(sealed, wrong[:]); err == nil {
		t.Fatal("a sealed genome unsealed under a different content address")
	}
	if got, err := origin.Unseal(sealed, addr[:]); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("genuine genome did not round-trip: %v", err)
	}
}

func TestGenome_EncodeDecodeRoundTrip(t *testing.T) {
	g := buildGenome(7, 3)
	raw, err := encodeGenome(g)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeGenome(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Fixtures) != 3 || len(back.Inputs) != 3 || back.Params.D != dim {
		t.Fatalf("round trip lost structure: %d fixtures, %d inputs, D=%d", len(back.Fixtures), len(back.Inputs), back.Params.D)
	}
	for i, f := range g.Fixtures {
		if !bytes.Equal(f.Expected.Raw, back.Fixtures[i].Expected.Raw) {
			t.Fatalf("fixture %s changed in the round trip", f.ID)
		}
	}
	if _, err := decodeGenome([]byte("not a gob stream")); err == nil {
		t.Fatal("decodeGenome accepted garbage")
	}
}
