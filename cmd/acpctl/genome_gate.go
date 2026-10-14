// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/genome/lora"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
)

// genomeGateCmd proves a restored model came back: it has a backend (the
// vg_genome door, or anything speaking the same protocol) recompute every
// fixture the genome sealed on this machine's hardware, and holds the
// results to the sealed references — byte-exact first, then within
// tolerance. Everything after "--" is the backend's command line.
//
//	acpctl genome gate --genome ./restored -- python3 -m vg_genome door --genome ./restored --base ./base --device cuda
func genomeGateCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		genomeDir   = fs.String("genome", "", "Restored genome directory holding genome.json and its fixtures (required)")
		atol        = fs.Float64("atol", 1e-2, "Absolute tolerance of the float door")
		rtol        = fs.Float64("rtol", 1e-3, "Relative tolerance of the float door")
		maxOutliers = fs.Int("max-outliers", 0, "Non-critical fixtures allowed outside tolerance (critical ones never are)")
		timeout     = fs.Duration("timeout", 30*time.Minute, "Time the backend has for every fixture")
		jsonOut     = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome gate --genome DIR [--atol A] [--rtol R] [--max-outliers N] [--json] -- BACKEND [ARGS...]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Recompute every sealed fixture with BACKEND on this machine and gate it:")
		fmt.Fprintln(stderr, "EXACT if every output is byte-identical to the reference, EQUIVALENT if every")
		fmt.Fprintln(stderr, "output is within tolerance, FAIL otherwise (exit 5).")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	backend := fs.Args()
	if *genomeDir == "" || len(backend) == 0 {
		fmt.Fprintln(stderr, "acpctl genome gate: --genome and a backend command after -- are required")
		fs.Usage()
		return 2
	}
	if *atol < 0 || *rtol < 0 || *maxOutliers < 0 {
		fmt.Fprintln(stderr, "acpctl genome gate: tolerances and --max-outliers must not be negative")
		return 2
	}
	g, err := lora.Load(*genomeDir)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome gate: %v\n", err)
		return 1
	}
	fixtures, err := lora.Fixtures(*genomeDir, g)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome gate: %v\n", err)
		return 1
	}

	integerFixtures, err := lora.IntegerFixtures(*genomeDir, g)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome gate: %v\n", err)
		return 1
	}
	be := &reconstruction.BatchedExternalBackend{Argv: backend, IDs: lora.IDs(fixtures), Timeout: *timeout}
	ib := &reconstruction.BatchedExternalBackend{Argv: backend, IDs: lora.IDs(fixtures), Timeout: *timeout, Which: reconstruction.DoorInteger}
	tol := equivalence.Tolerance{Atol: *atol, Rtol: *rtol}
	pol := equivalence.Policy{MaxNonCriticalOutliers: *maxOutliers}
	ladder := []reconstruction.Strategy{
		be.Door(0, reconstruction.KindPinnedReplay, "pinned replay", reconstruction.ExactTolerance, equivalence.StrictPolicy()),
		be.Door(1, reconstruction.KindNativeFloat, "native float", tol, pol),
	}
	if integerFixtures != nil {
		ladder = append(ladder, ib.IntegerDoor(2, "integer", integerFixtures))
	}
	res, err := reconstruction.Regenerate(g.Base.Manifest.Digest, fixtures, ladder)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome gate: %v\n", err)
		return 1
	}

	out := gateResult{
		Genome:         *genomeDir,
		Base:           g.Base.Name,
		BaseDigest:     g.Base.Manifest.Digest,
		Fixtures:       len(fixtures),
		IntegerDoor:    integerFixtures != nil,
		BackendSeconds: be.Seconds + ib.Seconds,
		Ladder:         res,
	}
	if res.Opened {
		out.Level = string(res.Verdict.Level)
	} else {
		out.Level = string(equivalence.LevelFail)
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(out)
	} else {
		mark := "✓"
		if !res.Opened {
			mark = "✗"
		}
		fmt.Fprintf(stdout, "%s %s — %d fixtures of %s, backend %.1fs\n", mark, out.Level, out.Fixtures, out.Base, out.BackendSeconds)
		for _, a := range res.Attempts {
			line := fmt.Sprintf("  door %d %-14s %-12s max|Δ| %.3g", a.Rung, a.Kind, a.Level, a.MaxAbsErr)
			if a.Err != "" {
				line += "  error: " + a.Err
			}
			fmt.Fprintln(stdout, line)
		}
	}
	if !res.Opened {
		return 5
	}
	return 0
}

type gateResult struct {
	Genome         string                      `json:"genome"`
	Base           string                      `json:"base"`
	BaseDigest     string                      `json:"base_digest"`
	Fixtures       int                         `json:"fixtures"`
	IntegerDoor    bool                        `json:"integer_door"` // the genome carries integer references: a third door
	Level          string                      `json:"level"`
	BackendSeconds float64                     `json:"backend_seconds"`
	Ladder         reconstruction.LadderResult `json:"ladder"`
}
