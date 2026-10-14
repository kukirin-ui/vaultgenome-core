// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/genome/lora"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
)

// GenomePlaceholder in a gate command argument stands for the restored
// genome's directory.
const GenomePlaceholder = "{genome}"

// GateConfig has the Restorer prove a restored model works before it signs
// for it: a backend (the vg_genome door) recomputes the genome's sealed
// fixtures on this machine, and the equivalence gate holds the outputs to
// the references — byte-exact first, then within Tolerance, then the
// integer door byte-exact against its own references when the genome
// carries them. The verdict goes into the receipt the TEE signs.
type GateConfig struct {
	Command     []string // GenomePlaceholder in an argument becomes the restored tree
	Env         []string // extra environment, KEY=VALUE
	Tolerance   equivalence.Tolerance
	MaxOutliers int
	Timeout     time.Duration
	// Required: a genome that cannot be gated (it has no model fixtures,
	// or the backend cannot run) fails its restore instead of being
	// signed for without a verdict.
	Required bool
}

var errNotAModel = errors.New("restorer: the restored genome holds no model fixtures (genome.json)")

// gate runs cfg over the restored genome at dir. A backend that cannot
// run returns an error — it says nothing about the model; a model whose
// outputs miss the references returns a FAIL verdict.
func (cfg *GateConfig) gate(dir string) (*receipt.Gate, error) {
	g, err := lora.Load(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNotAModel
	}
	if err != nil {
		return nil, err
	}
	fixtures, err := lora.Fixtures(dir, g)
	if err != nil {
		return nil, err
	}
	integerFixtures, err := lora.IntegerFixtures(dir, g)
	if err != nil {
		return nil, err
	}
	argv := make([]string, len(cfg.Command))
	for i, a := range cfg.Command {
		argv[i] = strings.ReplaceAll(a, GenomePlaceholder, dir)
	}
	be := &reconstruction.BatchedExternalBackend{Argv: argv, Env: cfg.Env, IDs: lora.IDs(fixtures), Timeout: cfg.Timeout}
	ladder := []reconstruction.Strategy{
		be.Door(0, reconstruction.KindPinnedReplay, "pinned replay", reconstruction.ExactTolerance, equivalence.StrictPolicy()),
		be.Door(1, reconstruction.KindNativeFloat, "native float", cfg.Tolerance, equivalence.Policy{MaxNonCriticalOutliers: cfg.MaxOutliers}),
	}
	// The integer door: a second run of the backend, only when the float
	// doors did not open — the same bytes on any device, held to the
	// references the genome's integer door sealed.
	ib := &reconstruction.BatchedExternalBackend{Argv: argv, Env: cfg.Env, IDs: lora.IDs(fixtures), Timeout: cfg.Timeout, Which: reconstruction.DoorInteger}
	if integerFixtures != nil {
		ladder = append(ladder, ib.IntegerDoor(2, "integer", integerFixtures))
	}
	res, err := reconstruction.Regenerate(g.Base.Manifest.Digest, fixtures, ladder)
	if err != nil {
		return nil, err
	}
	out := &receipt.Gate{
		Fixtures:       len(fixtures),
		Atol:           cfg.Tolerance.Atol,
		Rtol:           cfg.Tolerance.Rtol,
		BackendSeconds: be.Seconds + ib.Seconds,
	}
	if res.Opened {
		out.Level, out.Door = string(res.Verdict.Level), res.Name
		out.MaxAbsErr, out.MaxRelErr = res.Verdict.MaxAbsErr, res.Verdict.MaxRelErr
		return out, nil
	}
	last := res.Attempts[len(res.Attempts)-1]
	if last.Err != "" {
		return nil, fmt.Errorf("restorer: the gate backend could not run: %s", last.Err)
	}
	out.Level, out.MaxAbsErr = receipt.GateFail, last.MaxAbsErr
	return out, nil
}
