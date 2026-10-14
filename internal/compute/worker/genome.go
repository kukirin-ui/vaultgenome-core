// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// Error codes the GenomeReconstructor returns, beside the shared ones.
const (
	// CodeGateJobMalformed (Structural): the components do not form a gate
	// job — no descriptor, a descriptor naming a component that is not
	// there, prompts that do not parse.
	CodeGateJobMalformed = "gate_job_malformed"

	// CodeComponentDigestMismatch (Integrity): a component's bytes are not
	// what the descriptor says they hash to.
	CodeComponentDigestMismatch = "component_digest_mismatch"

	// CodeDoorFailed (Operational): the door did not run to completion —
	// it could not start, exited non-zero, or ran out of time.
	CodeDoorFailed = "door_failed"

	// CodeDoorOutputInvalid (Operational): the door ran but what it wrote
	// is not an answer to the job — malformed, or not one output per
	// prompt.
	CodeDoorOutputInvalid = "door_output_invalid"

	// CodeOutputOverBudget (Operational): the output is larger than the
	// manifest's ExpectedOutputMaxBytes.
	CodeOutputOverBudget = "output_over_budget"
)

// MaxDoorResponseBytes bounds what the worker reads from the door's
// stdout: an output is a few kilobytes per fixture, never megabytes.
const MaxDoorResponseBytes = 64 << 20

// GenomeConfig configures the door a GenomeReconstructor runs.
type GenomeConfig struct {
	// Command runs the door: a program that reads a gatejob.DoorRequest on
	// stdin, restores the genome's model in memory, recomputes each
	// prompt, and writes a gatejob.DoorResponse on stdout. The reference
	// door is `python -m vg_genome door --stdin-genome --base BASE_DIR`
	// (workers/genome).
	Command []string

	// Env is extra environment for the door, KEY=VALUE, on top of the
	// worker's own.
	Env []string

	// Timeout bounds one door run. Zero leaves the job's own deadline —
	// the manifest's, and the session's — as the only bound.
	Timeout time.Duration
}

// GenomeReconstructor is the R-11 backend: it brings a sealed genome's
// model back and recomputes the genome's reference fixtures.
//
// A gate job's components are a descriptor (gatejob.Descriptor) and the
// files it names — the genome's description, its adapter, the fixtures'
// prompts. The reconstructor checks every file against the descriptor's
// digests, hands them to the door on stdin, and returns the door's
// outputs, canonically encoded (gatejob.Output), as the candidate. The
// door loads the public base model from the worker's own disk and the
// adapter from memory; nothing of the genome is written anywhere.
//
// The authority that issued the job holds the sealed references and
// judges the outputs with the equivalence gate; the worker never sees
// what the outputs are supposed to be.
//
// Purity: the same job gives the same bytes when the door is
// deterministic — on the pinned runtime that sealed the genome it is, and
// the gate's byte-exact door records that; on other hardware the gate
// measures the difference instead of assuming it away.
type GenomeReconstructor struct {
	cfg   GenomeConfig
	clock shared_time.Clock
}

// NewGenomeReconstructor builds a GenomeReconstructor. A nil clock or an
// empty command is rejected Structurally.
func NewGenomeReconstructor(cfg GenomeConfig, clock shared_time.Clock) (*GenomeReconstructor, error) {
	if clock == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"worker: GenomeReconstructor requires a non-nil Clock", nil)
	}
	if len(cfg.Command) == 0 || strings.TrimSpace(cfg.Command[0]) == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"worker: GenomeReconstructor requires a door command", nil)
	}
	for _, kv := range cfg.Env {
		if !strings.Contains(kv, "=") {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("worker: door environment entry %q is not KEY=VALUE", kv), nil)
		}
	}
	if cfg.Timeout < 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"worker: door timeout must not be negative", nil)
	}
	return &GenomeReconstructor{
		cfg:   GenomeConfig{Command: append([]string(nil), cfg.Command...), Env: append([]string(nil), cfg.Env...), Timeout: cfg.Timeout},
		clock: clock,
	}, nil
}

// Reconstruct implements the R-11 contract.
//
// Error behaviour
//
//   - CategoryStructural when the job is malformed: missing manifest
//     fields, no components, duplicate ids, an output kind other than
//     bytes/fixed-length, or components that do not form a gate job
//     (CodeGateJobMalformed).
//   - CategoryIntegrity when a component does not hash to what the
//     descriptor says (CodeComponentDigestMismatch).
//   - CategoryOperational when the context is already done, the door
//     fails or runs out of time (CodeDoorFailed), answers wrongly
//     (CodeDoorOutputInvalid), or the output exceeds the manifest's budget
//     (CodeOutputOverBudget).
func (r *GenomeReconstructor) Reconstruct(
	ctx context.Context,
	manifest rjm.ReconstructionJobManifest,
	components []ComponentMaterial,
) (returnpath.CandidateOutput, error) {
	var zero returnpath.CandidateOutput

	if err := ctx.Err(); err != nil {
		return zero, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"worker: context already done at Reconstruct entry", err)
	}
	if manifest.ManifestID.IsZero() {
		return zero, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing, "worker: manifest.ManifestID is empty", nil)
	}
	if manifest.SessionID.IsZero() {
		return zero, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing, "worker: manifest.SessionID is empty", nil)
	}
	if manifest.ExpectedOutputMaxBytes == 0 {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid, "worker: manifest.ExpectedOutputMaxBytes must be > 0", nil)
	}
	if manifest.ExpectedOutputKind != rjm.OutputKindBytesFixedLength {
		return zero, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("worker: a gate job's output kind is %s, not %q", rjm.OutputKindBytesFixedLength, manifest.ExpectedOutputKind), nil)
	}
	if len(components) == 0 {
		return zero, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing, "worker: at least one component material required", nil)
	}

	seen := make(map[ids.ComponentID]struct{}, len(components))
	byIndex := make(map[uint32]ComponentMaterial, len(components))
	for _, c := range components {
		if c.ComponentID.IsZero() {
			return zero, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing, "worker: ComponentMaterial.ComponentID is empty", nil)
		}
		if _, dup := seen[c.ComponentID]; dup {
			return zero, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid, "worker: duplicate ComponentID in components", nil)
		}
		seen[c.ComponentID] = struct{}{}
		if _, dup := byIndex[c.SequenceIndex]; dup {
			return zero, shared_errors.Structural(
				CodeGateJobMalformed, fmt.Sprintf("worker: two components carry sequence index %d", c.SequenceIndex), nil)
		}
		byIndex[c.SequenceIndex] = c
	}

	// Component 0 describes the job.
	head, ok := byIndex[0]
	if !ok {
		return zero, shared_errors.Structural(
			CodeGateJobMalformed, "worker: no component 0 (the gate-job descriptor)", nil)
	}
	desc, err := gatejob.DecodeDescriptor(head.Plaintext)
	if err != nil {
		return zero, shared_errors.Structural(CodeGateJobMalformed, "worker: component 0 is not a gate-job descriptor", err)
	}

	// Every file the descriptor names must be there and hash as described;
	// every component must be named by it.
	files := make(map[string][]byte, len(desc.Files))
	used := map[uint32]bool{0: true}
	for _, f := range desc.Files {
		c, ok := byIndex[f.Component]
		if !ok {
			return zero, shared_errors.Structural(
				CodeGateJobMalformed, fmt.Sprintf("worker: descriptor names component %d for %s, which the job does not carry", f.Component, f.Path), nil)
		}
		used[f.Component] = true
		sum := sha256.Sum256(c.Plaintext)
		if int64(len(c.Plaintext)) != f.Bytes || hex.EncodeToString(sum[:]) != f.SHA256 {
			return zero, shared_errors.Integrity(
				CodeComponentDigestMismatch, fmt.Sprintf("worker: component %d is not the %s the descriptor describes", f.Component, f.Path), nil)
		}
		files[f.Path] = c.Plaintext
	}
	for idx := range byIndex {
		if !used[idx] {
			return zero, shared_errors.Structural(
				CodeGateJobMalformed, fmt.Sprintf("worker: component %d is not named by the descriptor", idx), nil)
		}
	}
	prompts, err := gatejob.DecodePrompts(files[gatejob.PromptsPath])
	if err != nil {
		return zero, shared_errors.Structural(CodeGateJobMalformed, "worker: the job's prompts do not parse", err)
	}

	request, err := gatejob.EncodeDoorRequest(desc.GenomeID, files)
	if err != nil {
		return zero, shared_errors.Structural(CodeGateJobMalformed, "worker: cannot build the door request", err)
	}

	stdout, err := r.runDoor(ctx, manifest.Deadline, request)
	if err != nil {
		return zero, err
	}
	outputs, integerOutputs, err := gatejob.DecodeDoorResponse(stdout)
	if err != nil {
		return zero, shared_errors.Operational(CodeDoorOutputInvalid, "worker: the door's answer does not parse", err)
	}
	want := prompts.IDs()
	if err := coversPrompts("output", outputs, want); err != nil {
		return zero, err
	}
	if prompts.Integer {
		if err := coversPrompts("integer output", integerOutputs, want); err != nil {
			return zero, err
		}
	} else {
		integerOutputs = nil // not asked for: not returned, so the output fills its budget
	}

	out, err := gatejob.EncodeOutput(desc.GenomeID, outputs, integerOutputs)
	if err != nil {
		return zero, shared_errors.Operational(CodeDoorOutputInvalid, "worker: cannot encode the door's outputs", err)
	}
	if uint64(len(out)) > manifest.ExpectedOutputMaxBytes {
		return zero, shared_errors.Operational(
			CodeOutputOverBudget,
			fmt.Sprintf("worker: output is %d bytes, over the manifest's %d", len(out), manifest.ExpectedOutputMaxBytes), nil)
	}
	return returnpath.CandidateOutput{
		ManifestID: manifest.ManifestID,
		SessionID:  manifest.SessionID,
		OutputKind: manifest.ExpectedOutputKind,
		Bytes:      out,
		ProducedAt: r.clock.Now(),
	}, nil
}

// coversPrompts checks the door answered every prompt, and nothing else.
func coversPrompts(what string, outputs map[string]equivalence.Tensor, want []string) error {
	if len(outputs) != len(want) {
		return shared_errors.Operational(
			CodeDoorOutputInvalid, fmt.Sprintf("worker: the door answered %d %ss for %d prompts", len(outputs), what, len(want)), nil)
	}
	for _, id := range want {
		if _, ok := outputs[id]; !ok {
			return shared_errors.Operational(
				CodeDoorOutputInvalid, fmt.Sprintf("worker: the door gave no %s for prompt %q", what, id), nil)
		}
	}
	return nil
}

// runDoor runs the door once with request on stdin and returns its
// stdout. The run is bounded by ctx, by the manifest's deadline and by
// the configured timeout, whichever ends first.
func (r *GenomeReconstructor) runDoor(ctx context.Context, deadline time.Time, request []byte) ([]byte, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if r.cfg.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(runCtx, r.cfg.Timeout)
		defer cancel()
	}
	if !deadline.IsZero() {
		runCtx, cancel = context.WithDeadline(runCtx, deadline)
		defer cancel()
	}

	cmd := exec.CommandContext(runCtx, r.cfg.Command[0], r.cfg.Command[1:]...)
	if len(r.cfg.Env) > 0 {
		cmd.Env = append(os.Environ(), r.cfg.Env...)
	}
	cmd.Stdin = bytes.NewReader(request)
	stdout := &boundedBuffer{max: MaxDoorResponseBytes}
	stderr := &boundedBuffer{max: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 5 * time.Second

	start := r.clock.Now()
	runErr := cmd.Run()
	if runErr != nil {
		msg := fmt.Sprintf("worker: door %q failed after %s: %v", r.cfg.Command[0], r.clock.Now().Sub(start).Round(time.Millisecond), runErr)
		if runCtx.Err() != nil && ctx.Err() == nil {
			msg = fmt.Sprintf("worker: door %q ran out of time after %s", r.cfg.Command[0], r.clock.Now().Sub(start).Round(time.Millisecond))
		}
		if tail := strings.TrimSpace(stderr.tail()); tail != "" {
			msg += ": " + tail
		}
		return nil, shared_errors.Operational(CodeDoorFailed, msg, runErr)
	}
	if stdout.overflowed {
		return nil, shared_errors.Operational(
			CodeDoorOutputInvalid, fmt.Sprintf("worker: the door wrote more than %d bytes", MaxDoorResponseBytes), nil)
	}
	return stdout.buf.Bytes(), nil
}

// boundedBuffer keeps at most max bytes and remembers whether more came.
type boundedBuffer struct {
	buf        bytes.Buffer
	max        int
	overflowed bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	room := b.max - b.buf.Len()
	if room < len(p) {
		b.overflowed = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

// tail is the end of what was written, for an error message.
func (b *boundedBuffer) tail() string {
	const n = 400
	s := b.buf.String()
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// Compile-time assertion: the production backend satisfies the frozen
// Reconstructor interface (frozen_test.go pins the interface's shape).
var _ Reconstructor = (*GenomeReconstructor)(nil)
