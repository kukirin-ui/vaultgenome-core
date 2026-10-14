// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// BatchedExternalBackend is ExternalBackend for a backend that loads a
// real model: it runs the backend once, for every fixture, and serves each
// door's recompute from those outputs. A model that takes seconds to load
// then loads once per gate, not once per fixture.
//
// Protocol (the vg_genome door speaks both forms):
//
//	request : {"fixture_ids":["<id>", ...]}                       the model's float kernels
//	request : {"fixture_ids":["<id>", ...], "door":"integer"}     the integer door
//	response: {"outputs":{"<id>":{"dtype":"f32","shape":[k],"raw_b64":"..."}, ...}}
//
// Every requested id must come back; anything else — a non-zero exit, a
// timeout, malformed output, a missing id — is an Operational error for
// every fixture, so the ladder records the door as errored and falls through.
type BatchedExternalBackend struct {
	Argv    []string
	Env     []string      // extra environment for the backend, KEY=VALUE
	IDs     []string      // every fixture id the gate will ask for
	Timeout time.Duration // for the whole batch; <=0 uses defaultBatchTimeout
	// Which names the door the backend should answer with: empty for the
	// model's float kernels, DoorInteger for the integer door.
	Which string

	once    sync.Once
	outputs map[string]equivalence.Tensor
	err     error
	Seconds float64 // wall time of the backend run, once it has run
}

const defaultBatchTimeout = 30 * time.Minute

// DoorInteger names the integer door in a batch request.
const DoorInteger = "integer"

type batchRequest struct {
	FixtureIDs []string `json:"fixture_ids"`
	Door       string   `json:"door,omitempty"`
}

type batchResponse struct {
	Outputs map[string]extResponse `json:"outputs"`
}

// Recompute is the RecomputeFunc: the first call runs the batch.
func (b *BatchedExternalBackend) Recompute(id string) (equivalence.Tensor, error) {
	b.once.Do(b.run)
	if b.err != nil {
		return equivalence.Tensor{}, b.err
	}
	t, ok := b.outputs[id]
	if !ok {
		return equivalence.Tensor{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("reconstruction: fixture %q was not in the batch", id), nil)
	}
	return t, nil
}

func (b *BatchedExternalBackend) run() {
	if len(b.Argv) == 0 || len(b.IDs) == 0 {
		b.err = shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
			"reconstruction: batched backend needs a command and fixture ids", nil)
		return
	}
	to := b.Timeout
	if to <= 0 {
		to = defaultBatchTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	req, err := json.Marshal(batchRequest{FixtureIDs: b.IDs, Door: b.Which})
	if err != nil {
		b.err = shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstruction: marshal batch request", err)
		return
	}
	cmd := exec.CommandContext(ctx, b.Argv[0], b.Argv[1:]...)
	if len(b.Env) > 0 {
		cmd.Env = append(os.Environ(), b.Env...)
	}
	cmd.Stdin = bytes.NewReader(req)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	start := time.Now()
	runErr := cmd.Run()
	b.Seconds = time.Since(start).Seconds()
	if runErr != nil {
		b.err = shared_errors.Operational(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("reconstruction: batched backend %q failed: %v: %s %s", b.Argv[0], runErr,
				strings.TrimSpace(tail(out.String())), strings.TrimSpace(tail(errb.String()))), runErr)
		return
	}
	var resp batchResponse
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		b.err = shared_errors.Operational(shared_errors.CodeFieldValueInvalid, "reconstruction: batched backend returned malformed JSON", err)
		return
	}
	b.outputs = make(map[string]equivalence.Tensor, len(b.IDs))
	for _, id := range b.IDs {
		r, ok := resp.Outputs[id]
		if !ok {
			b.err = shared_errors.Operational(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("reconstruction: batched backend returned no output for %q", id), nil)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(r.RawB64)
		if err != nil {
			b.err = shared_errors.Operational(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("reconstruction: batched backend output for %q is not base64", id), err)
			return
		}
		dt := equivalence.DType(r.DType)
		if dt != equivalence.F32 && dt != equivalence.F64 {
			b.err = shared_errors.Operational(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("reconstruction: batched backend output for %q has dtype %q", id, r.DType), nil)
			return
		}
		b.outputs[id] = equivalence.Tensor{DType: dt, Shape: r.Shape, Raw: raw}
	}
}

// tail keeps the end of a long backend message.
func tail(s string) string {
	const n = 400
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// Door builds a ladder Strategy served by this backend.
func (b *BatchedExternalBackend) Door(rung int, kind StrategyKind, name string, tol equivalence.Tolerance, pol equivalence.Policy) Strategy {
	return Strategy{Rung: rung, Kind: kind, Name: name, Recompute: b.Recompute, Tol: tol, Pol: pol}
}

// IntegerDoor builds the fixed-point rung served by an integer-door
// backend: held byte for byte (tol 0, strict) to refs, the references
// that arithmetic sealed, not to the ladder's float ones.
func (b *BatchedExternalBackend) IntegerDoor(rung int, name string, refs []equivalence.Fixture) Strategy {
	return Strategy{Rung: rung, Kind: KindFixedPoint, Name: name, Recompute: b.Recompute, Tol: ExactTolerance, Pol: equivalence.StrictPolicy(), Fixtures: refs}
}
