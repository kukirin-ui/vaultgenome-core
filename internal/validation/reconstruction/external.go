// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// ExternalBackend adapts an out-of-process "recompute backend" into a
// RecomputeFunc, so a ladder door can be served by a program written in any
// language. This is the integration seam for the reproducible-float rung
// (KindReproducibleFloat), whose reference backend is a RepDL/ReproBLAS-class
// runner — borrowed, not ours (see docs/prior-art-and-attribution.md). Keeping
// it out of process keeps the Go core free of any heavy numeric/Python
// dependency while letting the attested Go orchestration drive and gate it.
//
// # Protocol
//
// The backend owns the restored model. For each fixture the adapter runs Argv,
// writes a one-line JSON request to stdin, and reads a one-line JSON response
// from stdout:
//
//	request : {"fixture_id":"<id>"}
//	response: {"dtype":"f64","shape":[8,16],"raw_b64":"<base64 of little-endian raw>"}
//
// A non-zero exit, malformed output, or timeout is returned as an Operational
// error — the ladder records the door as errored and falls through to the next
// one, so a broken backend never crashes a regeneration (fail-safe). A reference
// runner implementing this protocol lives at
// scripts/reconstruction/repdl-door-runner.py.
type ExternalBackend struct {
	Argv    []string      // command and arguments (Argv[0] is the executable)
	Timeout time.Duration // per-fixture timeout; <=0 uses defaultExternalTimeout
}

const defaultExternalTimeout = 30 * time.Second

type extRequest struct {
	FixtureID string `json:"fixture_id"`
}

type extResponse struct {
	DType  string `json:"dtype"`
	Shape  []int  `json:"shape"`
	RawB64 string `json:"raw_b64"`
}

// Recompute is the RecomputeFunc: it invokes the backend for one fixture id.
func (b ExternalBackend) Recompute(id string) (equivalence.Tensor, error) {
	if len(b.Argv) == 0 {
		return equivalence.Tensor{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing, "reconstruction: external backend has empty argv", nil)
	}
	to := b.Timeout
	if to <= 0 {
		to = defaultExternalTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()

	req, err := json.Marshal(extRequest{FixtureID: id})
	if err != nil {
		return equivalence.Tensor{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstruction: marshal request", err)
	}
	cmd := exec.CommandContext(ctx, b.Argv[0], b.Argv[1:]...)
	cmd.Stdin = bytes.NewReader(req)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return equivalence.Tensor{}, shared_errors.Operational(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("reconstruction: external backend %q failed for fixture %q: %v: %s",
				b.Argv[0], id, err, strings.TrimSpace(errb.String())), err)
	}
	var r extResponse
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &r); err != nil {
		return equivalence.Tensor{}, shared_errors.Operational(
			shared_errors.CodeFieldValueInvalid, "reconstruction: external backend returned malformed JSON", err)
	}
	raw, err := base64.StdEncoding.DecodeString(r.RawB64)
	if err != nil {
		return equivalence.Tensor{}, shared_errors.Operational(
			shared_errors.CodeFieldValueInvalid, "reconstruction: external backend raw_b64 not valid base64", err)
	}
	dt := equivalence.DType(r.DType)
	if dt != equivalence.F32 && dt != equivalence.F64 {
		return equivalence.Tensor{}, shared_errors.Operational(
			shared_errors.CodeFieldValueInvalid, "reconstruction: external backend returned unknown dtype "+r.DType, nil)
	}
	return equivalence.Tensor{DType: dt, Shape: r.Shape, Raw: raw}, nil
}

// Door builds a ladder Strategy served by this external backend. Kind defaults
// to KindReproducibleFloat (the borrowed RepDL/ReproBLAS rung); pass a different
// kind explicitly if the backend implements another door class.
func (b ExternalBackend) Door(rung int, name string, tol equivalence.Tolerance, pol equivalence.Policy) Strategy {
	return Strategy{
		Rung:      rung,
		Kind:      KindReproducibleFloat,
		Name:      name,
		Recompute: b.Recompute,
		Tol:       tol,
		Pol:       pol,
	}
}
