// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// The test door. When the test binary starts with VG_TEST_DOOR set it is
// the door the GenomeReconstructor under test runs: it reads the request
// on stdin and answers as that mode says, then exits. A door is a
// separate program; this keeps the test free of Python while exercising
// the real process boundary.
func TestMain(m *testing.M) {
	if mode := os.Getenv("VG_TEST_DOOR"); mode != "" {
		os.Exit(testDoor(mode))
	}
	os.Exit(m.Run())
}

// doorValue is the arithmetic the test door and the test's references
// share: a model whose logit at token idx for a prompt is the prompt's
// token sum plus half the index.
func doorValue(inputIDs []int, idx int) float32 {
	sum := 0
	for _, id := range inputIDs {
		sum += id
	}
	return float32(sum) + float32(idx)*0.5
}

func testDoor(mode string) int {
	switch mode {
	case "fail":
		fmt.Fprintln(os.Stderr, "boom: the base model does not match")
		return 3
	case "hang":
		time.Sleep(30 * time.Second)
		return 0
	case "garbage":
		fmt.Print("not json at all")
		return 0
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 2
	}
	req, err := gatejob.DecodeDoorRequest(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "door: bad request:", err)
		return 2
	}
	if want := os.Getenv("VG_TEST_EXPECT_ENV"); want != "" && os.Getenv("VG_TEST_ENV") != want {
		fmt.Fprintln(os.Stderr, "door: environment not passed through")
		return 2
	}
	for _, p := range []string{gatejob.GenomePath, "adapter/adapter_config.json", "adapter/adapter_model.safetensors"} {
		if len(req.Files[p]) == 0 {
			fmt.Fprintln(os.Stderr, "door: request lacks", p)
			return 2
		}
	}
	prompts, err := gatejob.DecodePrompts(req.Files[gatejob.PromptsPath])
	if err != nil {
		fmt.Fprintln(os.Stderr, "door: bad prompts:", err)
		return 2
	}
	outputs := map[string]gatejob.Tensor{}
	for i, p := range prompts.Prompts {
		if mode == "missing-id" && i == len(prompts.Prompts)-1 {
			continue
		}
		vals := make([]float32, len(p.TopKIndex))
		for j, idx := range p.TopKIndex {
			vals[j] = doorValue(p.InputIDs, idx)
		}
		outputs[p.ID] = gatejob.FromTensor(equivalence.Tensor{DType: equivalence.F32, Shape: []int{len(vals)}, Raw: f32(vals...)})
	}
	if mode == "extra-id" {
		outputs["fx-extra"] = gatejob.FromTensor(equivalence.Tensor{DType: equivalence.F32, Shape: []int{1}, Raw: f32(1)})
	}
	resp := gatejob.DoorResponse{Outputs: outputs}
	// The integer door answers when the prompts ask for it (its own
	// arithmetic: a different value), or unasked in the "unasked-integer"
	// mode; the "no-integer" mode ignores the request.
	if (prompts.Integer && mode != "no-integer") || mode == "unasked-integer" {
		resp.IntegerOutputs = map[string]gatejob.Tensor{}
		for _, p := range prompts.Prompts {
			vals := make([]float32, len(p.TopKIndex))
			for j, idx := range p.TopKIndex {
				vals[j] = integerDoorValue(p.InputIDs, idx)
			}
			resp.IntegerOutputs[p.ID] = gatejob.FromTensor(equivalence.Tensor{DType: equivalence.F32, Shape: []int{len(vals)}, Raw: f32(vals...)})
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		return 2
	}
	return 0
}

// integerDoorValue is the test integer door's arithmetic: near the float
// door's, never equal to it.
func integerDoorValue(inputIDs []int, idx int) float32 {
	return doorValue(inputIDs, idx) + 0.125
}

func f32(vals ...float32) []byte {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	return b
}

// gateJob is a gate job as the authority builds it: the files, the
// descriptor in component 0, and the references a right answer meets.
type gateJob struct {
	genomeID   string
	prompts    gatejob.Prompts
	files      map[string][]byte
	components []worker.ComponentMaterial
	manifest   rjm.ReconstructionJobManifest
	expected   []byte // the canonical output a right door gives
}

func newGateJob(t *testing.T) *gateJob {
	t.Helper()
	weights := make([]byte, 4096)
	rand.New(rand.NewSource(7)).Read(weights)
	j := &gateJob{
		genomeID: "genome-0123456789ab-g0-0123456789ab",
		prompts: gatejob.Prompts{Schema: gatejob.PromptsSchema, Prompts: []gatejob.Prompt{
			{ID: "fx-000", InputIDs: []int{3, 5, 8}, TopKIndex: []int{7, 1, 4}},
			{ID: "fx-001", InputIDs: []int{4, 4}, TopKIndex: []int{0, 9, 2}},
			{ID: "fx-002", InputIDs: []int{12}, TopKIndex: []int{5, 6, 1}},
		}},
	}
	promptsJSON, err := gatejob.EncodePrompts(j.prompts)
	require.NoError(t, err)
	j.files = map[string][]byte{
		gatejob.GenomePath:                  []byte(`{"schema":"vault-genome/lora-genome/v1","adapter":{"dir":"adapter"}}`),
		"adapter/adapter_config.json":       []byte(`{"peft_type":"LORA","r":8}`),
		"adapter/adapter_model.safetensors": weights,
		gatejob.PromptsPath:                 promptsJSON,
	}
	j.rebuild(t)
	return j
}

// rebuild derives the descriptor, the components, the manifest and the
// expected output from the job's files and prompts.
func (j *gateJob) rebuild(t *testing.T) {
	t.Helper()
	paths := []string{gatejob.GenomePath, "adapter/adapter_config.json", "adapter/adapter_model.safetensors", gatejob.PromptsPath}
	desc := gatejob.Descriptor{Schema: gatejob.DescriptorSchema, GenomeID: j.genomeID}
	j.components = nil
	for i, p := range paths {
		data := j.files[p]
		sum := sha256.Sum256(data)
		desc.Files = append(desc.Files, gatejob.File{Path: p, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data)), Component: uint32(i + 1)})
		j.components = append(j.components, worker.ComponentMaterial{
			ComponentID: ids.ComponentID(fmt.Sprintf("c-%d", i+1)), SequenceIndex: uint32(i + 1), Plaintext: data,
		})
	}
	raw, err := gatejob.EncodeDescriptor(desc)
	require.NoError(t, err)
	j.components = append([]worker.ComponentMaterial{{ComponentID: "c-0", SequenceIndex: 0, Plaintext: raw}}, j.components...)

	var fixtures, integerFixtures []equivalence.Fixture
	expected := map[string]equivalence.Tensor{}
	var expectedInteger map[string]equivalence.Tensor
	if j.prompts.Integer {
		expectedInteger = map[string]equivalence.Tensor{}
	}
	for _, p := range j.prompts.Prompts {
		vals := make([]float32, len(p.TopKIndex))
		ivals := make([]float32, len(p.TopKIndex))
		for k, idx := range p.TopKIndex {
			vals[k] = doorValue(p.InputIDs, idx)
			ivals[k] = integerDoorValue(p.InputIDs, idx)
		}
		tensor := equivalence.Tensor{DType: equivalence.F32, Shape: []int{len(vals)}, Raw: f32(vals...)}
		fixtures = append(fixtures, equivalence.Fixture{ID: p.ID, Expected: tensor})
		expected[p.ID] = tensor
		if j.prompts.Integer {
			itensor := equivalence.Tensor{DType: equivalence.F32, Shape: []int{len(ivals)}, Raw: f32(ivals...)}
			integerFixtures = append(integerFixtures, equivalence.Fixture{ID: p.ID, Expected: itensor})
			expectedInteger[p.ID] = itensor
		}
	}
	budget, err := gatejob.OutputBudget(j.genomeID, fixtures, integerFixtures)
	require.NoError(t, err)
	j.expected, err = gatejob.EncodeOutput(j.genomeID, expected, expectedInteger)
	require.NoError(t, err)
	j.manifest = rjm.ReconstructionJobManifest{
		SchemaVersion:          rjm.SchemaVersionCurrent,
		ManifestID:             "mf-gate-1",
		SessionID:              "ses-gate-1",
		GenomeID:               ids.GenomeID(j.genomeID),
		ExpectedOutputKind:     rjm.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: budget,
		// The door runs under the real clock, so the deadline is real time.
		Deadline: time.Now().Add(10 * time.Minute),
		IssuedAt: time.Now(),
	}
}

// doorEnv names the door's mode and gives the door its own coverage
// directory: under `go test -cover` the door is this test binary, which
// writes its coverage meta file under a name that carries only a
// timestamp, so two doors started in the same instant into the parent's
// GOCOVERDIR collide on the rename and one of them exits with the
// coverage error in place of its own message.
func doorEnv(t *testing.T, mode string, extraEnv ...string) []string {
	t.Helper()
	return append([]string{"VG_TEST_DOOR=" + mode, "GOCOVERDIR=" + t.TempDir()}, extraEnv...)
}

func doorReconstructor(t *testing.T, mode string, extraEnv ...string) *worker.GenomeReconstructor {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	r, err := worker.NewGenomeReconstructor(worker.GenomeConfig{
		Command: []string{exe},
		Env:     doorEnv(t, mode, extraEnv...),
		Timeout: 20 * time.Second,
	}, fixtureClock(t))
	require.NoError(t, err)
	return r
}

func TestGenome_RightDoorGivesTheCanonicalOutput(t *testing.T) {
	t.Parallel()
	j := newGateJob(t)
	r := doorReconstructor(t, "echo-sum", "VG_TEST_ENV=through", "VG_TEST_EXPECT_ENV=through")

	out, err := r.Reconstruct(context.Background(), j.manifest, j.components)
	require.NoError(t, err)
	require.Equal(t, j.manifest.ManifestID, out.ManifestID)
	require.Equal(t, j.manifest.SessionID, out.SessionID)
	require.Equal(t, rjm.OutputKindBytesFixedLength, out.OutputKind)
	require.Equal(t, j.expected, out.Bytes, "the door's outputs come back canonically encoded")
	require.Equal(t, j.manifest.ExpectedOutputMaxBytes, uint64(len(out.Bytes)), "the authority's budget is the output's exact size")
	require.Equal(t, fixtureClock(t).Now(), out.ProducedAt, "ProducedAt comes from the injected clock")

	gid, outputs, _, err := gatejob.DecodeOutput(out.Bytes)
	require.NoError(t, err)
	require.Equal(t, j.genomeID, gid)
	require.Len(t, outputs, 3)
	require.Equal(t, doorValue([]int{3, 5, 8}, 7), math.Float32frombits(binary.LittleEndian.Uint32(outputs["fx-000"].Raw)))
}

func TestGenome_DeterministicAndOrderInsensitive(t *testing.T) {
	t.Parallel()
	j := newGateJob(t)
	r := doorReconstructor(t, "echo-sum")
	a, err := r.Reconstruct(context.Background(), j.manifest, j.components)
	require.NoError(t, err)
	shuffled := append([]worker.ComponentMaterial(nil), j.components...)
	rand.New(rand.NewSource(3)).Shuffle(len(shuffled), func(x, y int) { shuffled[x], shuffled[y] = shuffled[y], shuffled[x] })
	b, err := r.Reconstruct(context.Background(), j.manifest, shuffled)
	require.NoError(t, err)
	require.Equal(t, a.Bytes, b.Bytes)
}

func TestGenome_MalformedJobsAreStructural(t *testing.T) {
	t.Parallel()
	r := doorReconstructor(t, "echo-sum")
	cases := map[string]struct {
		mutate func(j *gateJob)
		code   string
	}{
		"no descriptor": {func(j *gateJob) { j.components = j.components[1:] }, worker.CodeGateJobMalformed},
		"descriptor is not one": {func(j *gateJob) {
			j.components[0].Plaintext = []byte(`{"schema":"vault-genome/gate-job/v1"}`)
		}, worker.CodeGateJobMalformed},
		"named component missing": {func(j *gateJob) { j.components = j.components[:len(j.components)-1] }, worker.CodeGateJobMalformed},
		"unnamed component": {func(j *gateJob) {
			j.components = append(j.components, worker.ComponentMaterial{ComponentID: "c-9", SequenceIndex: 9, Plaintext: []byte("stray")})
		}, worker.CodeGateJobMalformed},
		"two components share an index": {func(j *gateJob) {
			j.components = append(j.components, worker.ComponentMaterial{ComponentID: "c-dup", SequenceIndex: 1, Plaintext: []byte("x")})
		}, worker.CodeGateJobMalformed},
		"prompts do not parse": {func(j *gateJob) {
			j.files[gatejob.PromptsPath] = []byte(`{"schema":"vault-genome/door-prompts/v1","prompts":[]}`)
			j.rebuild(t)
		}, worker.CodeGateJobMalformed},
		"wrong output kind": {func(j *gateJob) { j.manifest.ExpectedOutputKind = rjm.OutputKindTokensStream }, shared_errors.CodeFieldValueInvalid},
		"empty components":  {func(j *gateJob) { j.components = nil }, shared_errors.CodeRequiredFieldMissing},
		"duplicate component id": {func(j *gateJob) {
			j.components[2].ComponentID = j.components[1].ComponentID
		}, shared_errors.CodeFieldValueInvalid},
		"empty manifest id": {func(j *gateJob) { j.manifest.ManifestID = "" }, shared_errors.CodeRequiredFieldMissing},
		"empty session id":  {func(j *gateJob) { j.manifest.SessionID = "" }, shared_errors.CodeRequiredFieldMissing},
		"zero budget":       {func(j *gateJob) { j.manifest.ExpectedOutputMaxBytes = 0 }, shared_errors.CodeFieldValueInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			j := newGateJob(t)
			tc.mutate(j)
			_, err := r.Reconstruct(context.Background(), j.manifest, j.components)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), err.Error())
			require.Equal(t, tc.code, shared_errors.CodeOf(err), err.Error())
		})
	}
}

func TestGenome_ComponentNotAsDescribedIsIntegrity(t *testing.T) {
	t.Parallel()
	r := doorReconstructor(t, "echo-sum")
	for name, mutate := range map[string]func(j *gateJob){
		"flipped byte": func(j *gateJob) { j.components[3].Plaintext[10] ^= 0x01 },
		"truncated":    func(j *gateJob) { j.components[3].Plaintext = j.components[3].Plaintext[:100] },
	} {
		t.Run(name, func(t *testing.T) {
			j := newGateJob(t)
			mutate(j)
			_, err := r.Reconstruct(context.Background(), j.manifest, j.components)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
			require.Equal(t, worker.CodeComponentDigestMismatch, shared_errors.CodeOf(err))
		})
	}
}

func TestGenome_DoorFailuresAreOperational(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		mode string
		code string
		msg  string
	}{
		"exits non-zero": {"fail", worker.CodeDoorFailed, "boom: the base model does not match"},
		"garbage":        {"garbage", worker.CodeDoorOutputInvalid, "does not parse"},
		"missing id":     {"missing-id", worker.CodeDoorOutputInvalid, "2 outputs for 3 prompts"},
		"extra id":       {"extra-id", worker.CodeDoorOutputInvalid, "4 outputs for 3 prompts"},
	} {
		t.Run(name, func(t *testing.T) {
			j := newGateJob(t)
			_, err := doorReconstructor(t, tc.mode).Reconstruct(context.Background(), j.manifest, j.components)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestGenome_DoorIsBoundedInTime(t *testing.T) {
	t.Parallel()
	exe, err := os.Executable()
	require.NoError(t, err)
	j := newGateJob(t)

	t.Run("configured timeout", func(t *testing.T) {
		r, err := worker.NewGenomeReconstructor(worker.GenomeConfig{
			Command: []string{exe}, Env: doorEnv(t, "hang"), Timeout: 300 * time.Millisecond,
		}, fixtureClock(t))
		require.NoError(t, err)
		start := time.Now()
		_, err = r.Reconstruct(context.Background(), j.manifest, j.components)
		require.Error(t, err)
		require.Less(t, time.Since(start), 10*time.Second)
		require.Equal(t, worker.CodeDoorFailed, shared_errors.CodeOf(err))
		require.Contains(t, err.Error(), "ran out of time")
	})
	t.Run("manifest deadline", func(t *testing.T) {
		past := j.manifest
		past.Deadline = time.Now().Add(-time.Second)
		_, err := doorReconstructor(t, "hang").Reconstruct(context.Background(), past, j.components)
		require.Error(t, err)
		require.Equal(t, worker.CodeDoorFailed, shared_errors.CodeOf(err))
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := doorReconstructor(t, "echo-sum").Reconstruct(ctx, j.manifest, j.components)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
		require.Equal(t, shared_errors.CodeResourceExhausted, shared_errors.CodeOf(err))
	})
}

func TestGenome_OutputOverBudgetIsRefused(t *testing.T) {
	t.Parallel()
	j := newGateJob(t)
	j.manifest.ExpectedOutputMaxBytes--
	_, err := doorReconstructor(t, "echo-sum").Reconstruct(context.Background(), j.manifest, j.components)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Equal(t, worker.CodeOutputOverBudget, shared_errors.CodeOf(err))
}

func TestNewGenomeReconstructor_RejectsBadConfig(t *testing.T) {
	t.Parallel()
	clock := fixtureClock(t)
	for name, tc := range map[string]struct {
		cfg   worker.GenomeConfig
		clock shared_time.Clock
	}{
		"nil clock":        {worker.GenomeConfig{Command: []string{"door"}}, nil},
		"no command":       {worker.GenomeConfig{}, clock},
		"blank command":    {worker.GenomeConfig{Command: []string{" "}}, clock},
		"bad env":          {worker.GenomeConfig{Command: []string{"door"}, Env: []string{"NOEQUALS"}}, clock},
		"negative timeout": {worker.GenomeConfig{Command: []string{"door"}, Timeout: -1}, clock},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := worker.NewGenomeReconstructor(tc.cfg, tc.clock)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
		})
	}
	r, err := worker.NewGenomeReconstructor(worker.GenomeConfig{Command: []string{"door", "--x"}}, clock)
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestGenome_AbsentDoorCommandFails(t *testing.T) {
	t.Parallel()
	j := newGateJob(t)
	r, err := worker.NewGenomeReconstructor(worker.GenomeConfig{Command: []string{"/nonexistent/vg-door"}}, fixtureClock(t))
	require.NoError(t, err)
	_, err = r.Reconstruct(context.Background(), j.manifest, j.components)
	require.Error(t, err)
	require.Equal(t, worker.CodeDoorFailed, shared_errors.CodeOf(err))
	require.True(t, strings.Contains(err.Error(), "vg-door"))
}
