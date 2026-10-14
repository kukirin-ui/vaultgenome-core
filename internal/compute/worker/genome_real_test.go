// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	"github.com/vault-genome/vaultgenome-core/internal/genome/lora"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// With the worker and torch installed (VG_GENOME_WORKER=workers/genome),
// the real door restores a genome the real finetune wrote — from memory,
// as the acp-compute worker delivers it — and the GenomeReconstructor's
// output meets the genome's own references EXACT.
func TestGenomeReconstructor_RealDoor(t *testing.T) {
	workerDir := os.Getenv("VG_GENOME_WORKER")
	if workerDir == "" {
		t.Skip("set VG_GENOME_WORKER to the workers/genome directory to run the real door")
	}
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	work := t.TempDir()
	env := append(os.Environ(), "PYTHONPATH="+workerDir, "TOKENIZERS_PARALLELISM=false")
	setup := exec.Command(py, "-c", `import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))`, filepath.Join(work, "base"), filepath.Join(work, "train.jsonl"))
	setup.Dir, setup.Env = workerDir, env
	out, err := setup.CombinedOutput()
	require.NoError(t, err, string(out))
	ft := exec.Command(py, "-m", "vg_genome", "finetune", "--base", filepath.Join(work, "base"), "--base-name", "tiny",
		"--data", filepath.Join(work, "train.jsonl"), "--out", filepath.Join(work, "genome"), "--targets", "q_proj,v_proj,lm_head",
		"--steps", "20", "--lr", "1e-2", "--max-len", "32", "--threads", "1", "--top-k", "8", "--new-tokens", "4")
	ft.Dir, ft.Env = workerDir, env
	out, err = ft.CombinedOutput()
	require.NoError(t, err, string(out))

	// The job as the authority builds it: genome.json, the adapter, the
	// prompts — never the references.
	genomeDir := filepath.Join(work, "genome")
	g, err := lora.Load(genomeDir)
	require.NoError(t, err)
	fxRaw, err := os.ReadFile(filepath.Join(genomeDir, g.Fixtures.File))
	require.NoError(t, err)
	fixtures, prompts, err := lora.ParseFixtures(g, fxRaw)
	require.NoError(t, err)
	require.Len(t, prompts, len(fixtures))
	doc := gatejob.Prompts{Schema: gatejob.PromptsSchema}
	for _, p := range prompts {
		doc.Prompts = append(doc.Prompts, gatejob.Prompt{ID: p.ID, InputIDs: p.InputIDs, TopKIndex: p.TopKIndex})
	}
	promptsJSON, err := gatejob.EncodePrompts(doc)
	require.NoError(t, err)
	read := func(rel string) []byte {
		b, err := os.ReadFile(filepath.Join(genomeDir, filepath.FromSlash(rel)))
		require.NoError(t, err)
		return b
	}
	files := map[string][]byte{
		gatejob.GenomePath:                  read("genome.json"),
		"adapter/adapter_config.json":       read("adapter/adapter_config.json"),
		"adapter/adapter_model.safetensors": read("adapter/adapter_model.safetensors"),
		gatejob.PromptsPath:                 promptsJSON,
	}
	const genomeID = "genome-0123456789ab-g0-0123456789ab"
	desc := gatejob.Descriptor{Schema: gatejob.DescriptorSchema, GenomeID: genomeID}
	components := []worker.ComponentMaterial{{ComponentID: "c-0", SequenceIndex: 0}}
	i := uint32(1)
	for _, p := range []string{gatejob.GenomePath, "adapter/adapter_config.json", "adapter/adapter_model.safetensors", gatejob.PromptsPath} {
		sum := sha256.Sum256(files[p])
		desc.Files = append(desc.Files, gatejob.File{Path: p, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(files[p])), Component: i})
		components = append(components, worker.ComponentMaterial{ComponentID: ids.ComponentID(fmt.Sprintf("c-%d", i)), SequenceIndex: i, Plaintext: files[p]})
		i++
	}
	components[0].Plaintext, err = gatejob.EncodeDescriptor(desc)
	require.NoError(t, err)
	budget, err := gatejob.OutputBudget(genomeID, fixtures, nil)
	require.NoError(t, err)

	r, err := worker.NewGenomeReconstructor(worker.GenomeConfig{
		Command: []string{py, "-m", "vg_genome", "door", "--stdin-genome", "--base", filepath.Join(work, "base"), "--device", "cpu"},
		Env:     []string{"PYTHONPATH=" + workerDir, "TOKENIZERS_PARALLELISM=false"},
		Timeout: 10 * time.Minute,
	}, shared_time.NewSystemClock())
	require.NoError(t, err)
	// The door resolves the module from its working directory only when
	// PYTHONPATH points there; the command runs from the test's cwd.
	manifest := rjm.ReconstructionJobManifest{
		SchemaVersion: rjm.SchemaVersionCurrent, ManifestID: "mf-real", SessionID: "ses-real", GenomeID: genomeID,
		ExpectedOutputKind: rjm.OutputKindBytesFixedLength, ExpectedOutputMaxBytes: budget,
		Deadline: time.Now().Add(10 * time.Minute), IssuedAt: time.Now(),
	}
	start := time.Now()
	cand, err := r.Reconstruct(context.Background(), manifest, components)
	require.NoError(t, err)
	t.Logf("real door answered %d prompts in %s", len(prompts), time.Since(start).Round(time.Millisecond))

	gid, outputs, _, err := gatejob.DecodeOutput(cand.Bytes)
	require.NoError(t, err)
	require.Equal(t, genomeID, gid)
	v, err := equivalence.Evaluate(genomeID, fixtures, outputs, equivalence.Tolerance{}, equivalence.StrictPolicy())
	require.NoError(t, err)
	require.Equal(t, equivalence.LevelExact, v.Level, "the model restored in memory reproduces its own references bit for bit on the runtime that sealed it")
	require.Equal(t, len(fixtures), v.NExact)
	raw, _ := json.Marshal(v)
	t.Logf("verdict: %s", raw)
}
