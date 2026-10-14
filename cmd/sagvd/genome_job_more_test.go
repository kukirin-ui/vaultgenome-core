// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Inside the bundle dir only a regular file is read: a directory, or a
// name that is not there, is refused with its size left unread.
func TestReadInRoot_RegularFilesOnly(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f"), []byte("five!"), 0o644))
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()

	_, _, err = readInRoot(root, "sub", 1<<20)
	require.ErrorContains(t, err, "is not a regular file")
	_, _, err = readInRoot(root, "absent", 1<<20)
	require.True(t, os.IsNotExist(err))
	_, size, err := readInRoot(root, "f", 4)
	require.ErrorIs(t, err, errFileTooLarge)
	require.Equal(t, int64(5), size, "the refusal names the size")
	data, size, err := readInRoot(root, "f", 5)
	require.NoError(t, err)
	require.Equal(t, []byte("five!"), data)
	require.Equal(t, int64(5), size)
}

// More shapes a gate job refuses at inspection: a bundle that is not a
// directory snapshot, a payload that is not a tar, a genome whose fixtures
// or adapter weights are missing, a key file that is a directory.
func TestGenomeJobs_RefusesMoreShapes(t *testing.T) {
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	g := newTestGenomeJobs(t, dir, "")
	writeSealed := func(name string, header bundle.Header, payload []byte) (string, string) {
		blob, dek, err := bundle.SealBytes(header, payload)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".genome"), blob, 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".key"), dek, 0o600))
		return name + ".genome", name + ".key"
	}
	ollamaBundle, ollamaKey := writeSealed("ollama", bundle.Header{ContentKind: bundle.ContentOllama, ContentRef: "llama3:8b", ContentSnapshot: []byte(`{"components":[]}`)}, []byte("weights"))
	notTarBundle, notTarKey := writeSealed("nottar", bundle.Header{ContentKind: bundle.ContentDir, ContentRef: "/adapter"}, []byte("this payload is not a tar archive at all"))
	noFixtures := sealTestGenome(t, dir, genomeOptions{name: "nofixtures", mutate: func(f map[string][]byte) { delete(f, "fixtures.json") }})
	noWeights := sealTestGenome(t, dir, genomeOptions{name: "noweights", mutate: func(f map[string][]byte) { delete(f, "adapter/adapter_model.safetensors") }})
	badGenome := sealTestGenome(t, dir, genomeOptions{name: "badgenome", mutate: func(f map[string][]byte) { f["genome.json"] = []byte("{") }})
	require.NoError(t, os.Mkdir(filepath.Join(dir, "keydir"), 0o700))
	huge := make([]byte, int(g.maxPayload)+bundle.MaxHeaderBytes+1<<20+1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "huge.genome"), huge, 0o644))

	for name, tc := range map[string]struct {
		ref  genomeRef
		code string
		want string
	}{
		"not a directory snapshot": {genomeRef{Bundle: ollamaBundle, KeyFile: ollamaKey}, CodeGenomeInvalid, "not a model genome directory"},
		"payload not a tar":        {genomeRef{Bundle: notTarBundle, KeyFile: notTarKey}, CodeGenomeInvalid, "payload is not the tar"},
		"fixtures missing":         {genomeRef{Bundle: noFixtures.Bundle, KeyFile: noFixtures.KeyFile}, CodeGenomeInvalid, "names fixtures"},
		"weights missing":          {genomeRef{Bundle: noWeights.Bundle, KeyFile: noWeights.KeyFile}, CodeGenomeInvalid, "adapter_model.safetensors"},
		"key file is a directory":  {genomeRef{Bundle: sealed.Bundle, KeyFile: "keydir"}, CodeGenomeNotFound, "key file keydir"},
		"genome.json malformed":    {genomeRef{Bundle: badGenome.Bundle, KeyFile: badGenome.KeyFile}, CodeGenomeInvalid, "genome badgenome.genome"},
		"too large to read":        {genomeRef{Bundle: "huge.genome", KeyFile: sealed.KeyFile}, CodeGenomeTooLarge, "a gate job carries at most"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := g.inspect(tc.ref)
			require.Error(t, err)
			require.Equal(t, tc.code, shared_errors.CodeOf(err), err.Error())
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// With an escrow key, a job without a key file opens the envelope beside
// its bundle: one that is not there, is not an envelope, holds another
// genome's key, or was sealed to another authority is refused.
func TestGenomeJobs_EscrowEnvelopeRefusals(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := escrowKeyPair(t, dir)
	g := newTestGenomeJobs(t, dir, privPath)
	escrowed := sealTestGenome(t, dir, genomeOptions{name: "escrowed", escrowPub: pubPath})
	other := sealTestGenome(t, dir, genomeOptions{name: "other", escrowPub: pubPath})
	keyed := sealTestGenome(t, dir, genomeOptions{name: "keyed"})
	_, strangerPub := escrowKeyPair(t, t.TempDir())
	stranger := sealTestGenome(t, dir, genomeOptions{name: "stranger", escrowPub: strangerPub})

	info, err := g.inspect(genomeRef{Bundle: escrowed.Bundle})
	require.NoError(t, err)
	require.Equal(t, "escrow", info.View.KeySource)

	otherEnv, err := os.ReadFile(filepath.Join(dir, other.Bundle+".escrow"))
	require.NoError(t, err)
	swapped := sealTestGenome(t, dir, genomeOptions{name: "swapped", escrowPub: pubPath})
	require.NoError(t, os.WriteFile(filepath.Join(dir, swapped.Bundle+".escrow"), otherEnv, 0o644))
	garbage := sealTestGenome(t, dir, genomeOptions{name: "garbage", escrowPub: pubPath})
	require.NoError(t, os.WriteFile(filepath.Join(dir, garbage.Bundle+".escrow"), []byte("{"), 0o644))

	for name, tc := range map[string]struct {
		bundle string
		code   string
		want   string
	}{
		"no envelope":       {keyed.Bundle, CodeGenomeNotFound, "no envelope"},
		"not an envelope":   {garbage.Bundle, CodeGenomeKeyInvalid, "envelope"},
		"another key":       {swapped.Bundle, CodeGenomeKeyInvalid, "holds key"},
		"another authority": {stranger.Bundle, CodeGenomeKeyInvalid, "envelope"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := g.inspect(genomeRef{Bundle: tc.bundle})
			require.Error(t, err)
			require.Equal(t, tc.code, shared_errors.CodeOf(err), err.Error())
			require.ErrorContains(t, err, tc.want)
		})
	}
	_ = escrow.KeyTag
}

// judge refuses, as Integrity, an answer that leaves a fixture out, one
// whose tensors do not decode, and one no door could judge: a model that
// misses the float references and gives the integer door nothing to hold
// to its references.
func TestJudge_RefusesWhatCannotBeJudged(t *testing.T) {
	sealed, spec := inspectTestGenome(t)
	outputs := map[string]equivalence.Tensor{}
	for i, p := range sealed.Prompts.Prompts {
		if i == 2 {
			continue
		}
		vals := make([]float32, len(p.TopKIndex))
		for j, idx := range p.TopKIndex {
			vals[j] = doorValue(p.InputIDs, idx)
		}
		outputs[p.ID] = equivalence.Tensor{DType: equivalence.F32, Shape: []int{len(vals)}, Raw: f32(vals...)}
	}
	partial, err := gatejob.EncodeOutput(sealed.KeyID, outputs, nil)
	require.NoError(t, err)
	_, err = judge(spec, candidate(sealed.KeyID, partial))
	require.Equal(t, CodeGateOutputInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, `no output for fixture "fx-002"`)
	otherGenome, err := gatejob.EncodeOutput("genome-000000000000-g0-000000000000", outputs, nil)
	require.NoError(t, err)
	_, err = judge(spec, candidate(sealed.KeyID, otherGenome))
	require.Equal(t, CodeGateOutputInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "answered for genome")

	outputs["fx-002"] = equivalence.Tensor{DType: equivalence.F32, Shape: []int{3}, Raw: f32(1, 2)}
	short, err := gatejob.EncodeOutput(sealed.KeyID, outputs, nil)
	require.NoError(t, err)
	_, err = judge(spec, candidate(sealed.KeyID, short))
	require.Equal(t, CodeGateOutputInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "do not fill shape")

	dir := t.TempDir()
	integer := sealTestGenome(t, dir, genomeOptions{integer: true})
	info, err := newTestGenomeJobs(t, dir, "").inspect(genomeRef{Bundle: integer.Bundle, KeyFile: integer.KeyFile})
	require.NoError(t, err)
	require.NotNil(t, info.Gate.IntegerFixtures)
	noIntegers := integer.output(t, map[[2]int]float32{{0, 0}: 5}, nil, false)
	j, err := judge(info.Gate, candidate(integer.KeyID, noIntegers))
	require.Equal(t, CodeGateOutputInvalid, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.ErrorContains(t, err, "no door could judge")
	require.Equal(t, "ERROR", j.Gate.Level)
	require.Len(t, j.Gate.Attempts, 3, "both float doors and the integer door were tried")
}

// A gate that judged nothing is a failed behavioural dimension with one
// finding that says so; a passing verdict is signed only under a key the
// authority holds.
func TestGateDimensionAndSignVerdict(t *testing.T) {
	dim := gateDimension(GateView{Level: "ERROR"})
	require.Equal(t, validation_result.VerdictFail, dim.Verdict)
	require.NotEmpty(t, dim.Details)

	store := keys.NewInMemoryStore(shared_time.NewSystemClock())
	view := GateView{Level: "EXACT", SignedVerdict: &equivalence.SignedVerdict{Verdict: equivalence.Verdict{Level: equivalence.LevelExact}}}
	err := signVerdict(&view, store, ids.KeyID("not-registered"), nil)
	require.Error(t, err)
	require.Empty(t, view.SignerKeyID, "nothing was signed")
	require.NoError(t, signVerdict(&GateView{}, store, "x", nil), "no verdict, nothing to sign")
}

// A payload that claims more than it holds, or ends inside a file, is not
// a genome.
func TestUntarFiles_TruncatedPayloads(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "big.bin", Mode: 0o644, Size: 10_000, Typeflag: tar.TypeReg}))
	_, err := tw.Write(make([]byte, 10_000))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	_, err = untarFiles(buf.Bytes()[:600])
	require.ErrorContains(t, err, "describes more bytes than it holds")

	buf.Reset()
	tw = tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "cut.bin", Mode: 0o644, Size: 1000, Typeflag: tar.TypeReg}))
	_, err = tw.Write(make([]byte, 1000))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	_, err = untarFiles(buf.Bytes()[:512+600])
	require.ErrorContains(t, err, "payload: cut.bin")
}
