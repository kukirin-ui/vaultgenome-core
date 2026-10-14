// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// newTestGenomeJobs wires an opener over a temp bundle dir.
func newTestGenomeJobs(t *testing.T, bundleDir, escrowKey string) *genomeJobs {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Genome.BundleDir = bundleDir
	cfg.Runtime.MaxPayloadBytes = 1 << 20
	var priv *ecdh.PrivateKey
	if escrowKey != "" {
		var err error
		priv, err = escrow.ReadPrivate(escrowKey)
		require.NoError(t, err)
	}
	g := newGenomeJobs(cfg, shared_time.NewSystemClock(), priv)
	require.NotNil(t, g)
	return g
}

func TestGenomeJobs_InspectKeepsTheReferencesAndComponentsLayOutTheModelSide(t *testing.T) {
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	g := newTestGenomeJobs(t, dir, "")

	info, err := g.inspect(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile})
	require.NoError(t, err)

	// The genome view is public and complete.
	require.Equal(t, sealed.Bundle, info.View.Bundle)
	require.Equal(t, sealed.KeyID, info.View.KeyID)
	require.Equal(t, sealed.KeyID, info.GenomeID)
	require.Equal(t, "key_file", info.View.KeySource)
	require.Equal(t, "tiny-llama", info.View.Base)
	require.Equal(t, 3, info.View.Fixtures)
	require.Equal(t, 2, info.View.Critical)
	require.Equal(t, 4, info.View.Files, "genome.json, two adapter files, prompts.json")
	require.Len(t, info.View.BundleSHA256, 64)
	require.Equal(t, info.View.BundleSHA256, info.BundleSHA256)

	// What is kept to judge: the references, under the operator's tolerance.
	require.Equal(t, sealed.KeyID, info.Gate.GenomeID)
	require.Equal(t, sealed.Fixtures, info.Gate.Fixtures)
	require.Equal(t, equivalence.Tolerance{Atol: 1e-2, Rtol: 1e-3}, info.Gate.Tol)

	// The budget is the exact size of a right answer.
	require.Equal(t, uint64(len(sealed.rightOutput(t, nil))), info.Budget)

	// At dispatch the model side is laid out as components: component 0
	// describes the rest; the fixtures' references and the training data
	// are not shipped.
	comps, err := g.components(info)
	require.NoError(t, err)
	require.Len(t, comps, 5)
	require.Equal(t, ComponentIDDescriptor, string(comps[0].ID))
	desc, err := gatejob.DecodeDescriptor(comps[0].Plaintext)
	require.NoError(t, err)
	require.Equal(t, sealed.KeyID, desc.GenomeID)
	var paths []string
	for _, f := range desc.Files {
		paths = append(paths, f.Path)
		require.Equal(t, f.Path, string(comps[f.Component].ID))
		sum := sha256.Sum256(comps[f.Component].Plaintext)
		require.Equal(t, hex.EncodeToString(sum[:]), f.SHA256)
		require.Equal(t, int64(len(comps[f.Component].Plaintext)), f.Bytes)
	}
	require.Equal(t, []string{"adapter/adapter_config.json", "adapter/adapter_model.safetensors", "genome.json", "prompts.json"}, paths)
	require.Equal(t, sealed.Files["adapter/adapter_model.safetensors"], comps[2].Plaintext)
	prompts, err := gatejob.DecodePrompts(comps[4].Plaintext)
	require.NoError(t, err)
	require.Equal(t, sealed.Prompts, prompts)
	for _, c := range comps {
		require.NotContains(t, string(c.Plaintext), "raw_b64", "no reference output leaves the authority")
		require.NotContains(t, string(c.Plaintext), `"completion"`, "the training data stays sealed")
	}

	// A bundle changed since submission is not the job's bundle.
	changed := info
	changed.BundleSHA256 = strings.Repeat("0", 64)
	_, err = g.components(changed)
	require.Equal(t, CodeGenomeChanged, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

func TestGenomeJobs_OpensAnEscrowedGenome(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := escrowKeyPair(t, t.TempDir())
	sealed := sealTestGenome(t, dir, genomeOptions{name: "esc", escrowPub: pubPath})
	g := newTestGenomeJobs(t, dir, privPath)

	info, err := g.inspect(genomeRef{Bundle: sealed.Bundle})
	require.NoError(t, err)
	require.Equal(t, "escrow", info.View.KeySource)
	require.Equal(t, sealed.KeyID, info.View.KeyID)
	comps, err := g.components(info)
	require.NoError(t, err)
	require.Len(t, comps, 5)

	// Without the escrow key configured there is nothing to open it with.
	noEscrow := newTestGenomeJobs(t, dir, "")
	_, err = noEscrow.inspect(genomeRef{Bundle: sealed.Bundle})
	require.Equal(t, CodeGenomeNotFound, shared_errors.CodeOf(err))

	// An envelope for another genome is refused before it is opened.
	other := sealTestGenome(t, dir, genomeOptions{name: "other", escrowPub: pubPath})
	require.NoError(t, os.Rename(filepath.Join(dir, other.Bundle+".escrow"), filepath.Join(dir, sealed.Bundle+".escrow")))
	_, err = g.inspect(genomeRef{Bundle: sealed.Bundle})
	require.Equal(t, CodeGenomeKeyInvalid, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

func TestGenomeJobs_RefusesWhatItShould(t *testing.T) {
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	g := newTestGenomeJobs(t, dir, "")
	otherDir := t.TempDir()
	foreign := sealTestGenome(t, otherDir, genomeOptions{name: "foreign"})
	require.NoError(t, os.Rename(filepath.Join(otherDir, foreign.KeyFile), filepath.Join(dir, "foreign.key")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "open.key"), bytes.Repeat([]byte{1}, 32), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "short.key"), []byte("nope"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "not-a-bundle.genome"), []byte("hello"), 0o644))

	for name, tc := range map[string]struct {
		ref  genomeRef
		code string
		cat  shared_errors.Category
	}{
		"no bundle":          {genomeRef{}, shared_errors.CodeRequiredFieldMissing, shared_errors.CategoryStructural},
		"path, not a name":   {genomeRef{Bundle: "../" + sealed.Bundle, KeyFile: sealed.KeyFile}, shared_errors.CodeFieldValueInvalid, shared_errors.CategoryStructural},
		"key path":           {genomeRef{Bundle: sealed.Bundle, KeyFile: "/etc/passwd"}, shared_errors.CodeFieldValueInvalid, shared_errors.CategoryStructural},
		"missing bundle":     {genomeRef{Bundle: "absent.genome", KeyFile: sealed.KeyFile}, CodeGenomeNotFound, shared_errors.CategoryStructural},
		"missing key":        {genomeRef{Bundle: sealed.Bundle, KeyFile: "absent.key"}, CodeGenomeNotFound, shared_errors.CategoryStructural},
		"not a bundle":       {genomeRef{Bundle: "not-a-bundle.genome", KeyFile: sealed.KeyFile}, CodeGenomeInvalid, shared_errors.CategoryStructural},
		"wrong key":          {genomeRef{Bundle: sealed.Bundle, KeyFile: "foreign.key"}, CodeGenomeKeyInvalid, shared_errors.CategoryAuthority},
		"key open to others": {genomeRef{Bundle: sealed.Bundle, KeyFile: "open.key"}, CodeGenomeKeyInvalid, shared_errors.CategoryAuthority},
		"key too short":      {genomeRef{Bundle: sealed.Bundle, KeyFile: "short.key"}, CodeGenomeKeyInvalid, shared_errors.CategoryAuthority},
		"no key, no escrow":  {genomeRef{Bundle: sealed.Bundle}, CodeGenomeNotFound, shared_errors.CategoryStructural},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := g.inspect(tc.ref)
			require.Error(t, err)
			require.Equal(t, tc.code, shared_errors.CodeOf(err), err.Error())
			require.Equal(t, tc.cat, shared_errors.CategoryOf(err), err.Error())
		})
	}

	// A name that still points outside the bundle dir — through a symlink
	// — is refused by the root the files are opened in.
	outside := t.TempDir()
	escaped := sealTestGenome(t, outside, genomeOptions{name: "escaped"})
	require.NoError(t, os.Symlink(filepath.Join(outside, escaped.Bundle), filepath.Join(dir, "link.genome")))
	require.NoError(t, os.Symlink(filepath.Join(outside, escaped.KeyFile), filepath.Join(dir, "link.key")))
	_, err := g.inspect(genomeRef{Bundle: "link.genome", KeyFile: "link.key"})
	require.Equal(t, CodeGenomeNotFound, shared_errors.CodeOf(err), err.Error())
	_, err = g.inspect(genomeRef{Bundle: sealed.Bundle, KeyFile: "link.key"})
	require.Equal(t, CodeGenomeNotFound, shared_errors.CodeOf(err), err.Error())
	// A bundle dir that is not there is the vault's problem, not the caller's.
	gone := *g // a copy: the opener under test keeps its directory
	gone.cfg.BundleDir = filepath.Join(t.TempDir(), "absent")
	_, err = gone.inspect(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile})
	require.Equal(t, CodeBundleDirUnavailable, shared_errors.CodeOf(err))
	require.Equal(t, http.StatusInternalServerError, statusForBuildError(err))

	// Genomes that open but cannot be gated.
	for name, opts := range map[string]genomeOptions{
		"fixtures without prompts":  {name: "noprompts", noPrompts: true},
		"adapter not the one named": {name: "wrongw", wrongWeigh: true},
		"no genome.json":            {name: "nogenome", mutate: func(f map[string][]byte) { delete(f, "genome.json") }},
		"no adapter config":         {name: "nocfg", mutate: func(f map[string][]byte) { delete(f, "adapter/adapter_config.json") }},
		"fixtures edited":           {name: "edited", mutate: func(f map[string][]byte) { f["fixtures.json"] = append(f["fixtures.json"], ' ') }},
	} {
		t.Run(name, func(t *testing.T) {
			s := sealTestGenome(t, dir, opts)
			_, err := g.inspect(genomeRef{Bundle: s.Bundle, KeyFile: s.KeyFile})
			require.Error(t, err)
			require.Equal(t, CodeGenomeInvalid, shared_errors.CodeOf(err), err.Error())
		})
	}

	// A genome the Return Path cannot carry.
	small := *g
	small.maxPayload = 4096
	_, err = small.inspect(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile})
	require.Equal(t, CodeGenomeTooLarge, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	tiny := *g
	tiny.maxPayload = 1
	_, err = tiny.inspect(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile})
	require.Equal(t, CodeGenomeTooLarge, shared_errors.CodeOf(err), "refused before the bundle is read")

	// Not configured at all.
	require.Nil(t, newGenomeJobs(DefaultConfig(), nil, nil))
}

func candidate(genomeID string, out []byte) returnpath.CandidateOutput {
	return returnpath.CandidateOutput{ManifestID: "rjm-1", SessionID: "ses-1", OutputKind: rjm.OutputKindBytesFixedLength, Bytes: out, ProducedAt: time.Now()}
}

func inspectTestGenome(t *testing.T) (testGenome, *gateSpec) {
	t.Helper()
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	info, err := newTestGenomeJobs(t, dir, "").inspect(genomeRef{Bundle: sealed.Bundle, KeyFile: sealed.KeyFile})
	require.NoError(t, err)
	return sealed, info.Gate
}

func TestEvaluateGate_LadderAndVerdicts(t *testing.T) {
	sealed, spec := inspectTestGenome(t)

	t.Run("byte-exact answer opens door 0", func(t *testing.T) {
		view, err := evaluateGate(spec, candidate(sealed.KeyID, sealed.rightOutput(t, nil)))
		require.NoError(t, err)
		require.Equal(t, "EXACT", view.Level)
		require.Equal(t, doorPinnedReplay, view.Door)
		require.Equal(t, 0, view.Rung)
		require.Equal(t, "pinned-replay", view.Kind)
		require.Equal(t, 3, view.Fixtures)
		require.Len(t, view.Attempts, 1)
		require.NotNil(t, view.SignedVerdict)
		require.Equal(t, equivalence.LevelExact, view.SignedVerdict.Verdict.Level)
		require.Equal(t, 3, view.SignedVerdict.Verdict.NExact)
		require.Equal(t, sealed.KeyID, view.SignedVerdict.Verdict.GenomeID)
	})
	t.Run("within tolerance opens door 1 as EQUIVALENT", func(t *testing.T) {
		out := sealed.rightOutput(t, map[[2]int]float32{{0, 1}: 2e-3, {2, 0}: -1e-3})
		view, err := evaluateGate(spec, candidate(sealed.KeyID, out))
		require.NoError(t, err)
		require.Equal(t, "EQUIVALENT", view.Level)
		require.Equal(t, doorNativeFloat, view.Door)
		require.Equal(t, 1, view.Rung)
		require.Len(t, view.Attempts, 2)
		require.Equal(t, equivalence.LevelFail, view.Attempts[0].Level, "door 0 refused it first, on the record")
		require.InDelta(t, 2e-3, view.SignedVerdict.Verdict.MaxAbsErr, 1e-6)
	})
	t.Run("outside tolerance fails every door", func(t *testing.T) {
		out := sealed.rightOutput(t, map[[2]int]float32{{1, 2}: 0.5})
		view, err := evaluateGate(spec, candidate(sealed.KeyID, out))
		require.Error(t, err)
		require.Equal(t, CodeGateFailed, shared_errors.CodeOf(err))
		require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
		require.Equal(t, "FAIL", view.Level)
		require.Nil(t, view.SignedVerdict)
		require.Len(t, view.Attempts, 2)
		require.Contains(t, err.Error(), "missed its references")
	})
	t.Run("a non-critical outlier within policy still passes", func(t *testing.T) {
		lenient := *spec
		lenient.Pol = equivalence.Policy{MaxNonCriticalOutliers: 1}
		out := sealed.rightOutput(t, map[[2]int]float32{{2, 0}: 0.5}) // fx-002 is not critical
		view, err := evaluateGate(&lenient, candidate(sealed.KeyID, out))
		require.NoError(t, err)
		require.Equal(t, "EQUIVALENT", view.Level)
		require.Equal(t, 1, view.SignedVerdict.Verdict.NMismatch)
		critical := sealed.rightOutput(t, map[[2]int]float32{{0, 0}: 0.5}) // fx-000 is critical
		_, err = evaluateGate(&lenient, candidate(sealed.KeyID, critical))
		require.Equal(t, CodeGateFailed, shared_errors.CodeOf(err))
	})
	t.Run("an answer that is not an answer is an integrity failure", func(t *testing.T) {
		for name, out := range map[string][]byte{
			"garbage": []byte("not an output"),
			"other genome": func() []byte {
				o := sealed
				o.KeyID = "genome-000000000000-g0-000000000000"
				return o.rightOutput(t, nil)
			}(),
			"missing fixture": []byte(`{"schema":"vault-genome/gate-output/v1","genome_id":"` + sealed.KeyID + `","outputs":{"fx-000":{"dtype":"f32","shape":[3],"raw_b64":"AAAAAAAAAAAAAAAA"}}}`),
		} {
			t.Run(name, func(t *testing.T) {
				view, err := evaluateGate(spec, candidate(sealed.KeyID, out))
				require.Error(t, err)
				require.Equal(t, CodeGateOutputInvalid, shared_errors.CodeOf(err), err.Error())
				require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
				require.Equal(t, "ERROR", view.Level)
			})
		}
	})
}

// judge answers both dimensions the validation service records: the
// top-1 agreement (semantic) and the ladder (behavioral).
func TestJudge_TwoDimensionsOfTheGate(t *testing.T) {
	sealed, spec := inspectTestGenome(t)

	t.Run("a right answer passes both", func(t *testing.T) {
		j, err := judge(spec, candidate(sealed.KeyID, sealed.rightOutput(t, nil)))
		require.NoError(t, err)
		require.NoError(t, j.GateErr)
		require.Equal(t, "EXACT", j.Gate.Level)
		require.Equal(t, 3, j.Top1.Agreed)
		require.Equal(t, "top1-agreement", j.Semantic.Evaluator)
		require.Equal(t, validation_result.VerdictPass, j.Semantic.Verdict.Verdict)
		require.Equal(t, 1.0, j.Semantic.Verdict.Score)
		require.Equal(t, "equivalence-ladder", j.Behavioral.Evaluator)
		require.Equal(t, validation_result.VerdictPass, j.Behavioral.Verdict.Verdict)
		require.True(t, json.Valid(j.Semantic.Detail) && json.Valid(j.Behavioral.Detail))
		require.Contains(t, string(j.Behavioral.Detail), `"level":"EXACT"`)
		require.Contains(t, string(j.Semantic.Detail), `"agreed":3`)
	})
	t.Run("numbers within tolerance, same answers: both pass", func(t *testing.T) {
		out := sealed.rightOutput(t, map[[2]int]float32{{0, 1}: 2e-3})
		j, err := judge(spec, candidate(sealed.KeyID, out))
		require.NoError(t, err)
		require.NoError(t, j.GateErr)
		require.Equal(t, "EQUIVALENT", j.Gate.Level)
		require.Equal(t, validation_result.VerdictPass, j.Semantic.Verdict.Verdict)
	})
	t.Run("a different answer fails semantic even when the ladder cannot judge closeness", func(t *testing.T) {
		// fx-001's reference is [4+... ] the largest at index 1 (9*0.5); a
		// big bump at position 0 flips the top-1 and blows the tolerance.
		out := sealed.rightOutput(t, map[[2]int]float32{{1, 0}: 10})
		j, err := judge(spec, candidate(sealed.KeyID, out))
		require.NoError(t, err)
		require.Error(t, j.GateErr)
		require.Equal(t, CodeGateFailed, shared_errors.CodeOf(j.GateErr))
		require.Equal(t, validation_result.VerdictFail, j.Behavioral.Verdict.Verdict)
		require.Equal(t, validation_result.VerdictFail, j.Semantic.Verdict.Verdict)
		require.Equal(t, 2, j.Top1.Agreed)
		require.Equal(t, 1, j.Top1.CriticalDisagreed)
		require.Len(t, j.Semantic.Verdict.Details, 1)
		require.Equal(t, "sem.top1_disagreement", j.Semantic.Verdict.Details[0].Code)
		require.Equal(t, validation_result.SeverityError, j.Semantic.Verdict.Details[0].Severity, "fx-001 is critical")
	})
	t.Run("an output that is not an answer is not judged", func(t *testing.T) {
		_, err := judge(spec, candidate(sealed.KeyID, []byte("nope")))
		require.Equal(t, CodeGateOutputInvalid, shared_errors.CodeOf(err))
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
		missing := []byte(`{"schema":"vault-genome/gate-output/v1","genome_id":"` + sealed.KeyID + `","outputs":{"fx-000":{"dtype":"f32","shape":[3],"raw_b64":"AAAAAAAAAAAAAAAA"}}}`)
		_, err = judge(spec, candidate(sealed.KeyID, missing))
		require.Equal(t, CodeGateOutputInvalid, shared_errors.CodeOf(err))
	})
}

func TestSignVerdict_VerifiesUnderTheAuthorityKey(t *testing.T) {
	sealed, spec := inspectTestGenome(t)
	view, err := evaluateGate(spec, candidate(sealed.KeyID, sealed.rightOutput(t, nil)))
	require.NoError(t, err)

	store := keys.NewInMemoryStore(shared_time.NewSystemClock())
	vk, err := store.RegisterSigningFromSeed("authority-1", keys.PurposeSigningAuthority, bytes.Repeat([]byte{7}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	require.NoError(t, signVerdict(&view, store, "authority-1", vk.PublicKey))
	require.Equal(t, "authority-1", view.SignerKeyID)
	require.NoError(t, equivalence.VerifySigned(*view.SignedVerdict))
	tampered := *view.SignedVerdict
	tampered.Verdict.MaxAbsErr = 1
	require.Error(t, equivalence.VerifySigned(tampered))

	// Nothing to sign when no door opened.
	none := GateView{Level: "FAIL"}
	require.NoError(t, signVerdict(&none, store, "authority-1", vk.PublicKey))
	require.Nil(t, none.SignedVerdict)
}

func TestUntarFiles_ReadsRegularFilesAndRefusesEscapes(t *testing.T) {
	pack := func(entries ...tar.Header) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for _, h := range entries {
			h.Format = tar.FormatPAX
			if h.Typeflag == 0 {
				h.Typeflag = tar.TypeReg
			}
			require.NoError(t, tw.WriteHeader(&h))
			if h.Typeflag == tar.TypeReg {
				_, err := tw.Write(bytes.Repeat([]byte{'x'}, int(h.Size)))
				require.NoError(t, err)
			}
		}
		require.NoError(t, tw.Close())
		return b.Bytes()
	}
	files, err := untarFiles(pack(tar.Header{Name: "a/b.txt", Size: 3}, tar.Header{Name: "dir/", Typeflag: tar.TypeDir}, tar.Header{Name: "c", Size: 0}))
	require.NoError(t, err)
	require.Equal(t, map[string][]byte{"a/b.txt": []byte("xxx"), "c": {}}, files)
	for name, raw := range map[string][]byte{
		"escape":    pack(tar.Header{Name: "../x", Size: 1}),
		"absolute":  pack(tar.Header{Name: "/x", Size: 1}),
		"duplicate": pack(tar.Header{Name: "x", Size: 1}, tar.Header{Name: "x", Size: 1}),
		"empty":     pack(),
		"not tar":   []byte("nope"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := untarFiles(raw)
			require.Error(t, err)
		})
	}
}

func TestBundleFileName(t *testing.T) {
	for _, ok := range []string{"gen-0.genome", "a.key", "x", "Model_7B.v2.genome.escrow", "a..b"} {
		got, err := bundleFileName(ok)
		require.NoError(t, err)
		require.Equal(t, ok, got)
	}
	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", "/abs", `a\b`, "../x", "a b", "a\nb", "ключ", strings.Repeat("a", 256)} {
		_, err := bundleFileName(bad)
		require.Error(t, err, bad)
	}
	require.Equal(t, "a b c", logSafe("a\nb\rc"))
}

func TestGenomeJobs_ToleranceFollowsTheGenomesDtype(t *testing.T) {
	dir := t.TempDir()
	bf16 := sealTestGenome(t, dir, genomeOptions{name: "bf16", dtype: "bfloat16"})
	f32 := sealTestGenome(t, dir, genomeOptions{name: "f32", dtype: "float32"})
	older := sealTestGenome(t, dir, genomeOptions{name: "older"}) // predates the field: float32

	// Without a bfloat16 table every genome is held to the float32 tolerance.
	g := newTestGenomeJobs(t, dir, "")
	for _, tg := range []testGenome{bf16, f32, older} {
		info, err := g.inspect(genomeRef{Bundle: tg.Bundle, KeyFile: tg.KeyFile})
		require.NoError(t, err)
		require.Equal(t, equivalence.Tolerance{Atol: 1e-2, Rtol: 1e-3}, info.Gate.Tol, tg.Bundle)
	}

	// With one, a genome that computed in bfloat16 is held to it; the others are not.
	g.cfg.Gate.Bfloat16 = &GateTolerance{Atol: 0.5, Rtol: 0.05}
	info, err := g.inspect(genomeRef{Bundle: bf16.Bundle, KeyFile: bf16.KeyFile})
	require.NoError(t, err)
	require.Equal(t, equivalence.Tolerance{Atol: 0.5, Rtol: 0.05}, info.Gate.Tol)
	for _, tg := range []testGenome{f32, older} {
		info, err := g.inspect(genomeRef{Bundle: tg.Bundle, KeyFile: tg.KeyFile})
		require.NoError(t, err)
		require.Equal(t, equivalence.Tolerance{Atol: 1e-2, Rtol: 1e-3}, info.Gate.Tol, tg.Bundle)
	}

	// The table is part of the policy every session is pinned to.
	c := Config{}
	c.Genome.Gate = GateConfig{Atol: 1e-2, Rtol: 1e-3}
	require.Equal(t, "gate-policy/v1;atol=0.01;rtol=0.001;outliers=0", c.PolicyVersion())
	c.Genome.Gate.Bfloat16 = &GateTolerance{Atol: 0.5, Rtol: 0.05}
	require.Equal(t, "gate-policy/v1;atol=0.01;rtol=0.001;outliers=0;bf16-atol=0.5;bf16-rtol=0.05", c.PolicyVersion())
	c.Genome.Gate.Bfloat16 = &GateTolerance{Atol: -1}
	require.ErrorContains(t, c.Validate(), "genome.gate.bfloat16")
}
