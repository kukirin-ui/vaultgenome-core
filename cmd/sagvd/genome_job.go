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
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	"github.com/vault-genome/vaultgenome-core/internal/genome/lora"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
	valservice "github.com/vault-genome/vaultgenome-core/internal/validation/service"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
)

// A gate job (ADR 0013). The operator seals a model genome — the
// vg_genome worker's genome.json, LoRA adapter, fixtures and recipe — into
// a v3 bundle and drops it in genome.bundle_dir with its key file or escrow
// envelope. POST /v1/jobs names the bundle. This file is the authority's
// side of the job:
//
//   - inspect (at submission): open the bundle in memory, check it is a
//     model genome, keep the fixtures' references and the answer's exact
//     budget (gatejob.OutputBudget); clear the plaintext.
//   - components (at dispatch): open it again and lay out the model side
//     — a gatejob.Descriptor, then genome.json, the adapter, the fixtures'
//     prompts — as the components the flow discloses, one signed, sealed
//     DisclosureMessage each under the session (ADR 0015).
//   - judge: decode the worker's signed candidate output and hold it to
//     the references on both dimensions the gate can answer — the top-1
//     agreement (semantic) and the determinism ladder (behavioral: the
//     byte-exact door first, then the native-float door within the
//     operator's tolerance) — for the validation service to record.
//
// The authority holds the genome's plaintext only for the time it takes
// to seal the components, in memory, and never writes any of it: it is a
// sealer here, as it is for every disclosure.

// Error codes of the gate-job path.
const (
	// CodeGateJobsDisabled (Structural): genome.bundle_dir is not
	// configured, so there is nothing a job could name.
	CodeGateJobsDisabled = "gate_jobs_disabled"

	// CodeGenomeNotFound (Structural): the named bundle, key file or
	// escrow envelope is not in genome.bundle_dir.
	CodeGenomeNotFound = "genome_not_found"

	// CodeBundleDirUnavailable (Operational): genome.bundle_dir cannot be
	// opened on the vault.
	CodeBundleDirUnavailable = "bundle_dir_unavailable"

	// CodeGenomeKeyInvalid (Authority): the key file or envelope does not
	// open the named bundle.
	CodeGenomeKeyInvalid = "genome_key_invalid"

	// CodeGenomeInvalid (Structural): the bundle opened but does not hold
	// a model genome a gate job can carry.
	CodeGenomeInvalid = "genome_invalid"

	// CodeGenomeTooLarge (Operational): the model side of the genome does
	// not fit one Return Path job.
	CodeGenomeTooLarge = "genome_too_large"

	// CodeGateFailed (Operational): the worker's outputs missed the
	// sealed references at every door.
	CodeGateFailed = "gate_failed"

	// CodeGateOutputInvalid (Integrity): the worker's signed output is not
	// an answer to the job it was given.
	CodeGateOutputInvalid = "gate_output_invalid"
)

// Names of the ladder doors a gate job tries, recorded in verdicts: the
// two float doors over the worker's outputs, and, for a genome that
// carries integer references, the integer door over the worker's integer
// outputs.
const (
	doorPinnedReplay = "pinned replay"
	doorNativeFloat  = "native float"
	doorInteger      = "integer"
)

// genomeRef is how POST /v1/jobs names a genome.
type genomeRef struct {
	// Bundle is the .genome file's name in genome.bundle_dir.
	Bundle string `json:"bundle"`
	// KeyFile is the key file's name in genome.bundle_dir (acpctl genome
	// seal --key-out). Empty: the envelope <bundle>.escrow is opened with
	// the authority's escrow key.
	KeyFile string `json:"key_file,omitempty"`
}

// GenomeView is the genome side of a job, as GET /v1/jobs/{id} shows it.
// Nothing in it is secret.
type GenomeView struct {
	Bundle        string `json:"bundle"`
	KeyID         string `json:"key_id"`
	KeySource     string `json:"key_source"` // key_file | escrow
	BundleSHA256  string `json:"bundle_sha256"`
	PayloadSHA256 string `json:"payload_sha256"`
	Generation    uint64 `json:"generation"`
	Base          string `json:"base"`
	BaseDigest    string `json:"base_digest"`
	Files         int    `json:"files"` // files shipped to the worker
	Bytes         int64  `json:"bytes"` // their plaintext bytes
	Fixtures      int    `json:"fixtures"`
	Critical      int    `json:"critical"`
}

// gateSpec is what the authority keeps, in memory, to judge the answer.
type gateSpec struct {
	GenomeID string
	Fixtures []equivalence.Fixture
	// IntegerFixtures are the integer door's references, held byte for
	// byte against the worker's integer outputs; nil for a genome without.
	IntegerFixtures []equivalence.Fixture
	Tol             equivalence.Tolerance
	Pol             equivalence.Policy
}

// GateView is a gate job's verdict, as GET /v1/jobs/{id} shows it.
type GateView struct {
	// Level is EXACT or EQUIVALENT when a door opened, FAIL when every
	// door judged the outputs and refused them, ERROR when no door could
	// judge (the output could not be read).
	Level    string                   `json:"level"`
	Door     string                   `json:"door,omitempty"`
	Rung     int                      `json:"rung"`
	Kind     string                   `json:"kind,omitempty"`
	Fixtures int                      `json:"fixtures"`
	Attempts []reconstruction.Attempt `json:"attempts"`
	// SignedVerdict is the passing verdict, signed by the authority's
	// signing key (equivalence.VerifySigned checks it); absent when no
	// door opened.
	SignedVerdict *equivalence.SignedVerdict `json:"signed_verdict,omitempty"`
	SignerKeyID   string                     `json:"signer_key_id,omitempty"`
}

// genomeJobs opens the genomes in genome.bundle_dir for gate jobs.
type genomeJobs struct {
	cfg GenomeConfig
	// escrow is the authority's escrow private key, held in memory (it
	// was unsealed from the TEE at start, ADR 0016); nil when none.
	escrow     *ecdh.PrivateKey
	maxPayload uint64
	clock      shared_time.Clock
}

// newGenomeJobs wires an opener; nil when gate jobs are not configured.
// escrowKey opens <bundle>.escrow envelopes; nil when the authority has
// no escrow key.
func newGenomeJobs(cfg Config, clock shared_time.Clock, escrowKey *ecdh.PrivateKey) *genomeJobs {
	if !cfg.Genome.Enabled() {
		return nil
	}
	return &genomeJobs{
		cfg:        cfg.Genome,
		escrow:     escrowKey,
		maxPayload: cfg.Runtime.MaxPayloadBytes,
		clock:      clock,
	}
}

// genomeInfo is what the authority keeps about a job's genome between
// submission and dispatch: how it was named, what it is, the references
// that judge the answer, the answer's exact budget. No plaintext.
type genomeInfo struct {
	Ref          genomeRef
	View         GenomeView
	Gate         *gateSpec
	Budget       uint64
	GenomeID     string
	BundleSHA256 string
}

// ComponentIDDescriptor names component 0 of every gate job.
const ComponentIDDescriptor = "descriptor"

// openedGenome is a genome opened in memory: the caller clears it.
type openedGenome struct {
	name         string
	bundleSHA256 string
	header       bundle.Header
	keySource    string
	files        map[string][]byte
	model        modelGenome
	shipped      map[string][]byte // the model side, by path
	paths        []string          // shipped paths, in component order
	shippedBytes int64
	budget       uint64
}

func (o *openedGenome) clear() {
	for _, b := range o.files {
		clear(b)
	}
	for _, b := range o.shipped {
		clear(b)
	}
}

// inspect opens the named genome, checks it is a model genome a gate job
// can carry, and keeps what judges the answer. The plaintext is cleared
// before it returns: the model side is opened again at dispatch, under
// the session it is disclosed to.
func (g *genomeJobs) inspect(ref genomeRef) (genomeInfo, error) {
	o, err := g.open(ref)
	if err != nil {
		return genomeInfo{}, err
	}
	defer o.clear()
	return genomeInfo{
		Ref: ref,
		View: GenomeView{
			Bundle:        o.name,
			KeyID:         o.header.KeyID,
			KeySource:     o.keySource,
			BundleSHA256:  o.bundleSHA256,
			PayloadSHA256: o.header.PayloadSHA256,
			Generation:    o.header.Generation,
			Base:          o.model.genome.Base.Name,
			BaseDigest:    o.model.genome.Base.Manifest.Digest,
			Files:         len(o.paths),
			Bytes:         o.shippedBytes,
			Fixtures:      len(o.model.fixtures),
			Critical:      o.model.critical,
		},
		Gate: &gateSpec{
			GenomeID:        o.header.KeyID,
			Fixtures:        o.model.fixtures,
			IntegerFixtures: o.model.integerFixtures,
			Tol:             g.cfg.Gate.ToleranceFor(o.model.genome.RecipeDtype()),
			Pol:             equivalence.Policy{MaxNonCriticalOutliers: g.cfg.Gate.MaxNonCriticalOutliers},
		},
		Budget:       o.budget,
		GenomeID:     o.header.KeyID,
		BundleSHA256: o.bundleSHA256,
	}, nil
}

// CodeGenomeChanged (Authority): the bundle a job named is not the one
// it named at submission.
const CodeGenomeChanged = "genome_changed"

// components opens the genome again at dispatch and returns the model
// side as the components a session discloses, in order: the descriptor
// (gatejob.Descriptor, component 0), then every file in path order. The
// bundle must be the one inspected. The flow zeroizes the plaintext once
// it is sealed.
func (g *genomeJobs) components(info genomeInfo) ([]orchestration.Component, error) {
	o, err := g.open(info.Ref)
	if err != nil {
		return nil, err
	}
	defer o.clear()
	if o.bundleSHA256 != info.BundleSHA256 {
		return nil, shared_errors.Authority(CodeGenomeChanged,
			fmt.Sprintf("genome %s is not the bundle the job named (sha256 %s, was %s)", o.name, o.bundleSHA256[:12], info.BundleSHA256[:12]), nil)
	}
	desc := gatejob.Descriptor{Schema: gatejob.DescriptorSchema, GenomeID: o.header.KeyID}
	for i, p := range o.paths {
		sum := sha256.Sum256(o.shipped[p])
		desc.Files = append(desc.Files, gatejob.File{Path: p, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(o.shipped[p])), Component: uint32(i + 1)})
	}
	descRaw, err := gatejob.EncodeDescriptor(desc)
	if err != nil {
		return nil, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", o.name, err), nil)
	}
	out := make([]orchestration.Component, 0, len(o.paths)+1)
	out = append(out, orchestration.Component{ID: ComponentIDDescriptor, Plaintext: descRaw})
	for _, p := range o.paths {
		out = append(out, orchestration.Component{ID: ids.ComponentID(p), Plaintext: append([]byte(nil), o.shipped[p]...)})
	}
	return out, nil
}

// open reads the named bundle through an os.Root, opens it with its key,
// and lays out the model side. Every refusal is classified for the REST
// API's status.
func (g *genomeJobs) open(ref genomeRef) (*openedGenome, error) {
	name, err := bundleFileName(ref.Bundle)
	if err != nil {
		return nil, err
	}
	// Every file a job names is opened relative to genome.bundle_dir
	// through an os.Root: a name that still pointed outside it — a
	// symlink, say — is refused by the kernel, not by string checks.
	root, err := os.OpenRoot(g.cfg.BundleDir)
	if err != nil {
		return nil, shared_errors.Operational(CodeBundleDirUnavailable, "genome.bundle_dir cannot be opened", err)
	}
	defer func() { _ = root.Close() }()

	// A bundle the Return Path could not carry is refused before it is
	// read into memory.
	blob, size, err := readInRoot(root, name, int64(g.maxPayload)+bundle.MaxHeaderBytes+1<<20)
	switch {
	case errors.Is(err, errFileTooLarge):
		return nil, shared_errors.Operational(CodeGenomeTooLarge,
			fmt.Sprintf("genome %s is %d bytes; a gate job carries at most runtime.max_payload_bytes (%d)", name, size, g.maxPayload), nil)
	case err != nil:
		return nil, shared_errors.Structural(CodeGenomeNotFound, fmt.Sprintf("genome %s is not in genome.bundle_dir", name), nil)
	}
	rd, err := bundle.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	if rd.Header.ContentKind != bundle.ContentDir {
		return nil, shared_errors.Structural(CodeGenomeInvalid,
			fmt.Sprintf("genome %s holds a %s snapshot, not a model genome directory", name, rd.Header.ContentKind), nil)
	}
	bundleSum := sha256.Sum256(blob)

	dek, keySource, err := g.openKey(root, ref, name, rd.Header.KeyID)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	payload, err := rd.PayloadWithKey(dek)
	if err != nil {
		return nil, shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	plain, err := io.ReadAll(payload)
	if err != nil {
		return nil, shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("genome %s does not open: %v", name, err), nil)
	}
	defer clear(plain)

	o := &openedGenome{name: name, bundleSHA256: hex.EncodeToString(bundleSum[:]), header: rd.Header, keySource: keySource}
	o.files, err = untarFiles(plain)
	if err != nil {
		return nil, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	o.model, err = modelSide(o.files)
	if err != nil {
		o.clear()
		return nil, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	promptsJSON, err := gatejob.EncodePrompts(o.model.prompts)
	if err != nil {
		o.clear()
		return nil, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	o.shipped = map[string][]byte{gatejob.GenomePath: o.files[gatejob.GenomePath], gatejob.PromptsPath: promptsJSON}
	for _, p := range o.model.adapterFiles {
		o.shipped[p] = o.files[p]
	}
	o.budget, err = gatejob.OutputBudget(rd.Header.KeyID, o.model.fixtures, o.model.integerFixtures)
	if err != nil {
		o.clear()
		return nil, shared_errors.Structural(CodeGenomeInvalid, fmt.Sprintf("genome %s: %v", name, err), nil)
	}
	for p := range o.shipped {
		o.paths = append(o.paths, p)
		o.shippedBytes += int64(len(o.shipped[p]))
	}
	sort.Strings(o.paths)
	if uint64(o.shippedBytes) > g.maxPayload {
		o.clear()
		return nil, shared_errors.Operational(CodeGenomeTooLarge,
			fmt.Sprintf("genome %s ships %d bytes to the worker; runtime.max_payload_bytes is %d", name, o.shippedBytes, g.maxPayload), nil)
	}
	return o, nil
}

// openKey finds the genome's key: the named key file, or the escrow
// envelope beside the bundle opened with the authority's escrow key. Both
// are read through root; the key is checked against the bundle's key ID
// before anything is opened.
func (g *genomeJobs) openKey(root *os.Root, ref genomeRef, bundleName, keyID string) ([]byte, string, error) {
	if ref.KeyFile != "" {
		name, err := bundleFileName(ref.KeyFile)
		if err != nil {
			return nil, "", err
		}
		f, err := root.Open(name)
		if err != nil {
			return nil, "", shared_errors.Structural(CodeGenomeNotFound, fmt.Sprintf("key file %s is not in genome.bundle_dir", name), nil)
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return nil, "", shared_errors.Structural(CodeGenomeNotFound, fmt.Sprintf("key file %s: %v", name, err), nil)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid,
				fmt.Sprintf("key file %s is open to other users (mode %04o); chmod 600 it", name, perm), nil)
		}
		dek, err := io.ReadAll(io.LimitReader(f, crypto.AES256KeySize+1))
		if err != nil {
			return nil, "", shared_errors.Structural(CodeGenomeNotFound, fmt.Sprintf("key file %s: %v", name, err), nil)
		}
		if err := bundle.CheckKey(keyID, dek); err != nil {
			clear(dek)
			return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("key file %s: %v", name, err), nil)
		}
		return dek, "key_file", nil
	}
	if g.escrow == nil {
		return nil, "", shared_errors.Structural(CodeGenomeNotFound,
			"no key_file named and no escrow key configured (genome.key_escrow_path)", nil)
	}
	raw, _, err := readInRoot(root, bundleName+".escrow", maxEnvelopeBytes)
	if err != nil {
		return nil, "", shared_errors.Structural(CodeGenomeNotFound,
			fmt.Sprintf("no key_file named and no envelope %s.escrow in genome.bundle_dir", bundleName), nil)
	}
	env, err := escrow.Parse(raw)
	if err != nil {
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("envelope %s.escrow: %v", bundleName, err), nil)
	}
	if env.KeyID != keyID {
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid,
			fmt.Sprintf("envelope %s.escrow holds key %s, the bundle is sealed under %s", bundleName, env.KeyID, keyID), nil)
	}
	dek, err := escrow.Open(env, g.escrow)
	if err != nil {
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("envelope %s.escrow: %v", bundleName, err), nil)
	}
	if err := bundle.CheckKey(keyID, dek); err != nil {
		clear(dek)
		return nil, "", shared_errors.Authority(CodeGenomeKeyInvalid, fmt.Sprintf("envelope %s.escrow: %v", bundleName, err), nil)
	}
	return dek, "escrow", nil
}

// maxEnvelopeBytes bounds an escrow envelope: a key ID, two tags and a
// wrapped 32-byte key.
const maxEnvelopeBytes = 16 << 10

var errFileTooLarge = errors.New("file too large")

// readInRoot reads the regular file name inside root, refusing one larger
// than limit before reading it. It returns the file's size with the error
// so a refusal can name it.
func readInRoot(root *os.Root, name string, limit int64) ([]byte, int64, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, info.Size(), fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > limit {
		return nil, info.Size(), errFileTooLarge
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, info.Size(), err
	}
	return data, info.Size(), nil
}

// modelGenome is the model side of an opened genome.
type modelGenome struct {
	genome   lora.Genome
	fixtures []equivalence.Fixture
	// integerFixtures are the integer door's references when the genome
	// carries them; the job then asks the worker for that door too.
	integerFixtures []equivalence.Fixture
	prompts         gatejob.Prompts
	adapterFiles    []string
	critical        int
}

// modelSide reads the genome's description and fixtures from the opened
// files and checks the adapter is the one the genome names.
func modelSide(files map[string][]byte) (modelGenome, error) {
	raw, ok := files[gatejob.GenomePath]
	if !ok {
		return modelGenome{}, errors.New("no genome.json: not a model genome (workers/genome)")
	}
	g, err := lora.Parse(raw)
	if err != nil {
		return modelGenome{}, err
	}
	fxRaw, ok := files[g.Fixtures.File]
	if !ok {
		return modelGenome{}, fmt.Errorf("genome.json names fixtures %s, which the bundle does not hold", g.Fixtures.File)
	}
	fixtures, prompts, err := lora.ParseFixtures(g, fxRaw)
	if err != nil {
		return modelGenome{}, err
	}
	if len(prompts) != len(fixtures) {
		return modelGenome{}, fmt.Errorf("%d of %d fixtures carry no prompt (input_ids, topk_index); the genome was written by a worker older than the gate job", len(fixtures)-len(prompts), len(fixtures))
	}
	integerFixtures, err := lora.ParseIntegerFixtures(g, fxRaw)
	if err != nil {
		return modelGenome{}, err
	}
	out := modelGenome{genome: g, fixtures: fixtures, integerFixtures: integerFixtures,
		prompts: gatejob.Prompts{Schema: gatejob.PromptsSchema, Integer: integerFixtures != nil}}
	for _, p := range prompts {
		out.prompts.Prompts = append(out.prompts.Prompts, gatejob.Prompt{ID: p.ID, InputIDs: p.InputIDs, TopKIndex: p.TopKIndex})
	}
	for _, f := range fixtures {
		if f.Critical {
			out.critical++
		}
	}
	prefix := path.Clean(g.Adapter.Dir) + "/"
	for p := range files {
		if strings.HasPrefix(p, prefix) {
			out.adapterFiles = append(out.adapterFiles, p)
		}
	}
	sort.Strings(out.adapterFiles)
	weights, ok := files[prefix+"adapter_model.safetensors"]
	if !ok {
		return modelGenome{}, fmt.Errorf("no %sadapter_model.safetensors in the bundle", prefix)
	}
	if _, ok := files[prefix+"adapter_config.json"]; !ok {
		return modelGenome{}, fmt.Errorf("no %sadapter_config.json in the bundle", prefix)
	}
	if got := "sha256:" + hex.EncodeToString(crypto.SHA256Slice(weights)); got != g.Adapter.WeightsSHA256 {
		return modelGenome{}, errors.New("the adapter weights are not the ones genome.json names")
	}
	return out, nil
}

// evaluateGate judges the worker's candidate output against the sealed
// references. It returns the verdict view and, when no door opened, a
// classified error; both are recorded on the job.
func evaluateGate(spec *gateSpec, out returnpath.CandidateOutput) (GateView, error) {
	view := GateView{Level: "ERROR", Fixtures: len(spec.Fixtures)}
	genomeID, outputs, integerOutputs, err := gatejob.DecodeOutput(out.Bytes)
	if err != nil {
		return view, shared_errors.Integrity(CodeGateOutputInvalid, "the worker's output is not a gate output", err)
	}
	if genomeID != spec.GenomeID {
		return view, shared_errors.Integrity(CodeGateOutputInvalid,
			fmt.Sprintf("the worker answered for genome %s, the job was for %s", genomeID, spec.GenomeID), nil)
	}
	from := func(what string, m map[string]equivalence.Tensor) reconstruction.RecomputeFunc {
		return func(id string) (equivalence.Tensor, error) {
			t, ok := m[id]
			if !ok {
				return equivalence.Tensor{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing,
					fmt.Sprintf("the worker gave no %s for fixture %q", what, id), nil)
			}
			return t, nil
		}
	}
	recompute := from("output", outputs)
	ladder := []reconstruction.Strategy{
		reconstruction.PinnedReplayDoor(doorPinnedReplay, recompute),
		{Rung: 1, Kind: reconstruction.KindNativeFloat, Name: doorNativeFloat, Recompute: recompute, Tol: spec.Tol, Pol: spec.Pol},
	}
	if spec.IntegerFixtures != nil {
		// The integer door: the worker's integer outputs, byte for byte
		// against the references the genome's integer door sealed.
		ladder = append(ladder, reconstruction.Strategy{Rung: 2, Kind: reconstruction.KindFixedPoint, Name: doorInteger,
			Recompute: from("integer output", integerOutputs), Tol: reconstruction.ExactTolerance, Pol: equivalence.StrictPolicy(),
			Fixtures: spec.IntegerFixtures})
	}
	res, err := reconstruction.Regenerate(spec.GenomeID, spec.Fixtures, ladder)
	if err != nil {
		return view, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "gate", err)
	}
	view.Attempts = res.Attempts
	if res.Opened {
		v := res.Verdict
		view.Level, view.Door, view.Rung, view.Kind = string(v.Level), res.Name, res.Rung, string(res.Kind)
		view.SignedVerdict = &equivalence.SignedVerdict{Verdict: v}
		return view, nil
	}
	last := res.Attempts[len(res.Attempts)-1]
	if last.Err != "" {
		return view, shared_errors.Integrity(CodeGateOutputInvalid, "no door could judge the worker's output: "+last.Err, nil)
	}
	view.Level = string(equivalence.LevelFail)
	return view, shared_errors.Operational(CodeGateFailed,
		fmt.Sprintf("the restored model missed its references at every door (max abs err %.3g at %q)", last.MaxAbsErr, last.Name), nil)
}

// judgement is what the authority found about a candidate: the ladder's
// verdict (behavioral) and the top-1 agreement (semantic), each as the
// validation service records it, and the gate error a refused answer
// fails the job with.
type judgement struct {
	Gate       GateView
	Top1       equivalence.Top1Report
	Semantic   valservice.EvaluatedDimension
	Behavioral valservice.EvaluatedDimension
	// GateErr is the classified gate_failed error when no door opened;
	// nil when one did.
	GateErr error
}

// judge holds the worker's candidate output to the sealed references on
// both dimensions the gate can answer: does the restored model give the
// same answer at every reference position (semantic, top-1 agreement),
// and are its numbers the references' within the operator's tolerance
// (behavioral, the determinism ladder)? An output that is not an answer
// to this job — undecodable, or for another genome — is an Integrity
// error and is not judged.
func judge(spec *gateSpec, out returnpath.CandidateOutput) (judgement, error) {
	var j judgement
	genomeID, outputs, _, err := gatejob.DecodeOutput(out.Bytes)
	if err != nil {
		return j, shared_errors.Integrity(CodeGateOutputInvalid, "the worker's output is not a gate output", err)
	}
	if genomeID != spec.GenomeID {
		return j, shared_errors.Integrity(CodeGateOutputInvalid,
			fmt.Sprintf("the worker answered for genome %s, the job was for %s", genomeID, spec.GenomeID), nil)
	}
	for _, f := range spec.Fixtures {
		if _, ok := outputs[f.ID]; !ok {
			return j, shared_errors.Integrity(CodeGateOutputInvalid, fmt.Sprintf("the worker gave no output for fixture %q", f.ID), nil)
		}
	}
	j.Gate, j.GateErr = evaluateGate(spec, out)
	if j.GateErr != nil && shared_errors.CategoryOf(j.GateErr) != shared_errors.CategoryOperational {
		return j, j.GateErr
	}
	j.Behavioral = valservice.EvaluatedDimension{Evaluator: "equivalence-ladder", Verdict: gateDimension(j.Gate)}
	if detail, err := json.Marshal(struct {
		Level    string                   `json:"level"`
		Door     string                   `json:"door,omitempty"`
		Rung     int                      `json:"rung"`
		Fixtures int                      `json:"fixtures"`
		Atol     float64                  `json:"atol"`
		Rtol     float64                  `json:"rtol"`
		Attempts []reconstruction.Attempt `json:"attempts"`
	}{j.Gate.Level, j.Gate.Door, j.Gate.Rung, j.Gate.Fixtures, spec.Tol.Atol, spec.Tol.Rtol, j.Gate.Attempts}); err == nil {
		j.Behavioral.Detail = detail
	}

	rep, err := equivalence.Top1Agreement(spec.Fixtures, outputs)
	if err != nil {
		return j, shared_errors.Integrity(CodeGateOutputInvalid, "the worker's output cannot be compared to the references", err)
	}
	j.Top1 = rep
	sem := validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: rep.Score(), Threshold: 1.0}
	for _, r := range rep.Results {
		if r.Agree {
			continue
		}
		sem.Verdict = validation_result.VerdictFail
		msg := fmt.Sprintf("fixture %s: top-1 index %d, reference %d", r.ID, r.ActualIndex, r.ExpectedIndex)
		if r.Note != "" {
			msg += " (" + r.Note + ")"
		}
		sev := validation_result.SeverityWarning
		if r.Critical {
			sev = validation_result.SeverityError
		}
		sem.Details = append(sem.Details, validation_result.Finding{Code: "sem.top1_disagreement", Severity: sev, Message: msg})
	}
	j.Semantic = valservice.EvaluatedDimension{Evaluator: "top1-agreement", Verdict: sem}
	if detail, err := json.Marshal(rep); err == nil {
		j.Semantic.Detail = detail
	}
	return j, nil
}

// gateDimension maps a gate's outcome onto the frozen ValidationResult
// behavioural dimension (ADR 0008), the same way the receive-side gate
// does.
func gateDimension(gate GateView) validation_result.DimensionVerdict {
	res := reconstruction.LadderResult{Attempts: gate.Attempts, Rung: gate.Rung, Name: gate.Door, Kind: reconstruction.StrategyKind(gate.Kind)}
	if gate.SignedVerdict != nil {
		res.Opened = true
		res.Verdict = gate.SignedVerdict.Verdict
	}
	if len(res.Attempts) == 0 && !res.Opened {
		res.Attempts = []reconstruction.Attempt{{Name: "gate", Level: equivalence.Level("ERROR"), Err: "the candidate output could not be judged"}}
	}
	return reconstruction.LadderToDimensionVerdict(res, 1.0)
}

// signVerdict signs a passing verdict with the authority's signing key.
func signVerdict(view *GateView, signer keys.Signer, kid ids.KeyID, pub crypto.PublicKey) error {
	if view.SignedVerdict == nil {
		return nil
	}
	msg, err := view.SignedVerdict.Verdict.CanonicalBytes()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(kid, keys.PurposeSigningAuthority, msg)
	if err != nil {
		return err
	}
	view.SignedVerdict.Signature = sig
	view.SignedVerdict.SignerPub = append([]byte(nil), pub...)
	view.SignerKeyID = string(kid)
	return nil
}

// untarFiles reads every regular file of a genome payload — the
// deterministic tar internal/contentdir writes — into memory.
func untarFiles(payload []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(payload))
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("payload is not the tar a genome holds: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := h.Name
		if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("payload holds %q, which is not a local path", name)
		}
		if _, dup := files[name]; dup {
			return nil, fmt.Errorf("payload holds %s twice", name)
		}
		if h.Size < 0 || total+h.Size > int64(len(payload)) {
			return nil, errors.New("payload describes more bytes than it holds")
		}
		data := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return nil, fmt.Errorf("payload: %s: %w", name, err)
		}
		files[name] = data
		total += h.Size
	}
	if len(files) == 0 {
		return nil, errors.New("payload holds no files")
	}
	return files, nil
}

// bundleFileNameRE is what a job may name: a file name of letters,
// digits, dots, dashes and underscores, starting with a letter or digit.
// No separators, no ".", no "..", no control characters.
var bundleFileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

// bundleFileName accepts a bare file name inside genome.bundle_dir and
// refuses anything else, so the name can be joined, opened and logged.
func bundleFileName(name string) (string, error) {
	if name == "" {
		return "", shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "genome.bundle required", nil)
	}
	if !bundleFileNameRE.MatchString(name) {
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("%q is not a file name in genome.bundle_dir (letters, digits, '.', '-', '_'; no paths)", name), nil)
	}
	return name, nil
}

// logSafe strips line breaks from a value before it goes into a log line,
// so a log entry is one line whatever the request carried.
func logSafe(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}
