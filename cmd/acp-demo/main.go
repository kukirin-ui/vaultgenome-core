// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command acp-demo runs the cross-hardware AI-regeneration flagship end to end,
// in simulation mode (no TEE hardware required), so anyone can see it work with
// one command:
//
//	go run ./cmd/acp-demo          # or: docker run vaultgenome demo
//
// It uses the real platform code — the simulated TEE Sealer, the canonical
// deterministic/integer kernels, the numerical equivalence gate, and the
// determinism-ladder reconstruction — to show:
//
//	① an AI genome sealed at the origin,
//	② byte-exact integrity on receipt (tamper is caught here),
//	③ regeneration on a "pinned" runtime → EXACT, with an Ed25519-signed verdict,
//	④ regeneration after simulated cross-hardware float drift → the ladder falls
//	   through to the byte-portable integer path → EQUIVALENT (the model still
//	   comes up), and
//	⑤ a corrupted genome → no door opens → reconstitution is blocked (fail-closed).
//
// What is real here: attested byte-exact continuity and the cross-hardware
// equivalence gate. What is NOT claimed: rebuilding a model from a compact
// recipe alone — the platform restores a sealed delta and proves it, it does
// not invent weights (see README, VERIFIABLE-CLAIMS).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- seeded, reproducible demo data; nothing here is a key, nonce or secret
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/canonical"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
)

const dim, seqLen = 16, 8

// Genome is the sealed asset: the model weights, the reference inputs, and the
// sealed reference outputs (the fixtures the destination must reproduce).
type Genome struct {
	Params   canonical.Params
	Inputs   map[string][]float64
	Fixtures []equivalence.Fixture
}

// outcome is what a run demonstrated, for tests and for any caller that wants
// the results rather than the narration.
type outcome struct {
	Same, Drift, Corrupt reconstruction.LadderResult
	// SignaturesVerified reports that every opened door's Ed25519-signed
	// verdict verified.
	SignaturesVerified bool
	// FileByteExact reports that a -model file was sealed and restored
	// byte-exact (false when no file was given or it could not be read).
	FileByteExact bool
}

func f64Tensor(shape []int, vals []float64) equivalence.Tensor {
	raw := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(raw[i*8:], math.Float64bits(v))
	}
	return equivalence.Tensor{DType: equivalence.F64, Shape: shape, Raw: raw}
}

func buildGenome(seed int64, nFixtures int) Genome {
	r := rand.New(rand.NewSource(seed))
	rv := func(n int) []float64 {
		out := make([]float64, n)
		for i := range out {
			out[i] = r.NormFloat64()
		}
		return out
	}
	p := canonical.Params{
		D: dim, Wq: rv(dim * dim), Wk: rv(dim * dim), Wv: rv(dim * dim), Wo: rv(dim * dim),
		W1: rv(dim * 4 * dim), W2: rv(4 * dim * dim), G: rv(dim), B: rv(dim), Eps: 1e-5,
	}
	g := Genome{Params: p, Inputs: map[string][]float64{}}
	for i := 0; i < nFixtures; i++ {
		id := string(rune('a' + i))
		rr := rand.New(rand.NewSource(seed*100 + int64(i)))
		x := make([]float64, seqLen*dim)
		for j := range x {
			x[j] = rr.NormFloat64()
		}
		g.Inputs[id] = x
		g.Fixtures = append(g.Fixtures, equivalence.Fixture{
			ID: id, Expected: f64Tensor([]int{seqLen, dim}, p.TransformerBlock(x, seqLen)), Critical: i == 0,
		})
	}
	return g
}

func encodeGenome(g Genome) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(g); err != nil {
		return nil, fmt.Errorf("encode genome: %w", err)
	}
	return buf.Bytes(), nil
}

func decodeGenome(b []byte) (Genome, error) {
	var g Genome
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&g); err != nil {
		return Genome{}, fmt.Errorf("decode genome: %w", err)
	}
	return g, nil
}

// pinnedDoor is the top rung: byte-exact replay on a pinned runtime. drift
// simulates a different hardware/BLAS build perturbing the float result by one
// ULP, which fails the tol-0 gate and makes the descent fall through.
func pinnedDoor(g Genome, drift bool) reconstruction.Strategy {
	return reconstruction.PinnedReplayDoor("pinned-f64-replay", func(id string) (equivalence.Tensor, error) {
		out := g.Params.TransformerBlock(g.Inputs[id], seqLen)
		if drift {
			out[0] = math.Nextafter(out[0], math.Inf(1))
		}
		return f64Tensor([]int{seqLen, dim}, out), nil
	})
}

// integerDoor is the byte-portable rung: the same block in integer arithmetic,
// identical on any CPU or GPU by construction.
func integerDoor(g Genome) reconstruction.Strategy {
	fp := canonical.QuantizeParams(g.Params)
	return reconstruction.Strategy{
		Rung: 3, Kind: reconstruction.KindFixedPoint, Name: "integer-portable",
		Tol: equivalence.Tolerance{Atol: 0.05, Rtol: 0.05}, Pol: equivalence.StrictPolicy(),
		Recompute: func(id string) (equivalence.Tensor, error) {
			o := canonical.DequantizeVec(fp.TransformerBlockQ(canonical.QuantizeVec(g.Inputs[id]), seqLen))
			return f64Tensor([]int{seqLen, dim}, o), nil
		},
	}
}

func main() {
	modelPath := flag.String("model", "", "optional path to a file to seal byte-exact as the genome asset")
	flag.Parse()
	if _, err := run(os.Stdout, *modelPath); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31mfatal:\033[0m %v\n", err)
		os.Exit(1)
	}
}

// run narrates the demonstration to w and returns what it showed. modelPath,
// if non-empty, is a file to seal and restore byte-exact at the end.
func run(w io.Writer, modelPath string) (outcome, error) {
	var out outcome
	p := printer{w}
	p.print(banner)

	seed := sha256.Sum256([]byte("vaultgenome-demo-workload"))
	origin, err := tee.NewSimulated([]byte("vaultgenome-origin"), seed[:])
	if err != nil {
		return out, fmt.Errorf("init origin TEE: %w", err)
	}

	// ① ORIGIN — build + seal the genome.
	g := buildGenome(1, 4)
	raw, err := encodeGenome(g)
	if err != nil {
		return out, err
	}
	addr := sha256.Sum256(raw)
	sealed, err := origin.Seal(raw, addr[:])
	if err != nil {
		return out, fmt.Errorf("seal: %w", err)
	}
	p.section("① ORIGIN NODE — sealing the AI genome")
	p.info("model: sample transformer (d=%d, seq=%d), %d sealed reference fixtures", dim, seqLen, len(g.Fixtures))
	p.info("genome content-address: %x…", addr[:10])
	p.info("sealed under simulated TEE, measurement %x…", []byte(origin.Measurement())[:10])

	// ② DESTINATION — integrity on receipt (the backup layer).
	p.section("② DESTINATION NODE — receiving on different hardware")
	dest, err := tee.NewSimulated([]byte("vaultgenome-origin"), seed[:]) // same code → same measurement
	if err != nil {
		return out, fmt.Errorf("init destination TEE: %w", err)
	}
	got, err := dest.Unseal(sealed, addr[:])
	if err != nil || sha256.Sum256(got) != addr {
		return out, errors.New("integrity check failed — genome rejected")
	}
	p.ok("integrity layer: unsealed bytes hash to the sealed address (a tampered genome is rejected here)")
	rg, err := decodeGenome(got)
	if err != nil {
		return out, err
	}

	pub, priv, err := crypto.GenerateEd25519(nil)
	if err != nil {
		return out, fmt.Errorf("generate verdict signing key: %w", err)
	}
	out.SignaturesVerified = true
	descend := func(ladder []reconstruction.Strategy) (reconstruction.LadderResult, error) {
		res, err := reconstruction.Regenerate("genome-demo", rg.Fixtures, ladder)
		if err != nil {
			return res, fmt.Errorf("regenerate: %w", err)
		}
		if !p.report(res, pub, priv) {
			out.SignaturesVerified = false
		}
		return res, nil
	}

	// ③ Same-hardware regeneration → EXACT.
	p.section("③ REGENERATION — determinism ladder + attested equivalence gate")
	if out.Same, err = descend([]reconstruction.Strategy{pinnedDoor(rg, false), integerDoor(rg)}); err != nil {
		return out, err
	}

	// ④ Cross-hardware float drift → fall through to the portable integer door.
	p.section("④ CROSS-HARDWARE — a different BLAS/GPU perturbs the float path")
	if out.Drift, err = descend([]reconstruction.Strategy{pinnedDoor(rg, true), integerDoor(rg)}); err != nil {
		return out, err
	}

	// ⑤ Corrupted genome → no door opens → blocked.
	p.section("⑤ SAFETY — a corrupted genome is blocked (fail-closed)")
	corrupt := Genome{Params: buildGenome(999, 4).Params, Inputs: rg.Inputs} // different weights, genuine fixtures
	if out.Corrupt, err = descend([]reconstruction.Strategy{pinnedDoor(corrupt, false), integerDoor(corrupt)}); err != nil {
		return out, err
	}

	if modelPath != "" {
		out.FileByteExact = p.sealRealFile(origin, dest, modelPath)
	}

	p.print(footer)
	return out, nil
}

// report narrates one descent. It returns false if an opened door's signed
// verdict failed to verify.
func (p printer) report(res reconstruction.LadderResult, pub crypto.PublicKey, priv crypto.PrivateKey) bool {
	if res.Opened {
		sv, err := equivalence.Sign(res.Verdict, pub, priv)
		verified := err == nil && equivalence.VerifySigned(sv) == nil
		p.ok("door opened: %q (rung %d, kind=%s) → verdict %s", res.Name, res.Rung, res.Kind, res.Verdict.Level)
		if err == nil {
			p.info("Ed25519-signed verdict %x… (signature verifies: %v)", sv.Signature[:10], verified)
		}
		p.info("reconstitution decision: %s — model goes live", reconstruction.Reason(res.Verdict))
		return verified
	}
	p.warn("NO door reproduced the sealed reference")
	for _, a := range res.Attempts {
		p.info("  · door %q (rung %d): %s", a.Name, a.Rung, a.Level)
	}
	p.warn("reconstitution decision: %s — model is NOT brought up (fail-closed)", reconstruction.Reason(res.Verdict))
	return true
}

// sealRealFile seals path at the origin, unseals it at the destination and
// reports whether the round trip was byte-exact. Problems are narrated as
// warnings: the file is an optional extra, not part of the demonstration.
func (p printer) sealRealFile(origin, dest *tee.Simulated, path string) bool {
	p.section("＋ YOUR FILE — byte-exact sealed continuity")
	data, err := os.ReadFile(path)
	if err != nil {
		p.warn("could not read %s: %v", path, err)
		return false
	}
	addr := sha256.Sum256(data)
	sealed, err := origin.Seal(data, addr[:])
	if err != nil {
		p.warn("seal failed: %v", err)
		return false
	}
	got, err := dest.Unseal(sealed, addr[:])
	if err != nil || sha256.Sum256(got) != addr || !bytes.Equal(got, data) {
		p.warn("restore mismatch — file NOT byte-exact")
		return false
	}
	p.ok("%s (%d bytes) sealed and restored BYTE-EXACT; address %x…", path, len(data), addr[:10])
	p.info("note: the equivalence gate needs reference input→output fixtures from YOUR model's")
	p.info("inference to certify a live recompute; byte-exact restore above needs no fixtures.")
	return true
}

// ---- terminal presentation -------------------------------------------------

const banner = `
┌──────────────────────────────────────────────────────────────────────┐
│  VaultGenome · AI Continuity Platform — cross-hardware regeneration    │
│  demonstration (simulation mode, no TEE hardware required)             │
└──────────────────────────────────────────────────────────────────────┘
`

const footer = `
────────────────────────────────────────────────────────────────────────
Done. This ran the real platform code: simulated TEE seal/unseal, the
canonical kernels, the equivalence gate, and the determinism ladder.
For REAL SEV-SNP attestation, run the daemon inside a confidential VM
(see docs). Byte-exact continuity + the cross-hardware gate are real;
nothing here rebuilds a model from a recipe alone: the delta is sealed.
────────────────────────────────────────────────────────────────────────
`

// printer writes the narration to a writer (stdout in main, a buffer in
// tests).
type printer struct{ w io.Writer }

func (p printer) print(s string)   { _, _ = io.WriteString(p.w, s) }
func (p printer) section(s string) { _, _ = fmt.Fprintf(p.w, "\n\033[1;36m%s\033[0m\n", s) }
func (p printer) ok(format string, a ...any) {
	_, _ = fmt.Fprintf(p.w, "  \033[32m✓\033[0m "+format+"\n", a...)
}
func (p printer) info(format string, a ...any) {
	_, _ = fmt.Fprintf(p.w, "    "+format+"\n", a...)
}
func (p printer) warn(format string, a ...any) {
	_, _ = fmt.Fprintf(p.w, "  \033[33m▲\033[0m "+format+"\n", a...)
}
