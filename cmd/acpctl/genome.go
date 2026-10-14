// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contentdir"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/restore"
	"github.com/vault-genome/vaultgenome-core/internal/ollama"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Bundles are written in the v3 format (internal/genome/bundle): the
// payload is sealed under a random key that is not in the file, and that
// key goes to a separate key file (or, cross-cloud, only to an attested
// destination). The v2 format below stored its own sealing key inside
// the bundle, so anyone holding a v2 bundle could open it (KNOWN_ISSUES
// #7). This build still reads v2 — to inspect, verify, walk chains, and
// open with --allow-v2 so old bundles can be resealed — but never writes
// it.

// genomeMagic distinguishes a Vault Genome model bundle from the older
// vault envelope used by `acpctl recover`. Same on-disk shape (magic ||
// metadata length || JSON metadata || sealed blob) so tooling stays
// uniform; the magic prevents an operator from accidentally feeding a
// model bundle into the vault recovery flow or vice versa.
const genomeMagic = "VG-GENOME-01\x00\x00\x00\x00"

// envelopeFormatV2 supersedes the v1 single-snapshot envelope. v2 adds
// Generation + ParentBundleSHA256 (continuous-cycle support) and
// ContentKind/ContentRef so the same bundle format can hold either an
// Ollama model snapshot or an arbitrary directory snapshot (LoRA
// adapter, fine-tune checkpoint, RAG corpus, anything else).
const envelopeFormatV2 = "vault-genome-v2"

// ContentKind discriminates which payload-source produced this bundle.
type ContentKind string

const (
	ContentKindOllama ContentKind = "ollama" // payload was an Ollama model
	ContentKindDir    ContentKind = "dir"    // payload was a generic directory
)

// GenomeEnvelope is the on-disk metadata for a sealed bundle. v2 adds
// chain-of-custody fields (Generation + ParentBundleSHA256) so a
// directory of .genome files can be walked as a continuity timeline.
type GenomeEnvelope struct {
	Format      string `json:"format"`       // envelopeFormatV2
	TEEProvider string `json:"tee_provider"` // tee.Provider value
	SealedAt    int64  `json:"sealed_at"`    // unix nano

	// --- Chain-of-custody ---
	// Generation is monotonically increasing. 0 = genesis (no parent).
	Generation uint64 `json:"generation"`
	// ParentBundleSHA256 is the sha256 of the parent .genome FILE on
	// disk. Zero-length string at genesis. This binds the chain even if
	// envelope contents are tampered with.
	ParentBundleSHA256 string `json:"parent_bundle_sha256,omitempty"`
	// ParentPayloadSHA256 cross-links to the parent's payload digest for
	// faster lineage walking without re-hashing parent files.
	ParentPayloadSHA256 string `json:"parent_payload_sha256,omitempty"`
	// ParentGeneration is the parent's generation. Redundant with the
	// parent's envelope but cheap to verify the chain is monotonic.
	ParentGeneration uint64 `json:"parent_generation,omitempty"`

	// --- Content payload ---
	ContentKind ContentKind `json:"content_kind"`
	ContentRef  string      `json:"content_ref"` // "llama3.2:3b" or "/path/to/dir"
	// ContentSnapshot holds the kind-specific structured metadata
	// (ollama.Snapshot for ContentKindOllama, contentdir.Snapshot for
	// ContentKindDir). We store as raw JSON so the envelope schema
	// doesn't have to grow a tagged-union shape.
	ContentSnapshot json.RawMessage `json:"content_snapshot"`

	// --- Crypto ---
	Measurement []byte `json:"measurement"`
	AAD         []byte `json:"aad"`

	// --- Simulated TEE recovery params ---
	SimulatedWorkloadDescriptor []byte `json:"simulated_workload_descriptor,omitempty"`
	SimulatedSeed               []byte `json:"simulated_seed,omitempty"`
}

// genomeCmd is the entry-point dispatcher for `acpctl genome <sub>`.
func genomeCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printGenomeUsage(stderr)
		return 2
	}
	switch args[0] {
	case "seal":
		return genomeSealCmd(args[1:], stdout, stderr)
	case "open", "rewind":
		// `rewind` is an alias for `open` — semantically clearer in chain context.
		return genomeOpenCmd(args[1:], stdout, stderr)
	case "verify":
		return genomeVerifyCmd(args[1:], stdout, stderr)
	case "inspect":
		return genomeInspectCmd(args[1:], stdout, stderr)
	case "chain":
		return genomeChainCmd(args[1:], stdout, stderr)
	case "lineage":
		return genomeLineageCmd(args[1:], stdout, stderr)
	case "gate":
		return genomeGateCmd(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printGenomeUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl genome: unknown subcommand %q\n\n", args[0])
		printGenomeUsage(stderr)
		return 2
	}
}

func printGenomeUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: acpctl genome <subcommand> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  seal      Seal an Ollama model OR an arbitrary directory into a .genome bundle")
	fmt.Fprintln(w, "  open      Restore a sealed bundle (alias: rewind)")
	fmt.Fprintln(w, "  verify    Re-hash a bundle and confirm components match envelope")
	fmt.Fprintln(w, "  inspect   Print envelope metadata (incl. generation + parent linkage)")
	fmt.Fprintln(w, "  chain     Walk a directory of .genome bundles, validate the lineage chain")
	fmt.Fprintln(w, "  lineage   From any bundle, walk parent references back to genesis")
	fmt.Fprintln(w, "  gate      Recompute a restored model's sealed fixtures here and gate them (EXACT/EQUIVALENT/FAIL)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Continuity quickstart:")
	fmt.Fprintln(w, "  acpctl genome seal --model=llama3.2:3b --output=gen-0.genome --key-out=gen-0.key")
	fmt.Fprintln(w, "  acpctl genome seal --content-dir=./adapters/1 --parent=gen-0.genome --output=gen-1.genome --key-out=gen-1.key")
	fmt.Fprintln(w, "  acpctl genome chain --dir=./generations")
	fmt.Fprintln(w, "  acpctl genome rewind --bundle=gen-1.genome --key-file=gen-1.key --target=/tmp/restored")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "A bundle opens only with its key. Keep key files with the release authority;")
	fmt.Fprintln(w, "`sagvd crosscloud-restore -key-file KID:PATH` delivers one to an attested destination.")
}

// ---------------------------------------------------------------------------
// genome seal
// ---------------------------------------------------------------------------

func genomeSealCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome seal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		modelRef     = fs.String("model", "", "Ollama model ref (mutually exclusive with --content-dir)")
		contentDir   = fs.String("content-dir", "", "Directory to seal as the payload (mutually exclusive with --model)")
		ollamaHome   = fs.String("ollama-home", defaultOllamaHome(), "Path to OLLAMA root")
		parentBundle = fs.String("parent", "", "Path to parent .genome bundle — links this seal as its successor")
		outputPath   = fs.String("output", "", "Path to write the sealed .genome bundle (required)")
		keyOut       = fs.String("key-out", "", "Path to write the bundle's 32-byte key, mode 0600")
		escrowTo     = fs.String("escrow-to", "", "Release authority's escrow public key (PEM): encapsulate the bundle's key to it")
		escrowOut    = fs.String("escrow-out", "", "Where to write the escrow envelope (default: OUTPUT.escrow)")
		jsonOut      = fs.Bool("json", false, "Emit machine-readable JSON output")
		force        = fs.Bool("force", false, "Overwrite the output and key files if they exist")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome seal {--model REF | --content-dir PATH} --output PATH")
		fmt.Fprintln(stderr, "                        {--key-out PATH | --escrow-to AUTHORITY.pem} [--parent BUNDLE] [...]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Seal a payload into a v3 .genome bundle under a fresh random key. The key goes")
		fmt.Fprintln(stderr, "to --key-out (a 0600 file), or — with --escrow-to — only to the release")
		fmt.Fprintln(stderr, "authority, encapsulated to its escrow key in OUTPUT.escrow: then this machine")
		fmt.Fprintln(stderr, "keeps nothing that opens the bundle. Either --model (Ollama model) or")
		fmt.Fprintln(stderr, "--content-dir (any directory of files) selects the payload. --parent attaches")
		fmt.Fprintln(stderr, "this seal as the next generation in a continuity chain.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *outputPath == "" || (*keyOut == "" && *escrowTo == "") {
		fmt.Fprintln(stderr, "acpctl genome seal: --output and --key-out or --escrow-to are required")
		fs.Usage()
		return 2
	}
	if *escrowOut == "" && *escrowTo != "" {
		*escrowOut = *outputPath + ".escrow"
	}
	var escrowPub *ecdh.PublicKey
	if *escrowTo != "" {
		raw, err := os.ReadFile(*escrowTo)
		if err == nil {
			escrowPub, err = escrow.ParsePublicPEM(raw)
		}
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome seal: --escrow-to: %v\n", err)
			return 2
		}
	}
	if (*modelRef == "") == (*contentDir == "") {
		fmt.Fprintln(stderr, "acpctl genome seal: pass exactly one of --model or --content-dir")
		fs.Usage()
		return 2
	}
	if !*force {
		for _, p := range []string{*outputPath, *keyOut, *escrowOut} {
			if p == "" {
				continue
			}
			if _, err := os.Stat(p); err == nil {
				fmt.Fprintf(stderr, "acpctl genome seal: refusing to overwrite %s (pass --force)\n", p)
				return 2
			}
		}
	}

	// --- The payload source (Ollama model OR generic dir) ---
	src := dirSource(*contentDir)
	if *modelRef != "" {
		src = ollamaSource(*modelRef, *ollamaHome)
	}

	// First pass: describe the payload without keeping it.
	h, err := bundle.Describe(string(src.kind), src.ref, src.capture)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome seal: %v\n", err)
		return 1
	}

	// --- Resolve parent linkage (a parent may be v2 or v3) ---
	if *parentBundle != "" {
		parent, err := loadGenome(*parentBundle)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome seal: parent bundle: %v\n", err)
			return 1
		}
		h.Generation = parent.Header.Generation + 1
		h.ParentBundleSHA256 = parent.SHA256
		h.ParentPayloadSHA256 = strings.TrimPrefix(parent.Header.PayloadSHA256, "sha256:")
		h.ParentGeneration = parent.Header.Generation
	}

	// Second pass: stream the payload through the sealer into a staging
	// file beside the output. Seal checks the stream is the payload the
	// first pass described.
	staged := *outputPath + ".partial"
	out, err := bundle.SealFile(staged, h, src.capture)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome seal: %v\n", err)
		return 1
	}
	sealed, dek, bundleBytes := out.Header, out.DEK, out.Size
	// The key before the bundle: never leave a bundle on disk whose key
	// was not written.
	if *keyOut != "" {
		if err := writeKeyFile(*keyOut, dek, *force); err != nil {
			_ = os.Remove(staged)
			fmt.Fprintf(stderr, "acpctl genome seal: key file: %v\n", err)
			return 1
		}
	}
	var escrowTag string
	if escrowPub != nil {
		env, err := escrow.Seal(dek, sealed.KeyID, escrowPub)
		var raw []byte
		if err == nil {
			raw, err = env.Marshal()
		}
		if err == nil {
			err = writeFileExclusive(*escrowOut, raw, *force)
		}
		if err != nil {
			_ = os.Remove(staged)
			if *keyOut != "" {
				_ = os.Remove(*keyOut) // a key for a bundle that was never written
			}
			fmt.Fprintf(stderr, "acpctl genome seal: escrow: %v\n", err)
			return 1
		}
		escrowTag = env.EscrowKey
	}
	clear(dek)
	if err := os.Rename(staged, *outputPath); err != nil {
		_ = os.Remove(staged)
		fmt.Fprintf(stderr, "acpctl genome seal: %v\n", err)
		return 1
	}

	emitGenome(stdout, *jsonOut, sealResult{
		OK:                 true,
		Output:             *outputPath,
		KeyFile:            *keyOut,
		EscrowFile:         *escrowOut,
		EscrowKey:          escrowTag,
		KeyID:              sealed.KeyID,
		ContentKind:        string(src.kind),
		ContentRef:         src.ref,
		Generation:         sealed.Generation,
		ParentBundle:       *parentBundle,
		ParentBundleSHA256: sealed.ParentBundleSHA256,
		PayloadBytes:       sealed.PayloadBytes,
		BundleBytes:        bundleBytes,
		SegmentBytes:       sealed.SegmentBytes,
		PayloadSHA256:      sealed.PayloadSHA256,
		ComponentCount:     countComponents(src.kind, h.ContentSnapshot),
		SealedAt:           sealed.SealedAt.Format(time.RFC3339),
	})
	return 0
}

// payloadSource is what a genome seals: an Ollama model or a directory.
type payloadSource struct {
	kind    ContentKind
	ref     string
	capture bundle.Capture
	// fingerprint changes whenever the content may have changed, and is
	// cheap: the sentinel asks for it every tick.
	fingerprint func() (string, error)
}

func dirSource(dir string) payloadSource {
	return payloadSource{
		kind: ContentKindDir,
		ref:  dir,
		capture: func(w io.Writer) (json.RawMessage, int64, error) {
			snap, n, err := contentdir.Capture(dir, w)
			if err != nil {
				return nil, 0, err
			}
			raw, err := json.Marshal(snap)
			return raw, n, err
		},
		fingerprint: func() (string, error) { return contentdir.Fingerprint(dir) },
	}
}

func ollamaSource(ref, home string) payloadSource {
	return payloadSource{
		kind: ContentKindOllama,
		ref:  ref,
		capture: func(w io.Writer) (json.RawMessage, int64, error) {
			snap, n, err := ollama.Capture(ref, home, w)
			if err != nil {
				return nil, 0, err
			}
			raw, err := json.Marshal(snap)
			return raw, n, err
		},
		fingerprint: func() (string, error) { return ollama.Fingerprint(ref, home) },
	}
}

// writeFileExclusive writes data with mode 0644, never over an existing
// file unless force.
func writeFileExclusive(path string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// writeKeyFile writes a bundle key with mode 0600, never over an existing
// file unless force.
func writeKeyFile(path string, key []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// ---------------------------------------------------------------------------
// genome open / rewind
// ---------------------------------------------------------------------------

func genomeOpenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome open", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundlePath = fs.String("bundle", "", "Path to .genome bundle (required)")
		targetDir  = fs.String("target", "", "Target directory for restore (required)")
		keyFile    = fs.String("key-file", "", "The bundle's 32-byte key file (required for v3 bundles)")
		allowV2    = fs.Bool("allow-v2", false, "Open a v2 bundle, whose key is stored inside it (not confidential)")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome open --bundle PATH --key-file PATH --target PATH [--json]")
		fmt.Fprintln(stderr, "       acpctl genome rewind --bundle PATH --key-file PATH --target PATH [--json]   (alias)")
		fmt.Fprintln(stderr, "       acpctl genome open --bundle V2-PATH --allow-v2 --target PATH   (legacy v2 bundles)")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" || *targetDir == "" {
		fmt.Fprintln(stderr, "acpctl genome open: --bundle and --target are required")
		fs.Usage()
		return 2
	}
	gf, err := loadGenome(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome open: %v\n", err)
		return 1
	}

	var payload io.Reader
	switch {
	case gf.V3:
		if *keyFile == "" {
			fmt.Fprintf(stderr, "acpctl genome open: %s opens only with its key: pass --key-file (key id %s)\n", *bundlePath, gf.Header.KeyID)
			return 2
		}
		dek, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome open: key file: %v\n", err)
			return 1
		}
		f, r, err := openV3(*bundlePath)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome open: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		if payload, err = r.PayloadWithKey(dek); err != nil {
			fmt.Fprintf(stderr, "acpctl genome open: %v\n", err)
			return 4
		}
	default:
		if !*allowV2 {
			fmt.Fprintf(stderr, "acpctl genome open: %s is a v2 bundle, which stores its own sealing key — anyone holding it can open it. Pass --allow-v2 to open it, then reseal the restored content as v3.\n", *bundlePath)
			return 2
		}
		plain, err := openV2(gf)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome open: %v\n", err)
			return 4
		}
		payload = bytes.NewReader(plain)
	}

	res, err := restore.Restore(gf.Header, payload, *targetDir)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome open: %v\n", err)
		return 4
	}

	emitGenome(stdout, *jsonOut, openResult{
		OK:            true,
		Bundle:        *bundlePath,
		Format:        gf.Format,
		KeyID:         gf.Header.KeyID,
		Target:        *targetDir,
		ContentKind:   gf.Header.ContentKind,
		ContentRef:    gf.Header.ContentRef,
		Generation:    gf.Header.Generation,
		Files:         res.Files,
		BytesWritten:  res.BytesWritten,
		PayloadSHA256: res.PayloadSHA256,
		TreeSHA256:    res.TreeSHA256,
	})
	return 0
}

// openV3 opens a v3 bundle file and reads its header.
func openV3(path string) (*os.File, *bundle.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	r, err := bundle.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, r, nil
}

// openV2 opens a legacy v2 bundle with the simulated-TEE seed it carries.
func openV2(gf *genomeFile) ([]byte, error) {
	env := gf.v2
	if env.TEEProvider != string(tee.ProviderSimulated) {
		return nil, fmt.Errorf("provider %q not supported by this build", env.TEEProvider)
	}
	sealer, err := tee.NewSimulated(env.SimulatedWorkloadDescriptor, env.SimulatedSeed)
	if err != nil {
		return nil, fmt.Errorf("NewSimulated: %w", err)
	}
	if live := sealer.Measurement(); !bytes.Equal(live[:], env.Measurement) {
		return nil, errors.New("measurement mismatch — refusing unseal")
	}
	payload, err := sealer.Unseal(gf.v2Sealed, env.AAD)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	if got := "sha256:" + hex.EncodeToString(sha256Sum(payload)); got != env.payloadDigest() {
		return nil, fmt.Errorf("payload digest mismatch (envelope=%s, computed=%s)", env.payloadDigest(), got)
	}
	return payload, nil
}

// ---------------------------------------------------------------------------
// genome verify
// ---------------------------------------------------------------------------

func genomeVerifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundlePath = fs.String("bundle", "", "Path to .genome bundle (required)")
		restored   = fs.String("restored", "", "Optional: restored target dir to re-hash blobs against")
		keyFile    = fs.String("key-file", "", "Optional: the bundle's key file — authenticates the header and payload")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome verify --bundle PATH [--key-file PATH] [--restored PATH] [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Without --key-file, verify checks the bundle is well-formed and, with")
		fmt.Fprintln(stderr, "--restored, that a restored tree matches the header. With --key-file it")
		fmt.Fprintln(stderr, "first opens the bundle in memory, so the header is the one that was sealed.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" {
		fmt.Fprintln(stderr, "acpctl genome verify: --bundle is required")
		fs.Usage()
		return 2
	}
	gf, err := loadGenome(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome verify: %v\n", err)
		return 1
	}
	res := verifyResult{
		OK:             true,
		Bundle:         *bundlePath,
		ContentKind:    gf.Header.ContentKind,
		ContentRef:     gf.Header.ContentRef,
		Generation:     gf.Header.Generation,
		EnvelopeFormat: gf.Format,
		KeyID:          gf.Header.KeyID,
		ComponentCount: countComponents(ContentKind(gf.Header.ContentKind), gf.Header.ContentSnapshot),
		BundleBytes:    gf.Size,
		BundleSHA256:   gf.SHA256,
		PayloadSHA256:  gf.Header.PayloadSHA256,
		SealedAt:       gf.Header.SealedAt.Format(time.RFC3339),
	}
	if *keyFile != "" {
		if !gf.V3 {
			fmt.Fprintf(stderr, "acpctl genome verify: %s is a v2 bundle; it has no key file and cannot be authenticated\n", *bundlePath)
			return 2
		}
		dek, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome verify: key file: %v\n", err)
			return 1
		}
		f, r, err := openV3(*bundlePath)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome verify: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()
		payload, err := r.PayloadWithKey(dek)
		if err == nil {
			_, err = io.Copy(io.Discard, payload)
		}
		if err != nil {
			fmt.Fprintf(stderr, "acpctl genome verify: %v\n", err)
			return 4
		}
		res.Authenticated = true
	}
	if *restored != "" {
		tree, err := restore.Verify(gf.Header, *restored)
		if err != nil {
			res.OK = false
			res.RestoredVerify = "fail: " + err.Error()
			emitGenome(stdout, *jsonOut, res)
			return 5
		}
		res.TreeSHA256 = tree
		res.RestoredVerify = "ok: every file matches its recorded digest"
	}
	emitGenome(stdout, *jsonOut, res)
	return 0
}

// ---------------------------------------------------------------------------
// genome inspect
// ---------------------------------------------------------------------------

func genomeInspectCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundlePath = fs.String("bundle", "", "Path to .genome bundle (required)")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome inspect --bundle PATH [--json]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" {
		fmt.Fprintln(stderr, "acpctl genome inspect: --bundle is required")
		fs.Usage()
		return 2
	}
	gf, err := loadGenome(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome inspect: %v\n", err)
		return 1
	}
	h := gf.Header
	if *jsonOut {
		out := map[string]any{
			"format":                gf.Format,
			"sealed_at":             h.SealedAt.Format(time.RFC3339),
			"generation":            h.Generation,
			"parent_bundle_sha256":  h.ParentBundleSHA256,
			"parent_payload_sha256": h.ParentPayloadSHA256,
			"parent_generation":     h.ParentGeneration,
			"content_kind":          h.ContentKind,
			"content_ref":           h.ContentRef,
			"payload_sha256":        h.PayloadSHA256,
			"bundle_bytes":          gf.Size,
			"bundle_sha256":         gf.SHA256,
			"content_snapshot":      h.ContentSnapshot,
		}
		if gf.V3 {
			out["key_id"] = h.KeyID
			out["payload_bytes"] = h.PayloadBytes
			out["segment_bytes"] = h.SegmentBytes
		} else {
			out["key_in_bundle"] = true
			out["tee_provider"] = gf.v2.TEEProvider
			out["measurement"] = hex.EncodeToString(gf.v2.Measurement)
		}
		_ = json.NewEncoder(stdout).Encode(out)
		return 0
	}
	fmt.Fprintf(stdout, "bundle:           %s\n", *bundlePath)
	fmt.Fprintf(stdout, "format:           %s\n", gf.Format)
	if gf.V3 {
		fmt.Fprintf(stdout, "key id:           %s  (the key is not in the bundle)\n", h.KeyID)
	} else {
		fmt.Fprintln(stdout, "key:              stored in the bundle (v2) — anyone holding it can open it; reseal as v3")
	}
	fmt.Fprintf(stdout, "sealed at (UTC):  %s\n", h.SealedAt.Format(time.RFC3339))
	fmt.Fprintf(stdout, "generation:       %d\n", h.Generation)
	if h.ParentBundleSHA256 != "" {
		fmt.Fprintf(stdout, "parent bundle:    sha256:%s (gen %d)\n", h.ParentBundleSHA256, h.ParentGeneration)
		fmt.Fprintf(stdout, "parent payload:   sha256:%s\n", h.ParentPayloadSHA256)
	} else {
		fmt.Fprintln(stdout, "parent bundle:    (none — genesis)")
	}
	fmt.Fprintf(stdout, "content kind:     %s\n", h.ContentKind)
	fmt.Fprintf(stdout, "content ref:      %s\n", h.ContentRef)
	fmt.Fprintf(stdout, "bundle bytes:     %d (%s)\n", gf.Size, humanBytes(gf.Size))
	fmt.Fprintf(stdout, "bundle sha256:    %s\n", gf.SHA256)
	fmt.Fprintf(stdout, "payload sha256:   %s\n", h.PayloadSHA256)
	if gf.V3 {
		fmt.Fprintf(stdout, "payload bytes:    %d (%s) in segments of %s\n", h.PayloadBytes, humanBytes(h.PayloadBytes), humanBytes(h.SegmentBytes))
	}
	kind := ContentKind(h.ContentKind)
	fmt.Fprintf(stdout, "components (%d):\n", countComponents(kind, h.ContentSnapshot))
	listComponents(stdout, kind, h.ContentSnapshot)
	return 0
}

func listComponents(w io.Writer, kind ContentKind, snapshot json.RawMessage) {
	switch kind {
	case ContentKindOllama:
		var snap ollama.Snapshot
		if err := json.Unmarshal(snapshot, &snap); err != nil {
			fmt.Fprintf(w, "  <decode error: %v>\n", err)
			return
		}
		for _, c := range snap.Components {
			fmt.Fprintf(w, "  [%s] %-50s %12d  %s\n", c.Role, c.Digest, c.Size, c.MediaType)
		}
	case ContentKindDir:
		var snap contentdir.Snapshot
		if err := json.Unmarshal(snapshot, &snap); err != nil {
			fmt.Fprintf(w, "  <decode error: %v>\n", err)
			return
		}
		for _, c := range snap.Components {
			fmt.Fprintf(w, "  %-44s %12d  %s\n", c.Path, c.Size, c.Digest)
		}
	}
}

func countComponents(kind ContentKind, snapshot json.RawMessage) int {
	switch kind {
	case ContentKindOllama:
		var snap ollama.Snapshot
		if err := json.Unmarshal(snapshot, &snap); err != nil {
			return -1
		}
		return len(snap.Components)
	case ContentKindDir:
		var snap contentdir.Snapshot
		if err := json.Unmarshal(snapshot, &snap); err != nil {
			return -1
		}
		return len(snap.Components)
	}
	return 0
}

// ---------------------------------------------------------------------------
// genome chain
// ---------------------------------------------------------------------------

type chainNode struct {
	Path                string
	Format              string
	KeyID               string `json:",omitempty"`
	Generation          uint64
	BundleSHA256        string
	PayloadSHA256       string
	ParentSHA256        string
	ParentPayloadSHA256 string `json:",omitempty"`
	ParentGeneration    uint64
	ContentKind         string
	ContentRef          string
	BundleBytes         int64
	SealedAt            time.Time
}

func nodeOf(gf *genomeFile) chainNode {
	return chainNode{
		Path:                gf.Path,
		Format:              gf.Format,
		KeyID:               gf.Header.KeyID,
		Generation:          gf.Header.Generation,
		BundleSHA256:        gf.SHA256,
		PayloadSHA256:       gf.Header.PayloadSHA256,
		ParentSHA256:        gf.Header.ParentBundleSHA256,
		ParentPayloadSHA256: gf.Header.ParentPayloadSHA256,
		ParentGeneration:    gf.Header.ParentGeneration,
		ContentKind:         gf.Header.ContentKind,
		ContentRef:          gf.Header.ContentRef,
		BundleBytes:         gf.Size,
		SealedAt:            gf.Header.SealedAt,
	}
}

// linkFault says why child does not follow parent, or "" when it does:
// the parent is the generation before the child, the one the child
// recorded, holding the payload the child recorded.
func linkFault(child, parent chainNode) string {
	switch {
	case parent.Generation != child.ParentGeneration:
		return fmt.Sprintf("parent is generation %d, child recorded %d", parent.Generation, child.ParentGeneration)
	case child.Generation != parent.Generation+1:
		return fmt.Sprintf("generation %d does not follow parent generation %d", child.Generation, parent.Generation)
	case child.ParentPayloadSHA256 != "" && child.ParentPayloadSHA256 != strings.TrimPrefix(parent.PayloadSHA256, "sha256:"):
		return "parent payload differs from the one the child recorded"
	}
	return ""
}

// readGenomeDir loads every .genome file in dir.
func readGenomeDir(dir string) ([]chainNode, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}
	var nodes []chainNode
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".genome") {
			continue
		}
		gf, err := loadGenome(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, nodeOf(gf))
	}
	return nodes, nil
}

func genomeChainCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome chain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		dir     = fs.String("dir", ".", "Directory containing .genome bundles")
		jsonOut = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome chain --dir PATH [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Walk every .genome file in PATH, sort by generation, and validate that")
		fmt.Fprintln(stderr, "every parent reference resolves to the bundle, generation and payload it")
		fmt.Fprintln(stderr, "names in the directory.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	nodes, err := readGenomeDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome chain: %v\n", err)
		return 1
	}
	if len(nodes) == 0 {
		fmt.Fprintf(stderr, "acpctl genome chain: no .genome files in %s\n", *dir)
		return 1
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Generation < nodes[j].Generation })

	bySHA := make(map[string]chainNode, len(nodes))
	for _, n := range nodes {
		bySHA[n.BundleSHA256] = n
	}
	var brokenLinks []string
	for _, n := range nodes {
		if n.Generation == 0 {
			continue
		}
		if n.ParentSHA256 == "" {
			brokenLinks = append(brokenLinks, fmt.Sprintf("%s (gen %d): missing parent_bundle_sha256", n.Path, n.Generation))
			continue
		}
		parent, ok := bySHA[n.ParentSHA256]
		if !ok {
			brokenLinks = append(brokenLinks, fmt.Sprintf("%s (gen %d): parent sha256:%s not found in dir", n.Path, n.Generation, n.ParentSHA256))
			continue
		}
		if fault := linkFault(n, parent); fault != "" {
			brokenLinks = append(brokenLinks, fmt.Sprintf("%s (gen %d): %s", n.Path, n.Generation, fault))
		}
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"ok":           len(brokenLinks) == 0,
			"dir":          *dir,
			"node_count":   len(nodes),
			"chain":        nodes,
			"broken_links": brokenLinks,
		})
		if len(brokenLinks) > 0 {
			return 5
		}
		return 0
	}

	fmt.Fprintf(stdout, "chain @ %s — %d generation(s)\n\n", *dir, len(nodes))
	for _, n := range nodes {
		marker := "├──"
		if n.Generation == 0 {
			marker = "●  "
		}
		fmt.Fprintf(stdout, "%s gen %3d  %s  %s  %s  (%s)\n",
			marker, n.Generation, humanBytes(n.BundleBytes),
			n.SealedAt.Format("15:04:05"), filepath.Base(n.Path), n.Format)
		fmt.Fprintf(stdout, "          bundle    sha256:%s\n", n.BundleSHA256[:16]+"…")
		if n.ParentSHA256 != "" {
			fmt.Fprintf(stdout, "          parent →  sha256:%s\n", shortHex(n.ParentSHA256))
		}
		fmt.Fprintf(stdout, "          content   %s · %s\n\n", n.ContentKind, n.ContentRef)
	}
	if len(brokenLinks) > 0 {
		fmt.Fprintln(stdout, "✗ chain has broken links:")
		for _, b := range brokenLinks {
			fmt.Fprintf(stdout, "  %s\n", b)
		}
		return 5
	}
	fmt.Fprintln(stdout, "✓ chain valid — every parent reference resolves to an in-dir bundle")
	return 0
}

// ---------------------------------------------------------------------------
// genome lineage
// ---------------------------------------------------------------------------

func genomeLineageCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("genome lineage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundlePath = fs.String("bundle", "", "Path to .genome bundle (required)")
		dir        = fs.String("dir", "", "Directory containing the chain's bundles (required)")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl genome lineage --bundle PATH --dir PATH [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Walk parent references back to the genesis bundle, printing every ancestor.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" || *dir == "" {
		fmt.Fprintln(stderr, "acpctl genome lineage: --bundle and --dir are required")
		fs.Usage()
		return 2
	}

	nodes, err := readGenomeDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome lineage: %v\n", err)
		return 1
	}
	bySHA := make(map[string]chainNode, len(nodes))
	for _, n := range nodes {
		bySHA[n.BundleSHA256] = n
	}
	start, err := loadGenome(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl genome lineage: %v\n", err)
		return 1
	}

	// Each step goes down exactly one generation, so the walk ends.
	ancestors := []chainNode{nodeOf(start)}
	for cur := ancestors[0]; cur.Generation > 0; {
		parent, ok := bySHA[cur.ParentSHA256]
		if !ok {
			fmt.Fprintf(stderr, "acpctl genome lineage: parent sha256:%s of %s not found in %s\n", cur.ParentSHA256, cur.Path, *dir)
			return 1
		}
		if fault := linkFault(cur, parent); fault != "" {
			fmt.Fprintf(stderr, "acpctl genome lineage: %s: %s\n", cur.Path, fault)
			return 5
		}
		ancestors = append(ancestors, parent)
		cur = parent
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"ok":        true,
			"bundle":    *bundlePath,
			"depth":     len(ancestors),
			"ancestors": ancestors,
		})
		return 0
	}
	fmt.Fprintf(stdout, "lineage of %s — depth %d\n\n", filepath.Base(*bundlePath), len(ancestors))
	for i, a := range ancestors {
		arrow := "├──"
		if i == len(ancestors)-1 {
			arrow = "●  "
		}
		fmt.Fprintf(stdout, "%s gen %3d  %s  %s  %s  (%s)\n",
			arrow, a.Generation, humanBytes(a.BundleBytes),
			a.SealedAt.Format("15:04:05"), filepath.Base(a.Path), a.Format)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "✓ lineage complete — every parent reference resolved to an existing bundle")
	return 0
}

// ---------------------------------------------------------------------------
// reading bundles of either format
// ---------------------------------------------------------------------------

// genomeFile is a bundle read from disk, v3 or v2, described by a v3
// header so every read-only subcommand handles both. A v3 bundle is read
// as far as its header and hashed as a stream, never loaded whole; a v2
// envelope is mapped onto the header, and its sealing key stays in v2.
type genomeFile struct {
	Path   string
	Size   int64
	SHA256 string // of the bundle file, hex
	Format string
	Header bundle.Header
	V3     bool

	v2       *GenomeEnvelope
	v2Sealed []byte
}

func loadGenome(path string) (*genomeFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var magic [len(bundle.Magic)]byte
	_, err = io.ReadFull(f, magic[:])
	_ = f.Close()
	if err == nil && bundle.IsV3(magic[:]) {
		id, err := bundle.Identify(path)
		if err != nil {
			return nil, err
		}
		return &genomeFile{Path: path, Size: id.Size, SHA256: id.SHA256, Format: bundle.Format, Header: id.Header, V3: true}, nil
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env, sealed, err := decodeGenome(blob)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &genomeFile{
		Path:   path,
		Size:   int64(len(blob)),
		SHA256: sha256Hex(blob),
		Format: envelopeFormatV2,
		Header: bundle.Header{
			Format:              envelopeFormatV2,
			SealedAt:            time.Unix(0, env.SealedAt).UTC(),
			Generation:          env.Generation,
			ParentBundleSHA256:  env.ParentBundleSHA256,
			ParentPayloadSHA256: env.ParentPayloadSHA256,
			ParentGeneration:    env.ParentGeneration,
			ContentKind:         string(env.ContentKind),
			ContentRef:          env.ContentRef,
			ContentSnapshot:     env.ContentSnapshot,
			PayloadSHA256:       env.payloadDigest(),
		},
		v2:       env,
		v2Sealed: sealed,
	}, nil
}

// decodeGenome splits a v2 bundle: magic ‖ u32 BE metadata length ‖
// metadata JSON ‖ sealed payload.
func decodeGenome(blob []byte) (*GenomeEnvelope, []byte, error) {
	if len(blob) < len(genomeMagic)+4 {
		return nil, nil, errors.New("decode: blob too short")
	}
	if string(blob[:len(genomeMagic)]) != genomeMagic {
		return nil, nil, errors.New("decode: magic mismatch (not a Vault Genome bundle)")
	}
	off := len(genomeMagic)
	metaLen := binary.BigEndian.Uint32(blob[off : off+4])
	off += 4
	if uint32(len(blob)-off) < metaLen {
		return nil, nil, errors.New("decode: truncated metadata")
	}
	var env GenomeEnvelope
	if err := json.Unmarshal(blob[off:off+int(metaLen)], &env); err != nil {
		return nil, nil, fmt.Errorf("decode: metadata json: %w", err)
	}
	if env.Format != envelopeFormatV2 {
		return nil, nil, fmt.Errorf("decode: unsupported format %q (this build expects %s)", env.Format, envelopeFormatV2)
	}
	return &env, blob[off+int(metaLen):], nil
}

// payloadDigest extracts the payload SHA-256 from the embedded snapshot.
// Both snapshot kinds expose a PayloadSHA256 field at the top level.
func (e *GenomeEnvelope) payloadDigest() string {
	var probe struct {
		PayloadSHA256 string `json:"payload_sha256"`
	}
	_ = json.Unmarshal(e.ContentSnapshot, &probe)
	return probe.PayloadSHA256
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func defaultOllamaHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/root/.ollama"
	}
	return filepath.Join(home, ".ollama")
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// shortHex abbreviates a digest for display; a value too short to
// abbreviate is shown whole.
func shortHex(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---------------------------------------------------------------------------
// result types — separate from the bundle header so JSON output stays
// stable as the format evolves.
// ---------------------------------------------------------------------------

type sealResult struct {
	OK                 bool   `json:"ok"`
	Output             string `json:"output"`
	KeyFile            string `json:"key_file,omitempty"`
	EscrowFile         string `json:"escrow_file,omitempty"`
	EscrowKey          string `json:"escrow_key,omitempty"`
	KeyID              string `json:"key_id"`
	ContentKind        string `json:"content_kind"`
	ContentRef         string `json:"content_ref"`
	Generation         uint64 `json:"generation"`
	ParentBundle       string `json:"parent_bundle,omitempty"`
	ParentBundleSHA256 string `json:"parent_bundle_sha256,omitempty"`
	PayloadBytes       int64  `json:"payload_bytes"`
	BundleBytes        int64  `json:"bundle_bytes"`
	SegmentBytes       int64  `json:"segment_bytes"`
	PayloadSHA256      string `json:"payload_sha256"`
	ComponentCount     int    `json:"component_count"`
	SealedAt           string `json:"sealed_at"`
}

type openResult struct {
	OK            bool   `json:"ok"`
	Bundle        string `json:"bundle"`
	Format        string `json:"format"`
	KeyID         string `json:"key_id,omitempty"`
	Target        string `json:"target"`
	ContentKind   string `json:"content_kind"`
	ContentRef    string `json:"content_ref"`
	Generation    uint64 `json:"generation"`
	Files         int    `json:"files"`
	BytesWritten  int64  `json:"bytes_written"`
	PayloadSHA256 string `json:"payload_sha256"`
	TreeSHA256    string `json:"tree_sha256"`
}

type verifyResult struct {
	OK             bool   `json:"ok"`
	Bundle         string `json:"bundle"`
	ContentKind    string `json:"content_kind"`
	ContentRef     string `json:"content_ref"`
	Generation     uint64 `json:"generation"`
	EnvelopeFormat string `json:"envelope_format"`
	KeyID          string `json:"key_id,omitempty"`
	// Authenticated is true only when the bundle was opened with its key
	// (--key-file): the GCM tag then vouches for every header field and
	// the payload. Without the key the header is only well-formed.
	Authenticated  bool   `json:"authenticated"`
	ComponentCount int    `json:"component_count"`
	BundleBytes    int64  `json:"bundle_bytes"`
	BundleSHA256   string `json:"bundle_sha256"`
	PayloadSHA256  string `json:"payload_sha256"`
	SealedAt       string `json:"sealed_at"`
	RestoredVerify string `json:"restored_verify,omitempty"`
	TreeSHA256     string `json:"tree_sha256,omitempty"`
}

func emitGenome(w io.Writer, asJSON bool, v any) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	switch r := v.(type) {
	case sealResult:
		fmt.Fprintf(w, "✓ sealed %s %q  (gen %d)\n", r.ContentKind, r.ContentRef, r.Generation)
		fmt.Fprintf(w, "  output:        %s\n", r.Output)
		if r.KeyFile != "" {
			fmt.Fprintf(w, "  key file:      %s  (0600 — it opens the bundle)\n", r.KeyFile)
		}
		if r.EscrowFile != "" {
			fmt.Fprintf(w, "  escrow:        %s  (the key, for release authority %s only)\n", r.EscrowFile, r.EscrowKey)
		}
		fmt.Fprintf(w, "  key id:        %s\n", r.KeyID)
		if r.ParentBundle != "" {
			fmt.Fprintf(w, "  parent:        %s (sha256:%s)\n", r.ParentBundle, shortHex(r.ParentBundleSHA256))
		}
		fmt.Fprintf(w, "  components:    %d\n", r.ComponentCount)
		fmt.Fprintf(w, "  bundle bytes:  %d (%s), payload %s in segments of %s\n", r.BundleBytes, humanBytes(r.BundleBytes), humanBytes(r.PayloadBytes), humanBytes(r.SegmentBytes))
		fmt.Fprintf(w, "  payload sha256:%s\n", r.PayloadSHA256)
		fmt.Fprintf(w, "  sealed at UTC: %s\n", r.SealedAt)
	case openResult:
		fmt.Fprintf(w, "✓ unsealed %s %q  (gen %d, %s)\n", r.ContentKind, r.ContentRef, r.Generation, r.Format)
		fmt.Fprintf(w, "  bundle:        %s\n", r.Bundle)
		if r.KeyID != "" {
			fmt.Fprintf(w, "  key id:        %s\n", r.KeyID)
		}
		fmt.Fprintf(w, "  target:        %s\n", r.Target)
		fmt.Fprintf(w, "  files:         %d, %d bytes (%s), each checked against its recorded digest\n", r.Files, r.BytesWritten, humanBytes(r.BytesWritten))
		fmt.Fprintf(w, "  payload sha256:%s\n", r.PayloadSHA256)
		fmt.Fprintf(w, "  tree sha256:   %s\n", r.TreeSHA256)
	case verifyResult:
		marker := "✓"
		if !r.OK {
			marker = "✗"
		}
		fmt.Fprintf(w, "%s envelope %s · %s %q  (gen %d)\n", marker, r.EnvelopeFormat, r.ContentKind, r.ContentRef, r.Generation)
		fmt.Fprintf(w, "  bundle:        %s\n", r.Bundle)
		if r.KeyID != "" {
			fmt.Fprintf(w, "  key id:        %s\n", r.KeyID)
		}
		if r.Authenticated {
			fmt.Fprintln(w, "  authenticated: yes — opened with its key; header and payload are as sealed")
		} else {
			fmt.Fprintln(w, "  authenticated: no — pass --key-file to check the header and payload against the seal")
		}
		fmt.Fprintf(w, "  components:    %d\n", r.ComponentCount)
		fmt.Fprintf(w, "  bundle:        %d bytes (%s), sha256 %s\n", r.BundleBytes, humanBytes(r.BundleBytes), shortHex(r.BundleSHA256))
		fmt.Fprintf(w, "  payload sha256:%s\n", r.PayloadSHA256)
		fmt.Fprintf(w, "  sealed at UTC: %s\n", r.SealedAt)
		if r.RestoredVerify != "" {
			fmt.Fprintf(w, "  restored:      %s\n", r.RestoredVerify)
		}
		if r.TreeSHA256 != "" {
			fmt.Fprintf(w, "  tree sha256:   %s\n", r.TreeSHA256)
		}
	}
}
