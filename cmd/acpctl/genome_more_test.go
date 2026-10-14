// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// writeV2Bundle frames a v2 envelope and sealed payload the way builds
// before v3 wrote them, with whatever the envelope says.
func writeV2Bundle(t *testing.T, path string, env GenomeEnvelope, sealed []byte) {
	t.Helper()
	meta, err := json.Marshal(env)
	require.NoError(t, err)
	var buf bytes.Buffer
	buf.WriteString(genomeMagic)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(meta)))
	buf.Write(n[:])
	buf.Write(meta)
	buf.Write(sealed)
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
}

// escrowPublicPEM writes a fresh escrow public key to dir and returns its path.
func escrowPublicPEM(t *testing.T, dir string) string {
	t.Helper()
	priv, err := escrow.GenerateKey()
	require.NoError(t, err)
	pemBytes, err := escrow.PublicPEM(priv.PublicKey())
	require.NoError(t, err)
	p := filepath.Join(dir, "escrow.pem")
	require.NoError(t, os.WriteFile(p, pemBytes, 0o644))
	return p
}

// Each content kind lists its components in its own columns; a snapshot
// that does not decode says so instead of listing nothing silently.
func TestListComponents(t *testing.T) {
	t.Parallel()
	ollamaSnap := json.RawMessage(`{"components":[
		{"role":"manifest","media_type":"application/vnd.docker.distribution.manifest.v2+json","digest":"sha256:aa","size":12},
		{"role":"layer","media_type":"application/vnd.ollama.image.model","digest":"sha256:bb","size":4096}]}`)
	dirSnap := json.RawMessage(`{"components":[{"path":"adapter/weights.safetensors","digest":"sha256:cc","size":7}]}`)

	for name, tc := range map[string]struct {
		kind  ContentKind
		snap  json.RawMessage
		lines int
		want  []string // one regexp per line, in order
	}{
		"ollama": {ContentKindOllama, ollamaSnap, 2, []string{
			`^  \[manifest\] sha256:aa {42,} +12  application/vnd\.docker\.distribution\.manifest\.v2\+json$`,
			`^  \[layer\] sha256:bb {42,} +4096  application/vnd\.ollama\.image\.model$`,
		}},
		"dir":                  {ContentKindDir, dirSnap, 1, []string{`^  adapter/weights\.safetensors {17,} +7  sha256:cc$`}},
		"ollama undecodable":   {ContentKindOllama, json.RawMessage(`{"components":`), 1, []string{`^  <decode error: .+>$`}},
		"dir undecodable":      {ContentKindDir, json.RawMessage(`[]`), 1, []string{`^  <decode error: .+>$`}},
		"unknown kind":         {ContentKind("tarball"), dirSnap, 0, nil},
		"ollama kind, no snap": {ContentKindOllama, json.RawMessage(`{}`), 0, nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			listComponents(&buf, tc.kind, tc.snap)
			if tc.lines == 0 {
				require.Empty(t, buf.String())
				return
			}
			lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
			require.Len(t, lines, tc.lines, buf.String())
			for i, w := range tc.want {
				require.Regexp(t, w, lines[i])
			}
		})
	}
}

func TestCountComponents(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		kind ContentKind
		snap json.RawMessage
		want int
	}{
		"ollama":             {ContentKindOllama, json.RawMessage(`{"components":[{"role":"layer"},{"role":"config"}]}`), 2},
		"dir":                {ContentKindDir, json.RawMessage(`{"components":[{"path":"a"}]}`), 1},
		"ollama undecodable": {ContentKindOllama, json.RawMessage(`nope`), -1},
		"dir undecodable":    {ContentKindDir, json.RawMessage(`{"components":"x"}`), -1},
		"unknown kind":       {ContentKind("tarball"), json.RawMessage(`{"components":[{}]}`), 0},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, countComponents(tc.kind, tc.snap))
		})
	}
}

// Neither writer touches an existing file unless forced; the key writer
// keeps its file private.
func TestWriteFileExclusiveAndWriteKeyFile(t *testing.T) {
	t.Parallel()
	for name, write := range map[string]func(string, []byte, bool) error{
		"writeFileExclusive": writeFileExclusive,
		"writeKeyFile":       writeKeyFile,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			p := filepath.Join(dir, "f")
			require.NoError(t, write(p, []byte("first"), false))
			err := write(p, []byte("second"), false)
			require.ErrorIs(t, err, os.ErrExist)
			got, err := os.ReadFile(p)
			require.NoError(t, err)
			require.Equal(t, []byte("first"), got, "the first bytes stay")

			require.NoError(t, write(p, []byte("third"), true))
			got, err = os.ReadFile(p)
			require.NoError(t, err)
			require.Equal(t, []byte("third"), got, "forced, the file is replaced whole")

			info, err := os.Stat(p)
			require.NoError(t, err)
			want := os.FileMode(0o644)
			if name == "writeKeyFile" {
				want = 0o600
			}
			require.Equal(t, want, info.Mode().Perm())

			require.Error(t, write(filepath.Join(dir, "absent", "f"), []byte("x"), true), "no directory is created")
			require.Error(t, write(dir, []byte("x"), true), "a directory is not written over")
		})
	}
}

// openV3 names a file it cannot open or that is not a v3 bundle.
func TestOpenV3_Errors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, _, err := openV3(filepath.Join(dir, "absent.genome"))
	require.ErrorIs(t, err, os.ErrNotExist)

	short := filepath.Join(dir, "short.genome")
	require.NoError(t, os.WriteFile(short, []byte(bundle.Magic), 0o644))
	_, _, err = openV3(short)
	require.ErrorContains(t, err, short+": bundle: truncated before the header")

	notV3 := filepath.Join(dir, "v2.genome")
	require.NoError(t, os.WriteFile(notV3, []byte(genomeMagic+"....more"), 0o644))
	_, _, err = openV3(notV3)
	require.ErrorContains(t, err, "not a v3 Vault Genome bundle")

	content, work := adapterDir(t, "v3"), t.TempDir()
	b := filepath.Join(work, "g.genome")
	r := sealDir(t, content, b, filepath.Join(work, "g.key"))
	f, reader, err := openV3(b)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.Equal(t, r.KeyID, reader.Header.KeyID)
	require.Equal(t, r.PayloadSHA256, reader.Header.PayloadSHA256)
}

// A v2 bundle opens only under the simulated TEE it names, at its
// measurement, with its AAD, and only to the payload it recorded.
func TestOpenV2_Refusals(t *testing.T) {
	t.Parallel()
	descriptor := []byte("v2-workload")
	seed := bytes.Repeat([]byte{0x42}, 32)
	sealer, err := tee.NewSimulated(descriptor, seed)
	require.NoError(t, err)
	payload := []byte("the sealed tree")
	aad := []byte("sha256:" + sha256Hex(payload))
	sealed, err := sealer.Seal(payload, aad)
	require.NoError(t, err)
	m := sealer.Measurement()
	good := GenomeEnvelope{
		Format:                      envelopeFormatV2,
		TEEProvider:                 string(tee.ProviderSimulated),
		ContentKind:                 ContentKindDir,
		ContentSnapshot:             json.RawMessage(`{"payload_sha256":"sha256:` + sha256Hex(payload) + `"}`),
		Measurement:                 m[:],
		AAD:                         aad,
		SimulatedWorkloadDescriptor: descriptor,
		SimulatedSeed:               seed,
	}
	wrongMeasurement := append([]byte(nil), m...)
	wrongMeasurement[0] ^= 1

	got, err := openV2(&genomeFile{v2: &good, v2Sealed: sealed})
	require.NoError(t, err)
	require.Equal(t, payload, got)

	for name, tc := range map[string]struct {
		edit func(*GenomeEnvelope)
		want string
	}{
		"hardware provider": {func(e *GenomeEnvelope) { e.TEEProvider = "aws-nitro" }, `provider "aws-nitro" not supported by this build`},
		"short seed":        {func(e *GenomeEnvelope) { e.SimulatedSeed = []byte("short") }, "NewSimulated:"},
		"other measurement": {func(e *GenomeEnvelope) { e.Measurement = wrongMeasurement }, "measurement mismatch"},
		"other aad":         {func(e *GenomeEnvelope) { e.AAD = []byte("other") }, "unseal:"},
		"other recorded digest": {func(e *GenomeEnvelope) {
			e.ContentSnapshot = json.RawMessage(`{"payload_sha256":"sha256:` + strings.Repeat("0", 64) + `"}`)
		}, "payload digest mismatch"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := good
			tc.edit(&env)
			got, err := openV2(&genomeFile{v2: &env, v2Sealed: sealed})
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, got)
		})
	}
}

// Every malformed v2 frame is named for what it is.
func TestDecodeGenome_Malformed(t *testing.T) {
	t.Parallel()
	frame := func(meta string) []byte {
		var buf bytes.Buffer
		buf.WriteString(genomeMagic)
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(meta)))
		buf.Write(n[:])
		buf.WriteString(meta)
		return buf.Bytes()
	}
	truncated := frame(`{"format":"vault-genome-v2"}`)
	binary.BigEndian.PutUint32(truncated[len(genomeMagic):], 1<<20)

	for name, tc := range map[string]struct {
		blob []byte
		want string
	}{
		"too short":          {[]byte(genomeMagic), "blob too short"},
		"wrong magic":        {[]byte(vaultEnvelopeMagic + "........"), "magic mismatch"},
		"truncated metadata": {truncated, "truncated metadata"},
		"metadata not json":  {frame(`{"format"`), "metadata json"},
		"unsupported format": {frame(`{"format":"vault-genome-v1"}`), `unsupported format "vault-genome-v1"`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env, sealed, err := decodeGenome(tc.blob)
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, env)
			require.Nil(t, sealed)
		})
	}

	env, sealed, err := decodeGenome(append(frame(`{"format":"vault-genome-v2","generation":3}`), 'x', 'y'))
	require.NoError(t, err)
	require.Equal(t, uint64(3), env.Generation)
	require.Equal(t, []byte("xy"), sealed)
}

// A file that starts like a v3 bundle but is not one is refused by every
// read-only subcommand, named with its path.
func TestLoadGenome_V3MagicWithoutABundle(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "broken.genome")
	require.NoError(t, os.WriteFile(p, append([]byte(bundle.Magic), 0, 0, 0, 2, '{', '}'), 0o644))
	_, err := loadGenome(p)
	require.ErrorContains(t, err, p)
	require.ErrorContains(t, err, "bundle:")

	code, _, stderr := runGenome("inspect", "--bundle", p)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl genome inspect: "+p)

	// A directory opens but holds no bytes to read as a bundle.
	_, err = loadGenome(filepath.Dir(p))
	require.ErrorContains(t, err, "is a directory")
}

func TestShortHex(t *testing.T) {
	t.Parallel()
	require.Equal(t, "", shortHex(""))
	require.Equal(t, "abcd", shortHex("abcd"))
	require.Equal(t, strings.Repeat("a", 16), shortHex(strings.Repeat("a", 16)))
	require.Equal(t, strings.Repeat("a", 16)+"…", shortHex(strings.Repeat("a", 17)))
	require.Equal(t, strings.Repeat("0", 16)+"…", shortHex(strings.Repeat("0", 64)))
}

// The Ollama home defaults to ~/.ollama, and to root's when there is no
// home to speak of.
func TestDefaultOllamaHome(t *testing.T) {
	t.Setenv("HOME", "/Users/someone")
	require.Equal(t, filepath.Join("/Users/someone", ".ollama"), defaultOllamaHome())
	t.Setenv("HOME", "")
	require.Equal(t, "/root/.ollama", defaultOllamaHome())
}

// A seal that cannot write its key or escrow leaves nothing behind: no
// bundle, no staging file, and no key for a bundle that was never written.
func TestGenomeSeal_WriteFailuresLeaveNothing(t *testing.T) {
	t.Parallel()
	content, work := adapterDir(t, "w"), t.TempDir()
	pub := escrowPublicPEM(t, work)
	absent := filepath.Join(work, "absent")
	b := filepath.Join(work, "g.genome")

	code, _, stderr := runGenome("seal", "--content-dir", content, "--output", b, "--key-out", filepath.Join(absent, "g.key"))
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "key file:")

	k := filepath.Join(work, "g.key")
	code, _, stderr = runGenome("seal", "--content-dir", content, "--output", b, "--key-out", k, "--escrow-to", pub, "--escrow-out", filepath.Join(absent, "g.escrow"))
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "escrow:")
	_, err := os.Stat(k)
	require.True(t, os.IsNotExist(err), "the key of a bundle that was never written is removed")

	code, _, stderr = runGenome("seal", "--content-dir", content, "--output", filepath.Join(absent, "g.genome"), "--key-out", k)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl genome seal:")
	_, err = os.Stat(k)
	require.True(t, os.IsNotExist(err), "no key before the bundle")

	entries, err := os.ReadDir(work)
	require.NoError(t, err)
	for _, e := range entries {
		require.NotContains(t, e.Name(), ".genome", "no bundle and no staging file: %s", e.Name())
	}
}

// The seal's text form names the parent and the escrow it wrote.
func TestGenomeSeal_TextNamesParentAndEscrow(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	pub := escrowPublicPEM(t, work)
	parent := filepath.Join(work, "gen-0.genome")
	r0 := sealDir(t, adapterDir(t, "p0"), parent, filepath.Join(work, "gen-0.key"))

	child := filepath.Join(work, "gen-1.genome")
	code, stdout, stderr := runGenome("seal", "--content-dir", adapterDir(t, "p1"), "--output", child, "--key-out", filepath.Join(work, "gen-1.key"),
		"--escrow-to", pub, "--parent", parent)
	require.Equal(t, 0, code, stderr)
	parentBlob, err := os.ReadFile(parent)
	require.NoError(t, err)
	require.Contains(t, stdout, `✓ sealed dir`)
	require.Contains(t, stdout, "(gen 1)")
	require.Contains(t, stdout, "  parent:        "+parent+" (sha256:"+shortHex(sha256Hex(parentBlob))+")")
	require.Contains(t, stdout, "  escrow:        "+child+".escrow  (the key, for release authority ")
	require.Contains(t, stdout, "  key file:      "+filepath.Join(work, "gen-1.key"))
	require.NotContains(t, stdout, r0.KeyID, "the child has its own key")
}

// A target that cannot become a directory fails the restore with exit 4
// and leaves it as it was.
func TestGenomeOpen_RestoreFailure(t *testing.T) {
	t.Parallel()
	content, work := adapterDir(t, "r"), t.TempDir()
	b, k := filepath.Join(work, "g.genome"), filepath.Join(work, "g.key")
	sealDir(t, content, b, k)
	target := filepath.Join(work, "target-file")
	require.NoError(t, os.WriteFile(target, []byte("in the way"), 0o644))

	code, _, stderr := runGenome("open", "--bundle", b, "--key-file", k, "--target", target)
	require.Equal(t, 4, code, stderr)
	require.Contains(t, stderr, "acpctl genome open:")
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("in the way"), got)
}

// verify's text form reports the restored tree's check and digest.
func TestGenomeVerify_TextWithRestoredTree(t *testing.T) {
	t.Parallel()
	content, work := adapterDir(t, "t"), t.TempDir()
	b, k, target := filepath.Join(work, "g.genome"), filepath.Join(work, "g.key"), filepath.Join(work, "restored")
	sealDir(t, content, b, k)
	code, _, stderr := runGenome("open", "--bundle", b, "--key-file", k, "--target", target)
	require.Equal(t, 0, code, stderr)

	code, stdout, stderr := runGenome("verify", "--bundle", b, "--restored", target)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "✓ envelope "+bundle.Format)
	require.Contains(t, stdout, "  authenticated: no — pass --key-file")
	require.Contains(t, stdout, "  restored:      ok: every file matches its recorded digest\n")
	require.Contains(t, stdout, "  tree sha256:   ")

	require.NoError(t, os.Remove(filepath.Join(target, "adapter_config.json")))
	code, stdout, _ = runGenome("verify", "--bundle", b, "--restored", target)
	require.Equal(t, 5, code)
	require.Contains(t, stdout, "✗ envelope")
	require.Contains(t, stdout, "  restored:      fail: ")
	require.NotContains(t, stdout, "tree sha256")
}

// A later generation that names no parent, or names a parent of another
// generation than the one it recorded, is a broken link.
func TestGenomeChain_RefusesParentlessAndMisrecordedLinks(t *testing.T) {
	t.Parallel()
	gens := t.TempDir()
	parent := filepath.Join(gens, "gen-0.genome")
	r0 := sealDir(t, adapterDir(t, "c0"), parent, filepath.Join(t.TempDir(), "k0"))
	parentBlob, err := os.ReadFile(parent)
	require.NoError(t, err)

	// Only a v2 envelope can claim a generation without a parent: the v3
	// header refuses to be sealed that way.
	orphan := filepath.Join(gens, "gen-1.genome")
	writeV2Bundle(t, orphan, GenomeEnvelope{
		Format: envelopeFormatV2, TEEProvider: "simulated", SealedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).UnixNano(),
		Generation: 1, ContentKind: ContentKindDir, ContentRef: "/orphan",
		ContentSnapshot: json.RawMessage(`{"payload_sha256":"sha256:` + strings.Repeat("1", 64) + `"}`),
	}, []byte("sealed"))
	code, stdout, _ := runGenome("chain", "--dir", gens)
	require.Equal(t, 5, code)
	require.Contains(t, stdout, "gen-1.genome (gen 1): missing parent_bundle_sha256")
	require.NoError(t, os.Remove(orphan))

	h := bundle.Header{Generation: 1, ParentGeneration: 7, ParentBundleSHA256: sha256Hex(parentBlob),
		ParentPayloadSHA256: strings.TrimPrefix(r0.PayloadSHA256, "sha256:"),
		ContentKind:         bundle.ContentDir, ContentRef: "/misrecorded", ContentSnapshot: json.RawMessage(`{"components":[]}`)}
	blob, _, err := bundle.SealBytes(h, []byte("forged payload"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(gens, "gen-1.genome"), blob, 0o644))
	code, stdout, _ = runGenome("chain", "--dir", gens, "--json")
	require.Equal(t, 5, code)
	require.Contains(t, stdout, "parent is generation 0, child recorded 7")
}

func TestLinkFault(t *testing.T) {
	t.Parallel()
	parent := chainNode{Generation: 2, PayloadSHA256: "sha256:" + strings.Repeat("a", 64)}
	for name, tc := range map[string]struct {
		child chainNode
		want  string
	}{
		"follows":              {chainNode{Generation: 3, ParentGeneration: 2, ParentPayloadSHA256: strings.Repeat("a", 64)}, ""},
		"no payload recorded":  {chainNode{Generation: 3, ParentGeneration: 2}, ""},
		"misrecorded parent":   {chainNode{Generation: 3, ParentGeneration: 1}, "parent is generation 2, child recorded 1"},
		"skips a generation":   {chainNode{Generation: 4, ParentGeneration: 2}, "generation 4 does not follow parent generation 2"},
		"other parent payload": {chainNode{Generation: 3, ParentGeneration: 2, ParentPayloadSHA256: strings.Repeat("b", 64)}, "parent payload differs from the one the child recorded"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, linkFault(tc.child, parent))
		})
	}
}

// inspect lists an Ollama model's components by role, digest and media type.
func TestGenomeInspect_OllamaText(t *testing.T) {
	t.Parallel()
	home, work := fakeOllamaHome(t, "llama3.2:3b"), t.TempDir()
	b := filepath.Join(work, "m.genome")
	code, _, stderr := runGenome("seal", "--model", "llama3.2:3b", "--ollama-home", home, "--output", b, "--key-out", filepath.Join(work, "m.key"))
	require.Equal(t, 0, code, stderr)

	code, stdout, stderr := runGenome("inspect", "--bundle", b)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "content kind:     ollama\n")
	require.Contains(t, stdout, "content ref:      llama3.2:3b\n")
	require.Contains(t, stdout, "components (4):\n")
	require.Contains(t, stdout, "  [manifest] ")
	require.Contains(t, stdout, "  [config] ")
	require.Equal(t, 2, strings.Count(stdout, "  [layer] "))
	require.Contains(t, stdout, "application/vnd.ollama.image.model")
	require.Contains(t, stdout, "parent bundle:    (none — genesis)\n")
}

// Opening a v2 bundle in the text form names its format and no key ID,
// since the key was inside the bundle.
func TestGenomeOpen_V2Text(t *testing.T) {
	t.Parallel()
	content, work := adapterDir(t, "v2text"), t.TempDir()
	v2 := filepath.Join(work, "gen-0.genome")
	sealV2(t, content, v2)
	target := filepath.Join(work, "restored")
	code, stdout, stderr := runGenome("open", "--bundle", v2, "--allow-v2", "--target", target)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, `✓ unsealed dir "`+content+`"  (gen 0, `+envelopeFormatV2+`)`)
	require.NotContains(t, stdout, "key id:")
	require.Contains(t, stdout, "  files:         3, ")
	requireSameTree(t, content, target)

	// A v2 bundle whose envelope names no simulated seed cannot open.
	blob, err := os.ReadFile(v2)
	require.NoError(t, err)
	env, sealed, err := decodeGenome(blob)
	require.NoError(t, err)
	env.TEEProvider = "gcp-sev-snp"
	hardware := filepath.Join(work, "hw.genome")
	writeV2Bundle(t, hardware, *env, sealed)
	code, _, stderr = runGenome("open", "--bundle", hardware, "--allow-v2", "--target", filepath.Join(work, "x"))
	require.Equal(t, 4, code)
	require.Contains(t, stderr, `provider "gcp-sev-snp" not supported by this build`)

	code, stdout, _ = runGenome("inspect", "--bundle", hardware, "--json")
	require.Equal(t, 0, code)
	var info map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &info))
	require.Equal(t, "gcp-sev-snp", info["tee_provider"])
	require.Equal(t, hex.EncodeToString(env.Measurement), info["measurement"])
}
