// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contentdir"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func runGenome(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := genomeCmd(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// adapterDir writes the kind of tree a fine-tune leaves behind: a LoRA
// adapter, its config, a nested tokenizer file. salt makes each one
// distinct.
func adapterDir(t *testing.T, salt string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, data := range map[string][]byte{
		"adapter_config.json":       []byte(`{"r":16,"lora_alpha":32,"salt":"` + salt + `"}`),
		"adapter_model.safetensors": bytes.Repeat([]byte("lora-delta-"+salt+"-"), 4096),
		"tokenizer/special.json":    []byte(`{"eos":"</s>"}`),
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, data, 0o644))
	}
	return dir
}

// requireSameTree fails unless got holds exactly want's regular files,
// byte for byte.
func requireSameTree(t *testing.T, want, got string) {
	t.Helper()
	files := func(root string) map[string][]byte {
		out := map[string][]byte{}
		require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(p)
			out[filepath.ToSlash(rel)] = data
			return err
		}))
		return out
	}
	require.Equal(t, files(want), files(got))
}

func sealDir(t *testing.T, content, out, key string, extra ...string) sealResult {
	t.Helper()
	args := append([]string{"seal", "--content-dir", content, "--output", out, "--key-out", key, "--json"}, extra...)
	code, stdout, stderr := runGenome(args...)
	require.Equal(t, 0, code, stderr)
	var r sealResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &r))
	return r
}

func verifyJSON(t *testing.T, wantCode int, args ...string) verifyResult {
	t.Helper()
	code, stdout, stderr := runGenome(append([]string{"verify", "--json"}, args...)...)
	require.Equal(t, wantCode, code, stderr)
	var r verifyResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &r))
	return r
}

// A sealed genome is useless without its key file: nothing in the bundle
// opens it, another key does not open it, and its own key restores the
// tree byte for byte.
func TestGenome_OpensOnlyWithItsKey(t *testing.T) {
	content, work := adapterDir(t, "a"), t.TempDir()
	b, k := filepath.Join(work, "gen-0.genome"), filepath.Join(work, "gen-0.key")
	r := sealDir(t, content, b, k)
	require.True(t, r.OK)
	require.Equal(t, uint64(0), r.Generation)
	require.Equal(t, 3, r.ComponentCount)
	require.Regexp(t, `^genome-[0-9a-f]{12}-g0-[0-9a-f]{12}$`, r.KeyID)

	key, err := os.ReadFile(k)
	require.NoError(t, err)
	require.Len(t, key, 32)
	info, err := os.Stat(k)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the key file is private")
	blob, err := os.ReadFile(b)
	require.NoError(t, err)
	require.True(t, bundle.IsV3(blob))
	require.False(t, bytes.Contains(blob, key), "the key is not in the bundle")
	require.False(t, bytes.Contains(blob, []byte("lora-delta-a-lora-delta-a")), "the weights are not in the clear")

	code, _, stderr := runGenome("open", "--bundle", b, "--target", filepath.Join(work, "nokey"))
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "--key-file")
	require.Contains(t, stderr, r.KeyID)

	other := filepath.Join(work, "other.key")
	require.NoError(t, os.WriteFile(other, bytes.Repeat([]byte{9}, 32), 0o600))
	code, _, stderr = runGenome("open", "--bundle", b, "--key-file", other, "--target", filepath.Join(work, "wrong"))
	require.Equal(t, 4, code, "another key does not open it")
	require.Contains(t, stderr, "this key is not")
	_, err = os.Stat(filepath.Join(work, "wrong"))
	require.True(t, os.IsNotExist(err), "nothing is written when the key is wrong")

	target := filepath.Join(work, "restored")
	code, stdout, stderr := runGenome("rewind", "--bundle", b, "--key-file", k, "--target", target)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "✓ unsealed dir")
	require.Contains(t, stdout, r.KeyID)
	requireSameTree(t, content, target)

	v := verifyJSON(t, 0, "--bundle", b, "--key-file", k, "--restored", target)
	require.True(t, v.OK)
	require.True(t, v.Authenticated)
	require.Equal(t, bundle.Format, v.EnvelopeFormat)
	require.Contains(t, v.RestoredVerify, "ok")

	v = verifyJSON(t, 0, "--bundle", b)
	require.False(t, v.Authenticated, "without the key the header is only well-formed")

	code, _, _ = runGenome("verify", "--bundle", b, "--key-file", other)
	require.Equal(t, 4, code)

	code, stdout, _ = runGenome("verify", "--bundle", b, "--key-file", k)
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "authenticated: yes")

	require.NoError(t, os.WriteFile(filepath.Join(target, "adapter_config.json"), []byte(`{"r":1}`), 0o644))
	v = verifyJSON(t, 5, "--bundle", b, "--restored", target)
	require.False(t, v.OK)
	require.Contains(t, v.RestoredVerify, "digest mismatch")
}

// Editing any byte of a bundle — header or ciphertext — makes it refuse
// to open, even with the right key.
func TestGenome_RefusesAnEditedBundle(t *testing.T) {
	content, work := adapterDir(t, "e"), t.TempDir()
	b, k := filepath.Join(work, "g.genome"), filepath.Join(work, "g.key")
	sealDir(t, content, b, k)
	blob, err := os.ReadFile(b)
	require.NoError(t, err)

	for name, edit := range map[string]func([]byte) []byte{
		"header": func(in []byte) []byte {
			return bytes.Replace(in, []byte(`"content_kind":"dir"`), []byte(`"content_kind":"dir" `), 1)
		},
		"ciphertext": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			out[len(out)-7] ^= 0x80
			return out
		},
	} {
		t.Run(name, func(t *testing.T) {
			edited := filepath.Join(t.TempDir(), "edited.genome")
			changed := edit(blob)
			require.NotEqual(t, blob, changed)
			if name == "header" {
				// Keep the length prefix honest so the header still parses.
				n := binary.BigEndian.Uint32(changed[len(bundle.Magic):])
				binary.BigEndian.PutUint32(changed[len(bundle.Magic):], n+1)
			}
			require.NoError(t, os.WriteFile(edited, changed, 0o644))
			code, _, stderr := runGenome("open", "--bundle", edited, "--key-file", k, "--target", filepath.Join(t.TempDir(), "out"))
			require.Equal(t, 4, code, stderr)
		})
	}
}

// Sealing never overwrites a bundle or a key file unless told to — a
// lost key is a lost genome.
func TestGenome_SealNeverOverwrites(t *testing.T) {
	content, work := adapterDir(t, "o"), t.TempDir()
	b, k := filepath.Join(work, "g.genome"), filepath.Join(work, "g.key")
	code, stdout, stderr := runGenome("seal", "--content-dir", content, "--output", b, "--key-out", k)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "key file:")
	first, err := os.ReadFile(k)
	require.NoError(t, err)

	code, _, stderr = runGenome("seal", "--content-dir", content, "--output", b, "--key-out", k)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "refusing to overwrite")

	require.NoError(t, os.Remove(b))
	code, _, stderr = runGenome("seal", "--content-dir", content, "--output", b, "--key-out", k)
	require.Equal(t, 2, code, "an existing key file alone stops the seal")
	require.Contains(t, stderr, k)
	kept, err := os.ReadFile(k)
	require.NoError(t, err)
	require.Equal(t, first, kept)

	sealDir(t, content, b, k, "--force")
	second, err := os.ReadFile(k)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "every seal draws a fresh key")
	old := filepath.Join(work, "old.key")
	require.NoError(t, os.WriteFile(old, first, 0o600))
	code, _, _ = runGenome("open", "--bundle", b, "--key-file", old, "--target", filepath.Join(work, "x"))
	require.Equal(t, 4, code, "the previous key does not open the new seal")
}

// Generations link into a chain of custody that chain and lineage walk
// and check, and each generation has its own key.
func TestGenome_ChainOfCustody(t *testing.T) {
	gens, keysDir := t.TempDir(), t.TempDir()
	bundleAt := func(g int) string { return filepath.Join(gens, "gen-"+string(rune('0'+g))+".genome") }
	keyAt := func(g int) string { return filepath.Join(keysDir, "gen-"+string(rune('0'+g))+".key") }

	r0 := sealDir(t, adapterDir(t, "0"), bundleAt(0), keyAt(0))
	r1 := sealDir(t, adapterDir(t, "1"), bundleAt(1), keyAt(1), "--parent", bundleAt(0))
	r2 := sealDir(t, adapterDir(t, "2"), bundleAt(2), keyAt(2), "--parent", bundleAt(1))
	require.Equal(t, []uint64{0, 1, 2}, []uint64{r0.Generation, r1.Generation, r2.Generation})
	gen0, err := os.ReadFile(bundleAt(0))
	require.NoError(t, err)
	require.Equal(t, sha256Hex(gen0), r1.ParentBundleSHA256)
	require.Contains(t, r2.KeyID, "-g2-")

	code, stdout, stderr := runGenome("inspect", "--bundle", bundleAt(2), "--json")
	require.Equal(t, 0, code, stderr)
	var info map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &info))
	require.Equal(t, bundle.Format, info["format"])
	require.Equal(t, r2.KeyID, info["key_id"])
	require.EqualValues(t, 1, info["parent_generation"])
	require.Equal(t, strings.TrimPrefix(r1.PayloadSHA256, "sha256:"), info["parent_payload_sha256"])

	code, stdout, _ = runGenome("inspect", "--bundle", bundleAt(1))
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "key id:           "+r1.KeyID)
	require.Contains(t, stdout, "adapter_model.safetensors")

	code, stdout, stderr = runGenome("chain", "--dir", gens)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "3 generation(s)")
	require.Contains(t, stdout, "✓ chain valid")

	code, stdout, _ = runGenome("chain", "--dir", gens, "--json")
	require.Equal(t, 0, code)
	var chainOut struct {
		OK        bool        `json:"ok"`
		NodeCount int         `json:"node_count"`
		Chain     []chainNode `json:"chain"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &chainOut))
	require.True(t, chainOut.OK)
	require.Equal(t, 3, chainOut.NodeCount)
	require.Equal(t, r1.KeyID, chainOut.Chain[1].KeyID)

	code, stdout, stderr = runGenome("lineage", "--bundle", bundleAt(2), "--dir", gens, "--json")
	require.Equal(t, 0, code, stderr)
	var lin struct {
		Depth     int         `json:"depth"`
		Ancestors []chainNode `json:"ancestors"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &lin))
	require.Equal(t, 3, lin.Depth)
	require.Equal(t, uint64(0), lin.Ancestors[2].Generation)

	code, stdout, _ = runGenome("lineage", "--bundle", bundleAt(2), "--dir", gens)
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "depth 3")

	code, _, _ = runGenome("open", "--bundle", bundleAt(1), "--key-file", keyAt(0), "--target", filepath.Join(t.TempDir(), "x"))
	require.Equal(t, 4, code, "a generation does not open with its parent's key")

	require.NoError(t, os.Remove(bundleAt(1)))
	code, stdout, _ = runGenome("chain", "--dir", gens)
	require.Equal(t, 5, code)
	require.Contains(t, stdout, "not found in dir")
	code, _, stderr = runGenome("lineage", "--bundle", bundleAt(2), "--dir", gens)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "not found")
}

// A bundle that names a real parent but lies about the generation or the
// parent's payload is a broken link.
func TestGenome_ChainRefusesForgedLinks(t *testing.T) {
	gens := t.TempDir()
	parent := filepath.Join(gens, "gen-0.genome")
	r0 := sealDir(t, adapterDir(t, "p"), parent, filepath.Join(t.TempDir(), "k"))
	parentBlob, err := os.ReadFile(parent)
	require.NoError(t, err)

	forge := func(name string, h bundle.Header) string {
		h.ContentKind, h.ContentRef = bundle.ContentDir, "/forged"
		h.ContentSnapshot = json.RawMessage(`{"components":[]}`)
		h.ParentBundleSHA256 = sha256Hex(parentBlob)
		blob, _, err := bundle.SealBytes(h, []byte("forged payload"))
		require.NoError(t, err)
		p := filepath.Join(gens, name)
		require.NoError(t, os.WriteFile(p, blob, 0o644))
		return p
	}

	skip := forge("gen-5.genome", bundle.Header{Generation: 5, ParentGeneration: 0,
		ParentPayloadSHA256: strings.TrimPrefix(r0.PayloadSHA256, "sha256:")})
	code, stdout, _ := runGenome("chain", "--dir", gens)
	require.Equal(t, 5, code)
	require.Contains(t, stdout, "does not follow parent generation 0")
	code, _, stderr := runGenome("lineage", "--bundle", skip, "--dir", gens)
	require.Equal(t, 5, code)
	require.Contains(t, stderr, "does not follow")
	require.NoError(t, os.Remove(skip))

	forge("gen-1.genome", bundle.Header{Generation: 1, ParentGeneration: 0,
		ParentPayloadSHA256: strings.Repeat("0", 64)})
	code, stdout, _ = runGenome("chain", "--dir", gens, "--json")
	require.Equal(t, 5, code)
	require.Contains(t, stdout, "parent payload differs")
}

// A snapshot is read from a bundle, so verify refuses component paths
// that leave the restored tree instead of reading them.
func TestGenome_VerifyStaysInsideTheRestoredTree(t *testing.T) {
	restored := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("outside"), 0o600))
	rel, err := filepath.Rel(restored, secret)
	require.NoError(t, err)

	snap, err := json.Marshal(contentdir.Snapshot{Components: []contentdir.Component{{Path: filepath.ToSlash(rel), Digest: "sha256:00", Size: 7}}})
	require.NoError(t, err)
	blob, _, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentDir, ContentRef: "/x", ContentSnapshot: snap}, []byte("p"))
	require.NoError(t, err)
	b := filepath.Join(t.TempDir(), "crafted.genome")
	require.NoError(t, os.WriteFile(b, blob, 0o644))
	v := verifyJSON(t, 5, "--bundle", b, "--restored", restored)
	require.Contains(t, v.RestoredVerify, "not inside the restored directory")
}

// sealV2 writes a bundle the way builds before v3 did: the simulated-TEE
// seed that seals the payload travels inside the envelope.
func sealV2(t *testing.T, content, out string) {
	t.Helper()
	snap, payload, err := contentdir.CapturePayload(content)
	require.NoError(t, err)
	snapJSON, err := json.Marshal(snap)
	require.NoError(t, err)
	wd := sha256.Sum256([]byte("vault-genome.v2\ndir\n" + content + "\n" + snap.PayloadSHA256))
	seed := bytes.Repeat([]byte{0x42}, 32)
	sealer, err := tee.NewSimulated(wd[:], seed)
	require.NoError(t, err)
	aad := []byte(snap.PayloadSHA256)
	sealed, err := sealer.Seal(payload, aad)
	require.NoError(t, err)
	m := sealer.Measurement()
	meta, err := json.Marshal(GenomeEnvelope{
		Format:                      envelopeFormatV2,
		TEEProvider:                 string(tee.ProviderSimulated),
		SealedAt:                    time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC).UnixNano(),
		ContentKind:                 ContentKindDir,
		ContentRef:                  content,
		ContentSnapshot:             snapJSON,
		Measurement:                 m[:],
		AAD:                         aad,
		SimulatedWorkloadDescriptor: wd[:],
		SimulatedSeed:               seed,
	})
	require.NoError(t, err)
	var buf bytes.Buffer
	buf.WriteString(genomeMagic)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(meta)))
	buf.Write(n[:])
	buf.Write(meta)
	buf.Write(sealed)
	require.NoError(t, os.WriteFile(out, buf.Bytes(), 0o644))
}

// A v2 bundle can still be read, opened on explicit request and resealed
// as v3; nothing writes v2 any more.
func TestGenome_V2IsReadOnly(t *testing.T) {
	content, gens := adapterDir(t, "legacy"), t.TempDir()
	v2 := filepath.Join(gens, "gen-0.genome")
	sealV2(t, content, v2)

	code, stdout, stderr := runGenome("inspect", "--bundle", v2, "--json")
	require.Equal(t, 0, code, stderr)
	var info map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &info))
	require.Equal(t, envelopeFormatV2, info["format"])
	require.Equal(t, true, info["key_in_bundle"])
	code, stdout, _ = runGenome("inspect", "--bundle", v2)
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "stored in the bundle (v2)")

	target := filepath.Join(t.TempDir(), "restored")
	code, _, stderr = runGenome("open", "--bundle", v2, "--target", target)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "stores its own sealing key")
	code, _, stderr = runGenome("open", "--bundle", v2, "--allow-v2", "--target", target, "--json")
	require.Equal(t, 0, code, stderr)
	requireSameTree(t, content, target)

	code, _, stderr = runGenome("verify", "--bundle", v2, "--key-file", v2)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "cannot be authenticated")
	v := verifyJSON(t, 0, "--bundle", v2, "--restored", target)
	require.Equal(t, envelopeFormatV2, v.EnvelopeFormat)
	require.False(t, v.Authenticated)

	// Reseal the restored tree as v3, continuing the v2 chain.
	r1 := sealDir(t, target, filepath.Join(gens, "gen-1.genome"), filepath.Join(t.TempDir(), "gen-1.key"), "--parent", v2)
	require.Equal(t, uint64(1), r1.Generation)
	code, stdout, stderr = runGenome("chain", "--dir", gens)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "(vault-genome-v2)")
	require.Contains(t, stdout, "(vault-genome-v3)")

	blob, err := os.ReadFile(v2)
	require.NoError(t, err)
	blob[len(blob)-3] ^= 0x01
	edited := filepath.Join(t.TempDir(), "edited.genome")
	require.NoError(t, os.WriteFile(edited, blob, 0o644))
	code, _, _ = runGenome("open", "--bundle", edited, "--allow-v2", "--target", filepath.Join(t.TempDir(), "x"))
	require.Equal(t, 4, code)
}

// fakeOllamaHome lays out an Ollama store holding one model.
func fakeOllamaHome(t *testing.T, ref string) string {
	t.Helper()
	home := t.TempDir()
	blobs := filepath.Join(home, "models", "blobs")
	require.NoError(t, os.MkdirAll(blobs, 0o755))
	layer := func(data []byte, mediaType string) map[string]any {
		d := sha256Hex(data)
		require.NoError(t, os.WriteFile(filepath.Join(blobs, "sha256-"+d), data, 0o644))
		return map[string]any{"mediaType": mediaType, "digest": "sha256:" + d, "size": len(data)}
	}
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.docker.distribution.manifest.v2+json",
		"config":        layer([]byte(`{"model_family":"llama"}`), "application/vnd.docker.container.image.v1+json"),
		"layers": []any{
			layer(bytes.Repeat([]byte("GGUF-weights-"), 8192), "application/vnd.ollama.image.model"),
			layer([]byte("{{ .Prompt }}"), "application/vnd.ollama.image.template"),
		},
	})
	require.NoError(t, err)
	name, tag, _ := strings.Cut(ref, ":")
	mp := filepath.Join(home, "models", "manifests", "registry.ollama.ai", "library", name, tag)
	require.NoError(t, os.MkdirAll(filepath.Dir(mp), 0o755))
	require.NoError(t, os.WriteFile(mp, manifest, 0o644))
	return home
}

// A whole Ollama model seals, opens with its key into a fresh store, and
// verifies blob by blob.
func TestGenome_OllamaModelRoundTrip(t *testing.T) {
	home, work := fakeOllamaHome(t, "llama3.2:3b"), t.TempDir()
	b, k := filepath.Join(work, "m.genome"), filepath.Join(work, "m.key")
	code, stdout, stderr := runGenome("seal", "--model", "llama3.2:3b", "--ollama-home", home, "--output", b, "--key-out", k, "--json")
	require.Equal(t, 0, code, stderr)
	var r sealResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &r))
	require.Equal(t, string(ContentKindOllama), r.ContentKind)
	require.Equal(t, 4, r.ComponentCount)

	target := filepath.Join(work, "ollama")
	code, _, stderr = runGenome("open", "--bundle", b, "--key-file", k, "--target", target)
	require.Equal(t, 0, code, stderr)
	requireSameTree(t, filepath.Join(home, "models"), filepath.Join(target, "models"))
	v := verifyJSON(t, 0, "--bundle", b, "--key-file", k, "--restored", target)
	require.True(t, v.Authenticated)
	require.Contains(t, v.RestoredVerify, "every file matches its recorded digest")
	require.Len(t, v.TreeSHA256, 64)

	code, _, _ = runGenome("seal", "--model", "absent:1b", "--ollama-home", home, "--output", filepath.Join(work, "n.genome"), "--key-out", filepath.Join(work, "n.key"))
	require.Equal(t, 1, code)
	_, err := os.Stat(filepath.Join(work, "n.key"))
	require.True(t, os.IsNotExist(err), "no key is written for a seal that failed")
}

func TestGenome_UsageErrors(t *testing.T) {
	work := t.TempDir()
	content := adapterDir(t, "u")
	b, k := filepath.Join(work, "g.genome"), filepath.Join(work, "g.key")
	sealDir(t, content, b, k)
	notBundle := filepath.Join(work, "not.genome")
	require.NoError(t, os.WriteFile(notBundle, []byte("hello, world"), 0o644))

	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"no subcommand":       {nil, 2},
		"unknown subcommand":  {[]string{"clone"}, 2},
		"help":                {[]string{"help"}, 0},
		"seal needs output":   {[]string{"seal", "--content-dir", content}, 2},
		"seal needs key-out":  {[]string{"seal", "--content-dir", content, "--output", filepath.Join(work, "a")}, 2},
		"seal needs a source": {[]string{"seal", "--output", filepath.Join(work, "a"), "--key-out", filepath.Join(work, "ak")}, 2},
		"seal one source":     {[]string{"seal", "--model", "m", "--content-dir", content, "--output", filepath.Join(work, "a"), "--key-out", filepath.Join(work, "ak")}, 2},
		"seal bad flag":       {[]string{"seal", "--nope"}, 2},
		"seal missing dir":    {[]string{"seal", "--content-dir", filepath.Join(work, "absent"), "--output", filepath.Join(work, "a"), "--key-out", filepath.Join(work, "ak")}, 1},
		"seal bad parent":     {[]string{"seal", "--content-dir", content, "--parent", notBundle, "--output", filepath.Join(work, "a"), "--key-out", filepath.Join(work, "ak")}, 1},
		"open needs target":   {[]string{"open", "--bundle", b}, 2},
		"open bad flag":       {[]string{"open", "--nope"}, 2},
		"open not a bundle":   {[]string{"open", "--bundle", notBundle, "--target", filepath.Join(work, "t")}, 1},
		"open missing key":    {[]string{"open", "--bundle", b, "--key-file", filepath.Join(work, "absent.key"), "--target", filepath.Join(work, "t")}, 1},
		"verify needs bundle": {[]string{"verify"}, 2},
		"verify bad flag":     {[]string{"verify", "--nope"}, 2},
		"verify missing file": {[]string{"verify", "--bundle", filepath.Join(work, "absent")}, 1},
		"verify missing key":  {[]string{"verify", "--bundle", b, "--key-file", filepath.Join(work, "absent.key")}, 1},
		"inspect needs path":  {[]string{"inspect"}, 2},
		"inspect bad flag":    {[]string{"inspect", "--nope"}, 2},
		"inspect not bundle":  {[]string{"inspect", "--bundle", notBundle}, 1},
		"chain bad flag":      {[]string{"chain", "--nope"}, 2},
		"chain missing dir":   {[]string{"chain", "--dir", filepath.Join(work, "absent")}, 1},
		"chain empty dir":     {[]string{"chain", "--dir", t.TempDir()}, 1},
		"chain bad bundle":    {[]string{"chain", "--dir", work}, 1},
		"lineage needs dir":   {[]string{"lineage", "--bundle", b}, 2},
		"lineage bad flag":    {[]string{"lineage", "--nope"}, 2},
		"lineage missing dir": {[]string{"lineage", "--bundle", b, "--dir", filepath.Join(work, "absent")}, 1},
		"lineage bad start":   {[]string{"lineage", "--bundle", filepath.Join(work, "absent"), "--dir", t.TempDir()}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, _ := runGenome(tc.args...)
			require.Equal(t, tc.code, code)
		})
	}
}

// With --escrow-to the sealing machine keeps nothing that opens the
// bundle: the key exists only encapsulated to the release authority.
func TestGenome_SealToEscrow(t *testing.T) {
	work := t.TempDir()
	priv, pub := filepath.Join(work, "escrow.key"), filepath.Join(work, "escrow.pem")
	var out, errOut bytes.Buffer
	require.Equal(t, 0, escrowCmd([]string{"keygen", "--out", priv, "--pub", pub}, &out, &errOut), errOut.String())
	info, err := os.Stat(priv)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.Equal(t, 1, escrowCmd([]string{"keygen", "--out", priv, "--pub", pub}, &out, &errOut), "never overwritten")

	content := adapterDir(t, "escrow")
	b := filepath.Join(work, "gen-1.genome")
	code, stdout, stderr := runGenome("seal", "--content-dir", content, "--output", b, "--escrow-to", pub, "--json")
	require.Equal(t, 0, code, stderr)
	var r sealResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &r))
	require.Equal(t, b+".escrow", r.EscrowFile)
	require.Empty(t, r.KeyFile)
	entries, err := os.ReadDir(work)
	require.NoError(t, err)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.ElementsMatch(t, []string{"escrow.key", "escrow.pem", "gen-1.genome", "gen-1.genome.escrow"}, names, "no key file")

	// The authority opens the envelope, and the key it holds opens the bundle.
	raw, err := os.ReadFile(r.EscrowFile)
	require.NoError(t, err)
	env, err := escrow.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, r.KeyID, env.KeyID)
	authority, err := escrow.ReadPrivate(priv)
	require.NoError(t, err)
	dek, err := escrow.Open(env, authority)
	require.NoError(t, err)
	k := filepath.Join(work, "released.key")
	require.NoError(t, os.WriteFile(k, dek, 0o600))
	code, _, stderr = runGenome("open", "--bundle", b, "--key-file", k, "--target", filepath.Join(work, "restored"))
	require.Equal(t, 0, code, stderr)
	requireSameTree(t, content, filepath.Join(work, "restored"))

	// Both custody forms at once, and the refusals.
	code, _, stderr = runGenome("seal", "--content-dir", content, "--output", filepath.Join(work, "g2.genome"),
		"--key-out", filepath.Join(work, "g2.key"), "--escrow-to", pub)
	require.Equal(t, 0, code, stderr)
	code, _, _ = runGenome("seal", "--content-dir", content, "--output", filepath.Join(work, "g3.genome"), "--escrow-to", filepath.Join(work, "absent.pem"))
	require.Equal(t, 2, code)
	code, _, _ = runGenome("seal", "--content-dir", content, "--output", filepath.Join(work, "g4.genome"), "--escrow-to", priv)
	require.Equal(t, 2, code, "a private key is not an escrow public key")
	code, _, stderr = runGenome("seal", "--content-dir", content, "--output", b, "--escrow-to", pub)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "refusing to overwrite")
	require.Equal(t, 2, escrowCmd(nil, &out, &errOut))
	require.Equal(t, 0, escrowCmd([]string{"help"}, &out, &errOut))
	require.Equal(t, 2, escrowCmd([]string{"keygen"}, &out, &errOut))
}
