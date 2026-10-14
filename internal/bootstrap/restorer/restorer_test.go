// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/crosscloud"
	"github.com/vault-genome/vaultgenome-core/internal/contentdir"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/genome/tree"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

var adapter = map[string]string{
	"adapter_config.json":       `{"r":16,"lora_alpha":32}`,
	"adapter_model.safetensors": strings.Repeat("lora-delta", 3000),
	"tokenizer/special.json":    `{"eos":"</s>"}`,
}

type fixture struct {
	t        *testing.T
	bundles  string
	restores string
	keys     *keys.InMemoryStore
	tee      *tee.Simulated
	r        *Restorer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	dest, err := tee.NewSimulated([]byte("acp-bootstrap-destination-v1"), bytes.Repeat([]byte{3}, 32))
	require.NoError(t, err)
	f := &fixture{
		t:        t,
		bundles:  filepath.Join(root, "bundles"),
		restores: filepath.Join(root, "restored"),
		keys:     keys.NewInMemoryStore(shared_time.NewSystemClock()),
		tee:      dest,
	}
	f.r = f.open()
	return f
}

func (f *fixture) open() *Restorer {
	f.t.Helper()
	r, err := New(Config{
		BundleDir: f.bundles, RestoreDir: f.restores,
		Keys: f.keys, Erase: f.keys.EraseSealing, TEE: f.tee, Kind: tee.ProviderSimulated,
		Rescan: 20 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(f.t, err)
	return r
}

// seal seals a tree the way acpctl does; it returns the bundle bytes, the
// key and the key ID.
func (f *fixture) seal(files map[string]string) ([]byte, []byte, string) {
	f.t.Helper()
	src := f.t.TempDir()
	writeTree(f.t, src, files)
	snap, payload, err := contentdir.CapturePayload(src)
	require.NoError(f.t, err)
	raw, err := json.Marshal(snap)
	require.NoError(f.t, err)
	blob, dek, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentDir, ContentRef: src, ContentSnapshot: raw}, payload)
	require.NoError(f.t, err)
	br, err := bundle.NewReader(bytes.NewReader(blob))
	require.NoError(f.t, err)
	return blob, dek, br.Header.KeyID
}

// release is what the Receiver does when a token arrives: register the
// key, then report the delivery.
func (f *fixture) release(kid string, dek []byte, decision string) {
	f.t.Helper()
	require.NoError(f.t, f.keys.RegisterSealing(ids.KeyID(kid), dek))
	f.deliver(kid, decision)
}

// deliver reports a delivery of a key the keystore already holds (the
// same key released again).
func (f *fixture) deliver(kid, decision string) {
	f.r.Delivered(crosscloud.Delivery{
		DecisionID: ids.DecisionID(decision), RequestID: ids.RequestID("req-" + decision),
		TokenID: ids.DecisionID("tok-" + decision), KeyIDs: []ids.KeyID{ids.KeyID(kid)}, At: time.Now().UTC(),
	})
}

func (f *fixture) record(kid string) Record {
	f.t.Helper()
	for _, rec := range f.r.Records() {
		if rec.KeyID == kid {
			return rec
		}
	}
	f.t.Fatalf("no record for %s", kid)
	return Record{}
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}
}

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = string(data)
		return err
	}))
	return out
}

// A released key brings its genome up: restored byte for byte, and a
// receipt the source can verify against this TEE.
func TestRestorer_RestoresAReleasedGenomeAndSignsIt(t *testing.T) {
	f := newFixture(t)
	blob, dek, kid := f.seal(adapter)
	require.NoError(t, os.MkdirAll(f.bundles, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "gen-1.genome"), blob, 0o644))

	f.release(kid, dek, "drill-1")
	require.Equal(t, StateWaiting, f.record(kid).State)
	f.r.work(context.Background())

	rec := f.record(kid)
	require.Equal(t, StateRestored, rec.State, rec.Error)
	require.Equal(t, adapter, readTree(t, filepath.Join(f.restores, kid)))
	require.Equal(t, hex.EncodeToString(sha(blob)), rec.BundleSHA256)
	require.Equal(t, 3, rec.Result.Files)

	signed, _, ok := f.r.Receipt(kid)
	require.True(t, ok)
	rc, m, err := receipt.Verify(signed, tee.NewSimulatedVerifier(f.tee.PublicKey(), f.tee.Measurement()))
	require.NoError(t, err)
	require.Equal(t, f.tee.Measurement(), m)
	require.Equal(t, kid, rc.KeyID)
	require.Equal(t, "drill-1", rc.DecisionID)
	require.Equal(t, "req-drill-1", rc.RequestID)
	require.Equal(t, "tok-drill-1", rc.TokenID)
	require.Equal(t, rec.BundleSHA256, rc.BundleSHA256)
	require.Equal(t, rec.Result.TreeSHA256, rc.TreeSHA256)

	// The source can predict the tree digest from the bundle it holds.
	br, err := bundle.NewReader(bytes.NewReader(blob))
	require.NoError(t, err)
	files, err := tree.Files(br.Header)
	require.NoError(t, err)
	require.Equal(t, tree.Digest(files), rc.TreeSHA256)

	// Its key did its one job and is gone from the keystore.
	_, err = f.keys.Open(ids.KeyID(kid), make([]byte, 12), make([]byte, 16), nil)
	require.ErrorContains(t, err, "unknown sealing kid")

	// Delivered again (a retried release), a finished restore stays done.
	f.deliver(kid, "drill-2")
	require.Equal(t, "drill-1", f.record(kid).DecisionID)

	// A restarted daemon still serves the receipt.
	again := f.open()
	s2, rec2, ok := again.Receipt(kid)
	require.True(t, ok)
	require.Equal(t, signed, s2)
	require.Equal(t, StateRestored, rec2.State)
}

func sha(b []byte) []byte {
	d := bundle.PayloadDigest(b)
	out, _ := hex.DecodeString(strings.TrimPrefix(d, "sha256:"))
	return out
}

// A key can arrive before its bundle: the restore waits, and starts when
// the bundle lands.
func TestRestorer_WaitsForALateBundle(t *testing.T) {
	f := newFixture(t)
	blob, dek, kid := f.seal(adapter)
	f.release(kid, dek, "late")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	time.Sleep(60 * time.Millisecond)
	require.Equal(t, StateWaiting, f.record(kid).State)
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "not-a-bundle.genome"), []byte("hello"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "late.genome"), blob, 0o644))
	require.Eventually(t, func() bool { return f.record(kid).State == StateRestored }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, adapter, readTree(t, filepath.Join(f.restores, kid)))
}

// Only genome keys are the Restorer's; other released keys are not.
func TestRestorer_IgnoresKeysThatNameNoGenome(t *testing.T) {
	f := newFixture(t)
	f.r.Delivered(crosscloud.Delivery{DecisionID: "d", KeyIDs: []ids.KeyID{"genome-dek-1", "vault-sealing"}})
	require.Empty(t, f.r.Records())
}

// A bundle that does not open under the released key fails its restore,
// leaves nothing behind, and signs nothing; a new release retries it.
func TestRestorer_FailsClosed(t *testing.T) {
	f := newFixture(t)
	blob, dek, kid := f.seal(adapter)
	corrupt := append([]byte(nil), blob...)
	corrupt[len(corrupt)-3] ^= 0x01
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), corrupt, 0o644))

	f.release(kid, dek, "bad")
	f.r.work(context.Background())
	rec := f.record(kid)
	require.Equal(t, StateFailed, rec.State)
	require.Contains(t, rec.Error, "does not open")
	_, err := os.Stat(filepath.Join(f.restores, kid))
	require.True(t, os.IsNotExist(err), "no partial tree")
	signed, _, ok := f.r.Receipt(kid)
	require.True(t, ok)
	require.Nil(t, signed.Receipt, "no receipt for a failed restore")
	// Asked for its receipt, the destination says the restore failed — a
	// final answer, so a confirming source stops waiting.
	rr := httptest.NewRecorder()
	f.r.Routes("")["/v1/genome/receipt"](rr, httptest.NewRequest(http.MethodGet, "/v1/genome/receipt?key_id="+kid, nil))
	require.Equal(t, http.StatusUnprocessableEntity, rr.Code)
	require.Contains(t, rr.Body.String(), "restore failed")

	// The operator replaces the bundle and the source releases again.
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
	f.deliver(kid, "retry")
	f.r.work(context.Background())
	require.Equal(t, StateRestored, f.record(kid).State)
	require.Equal(t, "retry", f.record(kid).DecisionID)
}

func TestRestorer_HTTP(t *testing.T) {
	f := newFixture(t)
	blob, dek, kid := f.seal(adapter)
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
	token := strings.Repeat("t", 32)
	mux := http.NewServeMux()
	for p, h := range f.r.Routes(token) {
		mux.HandleFunc(p, h)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	get := func(path, bearer string) (int, []byte) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, body
	}

	code, _ := get("/v1/genome/restores", "")
	require.Equal(t, http.StatusUnauthorized, code)
	code, _ = get("/v1/genome/restores", "wrong-token-wrong-token-wrong-tok")
	require.Equal(t, http.StatusUnauthorized, code)
	code, _ = get("/v1/genome/receipt", token)
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = get("/v1/genome/receipt?key_id="+kid, token)
	require.Equal(t, http.StatusNotFound, code)

	f.release(kid, dek, "http")
	code, body := get("/v1/genome/receipt?key_id="+kid, token)
	require.Equal(t, http.StatusConflict, code)
	require.Contains(t, string(body), string(StateWaiting))

	f.r.work(context.Background())
	code, body = get("/v1/genome/receipt?key_id="+kid, token)
	require.Equal(t, http.StatusOK, code)
	var signed receipt.Signed
	require.NoError(t, json.Unmarshal(body, &signed))
	_, _, err := receipt.Verify(signed, tee.NewSimulatedVerifier(f.tee.PublicKey(), f.tee.Measurement()))
	require.NoError(t, err)

	code, body = get("/v1/genome/restores", token)
	require.Equal(t, http.StatusOK, code)
	var list struct {
		Restores []Record `json:"restores"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	require.Len(t, list.Restores, 1)
	require.Equal(t, StateRestored, list.Restores[0].State)

	resp, err := http.Post(srv.URL+"/v1/genome/restores", "application/json", nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestNew_RefusesAnIncompleteConfig(t *testing.T) {
	dir := t.TempDir()
	dest, err := tee.NewSimulated([]byte("w"), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	store := keys.NewInMemoryStore(shared_time.NewSystemClock())
	for name, cfg := range map[string]Config{
		"no dirs": {Keys: store, TEE: dest, Kind: tee.ProviderSimulated},
		"no keys": {BundleDir: dir, RestoreDir: dir, TEE: dest, Kind: tee.ProviderSimulated},
		"no tee":  {BundleDir: dir, RestoreDir: dir, Keys: store, Kind: tee.ProviderSimulated},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(cfg)
			require.Error(t, err)
		})
	}

	restores := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(restores, "genome-x.receipt.json"), []byte("{"), 0o644))
	_, err = New(Config{BundleDir: dir, RestoreDir: restores, Keys: store, TEE: dest, Kind: tee.ProviderSimulated})
	require.Error(t, err, "a receipt it cannot read stops startup rather than being forgotten")
}
