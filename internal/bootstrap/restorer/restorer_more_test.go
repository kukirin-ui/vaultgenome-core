// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// --- construction --------------------------------------------------------

// A directory that cannot be created, or a restore directory whose name
// is not a valid glob pattern, stops New: the daemon must not come up
// unable to find bundles or serve receipts.
func TestNew_RefusesDirectoriesItCannotUse(t *testing.T) {
	dest, err := tee.NewSimulated([]byte("w"), []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	store := keys.NewInMemoryStore(shared_time.NewSystemClock())
	root := t.TempDir()
	file := filepath.Join(root, "a-file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	cases := []struct {
		name       string
		bundle     string
		restore    string
		wantSubstr string
	}{
		{"bundle dir under a regular file", filepath.Join(file, "bundles"), filepath.Join(root, "restores"), "not a directory"},
		{"restore dir is not a glob pattern", filepath.Join(root, "bundles"), filepath.Join(root, "bad["), "syntax error in pattern"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(Config{BundleDir: tc.bundle, RestoreDir: tc.restore, Keys: store, TEE: dest, Kind: tee.ProviderSimulated})
			require.Nil(t, r)
			require.Error(t, err)
			require.Contains(t, err.Error(), "restorer: ")
			require.Contains(t, err.Error(), tc.wantSubstr)
		})
	}
}

// --- the work loop --------------------------------------------------------

// With no key waiting, work does not even look at the bundle directory.
func TestWork_DoesNothingWhenNoKeyIsWaiting(t *testing.T) {
	f := newFixture(t)
	blob, _, _ := f.seal(adapter)
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
	f.r.work(context.Background())
	require.Empty(t, f.r.Records())
	require.Empty(t, f.r.index, "no scan without a waiting key")
}

// A context that is already over stops work before any restore starts,
// so a daemon shutting down does not begin a restore it cannot finish.
func TestWork_StopsWhenTheContextIsOver(t *testing.T) {
	f := newFixture(t)
	blob, dek, kid := f.seal(adapter)
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
	f.release(kid, dek, "shutdown")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.r.work(ctx)
	require.Equal(t, StateWaiting, f.record(kid).State)
	require.Contains(t, f.r.index, filepath.Join(f.bundles, "g.genome"), "the scan ran; the restore did not")
	_, err := os.Stat(filepath.Join(f.restores, kid))
	require.True(t, os.IsNotExist(err))

	f.r.work(context.Background())
	require.Equal(t, StateRestored, f.record(kid).State)
}

// A bundle directory whose name is not a valid glob pattern yields no
// bundles: the key keeps waiting and the failure is logged, not fatal.
func TestScan_SurvivesABundleDirectoryThatIsNotAPattern(t *testing.T) {
	f := newFixture(t)
	bad := filepath.Join(t.TempDir(), "bad[")
	r, err := New(Config{BundleDir: bad, RestoreDir: f.restores, Keys: f.keys, TEE: f.tee, Kind: tee.ProviderSimulated,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	require.NoError(t, err)
	f.r = r
	blob, dek, kid := f.seal(adapter)
	require.NoError(t, os.WriteFile(filepath.Join(bad, "g.genome"), blob, 0o644))
	f.release(kid, dek, "pattern")

	require.Nil(t, r.scan())
	r.work(context.Background())
	require.Equal(t, StateWaiting, f.record(kid).State)
}

// Only regular files are bundles: a directory with the bundle suffix is
// passed over without being indexed, and a bundle that cannot be opened
// is indexed as "not a bundle" so it is not read again until it changes.
func TestScan_SkipsWhatIsNotAReadableBundle(t *testing.T) {
	f := newFixture(t)
	blob, dek, kid := f.seal(adapter)
	dir := filepath.Join(f.bundles, "dir.genome")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	unreadable := filepath.Join(f.bundles, "unreadable.genome")
	require.NoError(t, os.WriteFile(unreadable, blob, 0o000))
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of their mode")
	}
	f.release(kid, dek, "skip")

	found := f.r.scan()
	require.Empty(t, found)
	require.NotContains(t, f.r.index, dir)
	require.Contains(t, f.r.index, unreadable)
	require.Empty(t, f.r.index[unreadable].kid)

	// Made readable, the file is a changed file and is read again.
	require.NoError(t, os.Chmod(unreadable, 0o644))
	later := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(unreadable, later, later))
	found = f.r.scan()
	require.Equal(t, unreadable, found[kid])
}

// --- restoreOne -----------------------------------------------------------

// Between the scan and the restore a bundle may vanish, be overwritten
// with something else, or be replaced by another genome's bundle. Each
// fails the restore with a reason; none signs anything.
func TestRestoreOne_FailsWhenTheBundleChangedSinceTheScan(t *testing.T) {
	f := newFixture(t)
	_, dek, kid := f.seal(adapter)
	other, _, otherKid := f.seal(map[string]string{"other.txt": "other genome"})
	require.NotEqual(t, kid, otherKid)
	garbage := filepath.Join(f.bundles, "garbage.genome")
	require.NoError(t, os.WriteFile(garbage, []byte("not a bundle at all"), 0o644))
	otherPath := filepath.Join(f.bundles, "other.genome")
	require.NoError(t, os.WriteFile(otherPath, other, 0o644))
	require.NoError(t, f.keys.RegisterSealing(ids.KeyID(kid), dek))

	cases := []struct {
		name string
		path string
		want string
	}{
		{"bundle vanished", filepath.Join(f.bundles, "gone.genome"), "no such file"},
		{"bundle overwritten with garbage", garbage, "bundle"},
		{"bundle now carries another key", otherPath, "now carries key " + otherKid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.deliver(kid, "changed-"+tc.name)
			f.r.restoreOne(kid, tc.path)
			rec := f.record(kid)
			require.Equal(t, StateFailed, rec.State)
			require.Contains(t, rec.Error, tc.want)
			require.Equal(t, tc.path, rec.Bundle)
			require.NotNil(t, rec.StartedAt)
			require.NotNil(t, rec.FinishedAt)
			signed, _, ok := f.r.Receipt(kid)
			require.True(t, ok)
			require.Nil(t, signed.Receipt)
			_, err := os.Stat(filepath.Join(f.restores, kid))
			require.True(t, os.IsNotExist(err), "nothing restored")
		})
	}
}

// --- sign -----------------------------------------------------------------

// quoteFailingTEE is a destination whose attestation device is down: it
// reports its measurement but cannot sign for anything.
type quoteFailingTEE struct{ inner *tee.Simulated }

var errNoQuote = errors.New("attestation device unavailable")

func (q quoteFailingTEE) Quote(tee.Nonce) (tee.Evidence, error) { return nil, errNoQuote }
func (q quoteFailingTEE) Measurement() tee.Measurement          { return q.inner.Measurement() }

// A restore the TEE cannot sign for is a failed restore: the tree is
// there, but without a receipt the source will never take it as done,
// and the key is kept so a later release can try again.
func TestSign_FailsWhenTheTEECannotQuote(t *testing.T) {
	f := newFixture(t)
	r, err := New(Config{BundleDir: f.bundles, RestoreDir: f.restores, Keys: f.keys, Erase: f.keys.EraseSealing,
		TEE: quoteFailingTEE{inner: f.tee}, Kind: tee.ProviderSimulated, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	require.NoError(t, err)
	f.r = r
	blob, dek, kid := f.seal(adapter)
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
	f.release(kid, dek, "no-quote")
	f.r.work(context.Background())

	rec := f.record(kid)
	require.Equal(t, StateFailed, rec.State)
	require.Contains(t, rec.Error, "receipt: quote")
	require.Contains(t, rec.Error, errNoQuote.Error())
	require.Equal(t, adapter, readTree(t, filepath.Join(f.restores, kid)), "the tree itself was restored")
	_, err = os.Stat(filepath.Join(f.restores, kid+receiptSuffix))
	require.True(t, os.IsNotExist(err), "no receipt")
	require.True(t, f.keys.EraseSealing(ids.KeyID(kid)), "the key was not erased")
}

// A receipt that cannot be kept on disk is not served either: a restore
// whose receipt would vanish at the next restart is reported as failed.
func TestSign_FailsWhenTheReceiptCannotBeKept(t *testing.T) {
	f := newFixture(t)
	blob, dek, kid := f.seal(adapter)
	require.NoError(t, os.WriteFile(filepath.Join(f.bundles, "g.genome"), blob, 0o644))
	// A directory squats on the receipt's path.
	require.NoError(t, os.MkdirAll(filepath.Join(f.restores, kid+receiptSuffix), 0o755))
	f.release(kid, dek, "no-save")
	f.r.work(context.Background())

	rec := f.record(kid)
	require.Equal(t, StateFailed, rec.State)
	require.Contains(t, rec.Error, "restorer: keep receipt")
	signed, _, ok := f.r.Receipt(kid)
	require.True(t, ok)
	require.Nil(t, signed.Receipt)
}

// --- the gate's own refusals -----------------------------------------------

// genomeFiles builds a model genome around fx; integer, when set, is
// genome.json's description of the integer door.
func genomeFiles(t *testing.T, fx []byte, integer map[string]any) map[string]string {
	t.Helper()
	sum := sha256.Sum256(fx)
	fixtures := map[string]any{"file": "fixtures.json", "sha256": "sha256:" + hex.EncodeToString(sum[:])}
	if integer != nil {
		fixtures["integer"] = integer
	}
	g, err := json.Marshal(map[string]any{
		"schema": "vault-genome/lora-genome/v1",
		"base": map[string]any{"name": "Qwen/Qwen2.5-0.5B-Instruct", "manifest": map[string]any{
			"files": map[string]string{"model.safetensors": "sha256:00"}, "digest": "sha256:base"}},
		"adapter":  map[string]any{"dir": "adapter", "weights_sha256": "sha256:cd"},
		"fixtures": fixtures,
	})
	require.NoError(t, err)
	return map[string]string{
		"genome.json":                       string(g),
		"fixtures.json":                     string(fx),
		"adapter/adapter_model.safetensors": "lora weights",
	}
}

// A genome whose model description cannot be read, whose fixtures do not
// match it, or whose integer references genome.json does not describe
// cannot be gated. With the gate required, each fails its restore with
// the reason; without, each is signed for without a verdict.
func TestGate_RefusesAGenomeItCannotRead(t *testing.T) {
	integerFx, err := json.Marshal(map[string]any{"schema": "vault-genome/lora-fixtures/v1", "fixtures": []map[string]any{
		{"id": "fx-000", "critical": true,
			"expected":         map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(1.5, -2)},
			"expected_integer": map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32b64(1.375, -2.125)}},
	}})
	require.NoError(t, err)

	malformed := modelGenome(t)
	malformed["genome.json"] = "{"
	tampered := modelGenome(t)
	tampered["fixtures.json"] += " "

	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"genome.json malformed", malformed, "lora: genome.json"},
		{"fixtures do not match", tampered, "fixtures do not match the genome"},
		{"undescribed integer references", genomeFiles(t, integerFx, nil), "integer references genome.json does not describe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, kid := restoreWith(t, &GateConfig{Command: []string{"true"}, Required: true}, tc.files)
			rec := f.record(kid)
			require.Equal(t, StateFailed, rec.State)
			require.Contains(t, rec.Error, tc.want)
			signed, _, _ := f.r.Receipt(kid)
			require.Nil(t, signed.Receipt)

			f, kid = restoreWith(t, &GateConfig{Command: []string{"true"}}, tc.files)
			require.Equal(t, StateRestored, f.record(kid).State)
			require.Nil(t, verified(t, f, kid).Gate)
		})
	}
}
