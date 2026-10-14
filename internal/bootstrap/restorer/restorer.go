// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package restorer brings a genome up on the destination once its key
// has been released here (ADR 0011).
//
// The source releases a genome's key only to a TEE its operator's policy
// admits (ADR 0009, 0010). When that key lands in this daemon's keystore,
// the Restorer finds the sealed bundle whose header names the key — in a
// directory bundles are replicated to ahead of time, since without their
// keys they are opaque — opens it with the key where it lies, restores it
// all or nothing (internal/genome/restore), and has this TEE sign a
// receipt that says exactly what was restored. The source verifies that
// receipt against the release before it records the restore as done.
//
// The Restorer acts only on keys the source released. It never asks for
// a key, never moves a genome anywhere, and holds no policy of its own.
package restorer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/crosscloud"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/genome/restore"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// DefaultRescan is how often the Restorer looks again for the bundle of
// a key that arrived before its bundle did.
const DefaultRescan = 5 * time.Second

// receiptSuffix names a restore's signed receipt beside its tree.
const receiptSuffix = ".receipt.json"

// Config bundles the Restorer's dependencies.
type Config struct {
	// BundleDir holds sealed .genome bundles waiting for their keys.
	BundleDir string
	// RestoreDir receives each genome at <RestoreDir>/<key id>/ and its
	// signed receipt at <RestoreDir>/<key id>.receipt.json.
	RestoreDir string
	// Keys holds released keys and opens with them in place; the
	// daemon's keystore.
	Keys bundle.Opener
	// Erase, if set, wipes a genome's key once its restore is signed for,
	// so the key does not stay in memory after its one use.
	Erase func(kid ids.KeyID) bool
	// TEE signs receipts; Kind is its family.
	TEE  tee.Producer
	Kind tee.Provider

	Logger *slog.Logger
	Clock  shared_time.Clock
	// Rescan: zero selects DefaultRescan.
	Rescan time.Duration

	// Gate, when set, runs the equivalence gate on every restored model
	// before the receipt is signed, and puts its verdict in the receipt.
	Gate *GateConfig
}

// State is where a released key's restore stands.
type State string

// States of a restore.
const (
	StateWaiting   State = "waiting_for_bundle"
	StateRestoring State = "restoring"
	StateGating    State = "gating"
	StateRestored  State = "restored"
	// StateGateFailed: restored, but the model's outputs miss their
	// references on this hardware. The receipt says so.
	StateGateFailed State = "gate_failed"
	StateFailed     State = "failed"
)

// Record is the public account of one released key's restore.
type Record struct {
	KeyID         string          `json:"key_id"`
	DecisionID    string          `json:"decision_id"`
	RequestID     string          `json:"request_id"`
	TokenID       string          `json:"token_id"`
	State         State           `json:"state"`
	KeyReceivedAt time.Time       `json:"key_received_at"`
	Bundle        string          `json:"bundle,omitempty"`
	BundleSHA256  string          `json:"bundle_sha256,omitempty"`
	StartedAt     *time.Time      `json:"started_at,omitempty"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
	Result        *restore.Result `json:"result,omitempty"`
	Gate          *receipt.Gate   `json:"gate,omitempty"`
	Error         string          `json:"error,omitempty"`
}

type entry struct {
	rec    Record
	signed *receipt.Signed
}

// indexed caches one bundle file's key ID, keyed by its size and mtime.
type indexed struct {
	size  int64
	mtime time.Time
	kid   string // "" when the file is not a readable v3 bundle
}

// Restorer restores released genomes. Construct with New; run Run in a
// goroutine; feed it deliveries with Delivered.
type Restorer struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	entries map[string]*entry
	order   []string // key IDs in arrival order
	index   map[string]indexed
	wake    chan struct{}
}

// New validates cfg, creates the directories, and loads the receipts of
// restores completed before a restart so they are still served.
func New(cfg Config) (*Restorer, error) {
	if cfg.BundleDir == "" || cfg.RestoreDir == "" {
		return nil, errors.New("restorer: BundleDir and RestoreDir required")
	}
	if cfg.Keys == nil || cfg.TEE == nil || cfg.Kind == "" {
		return nil, errors.New("restorer: Keys, TEE and Kind required")
	}
	if cfg.Clock == nil {
		cfg.Clock = shared_time.NewSystemClock()
	}
	if cfg.Rescan <= 0 {
		cfg.Rescan = DefaultRescan
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	for _, d := range []string{cfg.BundleDir, cfg.RestoreDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("restorer: %w", err)
		}
	}
	r := &Restorer{
		cfg:     cfg,
		log:     log,
		entries: map[string]*entry{},
		index:   map[string]indexed{},
		wake:    make(chan struct{}, 1),
	}
	if err := r.loadReceipts(); err != nil {
		return nil, err
	}
	return r, nil
}

// loadReceipts reinstates completed restores from their receipts.
func (r *Restorer) loadReceipts() error {
	names, err := filepath.Glob(filepath.Join(r.cfg.RestoreDir, "*"+receiptSuffix))
	if err != nil {
		return fmt.Errorf("restorer: %w", err)
	}
	sort.Strings(names)
	for _, name := range names {
		s, rc, err := receipt.Load(name)
		if err != nil {
			return fmt.Errorf("restorer: %w", err)
		}
		restoredAt := rc.RestoredAt
		state := StateRestored
		if rc.Gate != nil && rc.Gate.Level == receipt.GateFail {
			state = StateGateFailed
		}
		r.entries[rc.KeyID] = &entry{
			rec: Record{
				KeyID: rc.KeyID, DecisionID: rc.DecisionID, RequestID: rc.RequestID, TokenID: rc.TokenID,
				State: state, KeyReceivedAt: rc.KeyReceivedAt, BundleSHA256: rc.BundleSHA256,
				FinishedAt: &restoredAt, Gate: rc.Gate,
				Result: &restore.Result{
					Target: filepath.Join(r.cfg.RestoreDir, rc.KeyID), Files: rc.Files, BytesWritten: rc.Bytes,
					PayloadSHA256: rc.PayloadSHA256, TreeSHA256: rc.TreeSHA256,
				},
			},
			signed: &s,
		}
		r.order = append(r.order, rc.KeyID)
	}
	return nil
}

// Delivered takes note of a key release the Receiver accepted. Keys that
// do not name a genome (bundle.IsKeyID) are not the Restorer's. It never
// blocks.
func (r *Restorer) Delivered(d crosscloud.Delivery) {
	r.mu.Lock()
	for _, k := range d.KeyIDs {
		kid := string(k)
		if !bundle.IsKeyID(kid) {
			continue
		}
		if e, ok := r.entries[kid]; ok && e.rec.State != StateFailed && e.rec.State != StateGateFailed {
			continue // already restored or on its way
		} else if !ok {
			r.order = append(r.order, kid)
		}
		r.entries[kid] = &entry{rec: Record{
			KeyID: kid, DecisionID: string(d.DecisionID), RequestID: string(d.RequestID), TokenID: string(d.TokenID),
			State: StateWaiting, KeyReceivedAt: d.At,
		}}
		r.log.Info("genome key released here; restore queued", slog.String("key_id", kid), slog.String("decision_id", string(d.DecisionID)))
	}
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run restores released genomes until ctx ends: at once when a key
// arrives, and every Rescan for keys whose bundle has not arrived yet.
// Restores run one at a time.
func (r *Restorer) Run(ctx context.Context) {
	t := time.NewTicker(r.cfg.Rescan)
	defer t.Stop()
	for {
		r.work(ctx)
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-t.C:
		}
	}
}

func (r *Restorer) work(ctx context.Context) {
	waiting := r.waiting()
	if len(waiting) == 0 {
		return
	}
	found := r.scan()
	for _, kid := range waiting {
		if ctx.Err() != nil {
			return
		}
		if path, ok := found[kid]; ok {
			r.restoreOne(kid, path)
		}
	}
}

func (r *Restorer) waiting() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, kid := range r.order {
		if r.entries[kid].rec.State == StateWaiting {
			out = append(out, kid)
		}
	}
	return out
}

// scan maps key IDs to the bundle files in BundleDir that carry them,
// reading only the header of files it has not seen unchanged before.
func (r *Restorer) scan() map[string]string {
	names, err := filepath.Glob(filepath.Join(r.cfg.BundleDir, "*.genome"))
	if err != nil {
		r.log.Warn("genome bundle scan failed", slog.String("err", err.Error()))
		return nil
	}
	found := map[string]string{}
	for _, name := range names {
		info, err := os.Stat(name)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		c, ok := r.index[name]
		if !ok || c.size != info.Size() || !c.mtime.Equal(info.ModTime()) {
			c = indexed{size: info.Size(), mtime: info.ModTime(), kid: headerKeyID(name)}
			if c.kid == "" {
				r.log.Warn("not a v3 genome bundle; ignored", slog.String("file", name))
			}
			r.index[name] = c
		}
		if c.kid != "" {
			found[c.kid] = name
		}
	}
	return found
}

func headerKeyID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	br, err := bundle.NewReader(bufio.NewReader(f))
	if err != nil {
		return ""
	}
	return br.Header.KeyID
}

func (r *Restorer) restoreOne(kid, path string) {
	started := r.cfg.Clock.Now().UTC()
	r.update(kid, func(rec *Record) {
		rec.State, rec.Bundle, rec.StartedAt = StateRestoring, path, &started
	})
	r.log.Info("genome restore started", slog.String("key_id", kid), slog.String("bundle", path))

	target := filepath.Join(r.cfg.RestoreDir, kid)
	res, bundleSHA, h, err := r.open(kid, path, target)
	finished := r.cfg.Clock.Now().UTC()
	var verdict *receipt.Gate
	if err == nil && r.cfg.Gate != nil {
		verdict, err = r.runGate(kid, target)
	}
	if err == nil {
		err = r.sign(kid, h, res, bundleSHA, started, finished, verdict)
	}
	if err != nil {
		r.update(kid, func(rec *Record) {
			rec.State, rec.FinishedAt, rec.Error = StateFailed, &finished, err.Error()
		})
		r.log.Error("genome restore failed", slog.String("key_id", kid), slog.String("err", err.Error()))
		return
	}
	r.log.Info("genome restored",
		slog.String("key_id", kid),
		slog.String("target", res.Target),
		slog.Int("files", res.Files),
		slog.Int64("bytes", res.BytesWritten),
		slog.String("payload_sha256", res.PayloadSHA256),
		slog.String("tree_sha256", res.TreeSHA256),
		slog.String("bundle_sha256", bundleSHA),
		slog.Float64("restore_seconds", finished.Sub(started).Seconds()),
	)
}

// open restores the bundle at path into target with the released key,
// hashing the bundle file as it streams.
func (r *Restorer) open(kid, path, target string) (restore.Result, string, bundle.Header, error) {
	f, err := os.Open(path)
	if err != nil {
		return restore.Result{}, "", bundle.Header{}, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	br, err := bundle.NewReader(io.TeeReader(bufio.NewReaderSize(f, 1<<20), h))
	if err != nil {
		return restore.Result{}, "", bundle.Header{}, err
	}
	if br.Header.KeyID != kid {
		return restore.Result{}, "", bundle.Header{}, fmt.Errorf("restorer: %s now carries key %s", path, br.Header.KeyID)
	}
	res, err := restore.Restore(br.Header, br.Payload(r.cfg.Keys), target)
	if err != nil {
		return restore.Result{}, "", bundle.Header{}, err
	}
	return res, hex.EncodeToString(h.Sum(nil)), br.Header, nil
}

// runGate proves the restored model works here, or says it does not. A
// genome that cannot be gated is signed for without a verdict, unless
// the gate is required.
func (r *Restorer) runGate(kid, target string) (*receipt.Gate, error) {
	r.update(kid, func(rec *Record) { rec.State = StateGating })
	r.log.Info("genome gate started", slog.String("key_id", kid))
	verdict, err := r.cfg.Gate.gate(target)
	switch {
	case err != nil && r.cfg.Gate.Required:
		return nil, err
	case err != nil:
		r.log.Warn("genome not gated", slog.String("key_id", kid), slog.String("reason", err.Error()))
		return nil, nil
	}
	r.log.Info("genome gated",
		slog.String("key_id", kid),
		slog.String("level", verdict.Level),
		slog.String("door", verdict.Door),
		slog.Int("fixtures", verdict.Fixtures),
		slog.Float64("max_abs_err", verdict.MaxAbsErr),
		slog.Float64("backend_seconds", verdict.BackendSeconds),
	)
	return verdict, nil
}

// sign has the TEE sign the restore's receipt and keeps it, on disk
// first, so a receipt that is served is also one that survives restarts.
func (r *Restorer) sign(kid string, h bundle.Header, res restore.Result, bundleSHA string, started, finished time.Time, verdict *receipt.Gate) error {
	r.mu.Lock()
	rec := r.entries[kid].rec
	r.mu.Unlock()
	signed, err := receipt.Sign(receipt.Receipt{
		Schema:                 receipt.Schema,
		KeyID:                  kid,
		DecisionID:             rec.DecisionID,
		RequestID:              rec.RequestID,
		TokenID:                rec.TokenID,
		DestinationKind:        string(r.cfg.Kind),
		DestinationMeasurement: hex.EncodeToString(r.cfg.TEE.Measurement()),
		BundleSHA256:           bundleSHA,
		Generation:             h.Generation,
		ContentKind:            h.ContentKind,
		PayloadSHA256:          res.PayloadSHA256,
		TreeSHA256:             res.TreeSHA256,
		Files:                  res.Files,
		Bytes:                  res.BytesWritten,
		KeyReceivedAt:          rec.KeyReceivedAt,
		RestoredAt:             finished,
		RestoreSeconds:         finished.Sub(started).Seconds(),
		Gate:                   verdict,
	}, r.cfg.TEE)
	if err != nil {
		return err
	}
	if err := receipt.Save(filepath.Join(r.cfg.RestoreDir, kid+receiptSuffix), signed); err != nil {
		return fmt.Errorf("restorer: keep receipt: %w", err)
	}
	state := StateRestored
	if verdict != nil && verdict.Level == receipt.GateFail {
		state = StateGateFailed
	}
	r.update(kid, func(rec *Record) {
		rec.State, rec.FinishedAt, rec.BundleSHA256, rec.Result, rec.Gate = state, &finished, bundleSHA, &res, verdict
	})
	r.mu.Lock()
	r.entries[kid].signed = &signed
	r.mu.Unlock()
	if r.cfg.Erase != nil && r.cfg.Erase(ids.KeyID(kid)) {
		r.log.Info("genome key erased after restore", slog.String("key_id", kid))
	}
	return nil
}

func (r *Restorer) update(kid string, f func(*Record)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(&r.entries[kid].rec)
}

// Records returns every restore this daemon knows of, in arrival order.
func (r *Restorer) Records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, 0, len(r.order))
	for _, kid := range r.order {
		out = append(out, r.entries[kid].rec)
	}
	return out
}

// Receipt returns the signed receipt of a completed restore, or the
// record of one that is not complete.
func (r *Restorer) Receipt(kid string) (receipt.Signed, Record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[kid]
	if !ok {
		return receipt.Signed{}, Record{}, false
	}
	if e.signed == nil {
		return receipt.Signed{}, e.rec, true
	}
	return *e.signed, e.rec, true
}
