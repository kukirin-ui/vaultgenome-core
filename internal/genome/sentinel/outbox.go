// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package sentinel

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
)

// maxRecordBytes bounds what the reader accepts as one record file.
const maxRecordBytes = 1 << 20

// Rejected is an outbox record the reader set aside, and why.
type Rejected struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// ReadChain reads every seal record in dir that verifies under the pinned
// sentinel key and returns the chain they form, oldest first: from the
// lowest generation present, each next generation names the one before as
// its parent. The chain ends at the first gap or break; records after it,
// and records that do not verify, are returned as rejected. Records say
// what the bundles hash to, but ReadChain does not open the bundles —
// CheckGenome does, for the genome actually chosen.
func ReadChain(dir string, pub ed25519.PublicKey) ([]SealRecord, []Rejected, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var (
		valid    []SealRecord
		rejected []Rejected
	)
	for _, e := range entries {
		m := recordNameRE.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		gen, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			rejected = append(rejected, Rejected{e.Name(), "generation out of range"})
			continue
		}
		raw, err := readBounded(filepath.Join(dir, e.Name()))
		if err != nil {
			rejected = append(rejected, Rejected{e.Name(), err.Error()})
			continue
		}
		rec, err := ParseRecord(raw, pub)
		if err != nil {
			rejected = append(rejected, Rejected{e.Name(), err.Error()})
			continue
		}
		if rec.Generation != gen {
			rejected = append(rejected, Rejected{e.Name(), fmt.Sprintf("the file is generation %d, the record says %d", gen, rec.Generation)})
			continue
		}
		valid = append(valid, rec)
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Generation < valid[j].Generation })
	var chain []SealRecord
	for i, rec := range valid {
		if i > 0 {
			prev := chain[len(chain)-1]
			if rec.Generation != prev.Generation+1 || rec.ParentBundleSHA256 != prev.BundleSHA256 {
				for _, r := range valid[i:] {
					rejected = append(rejected, Rejected{RecordName(r.Generation), fmt.Sprintf("does not follow generation %d: the chain breaks there", prev.Generation)})
				}
				break
			}
		}
		chain = append(chain, rec)
	}
	return chain, rejected, nil
}

// CheckGenome opens nothing and trusts nothing but the record: it checks
// that the outbox holds the bundle the record describes — its SHA-256, its
// header's key ID, generation, parent and payload — and an escrow envelope
// for that key, sealed to the escrow key the record names. It returns the
// bundle's identity and the envelope.
func CheckGenome(dir string, rec SealRecord) (bundle.Identity, escrow.Envelope, error) {
	id, err := bundle.Identify(filepath.Join(dir, rec.Bundle))
	if err != nil {
		return bundle.Identity{}, escrow.Envelope{}, err
	}
	h := id.Header
	switch {
	case id.SHA256 != rec.BundleSHA256 || id.Size != rec.BundleBytes:
		return bundle.Identity{}, escrow.Envelope{}, fmt.Errorf("sentinel: %s hashes to %s (%d bytes), the record says %s (%d bytes)", rec.Bundle, id.SHA256, id.Size, rec.BundleSHA256, rec.BundleBytes)
	case h.KeyID != rec.KeyID || h.Generation != rec.Generation || h.PayloadSHA256 != rec.PayloadSHA256 || h.ParentBundleSHA256 != rec.ParentBundleSHA256:
		return bundle.Identity{}, escrow.Envelope{}, fmt.Errorf("sentinel: %s's header is not the one its record describes", rec.Bundle)
	}
	raw, err := readBounded(filepath.Join(dir, rec.Escrow))
	if err != nil {
		return bundle.Identity{}, escrow.Envelope{}, err
	}
	env, err := escrow.Parse(raw)
	if err != nil {
		return bundle.Identity{}, escrow.Envelope{}, err
	}
	if env.KeyID != rec.KeyID || env.EscrowKey != rec.EscrowKey {
		return bundle.Identity{}, escrow.Envelope{}, fmt.Errorf("sentinel: %s escrows key %s to %s, the record says %s to %s", rec.Escrow, env.KeyID, env.EscrowKey, rec.KeyID, rec.EscrowKey)
	}
	return id, env, nil
}

// ErrAbsent reports that the outbox has no such record.
var ErrAbsent = errors.New("sentinel: no such record")

// ReadHeartbeat reads the outbox's heartbeat and its raw bytes. A heartbeat
// that is present but does not verify is an error, never ErrAbsent.
func ReadHeartbeat(dir string, pub ed25519.PublicKey) (Heartbeat, []byte, error) {
	raw, err := readRecord(dir, HeartbeatFile)
	if err != nil {
		return Heartbeat{}, nil, err
	}
	h, err := ParseHeartbeat(raw, pub)
	return h, raw, err
}

// ReadCompromise reads the outbox's compromise report and its raw bytes.
func ReadCompromise(dir string, pub ed25519.PublicKey) (Compromise, []byte, error) {
	raw, err := readRecord(dir, CompromiseFile)
	if err != nil {
		return Compromise{}, nil, err
	}
	c, err := ParseCompromise(raw, pub)
	return c, raw, err
}

func readRecord(dir, name string) ([]byte, error) {
	raw, err := readBounded(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrAbsent
	}
	return raw, err
}

func readBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("sentinel: %s is not a regular file", filepath.Base(path))
	}
	if info.Size() > maxRecordBytes {
		return nil, fmt.Errorf("sentinel: %s is %d bytes, over %d", filepath.Base(path), info.Size(), maxRecordBytes)
	}
	return os.ReadFile(path)
}

// writeAtomic replaces dir/name with data: written to a hidden file beside
// it, synced, renamed into place, and the directory synced, so a reader
// sees the old record or the new one and never half of either. With
// exclusive, an existing dir/name is an error instead.
func writeAtomic(dir, name string, data []byte, exclusive bool) error {
	final := filepath.Join(dir, name)
	if exclusive {
		if _, err := os.Lstat(final); err == nil {
			return fmt.Errorf("sentinel: %s already exists", name)
		}
	}
	tmp := filepath.Join(dir, "."+name+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, final)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
