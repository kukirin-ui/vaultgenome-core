// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package receipt is a destination's attested word that it restored a
// genome: which genome (bundle, payload and restored-tree digests), under
// which key release (decision, request, token, key), and how long it
// took.
//
// The destination's TEE quotes over Challenge(receipt bytes), so the
// receipt is signed by the same hardware whose Evidence won the key
// release. The source verifies that Evidence with the verifier it used
// for the release, checks the measurement is the one it released to, and
// only then records the restore as completed (ADR 0011). A receipt
// cannot be forged by the network, the operator's scripts, or a host
// that did not attest.
package receipt

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Schema names this receipt format.
const Schema = "vault-genome/restore-receipt/v1"

const challengeLabel = "vault-genome restore-receipt v1"

// Receipt describes one completed restore.
type Receipt struct {
	Schema string `json:"schema"`

	// The key release this restore used.
	KeyID      string `json:"key_id"`
	DecisionID string `json:"decision_id"`
	RequestID  string `json:"request_id"`
	TokenID    string `json:"token_id"`

	// The destination that restored it: its TEE family and measurement
	// (hex). The Evidence over this receipt must verify to the same
	// measurement.
	DestinationKind        string `json:"destination_kind"`
	DestinationMeasurement string `json:"destination_measurement"`

	// What was restored.
	BundleSHA256  string `json:"bundle_sha256"`  // hex, of the bundle file
	Generation    uint64 `json:"generation"`     // from the bundle header
	ContentKind   string `json:"content_kind"`   // from the bundle header
	PayloadSHA256 string `json:"payload_sha256"` // "sha256:<hex>", as the header records it
	TreeSHA256    string `json:"tree_sha256"`    // hex, tree.Digest of the restored files
	Files         int    `json:"files"`
	Bytes         int64  `json:"bytes"`

	// When, and how long: from the key's arrival to the restored tree
	// verified, and the restore itself.
	KeyReceivedAt  time.Time `json:"key_received_at"`
	RestoredAt     time.Time `json:"restored_at"`
	RestoreSeconds float64   `json:"restore_seconds"`

	// Gate is the equivalence gate's verdict on the restored model, when
	// the destination ran it: its sealed fixtures recomputed on this
	// hardware and held to their references.
	Gate *Gate `json:"gate,omitempty"`
}

// Gate is a restored model's gate verdict.
type Gate struct {
	Level          string  `json:"level"` // EXACT, EQUIVALENT or FAIL
	Door           string  `json:"door,omitempty"`
	Fixtures       int     `json:"fixtures"`
	MaxAbsErr      float64 `json:"max_abs_err"`
	MaxRelErr      float64 `json:"max_rel_err"`
	Atol           float64 `json:"atol"`
	Rtol           float64 `json:"rtol"`
	BackendSeconds float64 `json:"backend_seconds"`
}

// Gate levels, in order of fidelity.
const (
	GateExact      = "EXACT"
	GateEquivalent = "EQUIVALENT"
	GateFail       = "FAIL"
)

// Meets reports whether the gate verdict is at least want (EXACT or
// EQUIVALENT). FAIL meets nothing.
func (g *Gate) Meets(want string) bool {
	if g == nil {
		return false
	}
	switch want {
	case GateExact:
		return g.Level == GateExact
	case GateEquivalent:
		return g.Level == GateExact || g.Level == GateEquivalent
	}
	return false
}

var (
	hex64RE       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	payloadRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	measurementRE = regexp.MustCompile(`^([0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})$`)
)

// Validate checks the receipt is complete and well-formed.
func (r Receipt) Validate() error {
	var errs []error
	if r.Schema != Schema {
		errs = append(errs, fmt.Errorf("schema %q, want %q", r.Schema, Schema))
	}
	for name, v := range map[string]string{
		"key_id": r.KeyID, "decision_id": r.DecisionID, "request_id": r.RequestID,
		"token_id": r.TokenID, "destination_kind": r.DestinationKind, "content_kind": r.ContentKind,
	} {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s required", name))
		}
	}
	if !measurementRE.MatchString(r.DestinationMeasurement) {
		errs = append(errs, errors.New("destination_measurement must be 32, 48 or 64 bytes of hex"))
	}
	if !hex64RE.MatchString(r.BundleSHA256) {
		errs = append(errs, errors.New("bundle_sha256 must be 64 hex"))
	}
	if !payloadRE.MatchString(r.PayloadSHA256) {
		errs = append(errs, errors.New("payload_sha256 must be sha256:<64 hex>"))
	}
	if !hex64RE.MatchString(r.TreeSHA256) {
		errs = append(errs, errors.New("tree_sha256 must be 64 hex"))
	}
	if r.Files <= 0 || r.Bytes < 0 || r.RestoreSeconds < 0 {
		errs = append(errs, errors.New("files, bytes and restore_seconds must be a real restore's"))
	}
	if r.KeyReceivedAt.IsZero() || r.RestoredAt.IsZero() || r.RestoredAt.Before(r.KeyReceivedAt) {
		errs = append(errs, errors.New("key_received_at and restored_at required, in that order"))
	}
	if g := r.Gate; g != nil {
		if g.Level != GateExact && g.Level != GateEquivalent && g.Level != GateFail {
			errs = append(errs, fmt.Errorf("gate level %q", g.Level))
		}
		if g.Fixtures <= 0 || g.MaxAbsErr < 0 || g.MaxRelErr < 0 || g.Atol < 0 || g.Rtol < 0 || g.BackendSeconds < 0 {
			errs = append(errs, errors.New("gate figures must be a real gate's"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("receipt: %w", err)
	}
	return nil
}

// Marshal validates r and encodes it. These bytes are what the
// destination quotes over and what the source verifies.
func (r Receipt) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// Parse decodes and validates receipt bytes, refusing unknown fields and
// trailing data.
func Parse(b []byte) (Receipt, error) {
	var r Receipt
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Receipt{}, fmt.Errorf("receipt: %w", err)
	}
	if dec.More() {
		return Receipt{}, errors.New("receipt: trailing data")
	}
	return r, r.Validate()
}

// Challenge is what the destination's TEE quotes over for these receipt
// bytes: SHA-512(label ‖ u32 BE len ‖ receipt).
func Challenge(receiptBytes []byte) []byte {
	h := sha512.New()
	h.Write([]byte(challengeLabel))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(receiptBytes)))
	h.Write(n[:])
	h.Write(receiptBytes)
	return h.Sum(nil)
}

// Signed is a receipt with the Evidence that vouches for it, as a
// destination serves and stores it.
type Signed struct {
	Receipt  []byte `json:"receipt"`  // Receipt.Marshal output
	Evidence []byte `json:"evidence"` // TEE Evidence over Challenge(Receipt)
}

// Sign marshals r and has the destination's TEE quote over it.
func Sign(r Receipt, p tee.Producer) (Signed, error) {
	b, err := r.Marshal()
	if err != nil {
		return Signed{}, err
	}
	ev, err := p.Quote(tee.Nonce(Challenge(b)))
	if err != nil {
		return Signed{}, fmt.Errorf("receipt: quote: %w", err)
	}
	return Signed{Receipt: b, Evidence: ev}, nil
}

// Verify checks s with v, the verifier for the destination's TEE family,
// and returns the receipt and the measurement its Evidence attests to —
// which must be the measurement the receipt names. Whether that is the
// destination the key was released to is the caller's to check.
func Verify(s Signed, v tee.Verifier) (Receipt, tee.Measurement, error) {
	m, err := v.Verify(tee.Evidence(s.Evidence), tee.Nonce(Challenge(s.Receipt)))
	if err != nil {
		return Receipt{}, nil, fmt.Errorf("receipt: evidence does not verify: %w", err)
	}
	r, err := Parse(s.Receipt)
	if err != nil {
		return Receipt{}, nil, err
	}
	if got := hex.EncodeToString(m); got != r.DestinationMeasurement {
		return Receipt{}, nil, fmt.Errorf("receipt: names measurement %s, but its Evidence attests %s", r.DestinationMeasurement, got)
	}
	return r, m, nil
}

// Save writes s to path atomically (a temporary file beside it, synced,
// then renamed), so a receipt on disk is always whole. A receipt is a
// public statement — digests, identifiers and TEE Evidence, no genome
// material.
func Save(path string, s Signed) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("receipt: save: %w", err)
	}
	name := tmp.Name()
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("receipt: save: %w", err)
	}
	return nil
}

// Load reads a receipt Save wrote and parses its receipt. It does not
// verify the Evidence; only a verifier for the destination's TEE can.
func Load(path string) (Signed, Receipt, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Signed{}, Receipt{}, fmt.Errorf("receipt: load: %w", err)
	}
	var s Signed
	if err := json.Unmarshal(raw, &s); err != nil {
		return Signed{}, Receipt{}, fmt.Errorf("receipt: load %s: %w", path, err)
	}
	r, err := Parse(s.Receipt)
	if err != nil {
		return Signed{}, Receipt{}, fmt.Errorf("receipt: load %s: %w", path, err)
	}
	return s, r, nil
}
