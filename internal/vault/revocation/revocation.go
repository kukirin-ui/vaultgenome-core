// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package revocation implements the operator stop (ADR 0010): a list,
// signed with an operator key that never lives on the release host,
// that either stops every cross-cloud key release or revokes specific
// destination measurements. The release authority applies the list it
// is given on every release and refuses to run without a valid one, so
// the people who hold the operator key — not the release authority,
// and not any workload — decide whether keys may move at all.
//
// Lists carry a serial. The serial a release was decided under is
// written into the signed audit log (as part of the policy version), and
// a list older than the newest serial on record is refused, so a stop
// cannot be undone by putting an earlier list back.
package revocation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// Schema identifies version 1 of the list format.
const Schema = "vault-genome/revocation/v1"

// List is one signed operator decision about which releases may happen.
type List struct {
	Schema string `json:"schema"`
	// Serial orders lists; each new list takes a higher serial.
	Serial   uint64    `json:"serial"`
	IssuedAt time.Time `json:"issued_at"`
	// StopAll refuses every release, whatever the destination.
	StopAll bool `json:"stop_all"`
	// RevokedMeasurements refuses releases to these measurements (hex),
	// per TEE provider.
	RevokedMeasurements map[string][]string `json:"revoked_measurements,omitempty"`
	// Reason is recorded with every refusal the list causes.
	Reason       string `json:"reason,omitempty"`
	SigningKeyID string `json:"signing_key_id"`
	Signature    []byte `json:"signature,omitempty"`
}

func (l List) signedBytes() ([]byte, error) {
	l.Signature = nil
	return crypto.CanonicalJSON(l)
}

func (l List) validate() error {
	if l.Schema != Schema {
		return fmt.Errorf("revocation: schema %q, want %q", l.Schema, Schema)
	}
	if l.Serial == 0 {
		return errors.New("revocation: serial must be at least 1")
	}
	if l.IssuedAt.IsZero() {
		return errors.New("revocation: issued_at required")
	}
	if l.SigningKeyID == "" {
		return errors.New("revocation: signing_key_id required")
	}
	for provider, list := range l.RevokedMeasurements {
		if _, err := tee.ParseProvider(provider); err != nil {
			return fmt.Errorf("revocation: revoked_measurements: %w", err)
		}
		for _, h := range list {
			b, err := hex.DecodeString(h)
			if err != nil {
				return fmt.Errorf("revocation: revoked_measurements[%s]: %q is not hex", provider, h)
			}
			if _, err := tee.MeasurementFromBytes(b); err != nil {
				return fmt.Errorf("revocation: revoked_measurements[%s]: %w", provider, err)
			}
		}
	}
	return nil
}

// Sign validates l and signs it with the operator key. Schema is filled
// in when empty.
func Sign(l List, priv ed25519.PrivateKey) (List, error) {
	if l.Schema == "" {
		l.Schema = Schema
	}
	if err := l.validate(); err != nil {
		return List{}, err
	}
	msg, err := l.signedBytes()
	if err != nil {
		return List{}, err
	}
	l.Signature = ed25519.Sign(priv, msg)
	return l, nil
}

// Parse decodes a signed list and accepts it only if it is well formed,
// names kid as its signer, and verifies under pub.
func Parse(raw []byte, pub ed25519.PublicKey, kid string) (List, error) {
	var l List
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return List{}, fmt.Errorf("revocation: decode: %w", err)
	}
	if err := l.validate(); err != nil {
		return List{}, err
	}
	if l.SigningKeyID != kid {
		return List{}, fmt.Errorf("revocation: list is signed by %q; this authority trusts %q", l.SigningKeyID, kid)
	}
	msg, err := l.signedBytes()
	if err != nil {
		return List{}, err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, msg, l.Signature) {
		return List{}, errors.New("revocation: signature does not verify under the operator key")
	}
	return l, nil
}

// Denies reports whether the list refuses a release to measurement on
// kind, and why.
func (l List) Denies(kind tee.Provider, measurement []byte) (bool, string) {
	if l.StopAll {
		return true, fmt.Sprintf("operator stop in force (revocation serial %d): %s", l.Serial, l.reason())
	}
	if slices.Contains(l.RevokedMeasurements[string(kind)], hex.EncodeToString(measurement)) {
		return true, fmt.Sprintf("destination measurement revoked by the operator (revocation serial %d): %s", l.Serial, l.reason())
	}
	return false, ""
}

func (l List) reason() string {
	if l.Reason == "" {
		return "no reason given"
	}
	return l.Reason
}

// Gate applies an operator list in front of a release policy: whatever
// the list refuses is refused before the inner policy is consulted.
type Gate struct {
	inner kms.KeyReleasePolicy
	list  List
}

// NewGate wraps inner with list.
func NewGate(inner kms.KeyReleasePolicy, list List) *Gate {
	return &Gate{inner: inner, list: list}
}

// AuthorizeKeyRelease implements kms.KeyReleasePolicy.
func (g *Gate) AuthorizeKeyRelease(kind tee.Provider, measurement []byte, decision ids.DecisionID, keyIDs []ids.KeyID) (kms.PolicyVerdict, error) {
	if denied, why := g.list.Denies(kind, measurement); denied {
		return kms.PolicyVerdict{Authorized: false, Reason: why}, nil
	}
	return g.inner.AuthorizeKeyRelease(kind, measurement, decision, keyIDs)
}

// PolicyVersion implements kms.KeyReleasePolicy. It names the list's
// serial alongside the inner policy's version, so every release
// decision on record says which operator list it was made under.
func (g *Gate) PolicyVersion() string {
	return fmt.Sprintf("%s;revocation=%d", g.inner.PolicyVersion(), g.list.Serial)
}

// Serial returns the serial of the list the gate applies.
func (g *Gate) Serial() uint64 { return g.list.Serial }

var serialInPolicyVersion = regexp.MustCompile(`;revocation=(\d+)$`)

// HighestSerial returns the newest operator-list serial any release
// decision in events was made under (0 if none). events should come from
// a verified audit log.
func HighestSerial(events []audit_event.AuditEvent) uint64 {
	var highest uint64
	for _, e := range events {
		if e.Kind != audit_event.KindKeyReleaseAuthorized && e.Kind != audit_event.KindKeyReleaseDenied {
			continue
		}
		var p struct {
			PolicyVersion string `json:"policy_version"`
		}
		if json.Unmarshal(e.Payload, &p) != nil {
			continue
		}
		if m := serialInPolicyVersion.FindStringSubmatch(p.PolicyVersion); m != nil {
			if n, err := strconv.ParseUint(m[1], 10, 64); err == nil && n > highest {
				highest = n
			}
		}
	}
	return highest
}

// CheckNotRolledBack refuses a list older than the newest serial a
// recorded release decision was made under.
func CheckNotRolledBack(l List, events []audit_event.AuditEvent) error {
	if highest := HighestSerial(events); l.Serial < highest {
		return fmt.Errorf("revocation: list serial %d is older than serial %d already applied in the audit log (rollback refused)", l.Serial, highest)
	}
	return nil
}
