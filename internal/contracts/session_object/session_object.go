// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package session_object defines the SessionObject canonical contract —
// the cryptographically authenticated, time-bounded session during which
// the AI Genome may be partially accessed under policy.
//
// # Doctrinal role
//
// No genome component is touched without a valid SessionObject. The session
// is issued by the vault after Trust Admission returns allow; it is bounded
// by an explicit expiration; it is invalidated on any incident event of
// severity ≥ warn; and it carries the identifiers that every downstream
// artifact references.
//
// Corresponds to P3 §[0036]. Canonical term: "Trusted Session" —
// docs/doctrine/terminology.md §2.
package session_object

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1
)

// State enumerates the session lifecycle states. These are the states the
// session can legitimately be in when serialized. Transitions between
// them are enforced by /internal/vault/session, not here.
type State string

const (
	StateActive      State = "active"
	StateSuspended   State = "suspended"   // policy-gated pause
	StateInvalidated State = "invalidated" // incident-triggered termination
	StateExpired     State = "expired"     // TTL elapsed
)

// SessionObject represents an active trusted session.
type SessionObject struct {
	SchemaVersion uint16            `json:"schema_version"`
	SessionID     ids.SessionID     `json:"session_id"`
	RequestID     ids.RequestID     `json:"request_id"`
	GenomeID      ids.GenomeID      `json:"genome_id"`
	PolicyVersion ids.PolicyVersion `json:"policy_version"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	State State `json:"state"`

	// SigningKeyID identifies the vault key that signed this object.
	SigningKeyID ids.KeyID `json:"signing_key_id"`

	// Signature is the Ed25519 signature over CanonicalBytes excluding
	// Signature itself (see docs/doctrine/open-decisions-resolved.md R-10).
	Signature []byte `json:"signature"`
}
