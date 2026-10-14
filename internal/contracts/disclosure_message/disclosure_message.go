// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package disclosure_message defines the DisclosureMessage canonical
// contract — the authorization artifact for one sequential release of an
// AI Genome component under policy.
//
// # Doctrinal role
//
// Staged disclosure is the rule: the full AI Genome is never materialized
// in one place. Every component emission carries a DisclosureMessage that
// names which component, under which session, under which policy version,
// authorized at which moment, by which key.
//
// The content released by a DisclosureMessage is sealed (AES-256-GCM,
// ephemeral key, bound to the ReconstructionJobManifest —
// docs/doctrine/open-decisions-resolved.md R-10). The DisclosureMessage carries only
// the envelope metadata and the sealed blob, never raw material.
//
// Corresponds to P3 §[0018].
package disclosure_message

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1

	// GCMNonceSize is the AES-256-GCM nonce size in bytes. Fixed at 12;
	// non-12-byte nonces are rejected at validation.
	GCMNonceSize = 12
)

// DisclosureMessage is one staged-disclosure authorization.
type DisclosureMessage struct {
	SchemaVersion uint16            `json:"schema_version"`
	DisclosureID  ids.DisclosureID  `json:"disclosure_id"`
	SessionID     ids.SessionID     `json:"session_id"`
	ComponentID   ids.ComponentID   `json:"component_id"`
	PolicyVersion ids.PolicyVersion `json:"policy_version"`

	// SequenceIndex is the 0-based order of this disclosure within the
	// session. Monotonically increasing with no gaps — enforced by
	// /internal/vault/disclosure, not here.
	SequenceIndex uint32 `json:"sequence_index"`

	// SealedPayload is the AES-256-GCM ciphertext of the component material.
	// Empty payloads are rejected as invalid authorizations.
	SealedPayload []byte `json:"sealed_payload"`

	// Nonce is the GCM nonce used to seal SealedPayload. Must be exactly
	// GCMNonceSize bytes.
	Nonce []byte `json:"nonce"`

	// RecipientKeyID identifies the external-compute binding key the
	// payload was sealed to.
	RecipientKeyID ids.KeyID `json:"recipient_key_id"`

	AuthorizedAt time.Time `json:"authorized_at"`

	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`
}
