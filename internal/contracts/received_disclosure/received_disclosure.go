// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package received_disclosure defines the ReceivedDisclosure canonical
// contract — the receive-side record of a single DisclosureMessage that
// was accepted by the bootstrap orchestrator.
//
// # Doctrinal role
//
// A ReceivedDisclosure is NOT a copy of a DisclosureMessage. It is the
// ASSERTION by the receive-side: "I received one wire payload whose
// SHA-256 is H, I treated it as the Nth disclosure in this bootstrap
// under this session, and I accepted it at time T."
//
// Keeping this as a distinct type (rather than re-serialising the
// release-side DisclosureMessage) makes a specific class of bug
// impossible to hide: if the bytes the receive-side accepted differ
// from the bytes the Vault emitted, the wire-hash recorded here will
// not match the canonical-bytes hash computed on the release side.
// Operational validation sub-check op.manifest_integrity (see
// docs/doctrine/validation-thresholds.md §4.2) has its receive-side mirror
// here: the bootstrap orchestrator MUST be able to prove, from these
// records alone, that every accepted payload hashes to what the Vault
// signed.
//
// Release side                     Receive side
// ──────────────────────────       ────────────────────────────
// DisclosureMessage            →   ReceivedDisclosure
//
//	(what the Vault signed)          (what the recipient recorded)
//
// ReceivedDisclosure records NO sealed payload, NO nonce, NO recipient
// key. Those belong on the release-side DisclosureMessage, which is
// already signed. The receive-side needs only the hashes and the
// provenance binding.
//
// Corresponds to P1 §[0052] and P3 §[0042].
package received_disclosure

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1

	// WireHashSize is the fixed byte length of the SHA-256 hash stored
	// in WireHash. Any other length is rejected as invalid.
	WireHashSize = 32
)

// ReceivedDisclosure is the receive-side record of one accepted
// DisclosureMessage.
type ReceivedDisclosure struct {
	SchemaVersion uint16                   `json:"schema_version"`
	ReceivedID    ids.ReceivedDisclosureID `json:"received_id"`

	// BootstrapID pins the BootstrapManifest this disclosure was
	// received under. A disclosure that arrives without an accepted
	// bootstrap is not admissible.
	BootstrapID ids.BootstrapManifestID `json:"bootstrap_id"`

	// SessionID pins the trusted session. MUST match the SessionID of
	// the accepted BootstrapManifest and the DisclosureMessage; a
	// mismatch is a structural violation and causes bootstrap failure.
	SessionID ids.SessionID `json:"session_id"`

	// DisclosureID is the release-side DisclosureMessage.DisclosureID
	// this record corresponds to. MUST appear in the accepted
	// BootstrapManifest.ExpectedDisclosureIDs; otherwise the bootstrap
	// orchestrator MUST refuse the disclosure.
	DisclosureID ids.DisclosureID `json:"disclosure_id"`

	// ComponentID names the component slot this disclosure filled. MUST
	// match the ExpectedComponentIDs entry at the corresponding
	// SequenceIndex in the BootstrapManifest.
	ComponentID ids.ComponentID `json:"component_id"`

	// SequenceIndex is the 0-based arrival index within the bootstrap.
	// MUST be strictly monotonic across successive ReceivedDisclosures
	// of the same BootstrapID; gap and out-of-order enforcement lives
	// in /internal/bootstrap, not here.
	SequenceIndex uint32 `json:"sequence_index"`

	// WireHash is the SHA-256 of the canonical cover-bytes of the
	// release-side DisclosureMessage (i.e. DisclosureMessage.
	// CanonicalBytes() on the Vault side). This is the value the
	// receive-side binds itself to; cross-checking it against the
	// release-side canonical hash is the receive-side equivalent of
	// op.manifest_integrity. MUST be exactly WireHashSize bytes.
	WireHash []byte `json:"wire_hash"`

	// ReceivedAt is the receive-side wall-clock moment of acceptance.
	ReceivedAt time.Time `json:"received_at"`

	// AuditEventID points at the DISCLOSURE_RECEIVED audit event that
	// immutably records this acceptance in the receive-side audit
	// chain. An un-evidenced acceptance is structurally invalid —
	// receive-side audit is first-class, mirroring release-side
	// invariant #8.
	AuditEventID ids.AuditEventID `json:"audit_event_id"`

	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`
}
