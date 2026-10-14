// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package recovery_request defines the RecoveryRequest canonical contract —
// the structured, continuity-relevant request entering the governed intake
// path of the AI Continuity Platform.
//
// # Doctrinal role
//
// A RecoveryRequest is the first object in the nine-stage flow. It carries
// the minimum information the vault needs to decide whether the request
// should be admitted: who is asking, which genome is being addressed, under
// which policy profile, and with what contour metadata. The vault then runs
// Trust Admission against it and either issues a TrustedSession or denies.
//
// This contract is FROZEN by name and by the presence of SchemaVersion as
// its first field. Local redefinition in any other package is forbidden
// (see docs/doctrine/terminology.md §3 and docs/doctrine/open-decisions-resolved.md R-13).
//
// Corresponds to P3 §[0042a]. Canonical term: "Recovery Request" —
// docs/doctrine/terminology.md §2.
package recovery_request

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// SchemaVersion constants for the RecoveryRequest contract.
//
// A reader MUST reject a message with SchemaVersion < Min or > Max
// (errors.CodeSchemaVersionUnsupported). Writers emit at Current.
const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1
)

// RecoveryRequest is the structured continuity-relevant request entering
// the vault.
type RecoveryRequest struct {
	// SchemaVersion is the wire-format version. Readers MUST validate this
	// first; see docs/doctrine/open-decisions-resolved.md R-13.
	SchemaVersion uint16 `json:"schema_version"`

	// RequestID is a globally unique identifier for this request.
	RequestID ids.RequestID `json:"request_id"`

	// GenomeID identifies the AI Genome being addressed. Never contains
	// genome material.
	GenomeID ids.GenomeID `json:"genome_id"`

	// PolicyProfile names the policy envelope under which the request will
	// be evaluated (e.g., "sovereign-ru", "research-default"). The full
	// Policy object is resolved by the vault, not carried in the request.
	PolicyProfile string `json:"policy_profile"`

	// RequesterIdentity is the cryptographic identity asserting the request.
	// MVP: a stable string form (fingerprint or subject). Stage D may add a
	// structured sibling field under a bumped SchemaVersion.
	RequesterIdentity string `json:"requester_identity"`

	// Contour is metadata about the operational contour originating the
	// request (jurisdiction, runtime environment class, operator role).
	// Must not carry genome material.
	Contour map[string]string `json:"contour,omitempty"`

	// CreatedAt is the wall-clock timestamp of request creation at the
	// originating contour. The vault assigns its own received-at timestamp
	// separately during intake.
	CreatedAt time.Time `json:"created_at"`
}
