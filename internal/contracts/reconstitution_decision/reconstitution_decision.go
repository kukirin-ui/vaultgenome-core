// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package reconstitution_decision defines the ReconstitutionDecision
// canonical contract — the receive-side terminal authority artifact
// asserting whether the reassembled AI Genome was accepted.
//
// # Doctrinal role
//
// ReconstitutionDecision is the RECEIVE-SIDE MIRROR of ReleaseDecision.
//
// Release side                     Receive side
// ────────────────────────────     ──────────────────────────────────
// ReleaseDecision              →   ReconstitutionDecision
//
//	(Vault authorises release)       (recipient asserts successful reassembly)
//
// A ReleaseDecision says: "I, the Vault, authorise that the Genome
// described by this manifest may be released under this session, on the
// basis of this ValidationResult." A ReconstitutionDecision says: "I,
// the receiving environment, assert that what I received reassembled
// into the same Genome the Vault authorised, as evidenced by this
// receive-side ValidationResultID and this receive-side
// AuditEventID."
//
// The two decisions are made by different authorities, signed by
// different keys, and audited in different chains. The receive-side
// validation threshold (receive-side invariant #5 mirror) and the
// receive-side audit binding (receive-side invariant #8 mirror) are
// structurally required here:
//
//	ValidationResultID MUST be present — an unvalidated reconstitution
//	  is not admissible, just as an unvalidated release is not.
//	AuditEventID MUST be present — an un-evidenced reconstitution is
//	  not admissible, just as an un-evidenced release is not.
//
// The Reason enum is closed; extending it is a schema bump. Unlike
// ReleaseDecision, the receive-side failure modes include cases that
// cannot arise on the release side (for example "reassembly_failed" —
// the receive-side got the disclosures but the ordered concatenation
// did not produce a well-formed Genome).
//
// Corresponds to P1 §[0051]–[0052] (self-bootstrapping) and P3 §[0042].
package reconstitution_decision

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1
)

// Reason enumerates the admissible reason codes. The set is closed; any
// addition is a schema bump.
type Reason string

const (
	// ReasonReconstructedOK — every expected disclosure was received in
	// order, the reassembled Genome hashes to the expected GenomeID,
	// and the receive-side ValidationResult was a full pass.
	ReasonReconstructedOK Reason = "reconstructed_ok"

	// ReasonReassemblyFailed — one or more expected disclosures was
	// missing, out of order, or arrived with a wire-hash mismatch. The
	// Genome cannot be assembled; nothing is reconstituted.
	ReasonReassemblyFailed Reason = "reassembly_failed"

	// ReasonValidationFailed — reassembly produced bytes, but the
	// receive-side validation refused them (operational or
	// behavioural). Reconstitution does NOT take effect.
	ReasonValidationFailed Reason = "validation_failed"
)

// ReconstitutionDecision is the terminal receive-side authority artifact.
type ReconstitutionDecision struct {
	SchemaVersion uint16                       `json:"schema_version"`
	DecisionID    ids.ReconstitutionDecisionID `json:"decision_id"`

	// BootstrapID pins the BootstrapManifest under which the
	// disclosures were accepted. Mirrors ReleaseDecision.ManifestID.
	BootstrapID ids.BootstrapManifestID `json:"bootstrap_id"`

	// SessionID pins the trusted session. MUST agree with the
	// BootstrapManifest.SessionID. Silent session drift between the
	// bootstrap and the decision is a structural violation.
	SessionID ids.SessionID `json:"session_id"`

	// GenomeID identifies the AI Genome the recipient claims was
	// reassembled. Cross-check against BootstrapManifest.GenomeID
	// happens in /internal/bootstrap, not here.
	GenomeID ids.GenomeID `json:"genome_id"`

	// ValidationResultID points at the receive-side ValidationResult
	// that gated this decision. MUST be present; receive-side
	// invariant #5 (validation precedes release) applies here in its
	// mirror form: validation precedes reconstitution.
	ValidationResultID ids.ValidationResultID `json:"validation_result_id"`

	// Accepted is the boolean outcome. True iff the recipient accepts
	// that reconstitution succeeded.
	Accepted bool `json:"accepted"`

	// Reason is the machine-readable reason code, drawn from the
	// closed set. Release/Reason coupling:
	//   reconstructed_ok    → Accepted=true
	//   reassembly_failed   → Accepted=false
	//   validation_failed   → Accepted=false
	Reason Reason `json:"reason"`

	// DecidedAt is the receive-side wall-clock moment the decision
	// was signed.
	DecidedAt time.Time `json:"decided_at"`

	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`

	// AuditEventID points at the RECONSTITUTION_DECIDED audit event
	// that immutably records this decision in the receive-side audit
	// chain. An un-evidenced reconstitution is structurally invalid,
	// mirroring release-side invariant #8.
	AuditEventID ids.AuditEventID `json:"audit_event_id"`
}
