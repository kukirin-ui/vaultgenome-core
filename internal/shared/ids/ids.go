// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package ids

// ID is the common behavior of every typed identifier: rendering to a
// plain string and a non-emptiness check. It is NOT a marker interface
// for cross-slot substitution — typed IDs are intentionally not
// mutually assignable.
type ID interface {
	String() string
	IsZero() bool
}

// ---- recovery / admission ---------------------------------------------------

// RequestID identifies a single RecoveryRequest.
type RequestID string

func (v RequestID) String() string { return string(v) }
func (v RequestID) IsZero() bool   { return v == "" }

// AttestationID identifies a single AttestationResult produced by Trust
// Admission.
type AttestationID string

func (v AttestationID) String() string { return string(v) }
func (v AttestationID) IsZero() bool   { return v == "" }

// ---- session / genome ------------------------------------------------------

// SessionID identifies a TrustedSession.
type SessionID string

func (v SessionID) String() string { return string(v) }
func (v SessionID) IsZero() bool   { return v == "" }

// GenomeID identifies the AI Genome being addressed. Never contains
// genome material.
type GenomeID string

func (v GenomeID) String() string { return string(v) }
func (v GenomeID) IsZero() bool   { return v == "" }

// ComponentID identifies one component within an AI Genome.
type ComponentID string

func (v ComponentID) String() string { return string(v) }
func (v ComponentID) IsZero() bool   { return v == "" }

// ---- disclosure / compute --------------------------------------------------

// DisclosureID identifies a single DisclosureMessage.
type DisclosureID string

func (v DisclosureID) String() string { return string(v) }
func (v DisclosureID) IsZero() bool   { return v == "" }

// ManifestID identifies a ReconstructionJobManifest.
type ManifestID string

func (v ManifestID) String() string { return string(v) }
func (v ManifestID) IsZero() bool   { return v == "" }

// ContinuityProofID identifies a single ContinuityProof bundle — the
// keystone artifact that binds an AGD's ancestry, behavioral probe
// scorecard, and witness-log inclusion into one stateless-verifiable
// object. The ID is assigned by the issuer; it is NOT content-addressed
// (the bytes are already self-authenticating via the authority
// signature), but it gives operators a stable handle for audit and
// operational logging.
type ContinuityProofID string

func (v ContinuityProofID) String() string { return string(v) }
func (v ContinuityProofID) IsZero() bool   { return v == "" }

// ---- validation / release --------------------------------------------------

// ValidationResultID identifies a ValidationResult.
type ValidationResultID string

func (v ValidationResultID) String() string { return string(v) }
func (v ValidationResultID) IsZero() bool   { return v == "" }

// DecisionID identifies a ReleaseDecision.
type DecisionID string

func (v DecisionID) String() string { return string(v) }
func (v DecisionID) IsZero() bool   { return v == "" }

// ---- audit -----------------------------------------------------------------

// AuditEventID identifies an AuditEvent in the hash-chained log.
type AuditEventID string

func (v AuditEventID) String() string { return string(v) }
func (v AuditEventID) IsZero() bool   { return v == "" }

// ---- bootstrap / receive-side ---------------------------------------------
//
// The bootstrap family mirrors the release-side contracts on the receive
// side. Release-side contracts (ReconstructionJobManifest, DisclosureMessage,
// ReleaseDecision) describe what the Vault AUTHORIZES; bootstrap contracts
// describe what the receiving environment ACCEPTED, in what order, and
// whether reconstitution succeeded. The two shapes are deliberately
// separate: silent drift between "authorized" and "received" is the class
// of bug the doctrine is set up to make structurally impossible.
//
// Corresponds to P1 §[0051]–[0052] (self-bootstrapping) and P3 §[0042].

// BootstrapManifestID identifies one BootstrapManifest — the receive-side
// recipe that names which disclosures are expected, in which order, bound
// to which SessionID. The ID is assigned by the receiving environment's
// bootstrap orchestrator.
type BootstrapManifestID string

func (v BootstrapManifestID) String() string { return string(v) }
func (v BootstrapManifestID) IsZero() bool   { return v == "" }

// ReceivedDisclosureID identifies one ReceivedDisclosure — the receive-side
// record of a single DisclosureMessage that was accepted, including the
// SHA-256 over the wire bytes. NOT equal to the release-side DisclosureID;
// the receive-side allocates its own handle so that an observer comparing
// the two ledgers can see identity mismatch without confusion.
type ReceivedDisclosureID string

func (v ReceivedDisclosureID) String() string { return string(v) }
func (v ReceivedDisclosureID) IsZero() bool   { return v == "" }

// ReconstitutionDecisionID identifies one ReconstitutionDecision — the
// receive-side terminal artifact asserting whether the reassembled AI
// Genome matches the release-side ContinuityProof. Mirror of DecisionID
// on the release side.
type ReconstitutionDecisionID string

func (v ReconstitutionDecisionID) String() string { return string(v) }
func (v ReconstitutionDecisionID) IsZero() bool   { return v == "" }

// ---- key material ----------------------------------------------------------

// KeyID identifies a signing or sealing key held by the vault. It is
// opaque to all callers except /internal/vault/keys and /internal/shared/tee.
type KeyID string

func (v KeyID) String() string { return string(v) }
func (v KeyID) IsZero() bool   { return v == "" }

// PolicyVersion identifies a specific revision of the active Policy. It
// is not an ID in the same sense as the above — two artifacts legitimately
// share a PolicyVersion — but it carries the same typed-string discipline.
type PolicyVersion string

func (v PolicyVersion) String() string { return string(v) }
func (v PolicyVersion) IsZero() bool   { return v == "" }
