// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package audit_event defines the AuditEvent canonical contract —
// the structured, binder-attached evidence record of an authority decision.
//
// # Doctrinal role
//
// Audit is first-class, not a log line. Every authority decision emits
// AuditEvent records BEFORE the decision becomes visible to its callers.
// VALIDATION_FINDING events in particular must be written before a fail or
// conditional_fail ValidationResult is returned — un-evidenced decisions
// are not governed decisions (docs/doctrine/validation-thresholds.md §9).
//
// AuditEvent records form a hash-chained append-only log. The chain is
// implemented in /internal/audit/chain; this contract is the record shape.
//
// Canonical term: "Audit Event" — docs/doctrine/terminology.md §2, §3.
package audit_event

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	// SchemaVersionMin is held at 1 to keep v1 readers compatible with v1
	// writers. v2 readers MUST be able to consume v1 events; a v1 reader
	// that encounters a v2 event MUST refuse — the new Kind values added
	// at v2 are uninterpretable by a v1 reader, and silently dropping
	// them would break the receive-side audit-first-class invariant.
	SchemaVersionMin uint16 = 1

	// SchemaVersionCurrent / SchemaVersionMax bumped three times:
	//   v1 → v2: Stage F.2 added KindDisclosureReceived and
	//            KindReconstitutionDecided.
	//   v2 → v3: Stage G added KindRecvValidationStarted and
	//            KindRecvValidationCompleted — the audit slots for the
	//            receive-side validator's operational-only dimension
	//            verdict. The struct shape is unchanged; this is purely
	//            a Kind-set extension.
	//   v3 → v4: Phase 4 added four cross-cloud KMS-mediated restore
	//            kinds — KindCrossCloudHandshakeInitiated,
	//            KindCrossCloudAttestationVerified,
	//            KindKeyReleaseAuthorized, KindCrossCloudRestoreCompleted.
	//            These are emitted by the new internal/vault/kms
	//            Coordinator package. Struct shape unchanged.
	//   v4 → v5: ADR 0010 added KindKeyReleaseDenied, so a refused
	//            key release is on the record as a decision of its own,
	//            not only as the absence of an authorisation. Struct
	//            shape unchanged.
	//   v5 → v6: ADR 0012 added KindFailoverDecided: the release
	//            authority's decision, under an operator-signed failover
	//            policy, to move a genome to the standby — or to decline.
	//            Struct shape unchanged.
	// See docs/doctrine/bootstrap-contracts.md §5 (contract-frozen
	// discipline), the Stage F.2 / Stage G doctrine notes in
	// docs/internal/status-journal.md, ADR 0006 (cross-cloud KMS-mediated
	// restore) and ADR 0010 (operator stop and recorded refusals).
	SchemaVersionMax     uint16 = 6
	SchemaVersionCurrent uint16 = 6

	// HashSize is the length in bytes of PrevHash and Hash (SHA-256).
	HashSize = 32
)

// Kind enumerates the event types. The list is frozen at any given
// SchemaVersion; new kinds require a schema-version bump (see the
// SchemaVersion constants above) and a migration plan.
//
// Kinds are partitioned into three families:
//
//   - Release-side (v1, stages 1–8 + incident arcs): the Vault's
//     terminal-authority audit slots — REQUEST_RECEIVED through
//     INCIDENT_TERMINATED.
//   - Receive-side envelope/decision (v2, Stage F): the recipient
//     environment's bootstrap-and-reconstitution audit slots —
//     DISCLOSURE_RECEIVED and RECONSTITUTION_DECIDED. See
//     docs/doctrine/bootstrap-contracts.md.
//   - Receive-side validator (v3, Stage G): the receive-side
//     operational-only validator's audit slots — RECV_VALIDATION_STARTED
//     and RECV_VALIDATION_COMPLETED. These are distinct from the
//     release-side VALIDATION_* kinds because an observer cross-checking
//     the two sides' ledgers must be able to tell release verdicts and
//     receive verdicts apart at the Kind level.
//   - The three families share the AuditEvent envelope contract but are
//     written into separate hash-chained logs (release-side chain vs
//     receive-side chain). The shared envelope keeps the schema small
//     and the cross-side cross-checks straightforward.
type Kind string

const (
	// Release-side Kinds (SchemaVersion 1).
	KindRequestReceived      Kind = "REQUEST_RECEIVED"
	KindTrustEvaluated       Kind = "TRUST_EVALUATED"
	KindSessionIssued        Kind = "SESSION_ISSUED"
	KindSessionInvalidated   Kind = "SESSION_INVALIDATED"
	KindDisclosureAuthorized Kind = "DISCLOSURE_AUTHORIZED"
	KindManifestIssued       Kind = "MANIFEST_ISSUED"
	KindCandidateReceived    Kind = "CANDIDATE_RECEIVED"
	KindValidationStarted    Kind = "VALIDATION_STARTED"
	KindValidationDimension  Kind = "VALIDATION_DIMENSION_EVALUATED"
	KindValidationFinding    Kind = "VALIDATION_FINDING"
	KindValidationCompleted  Kind = "VALIDATION_COMPLETED"
	KindReleaseDecided       Kind = "RELEASE_DECIDED"
	KindIncidentDetected     Kind = "INCIDENT_DETECTED"
	KindIncidentTerminated   Kind = "INCIDENT_TERMINATED"

	// Receive-side Kinds (SchemaVersion 2). Added in Stage F.2 to make
	// receive-side audit a first-class artifact, mirroring release-side
	// invariant #8. See docs/doctrine/bootstrap-contracts.md §2.2 and §2.3.
	//
	// KindDisclosureReceived records the bootstrap orchestrator's
	// acceptance of one DisclosureMessage as a ReceivedDisclosure. The
	// audit record MUST be appended BEFORE the ReceivedDisclosure is
	// surfaced to the caller — the same audit-event-before-message-surface
	// discipline the StagedSequencer applies on the release side.
	KindDisclosureReceived Kind = "DISCLOSURE_RECEIVED"

	// KindReconstitutionDecided records the receive-side terminal
	// ReconstitutionDecision (accept / reassembly_failed / validation_failed).
	// It is the receive-side mirror of KindReleaseDecided and is bound
	// one-to-one to a ReconstitutionDecision via AuditEventID.
	KindReconstitutionDecided Kind = "RECONSTITUTION_DECIDED"

	// Receive-side validator Kinds (SchemaVersion 3). Added in Stage G
	// to bind the receive-side operational-only validator's verdict
	// into the receive-side audit chain. The release-side validator
	// emits VALIDATION_STARTED / VALIDATION_DIMENSION_EVALUATED /
	// VALIDATION_FINDING / VALIDATION_COMPLETED into the release-side
	// chain; the receive-side validator emits only the two terminal
	// markers (start + complete) because its dimension set is a
	// singleton — operational. Per-finding records live inside the
	// completed payload's DimensionVerdict.Details; no separate FINDING
	// kind is introduced.
	//
	// KindRecvValidationStarted is appended BEFORE the validator begins
	// running its six sub-checks. It pins the BootstrapManifest ID,
	// ManifestID, SessionID, and PolicyVersion into the audit chain so
	// an observer can replay the pre-flight binding without seeing the
	// verdict payload itself.
	KindRecvValidationStarted Kind = "RECV_VALIDATION_STARTED"

	// KindRecvValidationCompleted is appended AFTER the validator
	// finalises the DimensionVerdict and BEFORE the verdict is surfaced
	// to the orchestrator (which consumes it to drive MarkValidated or
	// MarkValidationFailed). Its payload carries the ValidationResult
	// ID, overall verdict, and score so cross-ledger observers can
	// confirm the receive-side outcome matches what the decision record
	// cites under ValidationResultID.
	KindRecvValidationCompleted Kind = "RECV_VALIDATION_COMPLETED"

	// Cross-cloud KMS-mediated restore Kinds (SchemaVersion 4). Added
	// in Phase 4 to bind cross-cloud authority decisions into the
	// release-side audit chain. Each cross-cloud restore emits four
	// kinds in strict order:
	//
	//   1. KindCrossCloudHandshakeInitiated — appended BEFORE the
	//      handshake request is dispatched to the destination. Pins
	//      DecisionID, DestinationTEEKind, DestinationEndpoint, and the
	//      handshake nonce into the audit chain so an observer can
	//      verify the cross-cloud flow began without seeing the
	//      destination's response.
	//
	//   2. KindCrossCloudAttestationVerified — appended AFTER local
	//      verification of the destination's Evidence (via the
	//      tee.Registry-resolved verifier) and BEFORE the
	//      KeyReleasePolicy is consulted. Pins the verified
	//      DestinationMeasurement so cross-ledger observers can
	//      confirm the policy decision was made against the same
	//      measurement that was attested.
	//
	//   3. KindKeyReleaseAuthorized — appended AFTER policy approval
	//      and BEFORE the KeyReleaseToken is dispatched. Pins the
	//      destination measurement, the set of KeyIDs released, and
	//      the policy version applied. This is the audit-first-class
	//      slot for the new authority decision introduced by Phase 4
	//      (key release across vendor TEEs).
	//
	//   4. KindCrossCloudRestoreCompleted — appended AFTER the
	//      destination signals successful restore via out-of-band
	//      confirmation. Pins the byte hash of the restored genome
	//      and the destination's local validation outcome.
	//
	// All four kinds are release-side; the receive-side chain records
	// its existing KindDisclosureReceived / KindRecvValidationStarted /
	// KindRecvValidationCompleted / KindReconstitutionDecided as today
	// — the cross-cloud handshake adds NO new receive-side kinds
	// because the receive-side decision points are unchanged (DEKs are
	// simply unwrapped before disclosure messages flow).
	//
	// See ADR 0006 (cross-cloud KMS-mediated restore) §"Audit Kinds (v4)"
	// and §"Detailed Design — Protocol Flow".
	KindCrossCloudHandshakeInitiated  Kind = "CROSS_CLOUD_HANDSHAKE_INITIATED"
	KindCrossCloudAttestationVerified Kind = "CROSS_CLOUD_ATTESTATION_VERIFIED"
	KindKeyReleaseAuthorized          Kind = "KEY_RELEASE_AUTHORIZED"
	KindCrossCloudRestoreCompleted    Kind = "CROSS_CLOUD_RESTORE_COMPLETED"

	// KindKeyReleaseDenied (v5, ADR 0010) closes a cross-cloud flow that
	// did not release: the destination could not prove its key or its
	// TEE, or the operator's policy (allow-list, operator stop) refused
	// it. Appended BEFORE the refusal is returned, so every flow that
	// began with KindCrossCloudHandshakeInitiated and reached a decision
	// ends with exactly one of KEY_RELEASE_AUTHORIZED or
	// KEY_RELEASE_DENIED. Pins the stage, the reason and the policy
	// version (which carries the operator-stop serial).
	KindKeyReleaseDenied Kind = "KEY_RELEASE_DENIED"

	// KindFailoverDecided (v6, ADR 0012) records the release authority's
	// decision on a failover trigger — a compromise report or a lost
	// heartbeat from the primary's sentinel — under the operator-signed
	// failover policy in force: fail over (to the standby the policy names,
	// with the genome it chose) or decline (and why). Appended BEFORE any
	// key moves; a failover then continues as an ordinary cross-cloud
	// release under the decision ID it names, so the handshake, attestation,
	// authorisation and restore that follow link back to it. At most one
	// failover is decided per policy serial.
	KindFailoverDecided Kind = "FAILOVER_DECIDED"
)

// AuditEvent is one record in the hash-chained audit log.
type AuditEvent struct {
	SchemaVersion uint16           `json:"schema_version"`
	EventID       ids.AuditEventID `json:"event_id"`

	Kind Kind `json:"kind"`

	// OccurredAt is the vault-side monotonic timestamp projected to wall-clock.
	OccurredAt time.Time `json:"occurred_at"`

	// SessionID, ManifestID, RequestID — correlators. Any may be empty if
	// not applicable to the event kind.
	SessionID  ids.SessionID  `json:"session_id,omitempty"`
	ManifestID ids.ManifestID `json:"manifest_id,omitempty"`
	RequestID  ids.RequestID  `json:"request_id,omitempty"`

	// Payload is the event-kind-specific structured body. Stage C stores
	// it as an opaque byte slice so the contract shape is stable; Stage D
	// introduces one typed body per Kind.
	Payload []byte `json:"payload"`

	// PrevHash is the SHA-256 of the prior event's canonical-form bytes.
	// The chain's genesis entry has PrevHash of 32 zero bytes.
	PrevHash []byte `json:"prev_hash"`

	// Hash is the SHA-256 of this event's canonical-form bytes
	// (including PrevHash, excluding Signature).
	Hash []byte `json:"hash"`

	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`
}
