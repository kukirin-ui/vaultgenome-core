// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"bytes"
	"encoding/hex"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/received_disclosure"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Stable per-orchestrator error codes. The agreement/validator codes
// cover what happens before any bytes arrive; the codes below cover the
// acceptance loop itself.
const (
	CodeAlreadyStarted              = "bootstrap.already_started"
	CodeNotYetStarted               = "bootstrap.not_started"
	CodeAlreadyDecided              = "bootstrap.already_decided"
	CodeIllegalTransition           = "bootstrap.illegal_transition"
	CodeAcceptWrongState            = "bootstrap.accept_wrong_state"
	CodeAcceptSessionMismatch       = "bootstrap.accept.session_mismatch"
	CodeAcceptPolicyMismatch        = "bootstrap.accept.policy_mismatch"
	CodeAcceptDisclosureNotExpected = "bootstrap.accept.disclosure_not_expected"
	CodeAcceptOutOfOrder            = "bootstrap.accept.out_of_order"
	CodeAcceptComponentMismatch     = "bootstrap.accept.component_mismatch"
	CodeAcceptSequenceMismatch      = "bootstrap.accept.sequence_mismatch"
	CodeAcceptWireHashMismatch      = "bootstrap.accept.wire_hash_mismatch"
)

// DefaultOrchestratorAuditIDPrefix, DefaultOrchestratorDisclosureIDPrefix,
// and DefaultOrchestratorDecisionIDPrefix prefix the receive-side
// identifiers the orchestrator mints. Production deployments may
// override to embed a deployment tag.
const (
	DefaultOrchestratorAuditIDPrefix      = "audit-recv-"
	DefaultOrchestratorDisclosureIDPrefix = "recv-disclosure-"
	DefaultOrchestratorDecisionIDPrefix   = "recv-decision-"
)

// OrchestratorOptions collects all construction-time dependencies. The
// orchestrator needs three signing capabilities (receive-side
// authority signer for the manifest envelope of ReceivedDisclosures
// and the ReconstitutionDecision; audit signer for the receive-side
// audit chain) plus the cross-artifact dependencies.
type OrchestratorOptions struct {
	// Manifest is the receive-side BootstrapManifest this orchestrator
	// admits. Required; must already be signed and its signature must
	// verify against the receive-side signing authority.
	Manifest *bootstrap_manifest.BootstrapManifest

	// JobManifest is the release-side ReconstructionJobManifest that
	// Manifest mirrors. Required; cross-manifest agreement with
	// Manifest is checked in Start.
	JobManifest *reconstruction_job_manifest.ReconstructionJobManifest

	// ExpectedWireHashes is the ordered list of canonical-cover SHA-256
	// hashes of the DisclosureMessages the release-side will emit. The
	// receive-side commits to these values up front so that every
	// Accept can verify the wire-hash locally, without depending on
	// out-of-band channels. Length MUST equal len(Manifest.
	// ExpectedDisclosureIDs); each element MUST be exactly 32 bytes.
	ExpectedWireHashes [][]byte

	// AuditChain is the receive-side hash-chained audit log. DISCLOSURE_RECEIVED
	// and RECONSTITUTION_DECIDED events are appended here. Required.
	AuditChain chain.Chain

	// AuditSigner signs AuditEvent records. Bound to
	// keys.PurposeSigningAudit. Required non-nil.
	AuditSigner keys.Signer

	// AuditKeyID is the KeyID under which AuditSigner was registered.
	// Required non-zero.
	AuditKeyID ids.KeyID

	// RecvAuthoritySigner signs ReceivedDisclosure and
	// ReconstitutionDecision. Bound to keys.PurposeSigningAuthority
	// (receive-side — operationally distinct from the Vault's
	// authority key, see docs/doctrine/bootstrap-contracts.md §4).
	RecvAuthoritySigner keys.Signer

	// RecvAuthorityKeyID is the KeyID under which RecvAuthoritySigner
	// was registered. Required non-zero.
	RecvAuthorityKeyID ids.KeyID

	// Clock is the receive-side monotonic clock. Timestamps on
	// ReceivedDisclosure.ReceivedAt, AuditEvent.OccurredAt, and
	// ReconstitutionDecision.DecidedAt come from Clock.Now().
	// Required non-nil.
	Clock shared_time.Clock

	// AuditIDPrefix / DisclosureIDPrefix / DecisionIDPrefix override
	// the default ID prefixes. Empty means use the package default.
	AuditIDPrefix      string
	DisclosureIDPrefix string
	DecisionIDPrefix   string
}

// Orchestrator is the receive-side state machine driver. One
// Orchestrator drives one BootstrapManifest to exactly one terminal
// ReconstitutionDecision.
type Orchestrator struct {
	mu sync.Mutex

	bm    *bootstrap_manifest.BootstrapManifest
	rjm   *reconstruction_job_manifest.ReconstructionJobManifest
	wireH [][]byte
	chain chain.Chain
	clock shared_time.Clock

	auditSigner keys.Signer
	auditKID    ids.KeyID
	recvSigner  keys.Signer
	recvSigKID  ids.KeyID

	auditPrefix    string
	discPrefix     string
	decisionPrefix string

	state State

	// received holds the signed ReceivedDisclosure records in arrival
	// order. Length equals the number of successful Accept calls.
	received []received_disclosure.ReceivedDisclosure

	// latched rejection state. Set by MarkReassemblyFailed,
	// MarkValidationFailed, or a refused Accept. Consumed by Decide.
	latchedReason *reconstitution_decision.Reason
	latchedVRID   ids.ValidationResultID

	// validatedVRID is set by MarkValidated for the accepted-path case.
	validatedVRID ids.ValidationResultID

	// decision, once set by Decide, is the terminal signed artifact.
	// Subsequent Decide calls refuse with CodeAlreadyDecided.
	decision *reconstitution_decision.ReconstitutionDecision

	// Monotonic counters for deterministic ID minting within the
	// lifetime of one Orchestrator.
	auditCtr uint64
	discCtr  uint64
}

// NewOrchestrator constructs an orchestrator. All OrchestratorOptions
// invariants are checked here; a refusal is Structural.
//
// NewOrchestrator does NOT verify the manifest signatures, run the
// per-artifact validators, or check cross-manifest agreement. Those
// are deferred to Start so that tests may inject pre-populated
// fixtures without re-performing work the Start call always performs.
func NewOrchestrator(opts OrchestratorOptions) (*Orchestrator, error) {
	if opts.Manifest == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: manifest is required",
			nil,
		)
	}
	if opts.JobManifest == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: job_manifest is required",
			nil,
		)
	}
	if opts.AuditChain == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: audit_chain is required",
			nil,
		)
	}
	if opts.AuditSigner == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: audit_signer is required",
			nil,
		)
	}
	if opts.AuditKeyID.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: audit_key_id is required",
			nil,
		)
	}
	if opts.RecvAuthoritySigner == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: recv_authority_signer is required",
			nil,
		)
	}
	if opts.RecvAuthorityKeyID.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: recv_authority_key_id is required",
			nil,
		)
	}
	if opts.Clock == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: clock is required",
			nil,
		)
	}

	// Defensive guard: the ExpectedWireHashes slice must parallel the
	// Manifest.ExpectedDisclosureIDs slice exactly. A length mismatch
	// here would mean we have no way to verify the Kth disclosure, so
	// the orchestrator refuses to start.
	n := len(opts.Manifest.ExpectedDisclosureIDs)
	if len(opts.ExpectedWireHashes) != n {
		return nil, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"bootstrap.orchestrator: expected_wire_hashes length must equal manifest.expected_disclosure_ids length",
			nil,
		)
	}
	for i, h := range opts.ExpectedWireHashes {
		if len(h) != crypto.HashSize {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"bootstrap.orchestrator: expected_wire_hashes["+positionLabel(i)+"] must be exactly 32 bytes (SHA-256)",
				nil,
			)
		}
	}

	// Deep-copy the wire-hashes so the caller cannot mutate them after
	// construction. The manifests are pointers-in by design (we want
	// identity for pre-validated fixtures) but the hash arrays are
	// defensive.
	hashesCopy := make([][]byte, n)
	for i, h := range opts.ExpectedWireHashes {
		cp := make([]byte, crypto.HashSize)
		copy(cp, h)
		hashesCopy[i] = cp
	}

	o := &Orchestrator{
		bm:             opts.Manifest,
		rjm:            opts.JobManifest,
		wireH:          hashesCopy,
		chain:          opts.AuditChain,
		clock:          opts.Clock,
		auditSigner:    opts.AuditSigner,
		auditKID:       opts.AuditKeyID,
		recvSigner:     opts.RecvAuthoritySigner,
		recvSigKID:     opts.RecvAuthorityKeyID,
		auditPrefix:    opts.AuditIDPrefix,
		discPrefix:     opts.DisclosureIDPrefix,
		decisionPrefix: opts.DecisionIDPrefix,
		state:          StateUnstarted,
		received:       make([]received_disclosure.ReceivedDisclosure, 0, n),
	}
	if o.auditPrefix == "" {
		o.auditPrefix = DefaultOrchestratorAuditIDPrefix
	}
	if o.discPrefix == "" {
		o.discPrefix = DefaultOrchestratorDisclosureIDPrefix
	}
	if o.decisionPrefix == "" {
		o.decisionPrefix = DefaultOrchestratorDecisionIDPrefix
	}
	return o, nil
}

// State returns the current state under the orchestrator's mutex.
// Primarily for tests and observability; production code should drive
// transitions through the explicit step methods rather than inspecting
// state.
func (o *Orchestrator) State() State {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.state
}

// ReceivedCount returns the number of successfully accepted disclosures.
func (o *Orchestrator) ReceivedCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.received)
}

// Start advances StateUnstarted → StateIngress after:
//
//   - Running the BootstrapManifest validator.
//   - Verifying the BootstrapManifest signature under the receive-side
//     signing-authority key (via opts.RecvAuthoritySigner, which also
//     implements keys.Resolver in the standard InMemoryStore case).
//   - Checking cross-manifest agreement against the
//     ReconstructionJobManifest via CheckAgreement. This is the only
//     place in the codebase where both manifests are held at once.
//
// On any refusal the state stays at StateUnstarted; the caller can
// construct a fresh Orchestrator if it wants to retry under a different
// configuration. The orchestrator never silently consumes a manifest.
func (o *Orchestrator) Start() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.state != StateUnstarted {
		return shared_errors.Structural(
			CodeAlreadyStarted,
			"bootstrap.orchestrator: Start called twice",
			nil,
		)
	}

	if err := o.bm.Validate(); err != nil {
		return err
	}

	// Receive-side signature verification. The RecvAuthoritySigner
	// doubles as a Resolver in the standard InMemoryStore case —
	// verify by type assertion; otherwise skip (tests may inject a
	// signer-only double and handle verification externally).
	if resolver, ok := o.recvSigner.(keys.Resolver); ok {
		if err := o.bm.VerifySignature(resolver); err != nil {
			return err
		}
	}

	if err := CheckAgreement(o.bm, o.rjm); err != nil {
		return err
	}

	o.state = StateIngress
	return nil
}

// Accept admits one DisclosureMessage. Semantics:
//
//  1. The orchestrator MUST be in StateIngress. Otherwise the call
//     is refused with CodeAcceptWrongState (Structural) — this prevents
//     late-arriving disclosures in StateReassemble/Validate/Ready from
//     silently widening the accepted set.
//
//  2. The disclosure is checked against the manifest-committed slot:
//     SessionID, PolicyVersion, DisclosureID, ComponentID,
//     SequenceIndex, and wire-hash MUST all match the manifest entry at
//     position len(received). The disclosure's own Validate() is
//     invoked first so malformed messages are rejected early.
//
//  3. On match, the orchestrator:
//     a. appends a DISCLOSURE_RECEIVED AuditEvent (BEFORE surfacing
//     the ReceivedDisclosure — receive-side invariant #8 mirror);
//     b. constructs, signs, and records a ReceivedDisclosure bound
//     to the audit event;
//     c. returns a copy of the ReceivedDisclosure to the caller.
//     If all expected disclosures have now been received, the state
//     advances to StateReassemble.
//
//  4. On any mismatch, the orchestrator latches
//     Reason=reassembly_failed, transitions to StateRejected, and
//     returns the refusal error. The caller must still call Decide to
//     emit the signed rejection artifact.
//
// Accept is serialized under the orchestrator's mutex; concurrent
// callers block in arrival order.
func (o *Orchestrator) Accept(msg *disclosure_message.DisclosureMessage) (*received_disclosure.ReceivedDisclosure, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.state != StateIngress {
		return nil, shared_errors.Structural(
			CodeAcceptWrongState,
			"bootstrap.orchestrator: Accept is only legal in StateIngress; current state is "+o.state.String(),
			nil,
		)
	}
	if msg == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: disclosure message is nil",
			nil,
		)
	}
	if err := msg.Validate(); err != nil {
		// A malformed message is a protocol-level refusal; latch as a
		// reassembly failure and transition.
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, err
	}

	// Position check: which slot is this disclosure meant to fill?
	slot := len(o.received)
	if slot >= len(o.bm.ExpectedDisclosureIDs) {
		// Should be unreachable because we would have already
		// transitioned out of Ingress on the last success, but be
		// defensive.
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, shared_errors.Structural(
			CodeAcceptOutOfOrder,
			"bootstrap.orchestrator: accepted more disclosures than expected",
			nil,
		)
	}

	expDID := o.bm.ExpectedDisclosureIDs[slot]
	expCID := o.bm.ExpectedComponentIDs[slot]
	expHash := o.wireH[slot]

	if msg.SessionID != o.bm.SessionID {
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, shared_errors.Structural(
			CodeAcceptSessionMismatch,
			"bootstrap.orchestrator: disclosure session_id does not match bootstrap manifest",
			nil,
		)
	}
	if msg.PolicyVersion != o.bm.PolicyVersion {
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, shared_errors.Structural(
			CodeAcceptPolicyMismatch,
			"bootstrap.orchestrator: disclosure policy_version does not match bootstrap manifest",
			nil,
		)
	}
	if msg.DisclosureID != expDID {
		// Distinguish "ID exists in manifest but out of order" from
		// "ID not in manifest at all" — both are rejections, but the
		// codes aid diagnosis.
		if o.manifestContainsDisclosure(msg.DisclosureID) {
			o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
			return nil, shared_errors.Structural(
				CodeAcceptOutOfOrder,
				"bootstrap.orchestrator: disclosure "+msg.DisclosureID.String()+" is expected but not at slot "+positionLabel(slot),
				nil,
			)
		}
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, shared_errors.Structural(
			CodeAcceptDisclosureNotExpected,
			"bootstrap.orchestrator: disclosure "+msg.DisclosureID.String()+" is not in ExpectedDisclosureIDs",
			nil,
		)
	}
	if msg.ComponentID != expCID {
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, shared_errors.Structural(
			CodeAcceptComponentMismatch,
			"bootstrap.orchestrator: disclosure component_id does not match manifest slot",
			nil,
		)
	}
	if uint32(slot) != msg.SequenceIndex {
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, shared_errors.Structural(
			CodeAcceptSequenceMismatch,
			"bootstrap.orchestrator: disclosure sequence_index does not match arrival slot",
			nil,
		)
	}

	// Wire-hash check: SHA-256 over the DisclosureMessage canonical
	// cover-bytes (the same bytes the release-side Signature covers)
	// MUST equal the committed expected hash. If not, the message was
	// altered in flight or a different message was re-signed — either
	// way the receive-side refuses.
	cb, err := msg.CanonicalBytes()
	if err != nil {
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, err
	}
	actualHash := crypto.SHA256Slice(cb)
	if !bytes.Equal(actualHash, expHash) {
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, shared_errors.Integrity(
			CodeAcceptWireHashMismatch,
			"bootstrap.orchestrator: disclosure wire-hash does not match committed hash for slot "+positionLabel(slot),
			nil,
		)
	}

	// ---- Audit-event-before-record-surface discipline ----
	//
	// Append the DISCLOSURE_RECEIVED event BEFORE constructing the
	// ReceivedDisclosure record we return to the caller. This
	// mirrors the release-side StagedSequencer's
	// "audit-event-before-message-surface" discipline. An audit-append
	// failure halts the Orchestrator with latched rejection and
	// surfaces the error to the caller; no ReceivedDisclosure is
	// issued in that case.
	now := o.clock.Now().UTC()
	payload, err := buildDisclosureReceivedPayload(o.bm, msg, actualHash, uint32(slot))
	if err != nil {
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, err
	}
	o.auditCtr++
	eventSkel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(o.auditPrefix + "disc-" + hex.EncodeToString(counterBytes(o.auditCtr))),
		Kind:          audit_event.KindDisclosureReceived,
		OccurredAt:    now,
		SessionID:     msg.SessionID,
		ManifestID:    o.bm.ManifestID,
		Payload:       payload,
		SigningKeyID:  o.auditKID,
	}
	sealed, err := o.chain.Append(eventSkel, o.auditSigner)
	if err != nil {
		// Chain-append failure is terminal for this orchestrator: an
		// audit gap would break the first-class-audit invariant.
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, err
	}

	// ---- Construct and sign the ReceivedDisclosure record ----
	o.discCtr++
	rd := received_disclosure.ReceivedDisclosure{
		SchemaVersion: received_disclosure.SchemaVersionCurrent,
		ReceivedID:    ids.ReceivedDisclosureID(o.discPrefix + hex.EncodeToString(counterBytes(o.discCtr))),
		BootstrapID:   o.bm.BootstrapID,
		SessionID:     msg.SessionID,
		DisclosureID:  msg.DisclosureID,
		ComponentID:   msg.ComponentID,
		SequenceIndex: uint32(slot),
		WireHash:      append([]byte(nil), actualHash...),
		ReceivedAt:    now,
		AuditEventID:  sealed.EventID,
		SigningKeyID:  o.recvSigKID,
	}
	if err := rd.SignWith(o.recvSigner); err != nil {
		// The audit event has already been appended; we cannot
		// retroactively remove it. Any signing failure after the
		// audit event is final: latch and surface. The chain now
		// records the DISCLOSURE_RECEIVED event but the paired
		// ReceivedDisclosure was never issued. Observers
		// cross-checking the ledgers will see the missing pair and
		// correctly conclude the bootstrap failed. This is the
		// intended semantic.
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, err
	}
	if err := rd.Validate(); err != nil {
		o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
		return nil, err
	}

	o.received = append(o.received, rd)

	// If this was the last expected disclosure, auto-transition to
	// StateReassemble. The reassembly engine itself is out of scope
	// here (Stage F.3); the orchestrator simply signals to the caller
	// that the ingress window is now closed.
	if len(o.received) == len(o.bm.ExpectedDisclosureIDs) {
		o.state = StateReassemble
	}

	out := rd // returning by value; WireHash/Signature/Payload slices
	// are backed by the stored record but the caller cannot
	// retroactively un-record an accepted disclosure. This
	// matches StagedSequencer's pattern.
	return &out, nil
}

// MarkReassembled advances StateReassemble → StateValidate after the
// injected reassembly engine has produced a well-formed Genome
// candidate. No on-disk or in-memory bytes are passed in — reassembly
// is the caller's responsibility and remains out of scope for this
// package.
func (o *Orchestrator) MarkReassembled() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.state != StateReassemble {
		return shared_errors.Structural(
			CodeIllegalTransition,
			"bootstrap.orchestrator: MarkReassembled legal only in StateReassemble; current state is "+o.state.String(),
			nil,
		)
	}
	o.state = StateValidate
	return nil
}

// MarkReassemblyFailed latches Reason=reassembly_failed and transitions
// to StateRejected from StateReassemble. The caller must still call
// Decide to emit the signed rejection artifact.
func (o *Orchestrator) MarkReassemblyFailed() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.state != StateReassemble {
		return shared_errors.Structural(
			CodeIllegalTransition,
			"bootstrap.orchestrator: MarkReassemblyFailed legal only in StateReassemble; current state is "+o.state.String(),
			nil,
		)
	}
	o.latchRejection(reconstitution_decision.ReasonReassemblyFailed, ids.ValidationResultID(""))
	return nil
}

// MarkValidated advances StateValidate → StateReady on a successful
// receive-side validation. vrid is the receive-side ValidationResult
// ID that gates the decision.
func (o *Orchestrator) MarkValidated(vrid ids.ValidationResultID) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.state != StateValidate {
		return shared_errors.Structural(
			CodeIllegalTransition,
			"bootstrap.orchestrator: MarkValidated legal only in StateValidate; current state is "+o.state.String(),
			nil,
		)
	}
	if vrid.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: validation_result_id required on MarkValidated",
			nil,
		)
	}
	o.validatedVRID = vrid
	o.state = StateReady
	return nil
}

// MarkValidationFailed latches Reason=validation_failed and transitions
// to StateRejected from StateValidate. vrid is the receive-side
// ValidationResult ID that produced the refusal. The caller must still
// call Decide to emit the signed rejection artifact.
func (o *Orchestrator) MarkValidationFailed(vrid ids.ValidationResultID) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.state != StateValidate {
		return shared_errors.Structural(
			CodeIllegalTransition,
			"bootstrap.orchestrator: MarkValidationFailed legal only in StateValidate; current state is "+o.state.String(),
			nil,
		)
	}
	if vrid.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.orchestrator: validation_result_id required on MarkValidationFailed",
			nil,
		)
	}
	o.latchRejection(reconstitution_decision.ReasonValidationFailed, vrid)
	return nil
}

// Decide emits the terminal signed ReconstitutionDecision.
//
//   - From StateReady → StateReconstituted with Accepted=true,
//     Reason=reconstructed_ok.
//   - From StateRejected (set by any Mark*Failed or refused Accept) →
//     stays at StateRejected, emits Accepted=false with the latched
//     Reason.
//
// A subsequent Decide refuses with CodeAlreadyDecided. Decide appends
// a RECONSTITUTION_DECIDED audit event BEFORE returning the signed
// decision — same first-class-audit discipline as the release-side
// ReleaseDecision path.
func (o *Orchestrator) Decide() (*reconstitution_decision.ReconstitutionDecision, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.decision != nil {
		return nil, shared_errors.Structural(
			CodeAlreadyDecided,
			"bootstrap.orchestrator: Decide called after terminal decision",
			nil,
		)
	}

	var (
		accepted bool
		reason   reconstitution_decision.Reason
		vrid     ids.ValidationResultID
	)
	switch o.state {
	case StateReady:
		accepted = true
		reason = reconstitution_decision.ReasonReconstructedOK
		vrid = o.validatedVRID
		if vrid.IsZero() {
			// Defensive: MarkValidated must have set this.
			return nil, shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"bootstrap.orchestrator: StateReady reached without validated ValidationResultID",
				nil,
			)
		}
	case StateRejected:
		if o.latchedReason == nil {
			return nil, shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"bootstrap.orchestrator: StateRejected without latched reason",
				nil,
			)
		}
		accepted = false
		reason = *o.latchedReason
		vrid = o.latchedVRID
		// For reassembly_failed cases the receive-side never ran
		// validation; we still require a ValidationResultID on the
		// ReconstitutionDecision contract. Mint a sentinel bound to
		// the bootstrap — observers cross-checking ledgers can tell
		// the difference by reading the Reason.
		if vrid.IsZero() {
			vrid = ids.ValidationResultID("vr-recv-noop-" + o.bm.BootstrapID.String())
		}
	default:
		return nil, shared_errors.Structural(
			CodeIllegalTransition,
			"bootstrap.orchestrator: Decide legal only in StateReady or StateRejected; current state is "+o.state.String(),
			nil,
		)
	}

	now := o.clock.Now().UTC()

	// Construct the decision record first (with placeholder AuditEventID);
	// we need the decision ID for the audit payload, and the audit
	// event's EventID goes back into the decision. The release-side
	// ReleaseDecision path does the same two-phase construction.
	//
	// The decision counter is seeded from 1 because one Orchestrator
	// produces at most one ReconstitutionDecision — a fresh counter
	// is cleaner than reusing an existing one.
	decisionID := ids.ReconstitutionDecisionID(
		o.decisionPrefix + hex.EncodeToString(counterBytes(1)) +
			"-" + o.bm.BootstrapID.String(),
	)
	rd := reconstitution_decision.ReconstitutionDecision{
		SchemaVersion:      reconstitution_decision.SchemaVersionCurrent,
		DecisionID:         decisionID,
		BootstrapID:        o.bm.BootstrapID,
		SessionID:          o.bm.SessionID,
		GenomeID:           o.bm.GenomeID,
		ValidationResultID: vrid,
		Accepted:           accepted,
		Reason:             reason,
		DecidedAt:          now,
		SigningKeyID:       o.recvSigKID,
	}

	// Audit-event-before-decision-surface.
	payload, err := buildReconstitutionDecidedPayload(o.bm, &rd)
	if err != nil {
		return nil, err
	}
	o.auditCtr++
	eventSkel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(o.auditPrefix + "dec-" + hex.EncodeToString(counterBytes(o.auditCtr))),
		Kind:          audit_event.KindReconstitutionDecided,
		OccurredAt:    now,
		SessionID:     o.bm.SessionID,
		ManifestID:    o.bm.ManifestID,
		Payload:       payload,
		SigningKeyID:  o.auditKID,
	}
	sealed, err := o.chain.Append(eventSkel, o.auditSigner)
	if err != nil {
		return nil, err
	}
	rd.AuditEventID = sealed.EventID

	if err := rd.SignWith(o.recvSigner); err != nil {
		return nil, err
	}
	if err := rd.Validate(); err != nil {
		return nil, err
	}

	o.decision = &rd
	// Transition only on accept; on reject we stay in StateRejected
	// (which is terminal by the state-machine table).
	if accepted {
		o.state = StateReconstituted
	}
	out := rd
	return &out, nil
}

// Decision returns the terminal ReconstitutionDecision if Decide has
// been called; nil otherwise. Returned copy is safe to inspect.
func (o *Orchestrator) Decision() *reconstitution_decision.ReconstitutionDecision {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.decision == nil {
		return nil
	}
	cp := *o.decision
	return &cp
}

// Received returns a defensive copy of the accepted
// ReceivedDisclosure slice.
func (o *Orchestrator) Received() []received_disclosure.ReceivedDisclosure {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]received_disclosure.ReceivedDisclosure, len(o.received))
	copy(out, o.received)
	return out
}

// ---- internal helpers -----------------------------------------------------

// latchRejection marks the orchestrator as in the rejected terminal
// with the given reason and (optional) vrid. Idempotent on re-call
// with the same reason; preserves the first latch if a different
// reason is supplied.
//
// Called under o.mu.
func (o *Orchestrator) latchRejection(reason reconstitution_decision.Reason, vrid ids.ValidationResultID) {
	if o.latchedReason == nil {
		r := reason
		o.latchedReason = &r
		o.latchedVRID = vrid
	}
	o.state = StateRejected
}

// manifestContainsDisclosure reports whether did appears anywhere in
// ExpectedDisclosureIDs. Used to classify Accept refusals more
// precisely than a single bucket.
//
// Called under o.mu.
func (o *Orchestrator) manifestContainsDisclosure(did ids.DisclosureID) bool {
	for _, x := range o.bm.ExpectedDisclosureIDs {
		if x == did {
			return true
		}
	}
	return false
}

// counterBytes renders a 64-bit counter in big-endian form for
// lexicographically sortable hex-encoded IDs.
func counterBytes(n uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(n & 0xFF)
		n >>= 8
	}
	return b[:]
}

// ---- audit payload shapes -------------------------------------------------

// disclosureReceivedPayload is the canonical-JSON body of a
// DISCLOSURE_RECEIVED AuditEvent. It commits to the provenance
// binding of the acceptance: session, component, disclosure,
// sequence slot, policy version, and the wire-hash the receive-side
// verified.
type disclosureReceivedPayload struct {
	SessionID     ids.SessionID           `json:"session_id"`
	ManifestID    ids.ManifestID          `json:"manifest_id"`
	BootstrapID   ids.BootstrapManifestID `json:"bootstrap_id"`
	ComponentID   ids.ComponentID         `json:"component_id"`
	DisclosureID  ids.DisclosureID        `json:"disclosure_id"`
	SequenceIndex uint32                  `json:"sequence_index"`
	PolicyVersion ids.PolicyVersion       `json:"policy_version"`
	WireHash      string                  `json:"wire_hash"` // hex SHA-256 over release-side canonical cover-bytes
}

func buildDisclosureReceivedPayload(bm *bootstrap_manifest.BootstrapManifest, msg *disclosure_message.DisclosureMessage, wireHash []byte, slot uint32) ([]byte, error) {
	p := disclosureReceivedPayload{
		SessionID:     msg.SessionID,
		ManifestID:    bm.ManifestID,
		BootstrapID:   bm.BootstrapID,
		ComponentID:   msg.ComponentID,
		DisclosureID:  msg.DisclosureID,
		SequenceIndex: slot,
		PolicyVersion: msg.PolicyVersion,
		WireHash:      hex.EncodeToString(wireHash),
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"bootstrap.orchestrator: audit payload encode failed",
			err,
		)
	}
	return out, nil
}

// reconstitutionDecidedPayload is the canonical-JSON body of a
// RECONSTITUTION_DECIDED AuditEvent. It commits to the acceptance
// outcome, the bound ValidationResultID, and the DecisionID. The
// signed ReconstitutionDecision itself is not inlined — the
// AuditEventID binding on the decision closes the loop.
type reconstitutionDecidedPayload struct {
	DecisionID         ids.ReconstitutionDecisionID `json:"decision_id"`
	BootstrapID        ids.BootstrapManifestID      `json:"bootstrap_id"`
	SessionID          ids.SessionID                `json:"session_id"`
	ManifestID         ids.ManifestID               `json:"manifest_id"`
	GenomeID           ids.GenomeID                 `json:"genome_id"`
	ValidationResultID ids.ValidationResultID       `json:"validation_result_id"`
	Accepted           bool                         `json:"accepted"`
	Reason             string                       `json:"reason"`
}

func buildReconstitutionDecidedPayload(bm *bootstrap_manifest.BootstrapManifest, rd *reconstitution_decision.ReconstitutionDecision) ([]byte, error) {
	p := reconstitutionDecidedPayload{
		DecisionID:         rd.DecisionID,
		BootstrapID:        rd.BootstrapID,
		SessionID:          rd.SessionID,
		ManifestID:         bm.ManifestID,
		GenomeID:           rd.GenomeID,
		ValidationResultID: rd.ValidationResultID,
		Accepted:           rd.Accepted,
		Reason:             string(rd.Reason),
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"bootstrap.orchestrator: audit payload encode failed",
			err,
		)
	}
	return out, nil
}
