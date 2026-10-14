// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure

import (
	"encoding/hex"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// DefaultSequencerAuditIDPrefix is prepended to a monotonic counter when
// a StagedSequencer generates AuditEventIDs for DISCLOSURE_AUTHORIZED
// events. Production deployments may override to embed a deployment tag.
const DefaultSequencerAuditIDPrefix = "audit-disclosure-"

// AuditSink is the narrow capability the sequencer needs to append
// audit events. audit/chain.Chain satisfies this; tests may substitute
// an in-memory double.
//
// The sequencer deliberately takes AuditSink rather than the full
// chain.Chain interface — this keeps the dependency surface one method
// wide and prevents the sequencer from accidentally reading chain
// state.
type AuditSink interface {
	Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error)
}

// Component is one pre-declared unit of the release-side disclosure
// sequence. Plaintext is the only plaintext surface in the whole
// sequencer API — it flows from caller → StagedIssuer.Emit →
// GCM-Seal → DisclosureMessage.SealedPayload → wire. The sequencer
// passes Plaintext through by reference; StagedIssuer.Emit zeroizes
// it in place before returning. Callers that need to retain the
// plaintext for their own bookkeeping should copy the bytes BEFORE
// adding the Component to the run.
type Component struct {
	// ID names the component being released. The pairing
	// (SessionID, ComponentID, SequenceIndex) must be unique across
	// the entire disclosure timeline; the sequencer enforces this
	// indirectly by refusing to continue after a refused emission.
	ID ids.ComponentID

	// Plaintext is the raw component material. REQUIRED non-empty.
	// ZEROIZED IN PLACE by the time Run returns, both on success and
	// on every refusal path (inherited from StagedIssuer.Emit).
	Plaintext []byte

	// RecipientKeyID identifies the external-compute binding key
	// for this specific component. REQUIRED non-zero. Different
	// components in the same run MAY bind to different recipients.
	RecipientKeyID ids.KeyID
}

// SequencerOptions configures a StagedSequencer. Zero values fall back
// to package defaults.
type SequencerOptions struct {
	// AuditSink, if non-nil, receives one appended event per
	// successful emission (Kind = DISCLOSURE_AUTHORIZED). Nil means
	// the sequencer runs without audit side effects — a useful mode
	// for dry-runs and unit tests, NOT for production.
	AuditSink AuditSink

	// AuditSigner is the keys.Signer the sink uses to seal each
	// AuditEvent. Required non-nil whenever AuditSink is non-nil.
	AuditSigner keys.Signer

	// AuditKeyID is the KeyID bound to keys.PurposeSigningAudit.
	// Required non-zero whenever AuditSink is non-nil.
	AuditKeyID ids.KeyID

	// AuditIDPrefix is the prefix for auto-generated AuditEventIDs.
	// Defaults to DefaultSequencerAuditIDPrefix.
	AuditIDPrefix string

	// FinalizeOnError, when true, calls StagedIssuer.Finalize()
	// after a refused emission before returning. Default false:
	// the caller may want to inspect issuer state (SequenceIndex,
	// IsFinalized) for diagnostics, and can call Finalize()
	// themselves if desired. Setting true is appropriate when the
	// sequencer is embedded in an orchestrator that treats any
	// refusal as flow-terminal.
	//
	// NOTE: stop-on-error is ALWAYS the refusal behavior in MVP —
	// a refused emission halts the sequence, full stop. There is
	// no opt-out. The doctrine is that a refused emission is a
	// signal to stop and investigate, not a signal to skip and
	// continue. FinalizeOnError only controls whether the issuer
	// is cooperatively closed on the way out; it does not change
	// the halt behavior itself.
	FinalizeOnError bool
}

// StagedSequencer drives a StagedIssuer over a pre-declared ordered
// list of Components, emitting one DisclosureMessage per Component
// and (optionally) one DISCLOSURE_AUTHORIZED audit event per emission.
//
// # Doctrinal role
//
// The sequencer is the release-side orchestration driver that closes
// the loop between session admission and component emission. Its
// responsibilities:
//
//   - Drive the StagedIssuer through a run, respecting monotonicity.
//   - Couple each successful emission to one DISCLOSURE_AUTHORIZED
//     audit event, appended BEFORE the message is surfaced to the
//     caller. This upholds the "audit is first-class" invariant
//     (docs/internal/stage-a-summary.md §2, invariant #8): no authority
//     decision is visible to its caller before the audit record
//     for that decision exists.
//   - Finalize the issuer on success (cooperative close).
//
// The sequencer does NOT perform trust attestation, session issuance,
// policy-drift detection, validation, or release decision construction.
// Those are upstream/downstream stages in the nine-stage orchestrated
// reconstruction flow (internal/vault/orchestration). The sequencer
// occupies exactly Stage 4: DISCLOSURE.
//
// # Concurrency
//
// Run holds a single mutex for the entire call. Sequencers are not
// intended to be shared across goroutines; a run is a single-shot
// drive against a single session's StagedIssuer.
type StagedSequencer struct {
	mu sync.Mutex

	issuer *StagedIssuer
	clock  shared_time.Clock

	auditSink     AuditSink
	auditSigner   keys.Signer
	auditKID      ids.KeyID
	auditIDPrefix string

	finalizeOnError bool

	auditCounter uint64
}

// NewStagedSequencer wires a sequencer around an existing StagedIssuer.
//
// issuer and clock are required non-nil. opts.AuditSink is optional;
// if provided, opts.AuditSigner and opts.AuditKeyID become required.
//
// Refusal cases are all Structural:
//
//   - issuer nil
//   - clock nil
//   - AuditSink non-nil but AuditSigner nil
//   - AuditSink non-nil but AuditKeyID zero
//
// A pre-finalized issuer is NOT refused at construction — the caller
// may legitimately hand a finalized issuer to a sequencer to exercise
// the IssuerFinalized refusal path in an integration test. The first
// Emit will refuse with CodeIssuerFinalized, and Run will report that
// as FailedIndex=0.
func NewStagedSequencer(
	issuer *StagedIssuer,
	clock shared_time.Clock,
	opts SequencerOptions,
) (*StagedSequencer, error) {
	if issuer == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_sequencer: issuer is required",
			nil,
		)
	}
	if clock == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_sequencer: clock is required",
			nil,
		)
	}

	if opts.AuditSink != nil {
		if opts.AuditSigner == nil {
			return nil, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"staged_sequencer: audit_signer is required when audit_sink is set",
				nil,
			)
		}
		if opts.AuditKeyID.IsZero() {
			return nil, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"staged_sequencer: audit_key_id is required when audit_sink is set",
				nil,
			)
		}
	}

	prefix := opts.AuditIDPrefix
	if prefix == "" {
		prefix = DefaultSequencerAuditIDPrefix
	}

	return &StagedSequencer{
		issuer:          issuer,
		clock:           clock,
		auditSink:       opts.AuditSink,
		auditSigner:     opts.AuditSigner,
		auditKID:        opts.AuditKeyID,
		auditIDPrefix:   prefix,
		finalizeOnError: opts.FinalizeOnError,
	}, nil
}

// SequenceResult is the outcome of one Run call. It is returned even
// on error so callers can observe how far the sequence progressed
// before abort.
type SequenceResult struct {
	// Messages is the ordered list of successfully emitted
	// DisclosureMessages. Under stop-on-error semantics (the only
	// behavior offered in MVP), Messages is a strict prefix of the
	// Components slice supplied to Run. Zero-length if the first
	// emission failed.
	Messages []disclosure_message.DisclosureMessage

	// AuditEventIDs lists the AuditEventIDs appended for the
	// messages in Messages, in the same order. Empty if AuditSink
	// was nil. One-to-one with Messages.
	AuditEventIDs []ids.AuditEventID

	// Finalized is true if the StagedIssuer was finalized by this
	// Run — either because the run completed all components
	// successfully (cooperative close) or because FinalizeOnError
	// was set and a refusal occurred.
	Finalized bool

	// FailedIndex is the index into the Components slice where the
	// run aborted; -1 if all components emitted successfully.
	FailedIndex int

	// FailedComponentID is the ComponentID at FailedIndex, or the
	// zero value if no failure.
	FailedComponentID ids.ComponentID

	// FinalSequenceIndex is the StagedIssuer's counter after the
	// run — the next SequenceIndex Emit would issue. Equal to
	// len(Messages) in a no-refusal run; less in a failed run.
	FinalSequenceIndex uint32
}

// Run emits each component in components in order, producing one
// DisclosureMessage per component. If opts.AuditSink is configured,
// one DISCLOSURE_AUTHORIZED event is appended per emission BEFORE
// the message is added to the result — so a returned message is
// always already audit-bound.
//
// Return shape:
//
//   - (result, nil)   — all components emitted successfully. Issuer
//     is finalized. result.FailedIndex == -1.
//   - (result, err)   — a refusal occurred. result is partial and
//     describes the state at abort. err is the underlying error
//     from StagedIssuer.Emit or the audit sink, propagated unwrapped.
//     Issuer state depends on FinalizeOnError.
//
// Structural pre-conditions:
//
//   - components nil or empty → Structural.
//   - any Component.ID zero, Plaintext empty, RecipientKeyID zero
//     surfaces from StagedIssuer.Emit as Structural; sequencer does
//     not re-check.
//
// Concurrency:
//
// Run serializes the entire sequence under the sequencer's mutex.
// A second concurrent call on the same sequencer blocks until the
// first completes. This is the correct semantic for the "one session,
// one sequence" model — a session's disclosure timeline is a single
// logical thread.
//
// Plaintext zeroization:
//
// For every Component c, c.Plaintext is zeroized in place before
// Run returns, regardless of outcome. This holds even if the Emit
// itself is refused (StagedIssuer.Emit's defer guarantees it) and
// even if the sequencer short-circuits before reaching a given
// component — we explicitly zero each un-processed component's
// Plaintext on the abort path. Callers may still zero their own
// slices after Run returns; that is a legitimate defense in depth.
func (s *StagedSequencer) Run(components []Component) (*SequenceResult, error) {
	// Outer guard: even on the nil/empty path we still want to
	// ensure any pre-populated Plaintext buffers in the slice get
	// zeroized on exit. A nil slice is a no-op here.
	defer zeroAllComponents(components)

	if len(components) == 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_sequencer: components slice is empty",
			nil,
		)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result := &SequenceResult{
		Messages:      make([]disclosure_message.DisclosureMessage, 0, len(components)),
		AuditEventIDs: make([]ids.AuditEventID, 0, len(components)),
		FailedIndex:   -1,
	}

	for i := range components {
		c := &components[i]

		msg, err := s.issuer.Emit(EmitParams{
			ComponentID:    c.ID,
			Plaintext:      c.Plaintext,
			RecipientKeyID: c.RecipientKeyID,
		})
		if err != nil {
			result.FailedIndex = i
			result.FailedComponentID = c.ID
			result.FinalSequenceIndex = s.issuer.SequenceIndex()
			if s.finalizeOnError {
				// Best-effort finalize; the Finalize call itself is
				// a no-op returning nil in the current implementation,
				// but we keep the call pattern symmetric.
				_ = s.issuer.Finalize()
				result.Finalized = true
			}
			return result, err
		}

		// Audit binding: append the DISCLOSURE_AUTHORIZED event BEFORE
		// surfacing the message. If audit append fails, the message
		// has already been emitted by the issuer — the sequence
		// counter has advanced — but we refuse to return the message
		// to the caller because the "every emission has an audit
		// event" invariant would be broken. The sequencer finalizes
		// the issuer unconditionally on audit-append failure (not
		// gated by FinalizeOnError): an audit-chain gap is a
		// terminal integrity condition for the sequencer's contract.
		var eventID ids.AuditEventID
		if s.auditSink != nil {
			sealed, appendErr := s.emitAuditEvent(msg)
			if appendErr != nil {
				result.FailedIndex = i
				result.FailedComponentID = c.ID
				result.FinalSequenceIndex = s.issuer.SequenceIndex()
				// Terminal — not gated by FinalizeOnError.
				_ = s.issuer.Finalize()
				result.Finalized = true
				return result, appendErr
			}
			eventID = sealed.EventID
		}

		result.Messages = append(result.Messages, *msg)
		// Only record the AuditEventID when an audit sink was wired —
		// otherwise we'd be returning a slice of empty strings to the
		// caller, which silently breaks every downstream invariant
		// (length-equality between Messages and AuditEventIDs, the
		// "every emission has a corresponding audit anchor" check in
		// the receive-side mirror, etc.). The dry-run / no-audit
		// path is opt-in and explicitly leaves AuditEventIDs empty.
		if s.auditSink != nil {
			result.AuditEventIDs = append(result.AuditEventIDs, eventID)
		}
	}

	// Happy-path cooperative close.
	if err := s.issuer.Finalize(); err != nil {
		// Finalize is currently infallible, but we propagate any
		// future error without losing result context.
		result.FinalSequenceIndex = s.issuer.SequenceIndex()
		return result, err
	}
	result.Finalized = true
	result.FinalSequenceIndex = s.issuer.SequenceIndex()
	return result, nil
}

// emitAuditEvent builds, signs-through-chain, and returns a
// DISCLOSURE_AUTHORIZED AuditEvent for msg. Called under s.mu.
func (s *StagedSequencer) emitAuditEvent(msg *disclosure_message.DisclosureMessage) (audit_event.AuditEvent, error) {
	s.auditCounter++
	eventID := ids.AuditEventID(
		s.auditIDPrefix + hex.EncodeToString(auditCounterBytes(s.auditCounter)),
	)

	payload, err := buildDisclosureAuthorizedPayload(msg)
	if err != nil {
		return audit_event.AuditEvent{}, err
	}

	skel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       eventID,
		Kind:          audit_event.KindDisclosureAuthorized,
		OccurredAt:    s.clock.Now().UTC(),
		SessionID:     msg.SessionID,
		Payload:       payload,
		SigningKeyID:  s.auditKID,
	}
	sealed, err := s.auditSink.Append(skel, s.auditSigner)
	if err != nil {
		return audit_event.AuditEvent{}, err
	}
	return sealed, nil
}

// ---- payload shape for DISCLOSURE_AUTHORIZED -----------------------------

// disclosureAuthorizedPayload is the canonical-JSON body of a
// DISCLOSURE_AUTHORIZED AuditEvent. The envelope contract is the
// AuditEvent outer frame; Payload is the event-kind body. Every
// field here is copied from the DisclosureMessage verbatim —
// enough for offline replay without reading the sealed payload.
//
// The sealed ciphertext itself is deliberately NOT included: an
// auditor does not need the ciphertext to reason about authority
// decisions, and logging it would defeat the GCM binding.
type disclosureAuthorizedPayload struct {
	SessionID      ids.SessionID     `json:"session_id"`
	ComponentID    ids.ComponentID   `json:"component_id"`
	DisclosureID   ids.DisclosureID  `json:"disclosure_id"`
	SequenceIndex  uint32            `json:"sequence_index"`
	PolicyVersion  ids.PolicyVersion `json:"policy_version"`
	RecipientKeyID ids.KeyID         `json:"recipient_key_id"`
	PayloadHash    string            `json:"payload_hash"` // hex SHA-256 of sealed ciphertext
}

// buildDisclosureAuthorizedPayload returns the canonical-JSON
// encoding of the payload for msg. The PayloadHash field commits
// to the sealed ciphertext so auditors can later cross-check a
// DisclosureMessage against its audit event without ever opening
// the seal.
func buildDisclosureAuthorizedPayload(msg *disclosure_message.DisclosureMessage) ([]byte, error) {
	sum := crypto.SHA256Slice(msg.SealedPayload)
	p := disclosureAuthorizedPayload{
		SessionID:      msg.SessionID,
		ComponentID:    msg.ComponentID,
		DisclosureID:   msg.DisclosureID,
		SequenceIndex:  msg.SequenceIndex,
		PolicyVersion:  msg.PolicyVersion,
		RecipientKeyID: msg.RecipientKeyID,
		PayloadHash:    hex.EncodeToString(sum),
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"staged_sequencer: audit payload encode failed",
			err,
		)
	}
	return out, nil
}

// ---- helpers -------------------------------------------------------------

// zeroAllComponents zeros every Plaintext slice across components.
// Safe on nil input. Runs at Run-exit to guarantee no caller buffer
// survives a run, even if we short-circuited before the relevant
// Emit had a chance to zero it.
func zeroAllComponents(components []Component) {
	for i := range components {
		zeroBytes(components[i].Plaintext)
	}
}

// auditCounterBytes renders a 64-bit counter in big-endian form.
// Fixed width so auto-generated AuditEventIDs sort lexicographically
// by issuance order within one sequencer instance.
func auditCounterBytes(n uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(n & 0xFF)
		n >>= 8
	}
	return b[:]
}
