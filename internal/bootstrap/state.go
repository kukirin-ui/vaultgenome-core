// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

// State names one of the receive-side bootstrap stages or the two
// terminal states. Transitions between States are governed by
// TransitionTable; any illegal transition is a program bug.
//
// The receive-side state machine is deliberately narrower than the
// release-side /internal/vault/orchestration state machine. Trust
// attestation, session issuance, and Incident Termination are Vault
// responsibilities; the receive side plays exactly four operational
// stages plus one pre-operational and two terminals.
type State uint8

const (
	// StateUnstarted is the zero value — no BootstrapManifest has been
	// admitted yet. Start() is the only legal transition out.
	StateUnstarted State = iota

	// StateIngress is the acceptance window: the BootstrapManifest has
	// been admitted and cross-manifest agreement with the
	// ReconstructionJobManifest has been verified. The orchestrator
	// now accepts DisclosureMessage arrivals via Accept().
	StateIngress

	// StateReassemble is entered once every expected DisclosureID has
	// been received and recorded as a ReceivedDisclosure. The
	// reassembly engine (injected — out of scope here) consumes the
	// accepted disclosures and produces candidate Genome bytes.
	StateReassemble

	// StateValidate is entered when MarkReassembled() has been called
	// with a successful candidate. The receive-side validation
	// pipeline (injected) runs and produces a ValidationResult. A
	// receive-side validation failure pushes the flow to StateRejected
	// with Reason=validation_failed.
	StateValidate

	// StateReady is the happy-path terminal: the orchestrator is ready
	// to issue a ReconstitutionDecision with Reason=reconstructed_ok.
	// Decide() converts StateReady → StateReconstituted.
	StateReady

	// StateReconstituted is the happy-path accepted terminal: the
	// ReconstitutionDecision has been signed, audit-bound, and
	// surfaced to the caller. No further transitions.
	StateReconstituted

	// StateRejected is the refused terminal. Reached from any
	// operational state when an acceptance or reassembly or validation
	// refusal fires. No further transitions. The ReconstitutionDecision
	// at StateRejected carries Accepted=false and one of the two
	// failure Reasons (reassembly_failed, validation_failed).
	StateRejected
)

// String returns a stable, lowercase identifier for s. These identifiers
// appear in AuditEvent payloads and in ReconstitutionDecision.Reason
// coupling checks.
func (s State) String() string {
	switch s {
	case StateUnstarted:
		return "unstarted"
	case StateIngress:
		return "ingress"
	case StateReassemble:
		return "reassemble"
	case StateValidate:
		return "validate"
	case StateReady:
		return "ready"
	case StateReconstituted:
		return "reconstituted"
	case StateRejected:
		return "rejected"
	default:
		return "invalid"
	}
}

// IsTerminal reports whether s is a flow-terminal state. No transitions
// are permitted out of a terminal state — a new bootstrap requires a
// new Orchestrator instance.
func (s State) IsTerminal() bool {
	return s == StateReconstituted || s == StateRejected
}

// IsOperational reports whether s is one of the receive-side
// operational stages (i.e., not Unstarted and not Terminal).
func (s State) IsOperational() bool {
	return s == StateIngress ||
		s == StateReassemble ||
		s == StateValidate ||
		s == StateReady
}

// Transition describes one legal state transition. Semantics match
// /internal/vault/orchestration.Transition.
type Transition struct {
	From State
	To   State
	// Trigger is a stable identifier for the event that moves the
	// machine, e.g. "bootstrap.accepted", "disclosure.received.all",
	// "reassembly.ok", "validation.pass", "validation.fail".
	Trigger string
}

// TransitionTable is the exhaustive list of legal transitions. Any
// transition not present here is illegal and MUST be refused at the
// call site.
//
// The table is in "happy-path then rejection arcs" order for
// readability. Rejection arcs are attachable from every operational
// state — they are generated at init time from RejectionCapableStates
// to avoid hand-maintained duplication, mirroring the incident-arc
// pattern in /internal/vault/orchestration.
var TransitionTable = buildTransitionTable()

// RejectionCapableStates enumerates the operational stages from which a
// rejection can fire. All four operational stages are reachable by
// rejection — a structural refusal can occur at ingress (wrong
// DisclosureID, out-of-order arrival, wire-hash mismatch), at
// reassembly (the injected reassembler failed), or at validation (the
// injected validator refused the reassembled bytes). Even StateReady
// can transition to rejection if the caller cancels before Decide().
var RejectionCapableStates = []State{
	StateIngress,
	StateReassemble,
	StateValidate,
	StateReady,
}

// happyPathTransitions covers the non-rejection operational
// progression.
var happyPathTransitions = []Transition{
	// Entry — Orchestrator.Start() after cross-manifest agreement
	// verified and BootstrapManifest accepted.
	{From: StateUnstarted, To: StateIngress, Trigger: "bootstrap.accepted"},

	// Ingress → Reassemble when the last expected disclosure is
	// accepted. The orchestrator fires this automatically when the
	// ReceivedDisclosures count reaches the ExpectedDisclosureIDs
	// length.
	{From: StateIngress, To: StateReassemble, Trigger: "disclosure.received.all"},

	// Reassemble → Validate on a successful reassembly candidate.
	{From: StateReassemble, To: StateValidate, Trigger: "reassembly.ok"},

	// Validate → Ready on a full-pass receive-side validation.
	{From: StateValidate, To: StateReady, Trigger: "validation.pass"},

	// Ready → Reconstituted once Decide() has signed and audit-bound
	// the accepted ReconstitutionDecision.
	{From: StateReady, To: StateReconstituted, Trigger: "decision.signed"},
}

// buildTransitionTable concatenates the hand-listed happy-path
// transitions with the auto-generated rejection arcs.
func buildTransitionTable() []Transition {
	out := make([]Transition, 0, len(happyPathTransitions)+len(RejectionCapableStates))
	out = append(out, happyPathTransitions...)
	for _, s := range RejectionCapableStates {
		out = append(out, Transition{
			From:    s,
			To:      StateRejected,
			Trigger: "bootstrap.rejected",
		})
	}
	return out
}

// CanTransition reports whether (from → to) under the given trigger is
// a legal transition. trigger may be empty to match any transition
// between the two states (useful for tests).
func CanTransition(from, to State, trigger string) bool {
	for _, tr := range TransitionTable {
		if tr.From == from && tr.To == to {
			if trigger == "" || tr.Trigger == trigger {
				return true
			}
		}
	}
	return false
}

// LegalTransitions returns the set of (To, Trigger) pairs reachable
// from the given state. Callers should not mutate the returned slice.
func LegalTransitions(from State) []Transition {
	var out []Transition
	for _, tr := range TransitionTable {
		if tr.From == from {
			out = append(out, tr)
		}
	}
	return out
}
