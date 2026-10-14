// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package orchestration

// State names one of the nine stages of Orchestrated Reconstruction, plus
// the optional Phase 4 cross-cloud handshake sub-stage (stage 8.5) and
// the two terminal states (release-authorized and incident-terminated).
// Transitions between States are governed by TransitionTable and by
// operational validation; any illegal transition is a program bug.
type State uint8

const (
	// StateUnstarted is the zero value — no request yet admitted.
	StateUnstarted State = iota

	// Nine operational stages, in canonical order (docs/internal/stage-a-summary.md §1).
	StateRequest         // stage 1 — intake
	StateTrust           // stage 2 — attestation
	StateSession         // stage 3 — trusted session issued
	StateDisclosure      // stage 4 — staged disclosure authorized
	StateExternalCompute // stage 5 — delegated compute
	StateReturn          // stage 6 — candidate returned
	StateValidation      // stage 7 — three-dimension validation
	StateRelease         // stage 8 — release decision constructed
	StateAudit           // stage 9 — audit chain closed for this flow

	// Terminal states.

	// StateReleaseAuthorized is the happy-path terminal: all nine stages
	// completed, ReleaseDecision.Release = true, audit chain sealed.
	StateReleaseAuthorized

	// StateIncidentTerminated is the safety terminal: Incident Termination
	// fired. Any genome material in flight is zeroized; the session is
	// invalidated; the flow cannot resume.
	StateIncidentTerminated

	// StateCrossCloudHandshake is the optional Phase 4 sub-stage 8.5
	// inserted between StateRelease and StateAudit when an operator-
	// supplied RecoveryRequest opts into cross-cloud delivery. The
	// release-side authority's KMS Coordinator runs the cross-cloud
	// attestation handshake here (see internal/vault/kms and
	// ADR 0006). On success, the machine transitions to StateAudit;
	// on attestation failure or policy denial, to StateIncidentTerminated.
	//
	// Local single-TEE flows skip this state entirely — the existing
	// StateRelease → StateAudit transition is still valid and is the
	// default. Cross-cloud is opt-in.
	//
	// Numeric position: appended after StateIncidentTerminated to keep
	// existing operational stages' iota values stable. IsOperational
	// special-cases this state.
	StateCrossCloudHandshake
)

// String returns a stable, lowercase identifier for s. These identifiers
// appear in AuditEvent payloads.
func (s State) String() string {
	switch s {
	case StateUnstarted:
		return "unstarted"
	case StateRequest:
		return "request"
	case StateTrust:
		return "trust"
	case StateSession:
		return "session"
	case StateDisclosure:
		return "disclosure"
	case StateExternalCompute:
		return "external_compute"
	case StateReturn:
		return "return"
	case StateValidation:
		return "validation"
	case StateRelease:
		return "release"
	case StateAudit:
		return "audit"
	case StateReleaseAuthorized:
		return "release_authorized"
	case StateIncidentTerminated:
		return "incident_terminated"
	case StateCrossCloudHandshake:
		return "cross_cloud_handshake"
	default:
		return "invalid"
	}
}

// IsTerminal reports whether s is a flow-terminal state. No transitions
// are permitted out of a terminal state — a new flow requires a new
// RecoveryRequest and therefore a new state machine instance.
func (s State) IsTerminal() bool {
	return s == StateReleaseAuthorized || s == StateIncidentTerminated
}

// IsOperational reports whether s is one of the operational stages
// (i.e., not Unstarted and not Terminal). The canonical nine stages
// (Request through Audit) are operational; the optional Phase 4
// sub-stage StateCrossCloudHandshake is also operational.
func (s State) IsOperational() bool {
	if s >= StateRequest && s <= StateAudit {
		return true
	}
	return s == StateCrossCloudHandshake
}

// Transition describes one legal state transition.
type Transition struct {
	From State
	To   State
	// Trigger is a stable identifier for the event that moves the machine,
	// e.g. "attestation.allow", "validation.pass", "incident.detected".
	Trigger string
}

// TransitionTable is the exhaustive list of legal transitions. Any
// transition not present here is illegal and MUST panic at the call site;
// orchestration does not silently drop requests.
//
// The table is in "happy-path then branches" order for readability. The
// incident-termination arcs are attachable from every operational stage —
// they are generated at init time from IncidentCapableStates to avoid
// hand-maintained duplication.
var TransitionTable = buildTransitionTable()

// IncidentCapableStates enumerates the operational stages from which an
// Incident Termination can fire. In the MVP that is "all of them",
// including the Phase 4 cross-cloud handshake sub-stage.
var IncidentCapableStates = []State{
	StateRequest,
	StateTrust,
	StateSession,
	StateDisclosure,
	StateExternalCompute,
	StateReturn,
	StateValidation,
	StateRelease,
	StateAudit,
	StateCrossCloudHandshake,
}

// happyPathTransitions covers the non-incident operational progression,
// including the non-release terminations on a failed or conditional-fail
// validation.
var happyPathTransitions = []Transition{
	// Entry
	{From: StateUnstarted, To: StateRequest, Trigger: "request.received"},

	// Stage 1 → Stage 2
	{From: StateRequest, To: StateTrust, Trigger: "request.validated"},

	// Stage 2 → Stage 3 on attestation allow; deny terminates as incident
	// if it carries incident-class codes, otherwise moves to StateRelease
	// with a fail decision (modeled below for clarity).
	{From: StateTrust, To: StateSession, Trigger: "attestation.allow"},
	{From: StateTrust, To: StateRelease, Trigger: "attestation.deny"},
	{From: StateTrust, To: StateRelease, Trigger: "attestation.restrict"},

	// Stage 3 → Stage 4
	{From: StateSession, To: StateDisclosure, Trigger: "session.issued"},

	// Stage 4 → Stage 5
	{From: StateDisclosure, To: StateExternalCompute, Trigger: "manifest.dispatched"},

	// Stage 5 → Stage 6
	{From: StateExternalCompute, To: StateReturn, Trigger: "candidate.received"},

	// Stage 6 → Stage 7
	{From: StateReturn, To: StateValidation, Trigger: "return.accepted"},

	// Stage 7 → Stage 8 on any verdict (pass, fail, conditional_fail).
	// The Release/Reason coupling is in the release_decision contract.
	{From: StateValidation, To: StateRelease, Trigger: "validation.completed"},

	// Stage 8 → Stage 9 (audit closes regardless of release=true/false).
	{From: StateRelease, To: StateAudit, Trigger: "decision.signed"},

	// Phase 4 cross-cloud branch: Stage 8 → Stage 8.5 → Stage 9.
	// Opt-in alternative path when the RecoveryRequest specifies a
	// cross-cloud destination. The KMS Coordinator runs the attestation
	// handshake and key-release flow here.
	{From: StateRelease, To: StateCrossCloudHandshake, Trigger: "cross_cloud.initiated"},
	// On successful handshake + token dispatch the machine joins the
	// existing post-Release flow at StateAudit.
	{From: StateCrossCloudHandshake, To: StateAudit, Trigger: "cross_cloud.token_dispatched"},
	// Attestation failure or policy denial inside the cross-cloud
	// branch fires Incident Termination (the generic incident-arc
	// generator below handles this).

	// Stage 9 → happy-path terminal on release=true; non-terminal audit
	// closure on release=false still terminates the flow, distinguished by
	// the trigger code.
	{From: StateAudit, To: StateReleaseAuthorized, Trigger: "audit.sealed.release_true"},
	{From: StateAudit, To: StateIncidentTerminated, Trigger: "audit.sealed.release_false"},
}

// buildTransitionTable concatenates the hand-listed happy-path transitions
// with the auto-generated incident arcs.
func buildTransitionTable() []Transition {
	out := make([]Transition, 0, len(happyPathTransitions)+len(IncidentCapableStates))
	out = append(out, happyPathTransitions...)
	for _, s := range IncidentCapableStates {
		out = append(out, Transition{
			From:    s,
			To:      StateIncidentTerminated,
			Trigger: "incident.detected",
		})
	}
	return out
}

// CanTransition reports whether (from → to) under the given trigger is a
// legal transition. trigger may be empty to match any transition between
// the two states (useful for tests).
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

// LegalTransitions returns the set of (To, Trigger) pairs reachable from
// the given state. Callers should not mutate the returned slice.
func LegalTransitions(from State) []Transition {
	var out []Transition
	for _, tr := range TransitionTable {
		if tr.From == from {
			out = append(out, tr)
		}
	}
	return out
}
