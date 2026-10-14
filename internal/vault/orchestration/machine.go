// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package orchestration

import (
	"fmt"
	"sync"
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// The triggers of TransitionTable, as names a driver can use.
const (
	TriggerRequestReceived      = "request.received"
	TriggerRequestValidated     = "request.validated"
	TriggerAttestationAllow     = "attestation.allow"
	TriggerAttestationDeny      = "attestation.deny"
	TriggerAttestationRestrict  = "attestation.restrict"
	TriggerSessionIssued        = "session.issued"
	TriggerManifestDispatched   = "manifest.dispatched"
	TriggerCandidateReceived    = "candidate.received"
	TriggerReturnAccepted       = "return.accepted"
	TriggerValidationCompleted  = "validation.completed"
	TriggerDecisionSigned       = "decision.signed"
	TriggerCrossCloudInitiated  = "cross_cloud.initiated"
	TriggerCrossCloudDispatched = "cross_cloud.token_dispatched"
	TriggerAuditSealedRelease   = "audit.sealed.release_true"
	TriggerAuditSealedRefusal   = "audit.sealed.release_false"
	TriggerIncidentDetected     = "incident.detected"
)

// CodeIllegalTransition (Structural): a driver asked for a transition the
// table does not have. Orchestration never takes it silently.
const CodeIllegalTransition = "orchestration.illegal_transition"

// Step is one transition a Machine took.
type Step struct {
	From    State     `json:"from"`
	To      State     `json:"to"`
	Trigger string    `json:"trigger"`
	At      time.Time `json:"at"`
}

// MarshalJSON renders the states by name.
func (s Step) MarshalJSON() ([]byte, error) {
	type wire struct {
		From    string    `json:"from"`
		To      string    `json:"to"`
		Trigger string    `json:"trigger"`
		At      time.Time `json:"at"`
	}
	return marshalJSON(wire{From: s.From.String(), To: s.To.String(), Trigger: s.Trigger, At: s.At})
}

// Machine is one flow's position in the nine stages. It starts
// Unstarted and moves only along TransitionTable; every move is kept, so
// the flow's history is on the machine itself.
type Machine struct {
	mu    sync.Mutex
	state State
	steps []Step
}

// NewMachine starts a machine at StateUnstarted.
func NewMachine() *Machine {
	return &Machine{state: StateUnstarted}
}

// State is where the machine is now.
func (m *Machine) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Advance takes the transition trigger from the current state, recorded
// at time at. A trigger the table does not allow from this state is
// refused with CodeIllegalTransition and the machine does not move.
func (m *Machine) Advance(trigger string, at time.Time) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tr := range TransitionTable {
		if tr.From == m.state && tr.Trigger == trigger {
			m.steps = append(m.steps, Step{From: m.state, To: tr.To, Trigger: trigger, At: at.UTC()})
			m.state = tr.To
			return tr.To, nil
		}
	}
	return m.state, shared_errors.Structural(CodeIllegalTransition,
		fmt.Sprintf("orchestration: no transition %q from state %s", trigger, m.state), nil)
}

// Steps is every transition taken, in order (a copy).
func (m *Machine) Steps() []Step {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Step(nil), m.steps...)
}
