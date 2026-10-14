// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestState_String_Stable(t *testing.T) {
	t.Parallel()
	cases := map[State]string{
		StateUnstarted:     "unstarted",
		StateIngress:       "ingress",
		StateReassemble:    "reassemble",
		StateValidate:      "validate",
		StateReady:         "ready",
		StateReconstituted: "reconstituted",
		StateRejected:      "rejected",
	}
	for s, want := range cases {
		require.Equalf(t, want, s.String(), "State(%d).String()", s)
	}
	require.Equal(t, "invalid", State(99).String())
}

func TestState_IsTerminal(t *testing.T) {
	t.Parallel()
	terminals := []State{StateReconstituted, StateRejected}
	for _, s := range terminals {
		require.Truef(t, s.IsTerminal(), "%s must be terminal", s)
	}
	nonTerminals := []State{StateUnstarted, StateIngress, StateReassemble, StateValidate, StateReady}
	for _, s := range nonTerminals {
		require.Falsef(t, s.IsTerminal(), "%s must not be terminal", s)
	}
}

func TestState_IsOperational(t *testing.T) {
	t.Parallel()
	operational := []State{StateIngress, StateReassemble, StateValidate, StateReady}
	for _, s := range operational {
		require.Truef(t, s.IsOperational(), "%s must be operational", s)
	}
	nonOperational := []State{StateUnstarted, StateReconstituted, StateRejected}
	for _, s := range nonOperational {
		require.Falsef(t, s.IsOperational(), "%s must not be operational", s)
	}
}

// TestHappyPath_CanTransition walks the canonical accepted path.
func TestHappyPath_CanTransition(t *testing.T) {
	t.Parallel()
	path := []struct {
		from, to State
		trigger  string
	}{
		{StateUnstarted, StateIngress, "bootstrap.accepted"},
		{StateIngress, StateReassemble, "disclosure.received.all"},
		{StateReassemble, StateValidate, "reassembly.ok"},
		{StateValidate, StateReady, "validation.pass"},
		{StateReady, StateReconstituted, "decision.signed"},
	}
	for _, step := range path {
		require.Truef(t, CanTransition(step.from, step.to, step.trigger),
			"happy-path transition %s → %s [%s] must be legal",
			step.from, step.to, step.trigger)
	}
}

// TestRejectionArcs_ExistFromEveryOperationalState asserts that every
// operational state has a rejection arc — any structural refusal at any
// stage must be able to land the flow in a terminal Rejected state.
func TestRejectionArcs_ExistFromEveryOperationalState(t *testing.T) {
	t.Parallel()
	for _, s := range RejectionCapableStates {
		require.Truef(t, CanTransition(s, StateRejected, "bootstrap.rejected"),
			"operational state %s must have a rejection arc to StateRejected", s)
	}
}

// TestNoTransitionsOutOfTerminal asserts that no transition in the
// table originates from a terminal state.
func TestNoTransitionsOutOfTerminal(t *testing.T) {
	t.Parallel()
	for _, tr := range TransitionTable {
		require.Falsef(t, tr.From.IsTerminal(),
			"transition %s → %s [%s] originates from terminal state — illegal",
			tr.From, tr.To, tr.Trigger)
	}
}

// TestCanTransition_IllegalReturnsFalse asserts that obviously-bogus
// transitions are not admitted.
func TestCanTransition_IllegalReturnsFalse(t *testing.T) {
	t.Parallel()
	// Jumping from ingress straight to reconstituted — skipping every
	// intermediate stage — is illegal.
	require.False(t, CanTransition(StateIngress, StateReconstituted, ""))
	// Going backwards is illegal.
	require.False(t, CanTransition(StateReady, StateIngress, ""))
	// A nonsense trigger on a legal (from, to) pair is rejected.
	require.False(t, CanTransition(StateIngress, StateReassemble, "vibes"))
}

func TestCanTransition_EmptyTriggerMatchesAny(t *testing.T) {
	t.Parallel()
	// Every (from, to) pair that appears in the table must be
	// reachable with the empty-trigger "any" wildcard.
	for _, tr := range TransitionTable {
		require.True(t, CanTransition(tr.From, tr.To, ""),
			"empty-trigger lookup must accept %s → %s", tr.From, tr.To)
	}
}

func TestTransitionTable_NonEmpty(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, TransitionTable,
		"TransitionTable must be non-empty — the happy path at minimum must be populated")
	// 5 happy-path + 4 rejection arcs = 9.
	require.Equal(t, 9, len(TransitionTable))
}

// TestLegalTransitions_Ingress asserts that the ingress state's legal
// successors are exactly what the happy path + rejection arc calls
// for — no hidden transitions, no missing ones.
func TestLegalTransitions_Ingress(t *testing.T) {
	t.Parallel()
	got := LegalTransitions(StateIngress)
	require.Len(t, got, 2, "ingress has exactly two successors: reassemble and rejected")

	targets := map[State]bool{}
	for _, tr := range got {
		targets[tr.To] = true
	}
	require.True(t, targets[StateReassemble])
	require.True(t, targets[StateRejected])
}

// TestLegalTransitions_Terminal asserts that no successors exist from
// a terminal state.
func TestLegalTransitions_Terminal(t *testing.T) {
	t.Parallel()
	require.Empty(t, LegalTransitions(StateReconstituted))
	require.Empty(t, LegalTransitions(StateRejected))
}

// TestStateUnstarted_IsZeroValue asserts that the zero value of State
// is StateUnstarted. Anchoring this in a test catches future
// reorderings of the const block that would silently break
// "newly-allocated Orchestrator starts at StateUnstarted."
func TestStateUnstarted_IsZeroValue(t *testing.T) {
	t.Parallel()
	var s State
	require.Equal(t, StateUnstarted, s)
}
