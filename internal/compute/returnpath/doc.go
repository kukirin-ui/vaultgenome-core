// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package returnpath is the Return Path — the governed handoff of a
// CandidateOutput from the external compute worker back to vault-side
// logic.
//
// # Doctrinal role
//
// The Return Path carries a CandidateOutput, not a validated or released
// artifact. The vault-side half re-checks operational preconditions (the
// six sub-checks in docs/doctrine/validation-thresholds.md §4.2) and, if those
// hold, invokes /internal/validation/service. A CandidateOutput that
// arrives after its manifest deadline is rejected with an operational
// fail.
//
// This package is distinct from the worker and manifest packages because
// the return path crosses the authority boundary: its worker-side half
// runs inside cmd/acp-compute; its vault-side half runs inside cmd/sagvd.
// The shared shape lives here; the two halves import it.
//
// Stage G (iteration 5 — R-11 placeholder hardening): the CandidateOutput
// shape is now populated so the /internal/compute/worker Reconstructor
// can return it and so the vault-side Return Path handler has a concrete
// type to validate. The transport envelope (wire framing, authentication
// between the two halves) is still a future task.
package returnpath
