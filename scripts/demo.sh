#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# demo.sh — narrated end-to-end walkthrough of the AI Continuity Platform
# vertical slice AND receive-side round trip. Drives the in-repo integration
# tests as a guided flow, with one-line commentary per stage so an observer
# on a pilot call can follow along in plain English.
#
# This is not a production tool. It is a teaching harness. It exercises the
# doctrine-frozen invariants described in 00_Stage_A_Summary.md §2 and the
# two-tier integrity split pinned down in 00_Bootstrap_Contracts_Doctrine.md
# §8.4 against the in-repo implementation.
#
# The demo is a two-act walkthrough:
#
#   Act I  — Release-side slice (Stages 1–9 of the release flow):
#            Intake → Trust Admission → Session → Staged Disclosure →
#            Delegated Compute → Return Path → Validation → Release Decision.
#            Carries invariants #2, #3, #4, #5, #8.
#            Test target: TestVerticalSlice_*
#
#   Act II — Receive-side round trip (Stages R.1–R.6 of the bootstrap flow):
#            BootstrapManifest → Orchestrator.Start → Accept (tier 1 wire-hash) →
#            Reassembler.Admit (tier 2 plaintext hash/size) → Finalize
#            (Merkle + GenomeID round-trip) → Decide (signed ReconstitutionDecision).
#            Carries the two-tier integrity split (§8.4), invariants #1, #5-mirror,
#            #8-mirror, and R-14 content-addressing on the receive side.
#            Test target: TestRoundtripSlice_*
#
# Usage:
#   make demo               # from core/
#   bash scripts/demo.sh    # from core/
#
# Exit codes:
#   0 — both acts passed; all 15 narrated stages exercised.
#   non-zero — at least one act failed; the demo surfaces the go test output.

set -euo pipefail

COLOR_RESET=$'\033[0m'
COLOR_BOLD=$'\033[1m'
COLOR_CYAN=$'\033[36m'
COLOR_MAGENTA=$'\033[35m'
COLOR_GREEN=$'\033[32m'
COLOR_YELLOW=$'\033[33m'
COLOR_DIM=$'\033[2m'

banner() {
    printf "\n${COLOR_BOLD}${COLOR_CYAN}%s${COLOR_RESET}\n" "$1"
}

act_banner() {
    printf "\n${COLOR_BOLD}${COLOR_MAGENTA}%s${COLOR_RESET}\n" "$1"
}

stage() {
    printf "${COLOR_BOLD}%s${COLOR_RESET}  %s\n" "$1" "$2"
}

note() {
    printf "      ${COLOR_DIM}%s${COLOR_RESET}\n" "$1"
}

# -----------------------------------------------------------------------------

banner "AI Continuity Platform — end-to-end demo (Act I + Act II)"

printf "${COLOR_DIM}%s${COLOR_RESET}\n" \
  "This walkthrough drives the in-repo integration tests through both halves" \
  "of the continuity story:" \
  "  Act I  — the release-side nine-stage flow (existing vertical slice)" \
  "  Act II — the receive-side six-stage bootstrap round trip" \
  "Each stage carries one or more doctrine invariants; the integration tests" \
  "assert them; the demo narrates them so an observer can follow along."

echo
stage "0" "Preflight — confirm the tree is in a state fit to demo."
note "Equivalent to docs/operator/01_preflight.md §1 (build health)."
if ! command -v go >/dev/null 2>&1; then
    echo "  ERROR: go not found in PATH. The demo requires a working Go toolchain." >&2
    exit 1
fi
GO_VERSION=$(go env GOVERSION 2>/dev/null || echo unknown)
note "Go toolchain: ${GO_VERSION}"

# =============================================================================
# ACT I — Release-side vertical slice
# =============================================================================

act_banner "Act I — Release-side vertical slice (stages 1–9)"

stage "1/9" "Recovery Request — the administrator files a RecoveryRequest."
note "Package: internal/vault/intake. Invariant asserted: #3 sessions are mandatory."

stage "2/9" "Trust Admission — policy evaluates the caller."
note "Package: internal/vault/trust. Invariant asserted: #2 trust is a gate, not a log."

stage "3/9" "Trusted Session — the Vault issues a signed SessionObject."
note "Package: internal/vault/session. The SessionID flows through every downstream message."

stage "4/9" "Staged Disclosure — the StagedSequencer drives the StagedIssuer."
note "Package: internal/vault/disclosure."
note "Invariants asserted: #4 disclosure is staged (one message per component),"
note "                     #8 audit is first-class (one audit event per message, appended first)."

stage "5/9" "Delegated External Compute — the worker runs a reconstruction step."
note "Package: internal/compute/worker. The worker holds delegated execution, not authority."

stage "6/9" "Return Path — the result returns on a Vault-owned surface."
note "Package: internal/compute/returnpath."

stage "7/9" "Validation — six operational sub-checks, threshold 1.0."
note "Package: internal/validation/operational."
note "Sub-checks: op.attestation_valid, op.attestation_ttl, op.session_valid,"
note "            op.manifest_integrity, op.tamper_absent, op.policy_alignment."
note "Invariant asserted: #5 validation precedes release."

stage "8/9" "Release Decision — signed by SigningAuthority, carries"
note "ValidationResultID (pins invariant #5) + AuditEventID (pins invariant #8)."
note "Package: internal/vault/orchestration + internal/contracts/release_decision."

stage "9/9" "Audit — every stage transition has already been audit-appended."
note "Package: internal/audit. The hash-chain tip advances under SigningAudit."

banner "Running Act I — TestVerticalSlice_*"

printf "${COLOR_DIM}%s${COLOR_RESET}\n" \
  "The next command runs go test against internal/integration with a -run" \
  "filter for the release-side slice. If the test passes, every narrated" \
  "stage above has been exercised and the corresponding invariant assertion" \
  "has held."

echo
if ! go test -count=1 -v -run TestVerticalSlice ./internal/integration/... ; then
    rc=$?
    echo
    printf "${COLOR_YELLOW}${COLOR_BOLD}ACT I FAILED${COLOR_RESET}\n"
    printf "  %s\n" "The release-side vertical slice did not complete cleanly."
    printf "  %s\n" "This is either a code regression or a doctrine drift."
    printf "  %s\n" "Triage: run 'make test-doctrine' to isolate whether invariants themselves"
    printf "  %s\n" "        are failing, vs. whether the integration flow regressed."
    exit "${rc}"
fi
printf "${COLOR_GREEN}${COLOR_BOLD}Act I PASSED${COLOR_RESET}  — nine release-side stages exercised; invariants #2/#3/#4/#5/#8 held.\n"

# =============================================================================
# ACT II — Receive-side bootstrap round trip
# =============================================================================

act_banner "Act II — Receive-side round trip (stages R.1–R.6)"

printf "${COLOR_DIM}%s${COLOR_RESET}\n" \
  "Act II demonstrates the full receive-side story: that the signed Genome" \
  "emitted in Act I can be reassembled byte-exact on the receive side under a" \
  "BootstrapManifest, and that the two-tier integrity split (§8.4) catches" \
  "both transit tampers and release-side plaintext fraud."

stage "R.1" "BootstrapManifest issued — signed by the receive-side authority, ordered DisclosureID list."
note "Package: internal/contracts/bootstrap_manifest. Invariant: #1 (receive side holds no release-side authority)."

stage "R.2" "Orchestrator.Start — cross-manifest agreement + AGD/BootstrapManifest signatures verified."
note "Package: internal/bootstrap. Seven-state machine begins at StateUnstarted -> StateIngress."
note "Agreement rule: ordered DisclosureIDs must match between the release-side RJM and the receive-side BootstrapManifest."

stage "R.3" "Accept loop — tier 1 wire-hash commitment per envelope."
note "Package: internal/bootstrap. Code: CodeAcceptWireHashMismatch (Integrity) on any canonical-bytes hash mismatch."
note "Audit discipline: every Accept appends DISCLOSURE_RECEIVED BEFORE the ReceivedDisclosure becomes visible (invariant #8 mirror)."

stage "R.4" "Reassembler.Admit loop — AES-256-GCM open under 5-field AAD, tier 2 plaintext hash + byte-size."
note "Package: internal/reassembly. The AAD shape (SessionID + ComponentID + SequenceIndex + PolicyVersion + RecipientKeyID)"
note "is shared with the release-side StagedIssuer via /contracts/disclosure_message/aad.go — byte-stable across sides."
note "Refusal order: finalized -> nil -> validate -> unknown -> duplicate -> AAD -> Open -> byte-size -> SHA-256."

stage "R.5" "Reassembler.Finalize — RFC 6962 Merkle tree rebuilt; GenomeID round-trip asserted."
note "Package: internal/reassembly + internal/genome/componenttree."
note "Closing checks: tree root must equal agd.ComponentTreeRoot; agd.DeriveID() must equal agd.GenomeID (R-14 content-addressing)."

stage "R.6" "Orchestrator.Decide — signed ReconstitutionDecision emitted; one RECONSTITUTION_DECIDED audit event."
note "Package: internal/bootstrap + internal/contracts/reconstitution_decision."
note "Chain length after round trip: N+1 (one DISCLOSURE_RECEIVED per Accept + one RECONSTITUTION_DECIDED)."

echo
printf "${COLOR_DIM}%s${COLOR_RESET}\n" \
  "Act II's test runner includes three scenarios back-to-back:" \
  "  TestRoundtripSlice_HappyPath        — the full narrated round trip." \
  "  TestRoundtripSlice_Tier1_WireTamper  — one byte flipped on the wire is" \
  "      caught at tier 1 by the Orchestrator's wire-hash check before the" \
  "      Reassembler is touched." \
  "  TestRoundtripSlice_Tier2_PayloadFraud — release-side forges same-byte-" \
  "      length plaintext, re-seals under the correct AAD, re-signs the" \
  "      envelope, and re-pins the wire-hash; tier 1 sees nothing wrong;" \
  "      tier 2 catches it because forging the AGD's committed leaf hash" \
  "      would require forging Ed25519. This is doctrine §8.4's acid test."

banner "Running Act II — TestRoundtripSlice_*"

if ! go test -count=1 -v -run TestRoundtripSlice ./internal/integration/... ; then
    rc=$?
    echo
    printf "${COLOR_YELLOW}${COLOR_BOLD}ACT II FAILED${COLOR_RESET}\n"
    printf "  %s\n" "The receive-side round trip did not complete cleanly."
    printf "  %s\n" "Triage steps:"
    printf "  %s\n" "  1) If Tier 1 (TestRoundtripSlice_Tier1_WireTamper) regressed, suspect the"
    printf "  %s\n" "     orchestrator's wire-hash commitment path in /internal/bootstrap."
    printf "  %s\n" "  2) If Tier 2 (TestRoundtripSlice_Tier2_PayloadFraud) regressed, suspect the"
    printf "  %s\n" "     reassembler's plaintext-hash check in /internal/reassembly."
    printf "  %s\n" "  3) If HappyPath regressed but both tamper tests pass, suspect the shared"
    printf "  %s\n" "     AAD helper in /internal/contracts/disclosure_message/aad.go."
    exit "${rc}"
fi
printf "${COLOR_GREEN}${COLOR_BOLD}Act II PASSED${COLOR_RESET}  — six receive-side stages exercised; two-tier integrity split held under both adversarial scenarios.\n"

# =============================================================================
# Closing verdict
# =============================================================================

echo
banner "Demo verdict"
printf "${COLOR_GREEN}${COLOR_BOLD}DEMO PASSED${COLOR_RESET}  — fifteen narrated stages (9 release-side + 6 receive-side).\n"
printf "  %s\n" "Invariants asserted end-to-end: #1, #2, #3, #4, #5, #5-mirror, #8, #8-mirror."
printf "  %s\n" "Two-tier integrity split (§8.4): tier 1 (wire-hash) and tier 2 (plaintext hash + size) both held."
printf "  %s\n" "GenomeID preserved byte-identically across release AGD, BootstrapManifest, RJM,"
printf "  %s\n" "reassembler result, and the terminal ReconstitutionDecision (R-14 content-addressing)."
echo
printf "  %s\n" "Next reading:"
printf "  %s\n" "  - docs/operator/02_recovery_flow.md §7 for the receive-side deep walk."
printf "  %s\n" "  - 00_Bootstrap_Contracts_Doctrine.md §8.4 for the two-tier split rationale."
exit 0
