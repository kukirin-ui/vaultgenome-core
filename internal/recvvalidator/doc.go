// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package recvvalidator implements Stage G — the receive-side validator.
//
// # Doctrinal role
//
// The receive-side validator is the terminal gate between the Reassembler
// finalising a byte-exact candidate genome and the Orchestrator emitting
// a signed ReconstitutionDecision. Without it the Orchestrator's
// StateValidate → StateReady transition would be driven by an externally
// supplied ValidationResultID with no receive-side-owned provenance —
// which is precisely the invariant-#8 gap Stage G exists to close.
//
// Scope: OPERATIONAL-ONLY by doctrine
//
// Release-side validation has three dimensions (semantic, behavioral,
// operational) because the release side gates DISCLOSURE of a previously
// validated genome. The receive side, by contrast, gates the ACCEPTANCE
// of a reconstructed candidate — and at Orchestrator.StateValidate time
// the candidate model has not yet been run, so semantic and behavioral
// dimensions are not defined over the receive-side surface. Their
// receive-side analogues belong in a post-reconstitution compute-side
// validator that lives OUTSIDE the Orchestrator's state machine.
//
// Stage G therefore mirrors only the operational dimension. Six
// receive-side sub-checks, all binary, all of which must pass:
//
//	op.recv.attestation_valid           — receiver's AttestationResult.Outcome
//	                                      is 'allow' and its signature verifies
//	op.recv.attestation_ttl             — receive-side attestation still within TTL
//	op.recv.session_valid               — receiver's SessionObject is active,
//	                                      not expired, matches the bootstrap
//	op.recv.bootstrap_manifest_integrity — BootstrapManifest signature verifies;
//	                                      this is the receive-side analogue of
//	                                      op.manifest_integrity
//	op.recv.reassembly_coverage         — the Reassembler admitted exactly
//	                                      the ExpectedDisclosureIDs count;
//	                                      no silent partial acceptance
//	op.recv.policy_alignment            — session.PolicyVersion == active policy
//
// Binary aggregation: any failing sub-check fails the dimension; any
// failing dimension fails the overall verdict. Score = passed/6 is
// reported so an external auditor can see which sub-check tripped even
// when Verdict=fail.
//
// # Audit contract
//
// The validator emits two new SchemaVersion-3 AuditEvent Kinds:
//
//   - KindRecvValidationStarted — appended BEFORE the six sub-checks run.
//     Pins BootstrapID, ManifestID, SessionID, and PolicyVersion.
//
//   - KindRecvValidationCompleted — appended AFTER the DimensionVerdict
//     is finalised and BEFORE the ValidationResult is surfaced to the
//     caller. Pins ValidationResultID, overall verdict, and score.
//
// This is the same audit-event-before-surface discipline the release
// side's StagedSequencer enforces and the Orchestrator's Accept and
// Decide paths mirror.
//
// What Stage G is NOT
//
//   - It is NOT a release-side validator replacement. The release side
//     retains its three-dimension service in /internal/validation/service
//     (Iteration 2) and the release-side aggregation rule in
//     docs/doctrine/validation-thresholds.md §5.
//
//   - It is NOT an in-process model runner. No weights are loaded, no
//     probes are executed. Behavioural/semantic validation of the
//     reconstructed model is a V2+ compute-side concern.
//
//   - It does NOT replace the Orchestrator's sentinel VRID at
//     StateRejected/ReasonReassemblyFailed. That sentinel is structurally
//     correct — it is only minted when reassembly failed BEFORE the
//     validator ran — and remains in place.
//
// Position in the receive-side pipeline
//
//	Orchestrator.Accept loop → StateReassemble →
//	Reassembler.Admit loop + Finalize →
//	Orchestrator.MarkReassembled → StateValidate →
//	↓
//	recvvalidator.ValidationService.Validate(...)
//	  emit KindRecvValidationStarted
//	  run six op.recv.* sub-checks
//	  build ValidationResult (operational-only dimension)
//	  emit KindRecvValidationCompleted
//	  return ValidationResult
//	↓
//	If OverallVerdict=pass: Orchestrator.MarkValidated(vrid) → StateReady
//	If OverallVerdict=fail: Orchestrator.MarkValidationFailed(vrid) → StateRejected
//	↓
//	Orchestrator.Decide → signed ReconstitutionDecision
//
// See docs/doctrine/bootstrap-contracts.md §9 (Stage G closure) and the
// operator playbook /docs/operator/02_recovery_flow.md §7.4–§7.6.
package recvvalidator
