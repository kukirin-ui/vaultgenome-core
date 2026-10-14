// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package operational implements the Operational dimension of validation:
// "is the operational context of this candidate still governed,
// untampered, and within the policy envelope?"
//
// # Doctrinal role
//
// The operational dimension is non-negotiable. Six binary sub-checks, all
// of which must pass:
//
//	op.attestation_valid   — AttestationResult.Outcome==allow + sig verifies
//	op.attestation_ttl     — attestation within its TTL at validation time
//	op.session_valid       — SessionObject not expired, not invalidated,
//	                         matches the manifest
//	op.manifest_integrity  — SHA-256 of the ReconstructionJobManifest
//	                         matches the session's disclosure record
//	op.tamper_absent       — no IncidentEvent of severity >= warn on
//	                         this session or workflow
//	op.policy_alignment    — active Policy version == session's pinned
//	                         PolicyVersion
//
// An operational fail short-circuits: semantic and behavioral are NOT
// evaluated. MVP and production are essentially the same shape here
// (docs/doctrine/validation-thresholds.md §4). Production adds two sub-checks
// (real TEE quote verification, jurisdictional binding) without
// weakening these six.
//
// Coverage target: 90% (docs/doctrine/ci-security-policy.md §8).
//
// Stage B: empty package, doctrinal purpose only.
package operational
