// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Per-field stable codes for cross-manifest agreement failures. These
// names appear in test assertions and in release notes; they must not
// drift silently. A mismatch here is structurally invalid — no
// agreement-level issue is ever classified as operational or
// authority, because the drift is static-shape, not policy.
const (
	CodeAgreementSessionMismatch         = "bootstrap.agreement.session_mismatch"
	CodeAgreementManifestMismatch        = "bootstrap.agreement.manifest_mismatch"
	CodeAgreementPolicyMismatch          = "bootstrap.agreement.policy_mismatch"
	CodeAgreementGenomeMismatch          = "bootstrap.agreement.genome_mismatch"
	CodeAgreementDisclosureLenMismatch   = "bootstrap.agreement.disclosure_len_mismatch"
	CodeAgreementDisclosureOrderMismatch = "bootstrap.agreement.disclosure_order_mismatch"
)

// CheckAgreement asserts that a receive-side BootstrapManifest and the
// release-side ReconstructionJobManifest it mirrors agree on every
// field doctrine requires them to agree on:
//
//   - SessionID — the same trusted session must gate both sides.
//   - ManifestID — the BootstrapManifest pins the ReconstructionJobManifest.
//   - PolicyVersion — the same policy revision governs both sides.
//   - GenomeID — the same Genome is being released and reconstituted.
//   - ExpectedDisclosureIDs — as an ordered list, matching
//     ReconstructionJobManifest.DisclosureIDs exactly. Order is
//     semantically significant: it is the acceptance order the
//     receive-side committed to, and it MUST be the emission order the
//     release-side committed to. A permutation is a doctrine
//     violation even if the sets are equal.
//
// Silent drift on any of these axes is what the Bootstrap Contracts
// Doctrine §3 exists to prevent. The contract validators do NOT assert
// cross-manifest agreement; they cannot, because they see only one
// artifact. This is the only place in the codebase that holds both
// artifacts at once, and it is the only place the agreement is
// structurally re-checked.
//
// Both arguments are required non-nil; a nil on either side is a
// structural refusal. The individual Validate() preconditions on each
// manifest are assumed — CheckAgreement does NOT re-run the
// per-artifact validators.
func CheckAgreement(
	b *bootstrap_manifest.BootstrapManifest,
	r *reconstruction_job_manifest.ReconstructionJobManifest,
) error {
	if b == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.agreement: bootstrap_manifest is nil",
			nil,
		)
	}
	if r == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap.agreement: reconstruction_job_manifest is nil",
			nil,
		)
	}

	if b.SessionID != r.SessionID {
		return shared_errors.Structural(
			CodeAgreementSessionMismatch,
			"bootstrap.agreement: session_id mismatch between bootstrap and reconstruction manifests",
			nil,
		)
	}
	if b.ManifestID != r.ManifestID {
		return shared_errors.Structural(
			CodeAgreementManifestMismatch,
			"bootstrap.agreement: manifest_id mismatch — bootstrap does not pin this reconstruction manifest",
			nil,
		)
	}
	if b.PolicyVersion != r.PolicyVersion {
		return shared_errors.Structural(
			CodeAgreementPolicyMismatch,
			"bootstrap.agreement: policy_version mismatch between bootstrap and reconstruction manifests",
			nil,
		)
	}
	if b.GenomeID != r.GenomeID {
		return shared_errors.Structural(
			CodeAgreementGenomeMismatch,
			"bootstrap.agreement: genome_id mismatch — bootstrap does not reconstitute this release's genome",
			nil,
		)
	}

	if len(b.ExpectedDisclosureIDs) != len(r.DisclosureIDs) {
		return shared_errors.Structural(
			CodeAgreementDisclosureLenMismatch,
			"bootstrap.agreement: expected_disclosure_ids length does not match reconstruction_job_manifest.disclosure_ids length",
			nil,
		)
	}
	for i := range b.ExpectedDisclosureIDs {
		if b.ExpectedDisclosureIDs[i] != r.DisclosureIDs[i] {
			return shared_errors.Structural(
				CodeAgreementDisclosureOrderMismatch,
				"bootstrap.agreement: expected_disclosure_ids differs from reconstruction_job_manifest.disclosure_ids at position "+positionLabel(i)+" — order is semantically significant",
				nil,
			)
		}
	}

	return nil
}

// positionLabel renders a small non-negative integer as a stable
// decimal string without pulling strconv into this error path. Used
// only in error messages.
func positionLabel(i int) string {
	if i == 0 {
		return "0"
	}
	var digits [20]byte
	n := i
	pos := len(digits)
	for n > 0 {
		pos--
		digits[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[pos:])
}
