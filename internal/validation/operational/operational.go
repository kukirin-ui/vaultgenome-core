// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package operational

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Machine-readable sub-check codes. These are the canonical strings used in
// Findings and in audit events — they are part of the contract with
// external auditors and MUST NOT change across schema versions.
const (
	CodeAttestationValid  = "op.attestation_valid"
	CodeAttestationTTL    = "op.attestation_ttl"
	CodeSessionValid      = "op.session_valid"
	CodeManifestIntegrity = "op.manifest_integrity"
	CodeTamperAbsent      = "op.tamper_absent"
	CodePolicyAlignment   = "op.policy_alignment"
)

// totalChecks is the fixed count of operational sub-checks. Changing this
// is a schema bump — it changes the score denominator and the meaning of
// a partial result.
const totalChecks = 6

// Inputs bundles every artifact the six sub-checks may need. The struct is
// deliberately concrete (no interfaces) so that the validator has zero
// latitude to reinterpret what "this artifact" means — any abstraction
// belongs above this layer.
type Inputs struct {
	// Attestation is the Trust Admission outcome for this request.
	Attestation attestation_result.AttestationResult
	// Session is the trusted session that governs the current disclosure.
	Session session_object.SessionObject
	// Manifest is the reconstruction job description referenced by the
	// candidate under validation.
	Manifest reconstruction_job_manifest.ReconstructionJobManifest
	// ActivePolicy is the policy version currently in force at the vault.
	// The session's pinned PolicyVersion must match this value.
	ActivePolicy ids.PolicyVersion
	// TamperSignalled is true when /internal/vault/incident has flagged
	// any tamper event of severity >= warn on this session or workflow.
	// MVP: a boolean; production walks IncidentEvent records.
	TamperSignalled bool
	// Now is the vault's clock reading at validation time. All TTL
	// comparisons are relative to this value, not time.Now() directly.
	Now time.Time
	// Resolver returns verifying keys for signature checks. Must resolve
	// every SigningKeyID referenced by Attestation, Session, and Manifest.
	Resolver keys.Resolver
}

// Run executes all six sub-checks and returns an aggregated
// DimensionVerdict. Operational is binary in doctrine
// (docs/doctrine/validation-thresholds.md §4): any sub-check failure fails the
// whole dimension. Score is reported as pass/total so external auditors
// can see which sub-check tripped even when Verdict==fail.
//
// No short-circuit: every sub-check always runs, even after a failure,
// because failing early would hide correlated failures from the audit
// record. A validator that wants per-check timing can wrap individual
// sub-checks in its own instrumentation.
func Run(in Inputs) validation_result.DimensionVerdict {
	checks := []struct {
		code string
		run  func(Inputs) (bool, string)
	}{
		{CodeAttestationValid, CheckAttestationValid},
		{CodeAttestationTTL, CheckAttestationTTL},
		{CodeSessionValid, CheckSessionValid},
		{CodeManifestIntegrity, CheckManifestIntegrity},
		{CodeTamperAbsent, CheckTamperAbsent},
		{CodePolicyAlignment, CheckPolicyAlignment},
	}

	passed := 0
	var details []validation_result.Finding
	for _, c := range checks {
		ok, reason := c.run(in)
		if ok {
			passed++
			continue
		}
		details = append(details, validation_result.Finding{
			Code:     c.code,
			Severity: validation_result.SeverityError,
			Message:  reason,
		})
	}

	verdict := validation_result.VerdictPass
	if passed < totalChecks {
		verdict = validation_result.VerdictFail
	}

	return validation_result.DimensionVerdict{
		Verdict:   verdict,
		Score:     float64(passed) / float64(totalChecks),
		Threshold: 1.0, // binary dimension: anything less than all passing fails
		Details:   details,
	}
}

// CheckAttestationValid verifies the attestation's Outcome is "allow" and
// that its signature holds under the resolver. A deny or restrict outcome
// is a fail even if the signature is valid — the doctrine rejects a
// trust admission that did not grant admission.
func CheckAttestationValid(in Inputs) (bool, string) {
	if in.Attestation.Outcome != attestation_result.OutcomeAllow {
		return false, "attestation outcome is not 'allow': " + string(in.Attestation.Outcome)
	}
	if err := in.Attestation.VerifySignature(in.Resolver); err != nil {
		return false, "attestation signature verification failed: " + err.Error()
	}
	return true, ""
}

// CheckAttestationTTL verifies that the attestation is still within its
// declared TTL at in.Now. TTL == 0 is treated as expired regardless of
// IssuedAt (a zero-TTL attestation grants no window and is rejected).
func CheckAttestationTTL(in Inputs) (bool, string) {
	if in.Attestation.TTL <= 0 {
		return false, "attestation has non-positive TTL"
	}
	expiry := in.Attestation.IssuedAt.Add(in.Attestation.TTL)
	if !in.Now.Before(expiry) {
		return false, "attestation expired at " + expiry.UTC().Format(time.RFC3339Nano) +
			"; now is " + in.Now.UTC().Format(time.RFC3339Nano)
	}
	return true, ""
}

// CheckSessionValid verifies that the session is active, not expired, and
// that the manifest under validation belongs to this session. It also
// checks the session's signature.
func CheckSessionValid(in Inputs) (bool, string) {
	if in.Session.State != session_object.StateActive {
		return false, "session state is not 'active': " + string(in.Session.State)
	}
	if !in.Now.Before(in.Session.ExpiresAt) {
		return false, "session expired"
	}
	if in.Manifest.SessionID != in.Session.SessionID {
		return false, "manifest session_id does not match session"
	}
	if err := in.Session.VerifySignature(in.Resolver); err != nil {
		return false, "session signature verification failed: " + err.Error()
	}
	return true, ""
}

// CheckManifestIntegrity verifies the manifest's signature, which is also
// the pre-image whose SHA-256 the external compute side re-checks as part
// of its own integrity contract. A failure here means either the manifest
// was mutated after issuance or the recorded SigningKeyID is wrong.
func CheckManifestIntegrity(in Inputs) (bool, string) {
	if err := in.Manifest.VerifySignature(in.Resolver); err != nil {
		return false, "manifest signature verification failed: " + err.Error()
	}
	return true, ""
}

// CheckTamperAbsent reports whether any tamper signal has been flagged on
// the current session or workflow. MVP: a boolean input. Production walks
// IncidentEvent records produced by /internal/vault/incident.
func CheckTamperAbsent(in Inputs) (bool, string) {
	if in.TamperSignalled {
		return false, "tamper signal present on this session or workflow"
	}
	return true, ""
}

// CheckPolicyAlignment verifies that the session's pinned PolicyVersion
// matches the vault's active policy. A mismatch means either the policy
// rotated mid-session (requiring the session to be re-issued) or the
// session is from a prior policy generation.
func CheckPolicyAlignment(in Inputs) (bool, string) {
	if in.Session.PolicyVersion.IsZero() {
		return false, "session has no pinned policy_version"
	}
	if in.ActivePolicy.IsZero() {
		return false, "active policy_version not set on validator input"
	}
	if in.Session.PolicyVersion != in.ActivePolicy {
		return false, "session policy_version '" + string(in.Session.PolicyVersion) +
			"' does not match active policy '" + string(in.ActivePolicy) + "'"
	}
	return true, ""
}
