// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recvvalidator

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Machine-readable sub-check codes for the receive-side operational
// dimension. These are the canonical strings that appear in Findings
// and in RECV_VALIDATION_COMPLETED audit payloads — they are part of
// the contract with external auditors and MUST NOT change across
// schema versions. The op.recv.* prefix is what distinguishes them
// from the release-side op.* codes in /internal/validation/operational.
const (
	CodeRecvAttestationValid           = "op.recv.attestation_valid"
	CodeRecvAttestationTTL             = "op.recv.attestation_ttl"
	CodeRecvSessionValid               = "op.recv.session_valid"
	CodeRecvBootstrapManifestIntegrity = "op.recv.bootstrap_manifest_integrity"
	CodeRecvReassemblyCoverage         = "op.recv.reassembly_coverage"
	CodeRecvPolicyAlignment            = "op.recv.policy_alignment"
)

// totalChecks is the fixed count of receive-side operational
// sub-checks. Changing this is a schema bump — it changes the score
// denominator and the meaning of a partial result.
const totalChecks = 6

// ReassemblyCoverage summarises what the receive-side Reassembler
// actually admitted. Stage G intentionally passes these two numbers
// as a plain struct (rather than the full ReassemblyResult) to avoid
// importing /internal/reassembly into this package — recvvalidator is
// meant to be a peer of bootstrap/ and reassembly/, not a consumer of
// either.
//
// Expected is the length of BootstrapManifest.ExpectedDisclosureIDs.
// Admitted is the number of DisclosureMessages the reassembler
// accepted (i.e. those that passed both tier-1 wire-hash and tier-2
// plaintext-hash checks). A successful bootstrap has Expected ==
// Admitted and Admitted > 0.
type ReassemblyCoverage struct {
	Expected int
	Admitted int
}

// OperationalInputs bundles every artifact the six sub-checks may
// need. The struct is deliberately concrete (no interfaces) so that
// the validator has zero latitude to reinterpret what "this artifact"
// means — any abstraction belongs above this layer.
type OperationalInputs struct {
	// BootstrapManifest is the receive-side recipe the Orchestrator is
	// driving. Its signature MUST verify under the receive-side
	// authority resolver before op.recv.bootstrap_manifest_integrity
	// will pass.
	BootstrapManifest *bootstrap_manifest.BootstrapManifest

	// Attestation is the Trust Admission outcome for the RECEIVE side.
	// It is a mirror of the release-side AttestationResult contract
	// but issued against the receiving environment's admission gate.
	Attestation attestation_result.AttestationResult

	// Session is the receive-side trusted session that governs this
	// reconstitution attempt. Mirror of the release-side SessionObject
	// contract; issued by the receive-side session authority.
	Session session_object.SessionObject

	// ActivePolicy is the policy version currently in force at the
	// receiving environment. The session's pinned PolicyVersion must
	// match this value for op.recv.policy_alignment to pass.
	ActivePolicy ids.PolicyVersion

	// Coverage summarises the Reassembler's admit-result set.
	// Expected == Admitted and Admitted > 0 is required for
	// op.recv.reassembly_coverage to pass.
	Coverage ReassemblyCoverage

	// Now is the receive-side clock reading at validation time. All
	// TTL comparisons are relative to this value, not time.Now()
	// directly.
	Now time.Time

	// Resolver returns verifying keys for signature checks. Must
	// resolve every SigningKeyID referenced by Attestation, Session,
	// and BootstrapManifest.
	Resolver keys.Resolver
}

// RunOperational executes all six receive-side sub-checks and returns
// an aggregated DimensionVerdict.
//
// Receive-side operational is binary by doctrine (Stage G §1 —
// mirroring docs/doctrine/validation-thresholds.md §4): any sub-check
// failure fails the whole dimension. Score is reported as pass/total
// so an external auditor can see which sub-check tripped even when
// Verdict=fail.
//
// No short-circuit: every sub-check always runs, even after a
// failure, because failing early would hide correlated failures from
// the audit record.
func RunOperational(in OperationalInputs) validation_result.DimensionVerdict {
	checks := []struct {
		code string
		run  func(OperationalInputs) (bool, string)
	}{
		{CodeRecvAttestationValid, CheckRecvAttestationValid},
		{CodeRecvAttestationTTL, CheckRecvAttestationTTL},
		{CodeRecvSessionValid, CheckRecvSessionValid},
		{CodeRecvBootstrapManifestIntegrity, CheckRecvBootstrapManifestIntegrity},
		{CodeRecvReassemblyCoverage, CheckRecvReassemblyCoverage},
		{CodeRecvPolicyAlignment, CheckRecvPolicyAlignment},
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

// CheckRecvAttestationValid verifies the receive-side attestation's
// Outcome is 'allow' and that its signature holds under the resolver.
// A deny or restrict outcome is a fail even if the signature is valid
// — the doctrine rejects a trust admission that did not grant
// admission.
func CheckRecvAttestationValid(in OperationalInputs) (bool, string) {
	if in.Attestation.Outcome != attestation_result.OutcomeAllow {
		return false, "receive-side attestation outcome is not 'allow': " + string(in.Attestation.Outcome)
	}
	if in.Resolver == nil {
		return false, "no key resolver supplied; cannot verify attestation signature"
	}
	if err := in.Attestation.VerifySignature(in.Resolver); err != nil {
		return false, "receive-side attestation signature verification failed: " + err.Error()
	}
	return true, ""
}

// CheckRecvAttestationTTL verifies that the receive-side attestation
// is still within its declared TTL at in.Now. TTL == 0 is treated as
// expired regardless of IssuedAt (a zero-TTL attestation grants no
// window and is rejected).
func CheckRecvAttestationTTL(in OperationalInputs) (bool, string) {
	if in.Attestation.TTL <= 0 {
		return false, "receive-side attestation has non-positive TTL"
	}
	expiry := in.Attestation.IssuedAt.Add(in.Attestation.TTL)
	if !in.Now.Before(expiry) {
		return false, "receive-side attestation expired at " + expiry.UTC().Format(time.RFC3339Nano) +
			"; now is " + in.Now.UTC().Format(time.RFC3339Nano)
	}
	return true, ""
}

// CheckRecvSessionValid verifies that the receive-side session is
// active, not expired, and that the bootstrap manifest under
// validation belongs to this session. It also checks the session's
// signature.
func CheckRecvSessionValid(in OperationalInputs) (bool, string) {
	if in.Session.State != session_object.StateActive {
		return false, "receive-side session state is not 'active': " + string(in.Session.State)
	}
	if !in.Now.Before(in.Session.ExpiresAt) {
		return false, "receive-side session expired"
	}
	if in.BootstrapManifest == nil {
		return false, "no bootstrap manifest supplied"
	}
	if in.BootstrapManifest.SessionID != in.Session.SessionID {
		return false, "bootstrap manifest session_id does not match session"
	}
	if in.Resolver == nil {
		return false, "no key resolver supplied; cannot verify session signature"
	}
	if err := in.Session.VerifySignature(in.Resolver); err != nil {
		return false, "receive-side session signature verification failed: " + err.Error()
	}
	return true, ""
}

// CheckRecvBootstrapManifestIntegrity verifies the BootstrapManifest's
// signature under the resolver. A failure here means either the
// manifest was mutated after issuance or the recorded SigningKeyID is
// wrong. This is the receive-side analogue of the release-side
// op.manifest_integrity sub-check.
func CheckRecvBootstrapManifestIntegrity(in OperationalInputs) (bool, string) {
	if in.BootstrapManifest == nil {
		return false, "no bootstrap manifest supplied"
	}
	if in.Resolver == nil {
		return false, "no key resolver supplied; cannot verify bootstrap manifest signature"
	}
	if err := in.BootstrapManifest.VerifySignature(in.Resolver); err != nil {
		return false, "bootstrap manifest signature verification failed: " + err.Error()
	}
	return true, ""
}

// CheckRecvReassemblyCoverage verifies that the reassembler admitted
// exactly the number of disclosures the bootstrap manifest expected.
// A mismatch means the reassembly finalised over a partial set of
// the expected envelopes — which the Orchestrator's state-machine
// would normally catch (StateReassemble does not advance to
// StateValidate without MarkReassembled), but the validator enforces
// it again as a defence-in-depth check: MarkReassembled is advisory;
// the coverage count is authoritative.
func CheckRecvReassemblyCoverage(in OperationalInputs) (bool, string) {
	if in.BootstrapManifest == nil {
		return false, "no bootstrap manifest supplied"
	}
	expected := len(in.BootstrapManifest.ExpectedDisclosureIDs)
	if expected == 0 {
		return false, "bootstrap manifest expects zero disclosures — empty bootstrap is invalid"
	}
	if in.Coverage.Expected != expected {
		return false, "coverage.expected does not match bootstrap manifest expected disclosure count"
	}
	if in.Coverage.Admitted <= 0 {
		return false, "reassembler admitted zero disclosures"
	}
	if in.Coverage.Admitted != in.Coverage.Expected {
		return false, "reassembler admitted only a partial set: admitted < expected"
	}
	return true, ""
}

// CheckRecvPolicyAlignment verifies that the receive-side session's
// pinned PolicyVersion matches the receive-side active policy AND
// that both agree with the bootstrap manifest's policy. A mismatch
// means either the policy rotated mid-reconstitution (requiring the
// session to be re-issued) or the session is from a prior policy
// generation.
func CheckRecvPolicyAlignment(in OperationalInputs) (bool, string) {
	if in.Session.PolicyVersion.IsZero() {
		return false, "receive-side session has no pinned policy_version"
	}
	if in.ActivePolicy.IsZero() {
		return false, "active policy_version not set on validator input"
	}
	if in.Session.PolicyVersion != in.ActivePolicy {
		return false, "session policy_version '" + string(in.Session.PolicyVersion) +
			"' does not match active policy '" + string(in.ActivePolicy) + "'"
	}
	if in.BootstrapManifest != nil {
		if in.BootstrapManifest.PolicyVersion.IsZero() {
			return false, "bootstrap manifest has no pinned policy_version"
		}
		if in.BootstrapManifest.PolicyVersion != in.ActivePolicy {
			return false, "bootstrap manifest policy_version '" + string(in.BootstrapManifest.PolicyVersion) +
				"' does not match active policy '" + string(in.ActivePolicy) + "'"
		}
	}
	return true, ""
}
