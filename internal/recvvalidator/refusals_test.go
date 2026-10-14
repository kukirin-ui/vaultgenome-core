// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recvvalidator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
)

// TestSubChecks_MissingInputsRefused proves that every sub-check refuses
// a missing dependency (no manifest, no resolver, no pinned policy) with
// a reason that names the missing piece, instead of passing by default.
// Each row starts from the fully consistent fixture and removes one input.
func TestSubChecks_MissingInputsRefused(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(in *OperationalInputs)
		check  func(OperationalInputs) (bool, string)
		reason string
	}{
		{
			name:   "attestation_valid without resolver",
			mutate: func(in *OperationalInputs) { in.Resolver = nil },
			check:  CheckRecvAttestationValid,
			reason: "no key resolver supplied; cannot verify attestation signature",
		},
		{
			name:   "session_valid without bootstrap manifest",
			mutate: func(in *OperationalInputs) { in.BootstrapManifest = nil },
			check:  CheckRecvSessionValid,
			reason: "no bootstrap manifest supplied",
		},
		{
			name:   "session_valid without resolver",
			mutate: func(in *OperationalInputs) { in.Resolver = nil },
			check:  CheckRecvSessionValid,
			reason: "no key resolver supplied; cannot verify session signature",
		},
		{
			name:   "bootstrap_manifest_integrity without bootstrap manifest",
			mutate: func(in *OperationalInputs) { in.BootstrapManifest = nil },
			check:  CheckRecvBootstrapManifestIntegrity,
			reason: "no bootstrap manifest supplied",
		},
		{
			name:   "bootstrap_manifest_integrity without resolver",
			mutate: func(in *OperationalInputs) { in.Resolver = nil },
			check:  CheckRecvBootstrapManifestIntegrity,
			reason: "no key resolver supplied; cannot verify bootstrap manifest signature",
		},
		{
			name:   "reassembly_coverage without bootstrap manifest",
			mutate: func(in *OperationalInputs) { in.BootstrapManifest = nil },
			check:  CheckRecvReassemblyCoverage,
			reason: "no bootstrap manifest supplied",
		},
		{
			name: "reassembly_coverage with empty expected set",
			mutate: func(in *OperationalInputs) {
				in.BootstrapManifest.ExpectedDisclosureIDs = nil
				in.Coverage = ReassemblyCoverage{Expected: 0, Admitted: 0}
			},
			check:  CheckRecvReassemblyCoverage,
			reason: "bootstrap manifest expects zero disclosures — empty bootstrap is invalid",
		},
		{
			name:   "policy_alignment without session policy",
			mutate: func(in *OperationalInputs) { in.Session.PolicyVersion = "" },
			check:  CheckRecvPolicyAlignment,
			reason: "receive-side session has no pinned policy_version",
		},
		{
			name:   "policy_alignment without active policy",
			mutate: func(in *OperationalInputs) { in.ActivePolicy = "" },
			check:  CheckRecvPolicyAlignment,
			reason: "active policy_version not set on validator input",
		},
		{
			name:   "policy_alignment without manifest policy",
			mutate: func(in *OperationalInputs) { in.BootstrapManifest.PolicyVersion = "" },
			check:  CheckRecvPolicyAlignment,
			reason: "bootstrap manifest has no pinned policy_version",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRecvFixtures(t)
			tc.mutate(&f.inputs)
			ok, reason := tc.check(f.inputs)
			require.False(t, ok)
			require.Equal(t, tc.reason, reason)
		})
	}
}

// TestCheckRecvPolicyAlignment_NoManifestStillPasses proves that the
// policy-alignment sub-check only inspects the bootstrap manifest when one
// is supplied: session and active policy agreeing is enough on its own.
// The other sub-checks are what refuse a missing manifest.
func TestCheckRecvPolicyAlignment_NoManifestStillPasses(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.BootstrapManifest = nil
	ok, reason := CheckRecvPolicyAlignment(f.inputs)
	require.True(t, ok)
	require.Empty(t, reason)
}

// TestRunOperational_NoResolverFailsEverySignatureCheck proves that
// withholding the resolver fails exactly the three signature-backed
// sub-checks and leaves the TTL, coverage and policy checks untouched, so
// the audit record names precisely what could not be verified.
func TestRunOperational_NoResolverFailsEverySignatureCheck(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.Resolver = nil
	v := RunOperational(f.inputs)
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Equal(t, 3.0/6.0, v.Score)
	codes := make([]string, 0, len(v.Details))
	for _, d := range v.Details {
		codes = append(codes, d.Code)
	}
	require.ElementsMatch(t, []string{
		CodeRecvAttestationValid,
		CodeRecvSessionValid,
		CodeRecvBootstrapManifestIntegrity,
	}, codes)
}

// TestValidate_ZeroNowFallsBackToClock proves that a caller who leaves
// Now unset gets the service clock's reading: the STARTED event and the
// result timestamp both carry the fake clock's instant, and the
// fixture (issued at that same instant) still validates.
func TestValidate_ZeroNowFallsBackToClock(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	in := ValidateInputs{OperationalInputs: sf.recvFixtures.inputs}
	in.Now = time.Time{}

	result, err := sf.service.Validate(in)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictPass, result.OverallVerdict)

	want := sf.clock.Now().UTC()
	require.Equal(t, want, result.ValidatedAt)
	started, ok := sf.chain.EventAt(0)
	require.True(t, ok)
	require.Equal(t, want, started.OccurredAt)
	completed, ok := sf.chain.EventAt(1)
	require.True(t, ok)
	require.Equal(t, want, completed.OccurredAt)
}

// TestValidate_BehavioralEmptyLadderIsCallerFault proves that a behavioral
// request with no doors is a structural error from the ladder, surfaced
// unchanged by the service after the STARTED event has been recorded, and
// that no COMPLETED event or result is produced.
func TestValidate_BehavioralEmptyLadderIsCallerFault(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	in := ValidateInputs{
		OperationalInputs: sf.recvFixtures.inputs,
		Behavioral: &BehavioralInputs{
			GenomeID:  "g",
			Fixtures:  []equivalence.Fixture{{ID: "a", Expected: f64T(1, 2, 3), Critical: true}},
			Threshold: 0.99,
			Ladder:    nil,
		},
	}
	result, err := sf.service.Validate(in)
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))

	require.Equal(t, 1, sf.chain.Len(), "STARTED is recorded before the ladder runs")
	started, ok := sf.chain.EventAt(0)
	require.True(t, ok)
	require.Equal(t, audit_event.KindRecvValidationStarted, started.Kind)
}

// TestValidate_BehavioralThresholdOutOfRangeFailsPostCondition proves that
// the service's final static check catches a malformed result: a
// behavioral threshold outside [0,1] is written into the dimension verdict,
// so ValidationResult.Validate rejects it and the caller gets the
// structural error instead of a malformed result. Both audit events have
// already landed by then, which is the audit-before-surface discipline.
func TestValidate_BehavioralThresholdOutOfRangeFailsPostCondition(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	good := map[string]equivalence.Tensor{"a": f64T(1, 2, 3)}
	in := ValidateInputs{
		OperationalInputs: sf.recvFixtures.inputs,
		Behavioral: &BehavioralInputs{
			GenomeID:  "g",
			Fixtures:  []equivalence.Fixture{{ID: "a", Expected: f64T(1, 2, 3), Critical: true}},
			Threshold: 1.5,
			Ladder:    []reconstruction.Strategy{fixedDoor(1, "exact", good, equivalence.Tolerance{})},
		},
	}
	result, err := sf.service.Validate(in)
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.Equal(t, 2, sf.chain.Len(), "both audit events land before the post-condition runs")
}

// TestCounterBytes_BigEndianAndSortable proves the counter encoding is
// 8-byte big-endian, so hex-encoded IDs sort in issue order.
func TestCounterBytes_BigEndianAndSortable(t *testing.T) {
	t.Parallel()
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, counterBytes(1))
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 1, 0}, counterBytes(256))
	require.Equal(t, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, counterBytes(^uint64(0)))
	require.Less(t, string(counterBytes(41)), string(counterBytes(42)))
}

// TestNewValidationService_CustomPrefixesKept proves that caller-supplied
// ID prefixes are used verbatim on the minted audit and result IDs.
func TestNewValidationService_CustomPrefixesKept(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	svc, err := NewValidationService(ServiceOptions{
		AuditChain:     sf.chain,
		AuditSigner:    sf.recvFixtures.store,
		AuditKeyID:     sf.auditKID,
		Clock:          sf.clock,
		AuditIDPrefix:  "site-a-audit-",
		ResultIDPrefix: "site-a-vr-",
	})
	require.NoError(t, err)
	result, err := svc.Validate(ValidateInputs{OperationalInputs: sf.recvFixtures.inputs})
	require.NoError(t, err)
	require.True(t, len(result.ValidationResultID) > len("site-a-vr-"))
	require.Equal(t, "site-a-vr-", string(result.ValidationResultID)[:len("site-a-vr-")])
	for i := 0; i < sf.chain.Len(); i++ {
		e, ok := sf.chain.EventAt(i)
		require.True(t, ok)
		require.Equal(t, "site-a-audit-", string(e.EventID)[:len("site-a-audit-")])
	}
}
