// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recvvalidator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// recvFixtures builds a fully signed, mutually consistent receive-side
// validator baseline. Each sub-check test starts from this state and
// mutates exactly one field.
type recvFixtures struct {
	inputs   OperationalInputs
	recvKID  ids.KeyID
	trustKID ids.KeyID
	store    *keys.InMemoryStore
}

func newRecvFixtures(t *testing.T) *recvFixtures {
	t.Helper()
	now := time.Date(2026, 4, 21, 9, 0, 0, 0, time.UTC)
	fc := shared_time.NewFakeClock(now)
	store := keys.NewInMemoryStore(fc)

	recvKID := ids.KeyID("recv-auth-g1")
	trustKID := ids.KeyID("recv-trust-g1")
	_, err := store.GenerateSigning(recvKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(trustKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	activePolicy := ids.PolicyVersion("policy-g1")
	sessionID := ids.SessionID("sess-g1-0001")
	manifestID := ids.ManifestID("mani-g1-0001")
	bootstrapID := ids.BootstrapManifestID("boot-g1-0001")
	requestID := ids.RequestID("req-g1-0001")
	genomeID := ids.GenomeID("genome-recv-g1")

	att := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: ids.AttestationID("att-g1-0001"),
		RequestID:     requestID,
		Outcome:       attestation_result.OutcomeAllow,
		IssuedAt:      now,
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  trustKID,
	}
	require.NoError(t, att.SignWith(store))

	sess := session_object.SessionObject{
		SchemaVersion: session_object.SchemaVersionCurrent,
		SessionID:     sessionID,
		RequestID:     requestID,
		GenomeID:      genomeID,
		PolicyVersion: activePolicy,
		IssuedAt:      now,
		ExpiresAt:     now.Add(5 * time.Minute),
		State:         session_object.StateActive,
		SigningKeyID:  recvKID,
	}
	require.NoError(t, sess.SignWith(store))

	bm := &bootstrap_manifest.BootstrapManifest{
		SchemaVersion:         bootstrap_manifest.SchemaVersionCurrent,
		BootstrapID:           bootstrapID,
		SessionID:             sessionID,
		ManifestID:            manifestID,
		GenomeID:              genomeID,
		PolicyVersion:         activePolicy,
		ExpectedDisclosureIDs: []ids.DisclosureID{"disc-g1-0", "disc-g1-1", "disc-g1-2"},
		ExpectedComponentIDs:  []ids.ComponentID{"c-0", "c-1", "c-2"},
		Deadline:              now.Add(10 * time.Minute),
		IssuedAt:              now,
		SigningKeyID:          recvKID,
	}
	require.NoError(t, bm.SignWith(store))

	return &recvFixtures{
		inputs: OperationalInputs{
			BootstrapManifest: bm,
			Attestation:       att,
			Session:           sess,
			ActivePolicy:      activePolicy,
			Coverage:          ReassemblyCoverage{Expected: 3, Admitted: 3},
			Now:               now.Add(time.Second),
			Resolver:          store,
		},
		recvKID:  recvKID,
		trustKID: trustKID,
		store:    store,
	}
}

// ---- aggregate-level behaviour -------------------------------------------

func TestRunOperational_AllPass(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	v := RunOperational(f.inputs)
	require.Equal(t, validation_result.VerdictPass, v.Verdict,
		"findings: %+v", v.Details)
	require.Equal(t, 1.0, v.Score)
	require.Equal(t, 1.0, v.Threshold)
	require.Empty(t, v.Details)
}

func TestRunOperational_OneFailureFailsDimension(t *testing.T) {
	t.Parallel()
	// Receive-side operational is binary: any failing sub-check fails the
	// whole dimension. Score reflects which fraction passed.
	f := newRecvFixtures(t)
	f.inputs.Coverage.Admitted = 2 // partial
	v := RunOperational(f.inputs)
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Equal(t, 5.0/6.0, v.Score)
	require.Len(t, v.Details, 1)
	require.Equal(t, CodeRecvReassemblyCoverage, v.Details[0].Code)
	require.Equal(t, validation_result.SeverityError, v.Details[0].Severity)
}

func TestRunOperational_ReportsAllFailures(t *testing.T) {
	t.Parallel()
	// No short-circuit: every sub-check always runs so auditors see the
	// full correlated set of failures.
	f := newRecvFixtures(t)
	f.inputs.Attestation.Outcome = attestation_result.OutcomeDeny
	f.inputs.ActivePolicy = ids.PolicyVersion("policy-rotated")
	f.inputs.Coverage.Admitted = 0

	v := RunOperational(f.inputs)
	require.Equal(t, validation_result.VerdictFail, v.Verdict)

	codes := map[string]bool{}
	for _, d := range v.Details {
		codes[d.Code] = true
	}
	require.True(t, codes[CodeRecvAttestationValid], "attestation-valid finding expected")
	require.True(t, codes[CodeRecvPolicyAlignment], "policy-alignment finding expected")
	require.True(t, codes[CodeRecvReassemblyCoverage], "coverage finding expected")
	require.GreaterOrEqual(t, len(v.Details), 3)
}

// ---- individual sub-check tests -----------------------------------------

func TestCheckRecvAttestationValid_DenyRejected(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.Attestation.Outcome = attestation_result.OutcomeDeny
	f.inputs.Attestation.Reason = "recv.peer_unknown"
	ok, reason := CheckRecvAttestationValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "outcome")
}

func TestCheckRecvAttestationValid_BadSignatureRejected(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	// Tamper post-signing — signature must not verify.
	f.inputs.Attestation.Reason = "injected-after-signing"
	ok, reason := CheckRecvAttestationValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "signature")
}

func TestCheckRecvAttestationTTL_Expired(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.Now = f.inputs.Attestation.IssuedAt.Add(f.inputs.Attestation.TTL + time.Second)
	ok, reason := CheckRecvAttestationTTL(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "expired")
}

func TestCheckRecvAttestationTTL_ZeroTTLRejected(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.Attestation.TTL = 0
	ok, reason := CheckRecvAttestationTTL(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "non-positive")
}

func TestCheckRecvSessionValid_NotActive(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.Session.State = session_object.StateSuspended
	ok, reason := CheckRecvSessionValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "active")
}

func TestCheckRecvSessionValid_Expired(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.Now = f.inputs.Session.ExpiresAt.Add(time.Second)
	ok, _ := CheckRecvSessionValid(f.inputs)
	require.False(t, ok)
}

func TestCheckRecvSessionValid_BootstrapMismatch(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.BootstrapManifest.SessionID = ids.SessionID("sess-other")
	ok, reason := CheckRecvSessionValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "session_id")
}

func TestCheckRecvSessionValid_BadSignatureRejected(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	// Tamper post-signing on the session.
	f.inputs.Session.ExpiresAt = f.inputs.Session.ExpiresAt.Add(time.Hour)
	ok, reason := CheckRecvSessionValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "signature")
}

func TestCheckRecvBootstrapManifestIntegrity_TamperedRejected(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	// Mutate the manifest after signing — signature must no longer hold.
	f.inputs.BootstrapManifest.Deadline = f.inputs.BootstrapManifest.Deadline.Add(time.Hour)
	ok, reason := CheckRecvBootstrapManifestIntegrity(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "signature")
}

func TestCheckRecvReassemblyCoverage_Partial(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.Coverage.Admitted = 2
	ok, reason := CheckRecvReassemblyCoverage(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "partial")
}

func TestCheckRecvReassemblyCoverage_ExpectedMismatch(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	// Coverage.Expected drifted from the manifest — a bug in the caller,
	// but the validator catches it before any verdict is surfaced.
	f.inputs.Coverage.Expected = 99
	ok, _ := CheckRecvReassemblyCoverage(f.inputs)
	require.False(t, ok)
}

func TestCheckRecvReassemblyCoverage_ZeroAdmitted(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.Coverage.Admitted = 0
	ok, _ := CheckRecvReassemblyCoverage(f.inputs)
	require.False(t, ok)
}

func TestCheckRecvPolicyAlignment_SessionMismatch(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	f.inputs.ActivePolicy = ids.PolicyVersion("policy-rotated")
	ok, reason := CheckRecvPolicyAlignment(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "session policy_version")
}

func TestCheckRecvPolicyAlignment_ManifestMismatch(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	// Rotate the bootstrap manifest's policy without re-issuing the
	// session — the rule requires BOTH to line up with the active policy.
	f.inputs.BootstrapManifest.PolicyVersion = ids.PolicyVersion("policy-other")
	ok, reason := CheckRecvPolicyAlignment(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "bootstrap manifest policy_version")
}
