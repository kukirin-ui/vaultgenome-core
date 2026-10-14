// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package operational

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// fixtures builds a fully-signed, mutually-consistent set of artifacts plus
// the resolver that can verify them all. Each sub-check test starts from
// this baseline and mutates exactly one field.
type fixtures struct {
	inputs   Inputs
	vaultKID ids.KeyID
	trustKID ids.KeyID
	store    *keys.InMemoryStore
}

func newFixtures(t *testing.T) *fixtures {
	t.Helper()
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	fc := shared_time.NewFakeClock(now)
	store := keys.NewInMemoryStore(fc)

	vaultKID := ids.KeyID("vault-auth-1")
	trustKID := ids.KeyID("trust-auth-1")
	_, err := store.GenerateSigning(vaultKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(trustKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	activePolicy := ids.PolicyVersion("policy-v1")
	sessionID := ids.SessionID("sess-0001")
	manifestID := ids.ManifestID("man-0001")
	requestID := ids.RequestID("req-0001")
	genomeID := ids.GenomeID("genome-alpha")

	// Trust admission: an "allow" attestation signed by the trust authority.
	att := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: ids.AttestationID("att-0001"),
		RequestID:     requestID,
		Outcome:       attestation_result.OutcomeAllow,
		IssuedAt:      now,
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  trustKID,
	}
	require.NoError(t, att.SignWith(store))

	// Trusted session: issued by the vault.
	sess := session_object.SessionObject{
		SchemaVersion: session_object.SchemaVersionCurrent,
		SessionID:     sessionID,
		RequestID:     requestID,
		GenomeID:      genomeID,
		PolicyVersion: activePolicy,
		IssuedAt:      now,
		ExpiresAt:     now.Add(5 * time.Minute),
		State:         session_object.StateActive,
		SigningKeyID:  vaultKID,
	}
	require.NoError(t, sess.SignWith(store))

	// Manifest: references the session and a disclosure.
	m := reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             manifestID,
		SessionID:              sessionID,
		GenomeID:               genomeID,
		PolicyVersion:          activePolicy,
		DisclosureIDs:          []ids.DisclosureID{"disc-0001"},
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 4096,
		RecipientKeyID:         ids.KeyID("recipient-1"),
		Deadline:               now.Add(10 * time.Minute),
		IssuedAt:               now,
		SigningKeyID:           vaultKID,
	}
	require.NoError(t, m.SignWith(store))

	return &fixtures{
		inputs: Inputs{
			Attestation:     att,
			Session:         sess,
			Manifest:        m,
			ActivePolicy:    activePolicy,
			TamperSignalled: false,
			Now:             now.Add(1 * time.Second), // one tick after issuance
			Resolver:        store,
		},
		vaultKID: vaultKID,
		trustKID: trustKID,
		store:    store,
	}
}

func TestRun_AllPass(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	v := Run(f.inputs)
	require.Equal(t, validation_result.VerdictPass, v.Verdict,
		"findings: %+v", v.Details)
	require.Equal(t, 1.0, v.Score)
	require.Empty(t, v.Details)
}

func TestRun_OneFailureFailsDimension(t *testing.T) {
	t.Parallel()
	// A single failed sub-check must fail the whole dimension — operational
	// is binary by doctrine.
	f := newFixtures(t)
	f.inputs.TamperSignalled = true

	v := Run(f.inputs)
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Equal(t, 5.0/6.0, v.Score)
	require.Len(t, v.Details, 1)
	require.Equal(t, CodeTamperAbsent, v.Details[0].Code)
	require.Equal(t, validation_result.SeverityError, v.Details[0].Severity)
}

func TestRun_ReportsAllFailures(t *testing.T) {
	t.Parallel()
	// Multiple failures must ALL surface in Details — operational does not
	// short-circuit. This is what lets auditors see correlated failures.
	f := newFixtures(t)
	f.inputs.TamperSignalled = true
	f.inputs.ActivePolicy = ids.PolicyVersion("policy-v2") // no match
	f.inputs.Attestation.Outcome = attestation_result.OutcomeDeny

	v := Run(f.inputs)
	require.Equal(t, validation_result.VerdictFail, v.Verdict)

	codes := map[string]bool{}
	for _, d := range v.Details {
		codes[d.Code] = true
	}
	require.True(t, codes[CodeAttestationValid])
	require.True(t, codes[CodeTamperAbsent])
	require.True(t, codes[CodePolicyAlignment])
	require.Len(t, v.Details, 3)
}

// --- individual sub-check tests ---

func TestCheckAttestationValid_DenyRejected(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.Attestation.Outcome = attestation_result.OutcomeDeny
	f.inputs.Attestation.Reason = "trust.peer_unknown"
	ok, reason := CheckAttestationValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "outcome")
}

func TestCheckAttestationValid_BadSignatureRejected(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	// Tamper with the attestation after signing — signature must not verify.
	f.inputs.Attestation.Reason = "injected-after-signing"
	ok, reason := CheckAttestationValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "signature")
}

func TestCheckAttestationTTL_Expired(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.Now = f.inputs.Attestation.IssuedAt.Add(f.inputs.Attestation.TTL + time.Second)
	ok, reason := CheckAttestationTTL(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "expired")
}

func TestCheckAttestationTTL_ZeroTTLRejected(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.Attestation.TTL = 0
	ok, reason := CheckAttestationTTL(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "non-positive")
}

func TestCheckSessionValid_NotActive(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.Session.State = session_object.StateSuspended
	ok, reason := CheckSessionValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "active")
}

func TestCheckSessionValid_Expired(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.Now = f.inputs.Session.ExpiresAt.Add(time.Second)
	ok, _ := CheckSessionValid(f.inputs)
	require.False(t, ok)
}

func TestCheckSessionValid_ManifestSessionMismatch(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.Manifest.SessionID = ids.SessionID("different-session")
	ok, reason := CheckSessionValid(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "session_id")
}

func TestCheckManifestIntegrity_BadSignature(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	// Tamper with manifest after signing.
	f.inputs.Manifest.ExpectedOutputMaxBytes = 1
	ok, reason := CheckManifestIntegrity(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "signature")
}

func TestCheckTamperAbsent_FlaggedRejected(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.TamperSignalled = true
	ok, reason := CheckTamperAbsent(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "tamper")
}

func TestCheckPolicyAlignment_Mismatch(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.ActivePolicy = ids.PolicyVersion("policy-v2")
	ok, reason := CheckPolicyAlignment(f.inputs)
	require.False(t, ok)
	require.Contains(t, reason, "policy")
}

func TestCheckPolicyAlignment_SessionPolicyMissing(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.Session.PolicyVersion = ""
	ok, _ := CheckPolicyAlignment(f.inputs)
	require.False(t, ok)
}

func TestCheckPolicyAlignment_ActivePolicyMissing(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.inputs.ActivePolicy = ""
	ok, _ := CheckPolicyAlignment(f.inputs)
	require.False(t, ok)
}
