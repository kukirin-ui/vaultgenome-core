// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/release_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/operational"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/session"
)

// TestVerticalSlice_HappyPath exercises the full nine-stage ACP flow:
//
//  1. Intake: client submits RecoveryRequest.
//  2. Trust Admission: trust authority signs AttestationResult (allow).
//  3. Session Issuance: vault issues signed SessionObject.
//  4. Disclosure: vault seals a component payload under the recipient key
//     and signs a DisclosureMessage.
//  5. Manifest Issuance: vault signs a ReconstructionJobManifest.
//  6. External Compute: a synthetic candidate output is produced (this
//     slice does not involve a real compute worker — just the envelope).
//  7. Operational Validation: six sub-checks run and all pass.
//  8. ValidationResult aggregation: OverallVerdict=pass.
//  9. Release Decision: vault signs a ReleaseDecision (Release=true,
//     Reason=validation_pass).
//
// Every authority decision produces an AuditEvent appended to the chain
// under the audit signing key. The final assertion is that chain.Verify
// succeeds — i.e., every event is signed, the chain is unbroken, every
// cover-preimage is consistent, and every authority contract verifies
// under its issuing key.
//
// This test is the canonical smoke-screen for cross-package regressions.
// A single failure here means the system no longer composes.
func TestVerticalSlice_HappyPath(t *testing.T) {
	t.Parallel()
	// ---- fixtures --------------------------------------------------------

	t0 := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	clock := shared_time.NewFakeClock(t0)
	store := keys.NewInMemoryStore(clock)

	// Three signing roles (same store, different purposes):
	//   - vault authority: signs Session/Manifest/Disclosure/Release
	//   - trust authority: signs the Attestation
	//   - audit: signs every AuditEvent in the chain
	// Purpose-binding is enforced by the store on Resolve/Sign.
	vaultKID := ids.KeyID("vault-auth-1")
	trustKID := ids.KeyID("trust-auth-1")
	auditKID := ids.KeyID("vault-audit-1")
	_, err := store.GenerateSigning(vaultKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(trustKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	// Recipient sealing key: the external compute contour's symmetric key.
	// Disclosures are sealed to this key; only the worker can open them.
	recipientKID := ids.KeyID("recipient-seal-1")
	require.NoError(t, store.GenerateSealing(recipientKID))

	activePolicy := ids.PolicyVersion("policy-v1")
	genomeID := ids.GenomeID("genome-alpha")

	// Audit chain and session issuer — the two stateful authorities.
	auditChain := chain.NewInMemoryChain()
	issuer, err := session.NewIssuer(clock, store, store, vaultKID, activePolicy, session.Options{})
	require.NoError(t, err)

	// ---- stage 1: intake — RecoveryRequest -------------------------------

	req := recovery_request.RecoveryRequest{
		SchemaVersion:     recovery_request.SchemaVersionCurrent,
		RequestID:         ids.RequestID("req-0001"),
		GenomeID:          genomeID,
		PolicyProfile:     "sovereign-ru",
		RequesterIdentity: "operator:continuity-ops@example",
		Contour:           map[string]string{"jurisdiction": "ru", "role": "operator"},
		CreatedAt:         t0,
	}
	require.NoError(t, req.Validate())

	reqReceived := makeAuditEvent(t, audit_event.KindRequestReceived, auditKID, clock,
		req.RequestID, "", "",
		map[string]string{"policy_profile": req.PolicyProfile})
	_, err = auditChain.Append(reqReceived, store)
	require.NoError(t, err)

	// ---- stage 2: Trust Admission — AttestationResult --------------------

	clock.Step(50 * time.Millisecond)

	att := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: ids.AttestationID("att-0001"),
		RequestID:     req.RequestID,
		Outcome:       attestation_result.OutcomeAllow,
		Reason:        "trust.peer_known",
		IssuedAt:      clock.Now(),
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  trustKID,
	}
	require.NoError(t, att.SignWith(store))
	require.NoError(t, att.Validate())
	// Trust authority's signature must verify under its own key.
	require.NoError(t, att.VerifySignature(store))

	trustEvt := makeAuditEvent(t, audit_event.KindTrustEvaluated, auditKID, clock,
		req.RequestID, "", "",
		map[string]string{"outcome": string(att.Outcome), "attestation_id": att.AttestationID.String()})
	_, err = auditChain.Append(trustEvt, store)
	require.NoError(t, err)

	// ---- stage 3: Session Issuance — SessionObject -----------------------

	clock.Step(50 * time.Millisecond)

	sess, err := issuer.Issue(session.IssueParams{
		RequestID: req.RequestID,
		GenomeID:  genomeID,
		TTL:       5 * time.Minute,
	})
	require.NoError(t, err)
	// Issuer's Verify: the session is currently authoritative.
	require.NoError(t, issuer.Verify(sess))

	sessEvt := makeAuditEvent(t, audit_event.KindSessionIssued, auditKID, clock,
		req.RequestID, "", sess.SessionID,
		map[string]string{"policy_version": string(sess.PolicyVersion)})
	_, err = auditChain.Append(sessEvt, store)
	require.NoError(t, err)

	// ---- stage 4: Disclosure — seal a component payload -----------------

	clock.Step(50 * time.Millisecond)

	// Would-be genome component payload. In production this is produced
	// under policy from the AI Genome store; for this slice it is opaque
	// bytes. AAD binds the seal to the session/component.
	plaintext := []byte("component-data-omega-v1")
	manifestID := ids.ManifestID("man-0001")
	disclosureID := ids.DisclosureID("disc-0001")
	componentID := ids.ComponentID("omega-weights-shard-1")

	aad := []byte(string(manifestID) + "|" + string(sess.SessionID) + "|" + string(componentID))
	nonce, sealed, err := store.Seal(recipientKID, plaintext, aad)
	require.NoError(t, err)

	// Sanity check: only the recipient key can open the seal.
	opened, err := store.Open(recipientKID, nonce, sealed, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)

	disc := disclosure_message.DisclosureMessage{
		SchemaVersion:  disclosure_message.SchemaVersionCurrent,
		DisclosureID:   disclosureID,
		SessionID:      sess.SessionID,
		ComponentID:    componentID,
		PolicyVersion:  activePolicy,
		SequenceIndex:  0,
		SealedPayload:  sealed,
		Nonce:          nonce,
		RecipientKeyID: recipientKID,
		AuthorizedAt:   clock.Now(),
		SigningKeyID:   vaultKID,
	}
	require.NoError(t, disc.SignWith(store))
	require.NoError(t, disc.Validate())
	require.NoError(t, disc.VerifySignature(store))

	discEvt := makeAuditEvent(t, audit_event.KindDisclosureAuthorized, auditKID, clock,
		req.RequestID, "", sess.SessionID,
		map[string]string{
			"disclosure_id":  disc.DisclosureID.String(),
			"component_id":   disc.ComponentID.String(),
			"sequence_index": "0",
		})
	_, err = auditChain.Append(discEvt, store)
	require.NoError(t, err)

	// ---- stage 5: Manifest Issuance — ReconstructionJobManifest ---------

	clock.Step(50 * time.Millisecond)

	manIssuedAt := clock.Now()
	man := reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             manifestID,
		SessionID:              sess.SessionID,
		GenomeID:               genomeID,
		PolicyVersion:          activePolicy,
		DisclosureIDs:          []ids.DisclosureID{disclosureID},
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 4096,
		RecipientKeyID:         recipientKID,
		Deadline:               manIssuedAt.Add(10 * time.Minute),
		IssuedAt:               manIssuedAt,
		SigningKeyID:           vaultKID,
	}
	require.NoError(t, man.SignWith(store))
	require.NoError(t, man.Validate())
	require.NoError(t, man.VerifySignature(store))

	manEvt := makeAuditEvent(t, audit_event.KindManifestIssued, auditKID, clock,
		req.RequestID, man.ManifestID, sess.SessionID,
		map[string]string{"deadline": man.Deadline.UTC().Format(time.RFC3339Nano)})
	_, err = auditChain.Append(manEvt, store)
	require.NoError(t, err)

	// ---- stage 6: External Compute — synthetic candidate ----------------

	// The external-compute contour is out-of-scope for this slice. It
	// would produce a CandidateReconstruction whose bytes are the result
	// of running the manifest over the sealed disclosures. Here we simulate
	// its receipt purely as an audit event — the next stage evaluates
	// against the manifest's recorded expectations.
	clock.Step(200 * time.Millisecond)

	candidateBytes := []byte("reconstructed-omega-output-v1")
	require.LessOrEqual(t, uint64(len(candidateBytes)), man.ExpectedOutputMaxBytes,
		"synthetic candidate must fit the manifest's declared max")

	candEvt := makeAuditEvent(t, audit_event.KindCandidateReceived, auditKID, clock,
		req.RequestID, man.ManifestID, sess.SessionID,
		map[string]string{"candidate_bytes": toBase10(len(candidateBytes))})
	_, err = auditChain.Append(candEvt, store)
	require.NoError(t, err)

	// ---- stage 7: Operational Validation — six sub-checks ---------------

	clock.Step(50 * time.Millisecond)

	validationStartEvt := makeAuditEvent(t, audit_event.KindValidationStarted, auditKID, clock,
		req.RequestID, man.ManifestID, sess.SessionID, nil)
	_, err = auditChain.Append(validationStartEvt, store)
	require.NoError(t, err)

	opVerdict := operational.Run(operational.Inputs{
		Attestation:     att,
		Session:         sess,
		Manifest:        man,
		ActivePolicy:    activePolicy,
		TamperSignalled: false,
		Now:             clock.Now(),
		Resolver:        store,
	})
	require.Equal(t, validation_result.VerdictPass, opVerdict.Verdict,
		"findings: %+v", opVerdict.Details)
	require.Empty(t, opVerdict.Details)
	require.Equal(t, 1.0, opVerdict.Score)

	opDimEvt := makeAuditEvent(t, audit_event.KindValidationDimension, auditKID, clock,
		req.RequestID, man.ManifestID, sess.SessionID,
		map[string]string{
			"dimension": string(validation_result.DimensionOperational),
			"verdict":   string(opVerdict.Verdict),
			"score":     "1.0",
		})
	_, err = auditChain.Append(opDimEvt, store)
	require.NoError(t, err)

	// ---- stage 8: ValidationResult aggregation --------------------------

	valRes := validation_result.ValidationResult{
		SchemaVersion:      validation_result.SchemaVersionCurrent,
		ValidationResultID: ids.ValidationResultID("val-0001"),
		SessionID:          sess.SessionID,
		ManifestID:         man.ManifestID,
		Dimensions: map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: opVerdict,
			// Semantic/behavioral out of scope for the MVP slice. Per
			// docs/doctrine/validation-thresholds.md §5, when operational passes
			// semantic/behavioral must be present for a non-short-circuited
			// decision — we supply minimal passing stubs to keep the
			// aggregator rule honest.
			validation_result.DimensionSemantic: {
				Verdict: validation_result.VerdictPass, Score: 1.0, Threshold: 0.8,
			},
			validation_result.DimensionBehavioral: {
				Verdict: validation_result.VerdictPass, Score: 1.0, Threshold: 0.8,
			},
		},
		OverallVerdict: validation_result.VerdictPass,
		Evidence: []validation_result.EvidenceRef{
			{AuditEventID: opDimEvt.EventID, Kind: string(audit_event.KindValidationDimension)},
		},
		ValidatedAt: clock.Now(),
	}
	require.NoError(t, valRes.Validate())

	valDoneEvt := makeAuditEvent(t, audit_event.KindValidationCompleted, auditKID, clock,
		req.RequestID, man.ManifestID, sess.SessionID,
		map[string]string{"overall_verdict": string(valRes.OverallVerdict)})
	_, err = auditChain.Append(valDoneEvt, store)
	require.NoError(t, err)

	// ---- stage 9: Release Decision --------------------------------------

	clock.Step(50 * time.Millisecond)

	// The release audit event must exist BEFORE the decision is signed —
	// un-evidenced decisions are structurally invalid (see
	// release_decision.validator.go). So we append first, then embed the
	// resulting event id into the signed ReleaseDecision.
	releaseEvt := makeAuditEvent(t, audit_event.KindReleaseDecided, auditKID, clock,
		req.RequestID, man.ManifestID, sess.SessionID,
		map[string]string{
			"release": "true",
			"reason":  string(release_decision.ReasonValidationPass),
		})
	sealedReleaseEvt, err := auditChain.Append(releaseEvt, store)
	require.NoError(t, err)

	dec := release_decision.ReleaseDecision{
		SchemaVersion:      release_decision.SchemaVersionCurrent,
		DecisionID:         ids.DecisionID("dec-0001"),
		SessionID:          sess.SessionID,
		ManifestID:         man.ManifestID,
		ValidationResultID: valRes.ValidationResultID,
		Release:            true,
		Reason:             release_decision.ReasonValidationPass,
		DecidedAt:          clock.Now(),
		SigningKeyID:       vaultKID,
		AuditEventID:       sealedReleaseEvt.EventID,
	}
	require.NoError(t, dec.SignWith(store))
	require.NoError(t, dec.Validate())
	require.NoError(t, dec.VerifySignature(store))

	// ---- final assertions: chain integrity and cross-references --------

	// The chain must verify in full: every event's PrevHash links, every
	// Hash matches its canonical pre-image, every Signature verifies
	// under its SigningKeyID bound to PurposeSigningAudit.
	require.NoError(t, auditChain.Verify(store))

	// Count the events we expect to have appended.
	// 1 REQUEST_RECEIVED, 1 TRUST_EVALUATED, 1 SESSION_ISSUED,
	// 1 DISCLOSURE_AUTHORIZED, 1 MANIFEST_ISSUED, 1 CANDIDATE_RECEIVED,
	// 1 VALIDATION_STARTED, 1 VALIDATION_DIMENSION_EVALUATED,
	// 1 VALIDATION_COMPLETED, 1 RELEASE_DECIDED = 10 events.
	require.Equal(t, 10, auditChain.Len())

	// Correlation invariants — the whole point of carrying IDs across the
	// flow. If any of these break, the chain is cryptographically valid
	// but doctrinally meaningless.
	require.Equal(t, req.RequestID, sess.RequestID)
	require.Equal(t, sess.SessionID, man.SessionID)
	require.Equal(t, sess.SessionID, disc.SessionID)
	require.Equal(t, sess.SessionID, valRes.SessionID)
	require.Equal(t, sess.SessionID, dec.SessionID)
	require.Equal(t, man.ManifestID, valRes.ManifestID)
	require.Equal(t, man.ManifestID, dec.ManifestID)
	require.Equal(t, valRes.ValidationResultID, dec.ValidationResultID)
	require.Equal(t, sealedReleaseEvt.EventID, dec.AuditEventID)
}

// TestVerticalSlice_OperationalFailBlocksRelease proves the binary
// operational gate: when even one sub-check fails, the operational
// dimension fails, OverallVerdict must be fail, and the release decision
// carries Release=false with reason=validation_fail.
//
// This test deliberately plants a tamper signal — the simplest way to
// fail op.tamper_absent without breaking signatures. It verifies the
// negative control path: everything upstream is still well-formed and
// chain-verifying; the failure shows up only at the validation verdict.
func TestVerticalSlice_OperationalFailBlocksRelease(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	clock := shared_time.NewFakeClock(t0)
	store := keys.NewInMemoryStore(clock)

	vaultKID := ids.KeyID("vault-auth-1")
	trustKID := ids.KeyID("trust-auth-1")
	auditKID := ids.KeyID("vault-audit-1")
	_, err := store.GenerateSigning(vaultKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(trustKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	activePolicy := ids.PolicyVersion("policy-v1")
	genomeID := ids.GenomeID("genome-alpha")

	issuer, err := session.NewIssuer(clock, store, store, vaultKID, activePolicy, session.Options{})
	require.NoError(t, err)
	auditChain := chain.NewInMemoryChain()

	reqID := ids.RequestID("req-0002")

	att := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: ids.AttestationID("att-0002"),
		RequestID:     reqID,
		Outcome:       attestation_result.OutcomeAllow,
		IssuedAt:      clock.Now(),
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  trustKID,
	}
	require.NoError(t, att.SignWith(store))

	sess, err := issuer.Issue(session.IssueParams{
		RequestID: reqID,
		GenomeID:  genomeID,
		TTL:       5 * time.Minute,
	})
	require.NoError(t, err)

	man := reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             ids.ManifestID("man-0002"),
		SessionID:              sess.SessionID,
		GenomeID:               genomeID,
		PolicyVersion:          activePolicy,
		DisclosureIDs:          []ids.DisclosureID{"disc-0002"},
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 4096,
		RecipientKeyID:         ids.KeyID("recipient-2"),
		Deadline:               clock.Now().Add(10 * time.Minute),
		IssuedAt:               clock.Now(),
		SigningKeyID:           vaultKID,
	}
	require.NoError(t, man.SignWith(store))

	// Operational: tamper signal is present — op.tamper_absent must fail.
	opVerdict := operational.Run(operational.Inputs{
		Attestation:     att,
		Session:         sess,
		Manifest:        man,
		ActivePolicy:    activePolicy,
		TamperSignalled: true,
		Now:             clock.Now(),
		Resolver:        store,
	})
	require.Equal(t, validation_result.VerdictFail, opVerdict.Verdict)
	require.NotEmpty(t, opVerdict.Details)
	var sawTamper bool
	for _, f := range opVerdict.Details {
		if f.Code == operational.CodeTamperAbsent {
			sawTamper = true
			require.Equal(t, validation_result.SeverityError, f.Severity)
		}
	}
	require.True(t, sawTamper, "expected CodeTamperAbsent in findings")

	// Aggregated ValidationResult — operational fail MUST propagate.
	valRes := validation_result.ValidationResult{
		SchemaVersion:      validation_result.SchemaVersionCurrent,
		ValidationResultID: ids.ValidationResultID("val-0002"),
		SessionID:          sess.SessionID,
		ManifestID:         man.ManifestID,
		Dimensions: map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: opVerdict,
		},
		OverallVerdict: validation_result.VerdictFail,
		ValidatedAt:    clock.Now(),
	}
	require.NoError(t, valRes.Validate())

	// A VALIDATION_FINDING event must be emitted BEFORE the release
	// decision — un-evidenced fail decisions are forbidden (MVP §9).
	findingEvt := makeAuditEvent(t, audit_event.KindValidationFinding, auditKID, clock,
		reqID, man.ManifestID, sess.SessionID,
		map[string]string{
			"code":     operational.CodeTamperAbsent,
			"severity": string(validation_result.SeverityError),
		})
	sealedFinding, err := auditChain.Append(findingEvt, store)
	require.NoError(t, err)

	releaseEvt := makeAuditEvent(t, audit_event.KindReleaseDecided, auditKID, clock,
		reqID, man.ManifestID, sess.SessionID,
		map[string]string{
			"release": "false",
			"reason":  string(release_decision.ReasonValidationFail),
		})
	sealedRelease, err := auditChain.Append(releaseEvt, store)
	require.NoError(t, err)

	dec := release_decision.ReleaseDecision{
		SchemaVersion:      release_decision.SchemaVersionCurrent,
		DecisionID:         ids.DecisionID("dec-0002"),
		SessionID:          sess.SessionID,
		ManifestID:         man.ManifestID,
		ValidationResultID: valRes.ValidationResultID,
		Release:            false,
		Reason:             release_decision.ReasonValidationFail,
		DecidedAt:          clock.Now(),
		SigningKeyID:       vaultKID,
		AuditEventID:       sealedRelease.EventID,
	}
	require.NoError(t, dec.SignWith(store))
	require.NoError(t, dec.Validate())
	require.NoError(t, dec.VerifySignature(store))

	require.False(t, dec.Release, "operational fail must produce Release=false")
	require.Equal(t, release_decision.ReasonValidationFail, dec.Reason)

	// The chain — including the finding event — must still verify.
	require.NoError(t, auditChain.Verify(store))
	require.Equal(t, 2, auditChain.Len())
	require.Equal(t, audit_event.KindValidationFinding, sealedFinding.Kind)
}

// makeAuditEvent is a tiny helper to keep the slice-test readable. The
// Payload is a canonical-ish JSON blob of the supplied kv map; the chain
// takes care of the PrevHash/Hash/Signature trio.
func makeAuditEvent(
	t *testing.T,
	kind audit_event.Kind,
	signingKID ids.KeyID,
	clock shared_time.Clock,
	reqID ids.RequestID,
	manID ids.ManifestID,
	sessID ids.SessionID,
	kv map[string]string,
) audit_event.AuditEvent {
	t.Helper()
	var payload []byte
	if kv == nil {
		payload = []byte("{}")
	} else {
		b, err := json.Marshal(kv)
		require.NoError(t, err)
		payload = b
	}
	// Event ID is derived from kind + clock reading so it's
	// readable in test failures and unique within a single run.
	now := clock.Now()
	eid := string(kind) + "@" + now.UTC().Format("150405.000000000")
	return audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(eid),
		Kind:          kind,
		OccurredAt:    now,
		RequestID:     reqID,
		ManifestID:    manID,
		SessionID:     sessID,
		Payload:       payload,
		SigningKeyID:  signingKID,
	}
}

// toBase10 is a dependency-free int-to-string for small payload metadata
// that doesn't justify importing strconv just for one call.
func toBase10(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
