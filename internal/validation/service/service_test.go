// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/behavioral"
	"github.com/vault-genome/vaultgenome-core/internal/validation/operational"
	"github.com/vault-genome/vaultgenome-core/internal/validation/semantic"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- release-side service fixtures ----------------------------------------

type serviceFixtures struct {
	service     *ValidationService
	chain       *chain.InMemoryChain
	store       *keys.InMemoryStore
	clock       shared_time.Clock
	auditKID    ids.KeyID
	inputs      ValidateInputs
	candidateOK []byte
	fixtureOK   []byte
}

// newServiceFixtures builds a fully consistent three-dimension baseline:
// attestation + session + manifest all signed, candidate matching the
// expected fixture byte-for-byte, behavioral suite of 3 critical + 7
// non-critical probes all passing. Each test mutates exactly one input
// before calling Validate.
func newServiceFixtures(t *testing.T) *serviceFixtures {
	t.Helper()
	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	fc := shared_time.NewFakeClock(now)
	store := keys.NewInMemoryStore(fc)

	vaultKID := ids.KeyID("vault-auth-rel-1")
	trustKID := ids.KeyID("trust-auth-rel-1")
	auditKID := ids.KeyID("release-audit-1")
	_, err := store.GenerateSigning(vaultKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(trustKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	activePolicy := ids.PolicyVersion("policy-rel-v1")
	sessionID := ids.SessionID("sess-rel-0001")
	manifestID := ids.ManifestID("man-rel-0001")
	requestID := ids.RequestID("req-rel-0001")
	genomeID := ids.GenomeID("genome-rel-1")

	// Attestation — allow, signed, within TTL.
	att := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: ids.AttestationID("att-rel-0001"),
		RequestID:     requestID,
		Outcome:       attestation_result.OutcomeAllow,
		IssuedAt:      now,
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  trustKID,
	}
	require.NoError(t, att.SignWith(store))

	// Session — active, in-window.
	sess := session_object.SessionObject{
		SchemaVersion: session_object.SchemaVersionCurrent,
		SessionID:     sessionID,
		RequestID:     requestID,
		GenomeID:      genomeID,
		PolicyVersion: activePolicy,
		IssuedAt:      now,
		ExpiresAt:     now.Add(30 * time.Minute),
		State:         session_object.StateActive,
		SigningKeyID:  vaultKID,
	}
	require.NoError(t, sess.SignWith(store))

	// Manifest — bound to the session.
	m := reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             manifestID,
		SessionID:              sessionID,
		GenomeID:               genomeID,
		PolicyVersion:          activePolicy,
		DisclosureIDs:          []ids.DisclosureID{"disc-rel-0001"},
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 4096,
		RecipientKeyID:         ids.KeyID("recipient-rel-1"),
		Deadline:               now.Add(20 * time.Minute),
		IssuedAt:               now,
		SigningKeyID:           vaultKID,
	}
	require.NoError(t, m.SignWith(store))

	// Semantic fixture — deterministic small payload.
	fixture := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	candidate := make([]byte, len(fixture))
	copy(candidate, fixture)

	// Behavioral suite — 3 critical + 7 non-critical, all pass.
	probes := []behavioral.Probe{
		{ID: "C-001", Name: "reproducibility", Critical: true, Evaluate: alwaysPass},
		{ID: "C-002", Name: "shape", Critical: true, Evaluate: alwaysPass},
		{ID: "C-003", Name: "side-effects", Critical: true, Evaluate: alwaysPass},
		{ID: "N-001", Name: "non-1", Critical: false, Evaluate: alwaysPass},
		{ID: "N-002", Name: "non-2", Critical: false, Evaluate: alwaysPass},
		{ID: "N-003", Name: "non-3", Critical: false, Evaluate: alwaysPass},
		{ID: "N-004", Name: "non-4", Critical: false, Evaluate: alwaysPass},
		{ID: "N-005", Name: "non-5", Critical: false, Evaluate: alwaysPass},
		{ID: "N-006", Name: "non-6", Critical: false, Evaluate: alwaysPass},
		{ID: "N-007", Name: "non-7", Critical: false, Evaluate: alwaysPass},
	}

	ch := chain.NewInMemoryChain()
	svc, err := NewValidationService(ServiceOptions{
		AuditChain:  ch,
		AuditSigner: store,
		AuditKeyID:  auditKID,
		Clock:       fc,
	})
	require.NoError(t, err)

	inputs := ValidateInputs{
		SessionID:  sessionID,
		ManifestID: manifestID,
		Semantic: semantic.Inputs{
			Candidate:    candidate,
			Expected:     fixture,
			HaveExpected: true,
		},
		Behavioral: behavioral.Inputs{
			Candidate: candidate,
			Probes:    probes,
		},
		Operational: operational.Inputs{
			Attestation:     att,
			Session:         sess,
			Manifest:        m,
			ActivePolicy:    activePolicy,
			TamperSignalled: false,
			Now:             now.Add(1 * time.Second),
			Resolver:        store,
		},
	}

	return &serviceFixtures{
		service:     svc,
		chain:       ch,
		store:       store,
		clock:       fc,
		auditKID:    auditKID,
		inputs:      inputs,
		candidateOK: candidate,
		fixtureOK:   fixture,
	}
}

func alwaysPass(_ []byte) (bool, string) { return true, "" }
func alwaysFail(_ []byte) (bool, string) { return false, "probe diagnostic" }

// ---- constructor refusals -------------------------------------------------

func TestNewValidationService_MissingAuditChain(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	_, err := NewValidationService(ServiceOptions{
		AuditChain:  nil,
		AuditSigner: f.store,
		AuditKeyID:  f.auditKID,
		Clock:       f.clock,
	})
	require.Error(t, err)
	require.Equal(t, CodeServiceMissingAuditChain, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewValidationService_MissingAuditSigner(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	_, err := NewValidationService(ServiceOptions{
		AuditChain:  chain.NewInMemoryChain(),
		AuditSigner: nil,
		AuditKeyID:  f.auditKID,
		Clock:       f.clock,
	})
	require.Error(t, err)
	require.Equal(t, CodeServiceMissingAuditSigner, shared_errors.CodeOf(err))
}

func TestNewValidationService_MissingAuditKeyID(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	_, err := NewValidationService(ServiceOptions{
		AuditChain:  chain.NewInMemoryChain(),
		AuditSigner: f.store,
		AuditKeyID:  "",
		Clock:       f.clock,
	})
	require.Error(t, err)
	require.Equal(t, CodeServiceMissingAuditKeyID, shared_errors.CodeOf(err))
}

func TestNewValidationService_MissingClock(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	_, err := NewValidationService(ServiceOptions{
		AuditChain:  chain.NewInMemoryChain(),
		AuditSigner: f.store,
		AuditKeyID:  f.auditKID,
		Clock:       nil,
	})
	require.Error(t, err)
	require.Equal(t, CodeServiceMissingClock, shared_errors.CodeOf(err))
}

// ---- Validate refusals ----------------------------------------------------

func TestValidate_MissingSessionID(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	f.inputs.SessionID = ""
	_, err := f.service.Validate(f.inputs)
	require.Error(t, err)
	require.Equal(t, CodeServiceMissingSessionID, shared_errors.CodeOf(err))
}

func TestValidate_MissingManifestID(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	f.inputs.ManifestID = ""
	_, err := f.service.Validate(f.inputs)
	require.Error(t, err)
	require.Equal(t, CodeServiceMissingManifestID, shared_errors.CodeOf(err))
}

// ---- happy path ----------------------------------------------------------

func TestValidate_HappyPath_AllPass(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.NotNil(t, vr)
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict,
		"all-pass inputs must yield overall=pass")

	// Every dimension present, all pass.
	require.Contains(t, vr.Dimensions, validation_result.DimensionOperational)
	require.Contains(t, vr.Dimensions, validation_result.DimensionSemantic)
	require.Contains(t, vr.Dimensions, validation_result.DimensionBehavioral)
	require.Equal(t, validation_result.VerdictPass, vr.Dimensions[validation_result.DimensionOperational].Verdict)
	require.Equal(t, validation_result.VerdictPass, vr.Dimensions[validation_result.DimensionSemantic].Verdict)
	require.Equal(t, validation_result.VerdictPass, vr.Dimensions[validation_result.DimensionBehavioral].Verdict)

	// Static validator must accept the returned result.
	require.NoError(t, vr.Validate(), "returned ValidationResult must pass static Validate()")

	// Audit chain length: STARTED + 3 DIMENSION + COMPLETED = 5 events
	// (no findings on the all-pass path).
	require.Equal(t, 5, f.chain.Len(), "expected STARTED + 3×DIMENSION + COMPLETED = 5 events")
	require.NoError(t, f.chain.Verify(f.store), "chain must verify under the audit resolver")

	// Evidence trail covers every sealed event.
	require.Len(t, vr.Evidence, 5)
	require.Equal(t, string(audit_event.KindValidationStarted), vr.Evidence[0].Kind)
	require.Equal(t, string(audit_event.KindValidationCompleted), vr.Evidence[len(vr.Evidence)-1].Kind)
}

// TestValidate_HappyPath_AuditOrder asserts the strict audit ordering
// required by §7: STARTED → one DIMENSION per dim → (FINDINGs) →
// COMPLETED, with COMPLETED last. On the all-pass path there are no
// findings, so the order collapses to STARTED, DIM, DIM, DIM, COMPLETED.
func TestValidate_HappyPath_AuditOrder(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	_, err := f.service.Validate(f.inputs)
	require.NoError(t, err)

	kinds := kindsInChain(f.chain)
	require.Equal(t, []audit_event.Kind{
		audit_event.KindValidationStarted,
		audit_event.KindValidationDimension,
		audit_event.KindValidationDimension,
		audit_event.KindValidationDimension,
		audit_event.KindValidationCompleted,
	}, kinds, "strict audit ordering violated")
}

// ---- §8 negative-test suite ----------------------------------------------

// §8(1): Candidate differs by one byte → semantic=fail →
// OverallVerdict=fail → Release=false.
func TestValidate_Negative1_SemanticOneByteDiff(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	// Flip one byte of the candidate so semantic sees byte-inequality.
	bad := make([]byte, len(f.candidateOK))
	copy(bad, f.candidateOK)
	bad[2] = 0xff
	f.inputs.Semantic.Candidate = bad
	// Behavioral still operates on original candidate (probes ignore it).

	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict,
		"§8(1): one-byte candidate divergence must fail release")
	require.Equal(t, validation_result.VerdictFail,
		vr.Dimensions[validation_result.DimensionSemantic].Verdict)
	require.Equal(t, validation_result.VerdictPass,
		vr.Dimensions[validation_result.DimensionOperational].Verdict,
		"operational must still pass — the failure is semantic")

	// At least one VALIDATION_FINDING event must reach the chain.
	require.GreaterOrEqual(t, countKind(f.chain, audit_event.KindValidationFinding), 1,
		"semantic-fail must emit a VALIDATION_FINDING event")
}

// §8(2): One critical behavioral probe fails → behavioral=fail →
// OverallVerdict=fail.
func TestValidate_Negative2_BehavioralCriticalFail(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	// Flip the first critical probe from pass to fail.
	f.inputs.Behavioral.Probes[1].Evaluate = alwaysFail

	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict,
		"§8(2): critical-probe fail must fail overall")
	require.Equal(t, validation_result.VerdictFail,
		vr.Dimensions[validation_result.DimensionBehavioral].Verdict)
	require.Equal(t, validation_result.VerdictPass,
		vr.Dimensions[validation_result.DimensionSemantic].Verdict,
		"semantic untouched — the failure is behavioral-critical")
	require.GreaterOrEqual(t, countKind(f.chain, audit_event.KindValidationFinding), 1,
		"behavioral-fail must emit a VALIDATION_FINDING event")
}

// §8(3): Session expired before validation ran → operational=fail →
// OverallVerdict=fail — and no semantic/behavioral evaluation performed.
func TestValidate_Negative3_SessionExpired_NoDownstreamDims(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	// Move Now past session.ExpiresAt.
	f.inputs.Operational.Now = f.inputs.Operational.Session.ExpiresAt.Add(time.Second)

	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict)
	require.Equal(t, validation_result.VerdictFail,
		vr.Dimensions[validation_result.DimensionOperational].Verdict)

	// §8(3) doctrine: semantic/behavioral must NOT be evaluated on
	// operational-fail. The ValidationResult must not carry their
	// dimension entries, and the audit chain must not contain a
	// VALIDATION_DIMENSION_EVALUATED event for them.
	require.NotContains(t, vr.Dimensions, validation_result.DimensionSemantic,
		"§8(3): semantic must not be evaluated when operational fails")
	require.NotContains(t, vr.Dimensions, validation_result.DimensionBehavioral,
		"§8(3): behavioral must not be evaluated when operational fails")
	require.Equal(t, 1, countKind(f.chain, audit_event.KindValidationDimension),
		"exactly one dimension event (operational) must be present on op-fail")
}

// §8(4): Manifest integrity fails (simulated tamper) → operational=fail
// → short-circuit.
func TestValidate_Negative4_ManifestTamperedShortCircuits(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	// Mutate the manifest after signing — signature no longer verifies.
	f.inputs.Operational.Manifest.ExpectedOutputMaxBytes = 1

	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict)
	require.Equal(t, validation_result.VerdictFail,
		vr.Dimensions[validation_result.DimensionOperational].Verdict)
	require.NotContains(t, vr.Dimensions, validation_result.DimensionSemantic)
	require.NotContains(t, vr.Dimensions, validation_result.DimensionBehavioral)
}

// §8(5): Attestation TTL expired → operational=fail → short-circuit.
func TestValidate_Negative5_AttestationTTLExpired(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	// Push Now past attestation TTL but keep session valid.
	f.inputs.Operational.Now = f.inputs.Operational.Attestation.IssuedAt.
		Add(f.inputs.Operational.Attestation.TTL).
		Add(time.Second)

	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict)
	require.Equal(t, validation_result.VerdictFail,
		vr.Dimensions[validation_result.DimensionOperational].Verdict)
	require.NotContains(t, vr.Dimensions, validation_result.DimensionSemantic)
	require.NotContains(t, vr.Dimensions, validation_result.DimensionBehavioral)
}

// §8(6): Non-critical behavioral pass-rate 90% → behavioral=
// conditional_fail → OverallVerdict=conditional_fail → Release=false
// (MVP policy).
func TestValidate_Negative6_BehavioralConditional(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	// Rebuild the probe suite with 3 critical + 10 non-critical,
	// 9 non-critical passing → 90.0% rate exactly.
	probes := []behavioral.Probe{
		{ID: "C-001", Critical: true, Evaluate: alwaysPass},
		{ID: "C-002", Critical: true, Evaluate: alwaysPass},
		{ID: "C-003", Critical: true, Evaluate: alwaysPass},
	}
	for i := 1; i <= 10; i++ {
		id := "N-" + itoaTest(i)
		ok := i != 5 // one failure
		probes = append(probes, behavioral.Probe{
			ID:       id,
			Critical: false,
			Evaluate: func(passed bool) func([]byte) (bool, string) {
				return func(_ []byte) (bool, string) {
					if passed {
						return true, ""
					}
					return false, "minor variance"
				}
			}(ok),
		})
	}
	f.inputs.Behavioral.Probes = probes

	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictConditionalFail, vr.OverallVerdict,
		"§8(6): 90%% non-critical rate must yield conditional_fail")
	require.Equal(t, validation_result.VerdictConditionalFail,
		vr.Dimensions[validation_result.DimensionBehavioral].Verdict)
}

// ---- audit-trail & ordering assertions -----------------------------------

// TestValidate_AuditTrail_StartedComesFirst — discipline check: no
// dimension event may precede STARTED in the chain. §9(4).
func TestValidate_AuditTrail_StartedComesFirst(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	_, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	evts := f.chain.Events()
	require.NotEmpty(t, evts)
	require.Equal(t, audit_event.KindValidationStarted, evts[0].Kind,
		"first audit event must be VALIDATION_STARTED")
}

// TestValidate_AuditTrail_CompletedComesLast — symmetric: COMPLETED is
// the final event per §7 (audit-event-before-surface).
func TestValidate_AuditTrail_CompletedComesLast(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	_, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	evts := f.chain.Events()
	require.NotEmpty(t, evts)
	require.Equal(t, audit_event.KindValidationCompleted, evts[len(evts)-1].Kind,
		"last audit event must be VALIDATION_COMPLETED")
}

// TestValidate_AuditTrail_FindingsAfterDimensionsBeforeCompleted —
// structural check on the combined ordering when findings exist.
func TestValidate_AuditTrail_FindingsAfterDimensionsBeforeCompleted(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	// Trigger a semantic finding.
	bad := make([]byte, len(f.candidateOK))
	copy(bad, f.candidateOK)
	bad[0] = 0xaa
	f.inputs.Semantic.Candidate = bad

	_, err := f.service.Validate(f.inputs)
	require.NoError(t, err)

	kinds := kindsInChain(f.chain)
	// Find positions: last DIMENSION must precede first FINDING; first
	// FINDING must precede COMPLETED.
	lastDim := -1
	firstFinding := -1
	completedPos := -1
	for i, k := range kinds {
		switch k {
		case audit_event.KindValidationDimension:
			lastDim = i
		case audit_event.KindValidationFinding:
			if firstFinding == -1 {
				firstFinding = i
			}
		case audit_event.KindValidationCompleted:
			completedPos = i
		}
	}
	require.GreaterOrEqual(t, firstFinding, 0, "at least one finding must appear")
	require.Greater(t, firstFinding, lastDim, "findings must come after dimensions")
	require.Greater(t, completedPos, firstFinding, "completed must come after findings")
}

// TestValidate_ResultIDsDistinctAcrossCalls — the counter-derived suffix
// must make VRIDs unique for distinct requests on the same service.
func TestValidate_ResultIDsDistinctAcrossCalls(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	vr1, err := f.service.Validate(f.inputs)
	require.NoError(t, err)

	// Second call with identical inputs — the service advances its
	// internal counter so IDs differ.
	vr2, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.NotEqual(t, vr1.ValidationResultID, vr2.ValidationResultID,
		"distinct validations must mint distinct VRIDs")
}

// TestValidate_EvidenceRefsPointAtChain — every EvidenceRef must cite an
// event that actually lives in the chain.
func TestValidate_EvidenceRefsPointAtChain(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)

	chainIDs := map[ids.AuditEventID]audit_event.Kind{}
	for _, e := range f.chain.Events() {
		chainIDs[e.EventID] = e.Kind
	}
	for _, ref := range vr.Evidence {
		k, ok := chainIDs[ref.AuditEventID]
		require.Truef(t, ok, "Evidence[%s] not found in chain", ref.AuditEventID)
		require.Equalf(t, string(k), ref.Kind,
			"Evidence ref kind mismatch for %s", ref.AuditEventID)
	}
}

// TestValidate_ValidatedAtNotBeforeNow — ValidatedAt must never be
// earlier than the STARTED timestamp.
func TestValidate_ValidatedAtNotBeforeNow(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	before := f.clock.Now().UTC()
	vr, err := f.service.Validate(f.inputs)
	require.NoError(t, err)
	require.Falsef(t, vr.ValidatedAt.Before(before),
		"ValidatedAt=%s must not be before Now=%s", vr.ValidatedAt, before)
}

// TestValidate_ChainVerifiesOnAllBranches runs the service on every
// §8 scenario and verifies the chain each time — the audit trail must
// stay integrity-consistent regardless of which dimension failed.
func TestValidate_ChainVerifiesOnAllBranches(t *testing.T) {
	t.Parallel()
	scenarios := []struct {
		name   string
		mutate func(*serviceFixtures)
	}{
		{"happy", func(_ *serviceFixtures) {}},
		{"semantic_fail", func(f *serviceFixtures) {
			bad := make([]byte, len(f.candidateOK))
			copy(bad, f.candidateOK)
			bad[1] = 0x99
			f.inputs.Semantic.Candidate = bad
		}},
		{"behavioral_critical_fail", func(f *serviceFixtures) {
			f.inputs.Behavioral.Probes[0].Evaluate = alwaysFail
		}},
		{"operational_session_expired", func(f *serviceFixtures) {
			f.inputs.Operational.Now = f.inputs.Operational.Session.ExpiresAt.Add(time.Second)
		}},
		{"operational_ttl_expired", func(f *serviceFixtures) {
			f.inputs.Operational.Now = f.inputs.Operational.Attestation.IssuedAt.
				Add(f.inputs.Operational.Attestation.TTL + time.Second)
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			f := newServiceFixtures(t)
			sc.mutate(f)
			_, err := f.service.Validate(f.inputs)
			require.NoError(t, err)
			require.NoError(t, f.chain.Verify(f.store),
				"chain must verify under the audit resolver on %s", sc.name)
		})
	}
}

// ---- helpers --------------------------------------------------------------

func kindsInChain(ch *chain.InMemoryChain) []audit_event.Kind {
	evts := ch.Events()
	out := make([]audit_event.Kind, 0, len(evts))
	for _, e := range evts {
		out = append(out, e.Kind)
	}
	return out
}

func countKind(ch *chain.InMemoryChain, k audit_event.Kind) int {
	n := 0
	for _, e := range ch.Events() {
		if e.Kind == k {
			n++
		}
	}
	return n
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// An evaluator that ran the model hands its semantic and behavioral
// verdicts in; the service records them as it records its own — one
// DIMENSION event naming the evaluator, one FINDING per finding — and
// aggregates them under the same rule.
func TestValidate_EvaluatedDimensionsAreRecordedAndAggregated(t *testing.T) {
	t.Parallel()
	f := newServiceFixtures(t)
	in := f.inputs
	in.Semantic = semantic.Inputs{}     // would fail: no fixture
	in.Behavioral = behavioral.Inputs{} // would fail: empty suite
	in.Evaluated = map[validation_result.Dimension]EvaluatedDimension{
		validation_result.DimensionSemantic: {
			Evaluator: "top1-agreement",
			Verdict:   validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: 1.0, Threshold: 1.0},
			Detail:    []byte(`{"agreed":6,"total":6}`),
		},
		validation_result.DimensionBehavioral: {
			Evaluator: "equivalence-ladder",
			Verdict: validation_result.DimensionVerdict{Verdict: validation_result.VerdictFail, Score: 0, Threshold: 1.0, Details: []validation_result.Finding{
				{Code: "reconstruction_no_door_opened", Severity: validation_result.SeverityError, Message: "no door opened"},
			}},
		},
	}
	vr, err := f.service.Validate(in)
	require.NoError(t, err)
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict)
	require.Equal(t, 1.0, vr.Dimensions[validation_result.DimensionSemantic].Score)
	require.Equal(t, validation_result.VerdictFail, vr.Dimensions[validation_result.DimensionBehavioral].Verdict)

	var sawSemantic, sawFinding bool
	for _, e := range f.chain.Events() {
		switch e.Kind {
		case audit_event.KindValidationDimension:
			if strings.Contains(string(e.Payload), `"dimension":"semantic"`) {
				sawSemantic = true
				require.Contains(t, string(e.Payload), `"evaluator":"top1-agreement"`)
				require.Contains(t, string(e.Payload), `"detail":{"agreed":6,"total":6}`)
			}
		case audit_event.KindValidationFinding:
			if strings.Contains(string(e.Payload), "reconstruction_no_door_opened") {
				sawFinding = true
			}
		}
	}
	require.True(t, sawSemantic && sawFinding)
	require.NoError(t, f.chain.Verify(f.store))

	// Operational is always the service's own.
	in.Evaluated[validation_result.DimensionOperational] = EvaluatedDimension{Verdict: validation_result.DimensionVerdict{Verdict: validation_result.VerdictPass, Score: 1, Threshold: 1}}
	_, err = f.service.Validate(in)
	require.Error(t, err)
	require.Equal(t, CodeServiceDimensionNotEvaluable, shared_errors.CodeOf(err))
}
