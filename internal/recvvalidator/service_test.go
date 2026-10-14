// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recvvalidator

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- service-level fixtures ----------------------------------------------

type serviceFixtures struct {
	recvFixtures *recvFixtures
	service      *ValidationService
	chain        *chain.InMemoryChain
	clock        shared_time.Clock
	auditKID     ids.KeyID
}

func newServiceFixtures(t *testing.T) *serviceFixtures {
	t.Helper()
	f := newRecvFixtures(t)

	// Register an audit-signing key in the same store so chain.Verify
	// can resolve it via the same resolver the sub-checks use.
	auditKID := ids.KeyID("recv-audit-g1")
	_, err := f.store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	ch := chain.NewInMemoryChain()
	// The service's completed-at fallback pulls from clock.Now(); pin the
	// clock to the same instant the fixtures used for Now so completed_at
	// is deterministic across runs.
	fc := shared_time.NewFakeClock(f.inputs.Now)

	svc, err := NewValidationService(ServiceOptions{
		AuditChain:  ch,
		AuditSigner: f.store,
		AuditKeyID:  auditKID,
		Clock:       fc,
	})
	require.NoError(t, err)

	return &serviceFixtures{
		recvFixtures: f,
		service:      svc,
		chain:        ch,
		clock:        fc,
		auditKID:     auditKID,
	}
}

// ---- constructor refusals -------------------------------------------------

func TestNewValidationService_MissingAuditChain(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	auditKID := ids.KeyID("recv-audit-g1")
	_, err := f.store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)
	_, err = NewValidationService(ServiceOptions{
		AuditChain:  nil,
		AuditSigner: f.store,
		AuditKeyID:  auditKID,
		Clock:       shared_time.NewFakeClock(f.inputs.Now),
	})
	require.Error(t, err)
	require.Equal(t, CodeValidatorMissingAuditChain, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewValidationService_MissingAuditSigner(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	auditKID := ids.KeyID("recv-audit-g1")
	_, err := f.store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)
	_, err = NewValidationService(ServiceOptions{
		AuditChain:  chain.NewInMemoryChain(),
		AuditSigner: nil,
		AuditKeyID:  auditKID,
		Clock:       shared_time.NewFakeClock(f.inputs.Now),
	})
	require.Error(t, err)
	require.Equal(t, CodeValidatorMissingAuditSigner, shared_errors.CodeOf(err))
}

func TestNewValidationService_MissingAuditKeyID(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	_, err := NewValidationService(ServiceOptions{
		AuditChain:  chain.NewInMemoryChain(),
		AuditSigner: f.store,
		AuditKeyID:  ids.KeyID(""),
		Clock:       shared_time.NewFakeClock(f.inputs.Now),
	})
	require.Error(t, err)
	require.Equal(t, CodeValidatorMissingAuditKeyID, shared_errors.CodeOf(err))
}

func TestNewValidationService_MissingClock(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	auditKID := ids.KeyID("recv-audit-g1")
	_, err := f.store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)
	_, err = NewValidationService(ServiceOptions{
		AuditChain:  chain.NewInMemoryChain(),
		AuditSigner: f.store,
		AuditKeyID:  auditKID,
		Clock:       nil,
	})
	require.Error(t, err)
	require.Equal(t, CodeValidatorMissingClock, shared_errors.CodeOf(err))
}

func TestNewValidationService_DefaultPrefixesApplied(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	auditKID := ids.KeyID("recv-audit-g1")
	_, err := f.store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)
	svc, err := NewValidationService(ServiceOptions{
		AuditChain:  chain.NewInMemoryChain(),
		AuditSigner: f.store,
		AuditKeyID:  auditKID,
		Clock:       shared_time.NewFakeClock(f.inputs.Now),
	})
	require.NoError(t, err)
	require.Equal(t, DefaultAuditIDPrefix, svc.auditPrefix)
	require.Equal(t, DefaultResultIDPrefix, svc.resultPrefix)
}

// ---- Validate input refusals ---------------------------------------------

func TestValidate_MissingBootstrapManifest(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	in := ValidateInputs{OperationalInputs: sf.recvFixtures.inputs}
	in.BootstrapManifest = nil
	_, err := sf.service.Validate(in)
	require.Error(t, err)
	require.Equal(t, CodeValidatorMissingBootstrapManifest, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Zero(t, sf.chain.Len(),
		"refused call must not write any audit events")
}

func TestValidate_MissingResolver(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	in := ValidateInputs{OperationalInputs: sf.recvFixtures.inputs}
	in.Resolver = nil
	_, err := sf.service.Validate(in)
	require.Error(t, err)
	require.Equal(t, CodeValidatorMissingResolver, shared_errors.CodeOf(err))
	require.Zero(t, sf.chain.Len(),
		"refused call must not write any audit events")
}

// ---- happy path -----------------------------------------------------------

// TestValidate_HappyPath asserts the full receive-side audit-and-surface
// discipline on a well-formed input:
//
//   - The two audit events are appended in order: STARTED then COMPLETED.
//   - Both events carry the configured audit KeyID and correct correlators.
//   - The ValidationResult references both events as evidence.
//   - The chain verifies end-to-end under the test resolver.
//   - ValidationResult.Validate() passes as a post-condition.
func TestValidate_HappyPath(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	in := ValidateInputs{OperationalInputs: sf.recvFixtures.inputs}

	result, err := sf.service.Validate(in)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Equal(t, validation_result.VerdictPass, result.OverallVerdict)
	require.Equal(t, validation_result.VerdictPass,
		result.Dimensions[validation_result.DimensionOperational].Verdict)
	require.Equal(t, 1.0,
		result.Dimensions[validation_result.DimensionOperational].Score)
	require.Empty(t, result.Dimensions[validation_result.DimensionOperational].Details)

	// Two audit events appended in order.
	require.Equal(t, 2, sf.chain.Len())
	started, ok := sf.chain.EventAt(0)
	require.True(t, ok)
	completed, ok := sf.chain.EventAt(1)
	require.True(t, ok)
	require.Equal(t, audit_event.KindRecvValidationStarted, started.Kind)
	require.Equal(t, audit_event.KindRecvValidationCompleted, completed.Kind)
	require.Equal(t, sf.auditKID, started.SigningKeyID)
	require.Equal(t, sf.auditKID, completed.SigningKeyID)

	// Correlators match the bootstrap manifest under validation.
	bm := sf.recvFixtures.inputs.BootstrapManifest
	require.Equal(t, bm.SessionID, started.SessionID)
	require.Equal(t, bm.ManifestID, started.ManifestID)
	require.Equal(t, bm.SessionID, completed.SessionID)
	require.Equal(t, bm.ManifestID, completed.ManifestID)

	// Prefixes and ordering: STARTED EventID must carry the audit
	// prefix and distinct suffix from COMPLETED.
	require.Contains(t, string(started.EventID), DefaultAuditIDPrefix)
	require.Contains(t, string(completed.EventID), DefaultAuditIDPrefix)
	require.NotEqual(t, started.EventID, completed.EventID)
	require.Contains(t, string(result.ValidationResultID), DefaultResultIDPrefix)
	require.Contains(t, string(result.ValidationResultID), string(bm.BootstrapID))

	// Evidence refs must name BOTH audit events, in order.
	require.Len(t, result.Evidence, 2)
	require.Equal(t, started.EventID, result.Evidence[0].AuditEventID)
	require.Equal(t, string(audit_event.KindRecvValidationStarted), result.Evidence[0].Kind)
	require.Equal(t, completed.EventID, result.Evidence[1].AuditEventID)
	require.Equal(t, string(audit_event.KindRecvValidationCompleted), result.Evidence[1].Kind)

	// ValidationResult.Validate() is the service's post-condition;
	// Validate() already called it, but re-assert here as a guard
	// against accidental post-hoc mutation.
	require.NoError(t, result.Validate())

	// Chain verifies end-to-end under the same store that signed it.
	require.NoError(t, sf.chain.Verify(sf.recvFixtures.store))
}

// TestValidate_OperationalFail_ProducesFailVerdict — a sub-check
// failure (coverage mismatch here) must produce VerdictFail AND still
// append both audit events. The COMPLETED audit event is emitted
// BEFORE the ValidationResult is surfaced to the caller, so no fail
// path can hide from the audit chain.
func TestValidate_OperationalFail_ProducesFailVerdict(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	sf.recvFixtures.inputs.Coverage.Admitted = 2 // partial < expected=3
	in := ValidateInputs{OperationalInputs: sf.recvFixtures.inputs}

	result, err := sf.service.Validate(in)
	require.NoError(t, err,
		"sub-check failure is a VERDICT fail, not a service-level error")
	require.Equal(t, validation_result.VerdictFail, result.OverallVerdict)
	require.Equal(t, validation_result.VerdictFail,
		result.Dimensions[validation_result.DimensionOperational].Verdict)
	require.GreaterOrEqual(t, len(
		result.Dimensions[validation_result.DimensionOperational].Details), 1)

	// Audit still fires both START and COMPLETE; the audit record
	// carries the fail verdict so an auditor sees the failure
	// regardless of caller behaviour.
	require.Equal(t, 2, sf.chain.Len())
	started, _ := sf.chain.EventAt(0)
	completed, _ := sf.chain.EventAt(1)
	require.Equal(t, audit_event.KindRecvValidationStarted, started.Kind)
	require.Equal(t, audit_event.KindRecvValidationCompleted, completed.Kind)

	require.NoError(t, sf.chain.Verify(sf.recvFixtures.store))
}

// TestValidate_CounterIsolationBetweenCalls — two Validate() calls on
// the same service must mint distinct EventIDs AND distinct
// ValidationResultIDs. The monotonic counter makes repeated
// invocations independently evident in the chain.
func TestValidate_CounterIsolationBetweenCalls(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)

	in1 := ValidateInputs{OperationalInputs: sf.recvFixtures.inputs}
	r1, err := sf.service.Validate(in1)
	require.NoError(t, err)

	// Advance the logical clock so Now is strictly greater for the
	// second call — prevents the clock-fallback branch from collapsing
	// completed_at to a stale value.
	in2 := ValidateInputs{OperationalInputs: sf.recvFixtures.inputs}
	in2.Now = sf.recvFixtures.inputs.Now.Add(time.Second)

	r2, err := sf.service.Validate(in2)
	require.NoError(t, err)

	require.NotEqual(t, r1.ValidationResultID, r2.ValidationResultID)

	// Four events total; all distinct.
	require.Equal(t, 4, sf.chain.Len())
	seen := map[ids.AuditEventID]struct{}{}
	for i := 0; i < sf.chain.Len(); i++ {
		e, ok := sf.chain.EventAt(i)
		require.True(t, ok)
		_, dup := seen[e.EventID]
		require.Falsef(t, dup, "duplicate EventID %q at index %d", e.EventID, i)
		seen[e.EventID] = struct{}{}
	}

	require.NoError(t, sf.chain.Verify(sf.recvFixtures.store))
}

// TestValidate_MultipleFailures_AllReportedInFinding — when several
// sub-checks fail simultaneously, every failure is captured in the
// DimensionVerdict's Details AND in the count embedded in the
// COMPLETED audit payload. This is the audit-observability promise of
// the no-short-circuit rule.
func TestValidate_MultipleFailures_AllReportedInFinding(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	sf.recvFixtures.inputs.Attestation.Outcome = attestation_result.OutcomeDeny
	sf.recvFixtures.inputs.ActivePolicy = ids.PolicyVersion("policy-rotated")
	sf.recvFixtures.inputs.Coverage.Admitted = 0

	result, err := sf.service.Validate(ValidateInputs{OperationalInputs: sf.recvFixtures.inputs})
	require.NoError(t, err)

	opDim := result.Dimensions[validation_result.DimensionOperational]
	require.Equal(t, validation_result.VerdictFail, opDim.Verdict)
	codes := map[string]bool{}
	for _, f := range opDim.Details {
		codes[f.Code] = true
	}
	require.True(t, codes[CodeRecvAttestationValid])
	require.True(t, codes[CodeRecvPolicyAlignment])
	require.True(t, codes[CodeRecvReassemblyCoverage])

	require.NoError(t, sf.chain.Verify(sf.recvFixtures.store))
}

// ---- failing-chain diagnostic -------------------------------------------

// failingChain is a minimal chain.Chain stub that returns an error
// from Append on the N-th call and behaves normally before that. The
// intent is to exercise the service's error-propagation behaviour
// without re-implementing chain mechanics.
type failingChain struct {
	failOn int // 1 = fail first append, 2 = fail second, 0 = never fail
	calls  int
	inner  *chain.InMemoryChain
}

func newFailingChain(failOn int) *failingChain {
	return &failingChain{failOn: failOn, inner: chain.NewInMemoryChain()}
}

func (c *failingChain) Append(evt audit_event.AuditEvent, signer keys.Signer) (audit_event.AuditEvent, error) {
	c.calls++
	if c.failOn > 0 && c.calls == c.failOn {
		return audit_event.AuditEvent{}, errors.New("simulated audit append failure")
	}
	return c.inner.Append(evt, signer)
}

func (c *failingChain) Verify(r keys.Resolver) error { return c.inner.Verify(r) }
func (c *failingChain) Tip() []byte                  { return c.inner.Tip() }
func (c *failingChain) Len() int                     { return c.inner.Len() }
func (c *failingChain) EventAt(i int) (audit_event.AuditEvent, bool) {
	return c.inner.EventAt(i)
}
func (c *failingChain) Events() []audit_event.AuditEvent { return c.inner.Events() }

// TestValidate_AuditChainStartedFailure_Propagates — if the STARTED
// audit append fails, the service aborts without running the
// sub-checks or minting a VRID. No partial state escapes.
func TestValidate_AuditChainStartedFailure_Propagates(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	auditKID := ids.KeyID("recv-audit-g1")
	_, err := f.store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	fc := newFailingChain(1) // fail on first Append
	svc, err := NewValidationService(ServiceOptions{
		AuditChain:  fc,
		AuditSigner: f.store,
		AuditKeyID:  auditKID,
		Clock:       shared_time.NewFakeClock(f.inputs.Now),
	})
	require.NoError(t, err)

	result, err := svc.Validate(ValidateInputs{OperationalInputs: f.inputs})
	require.Error(t, err)
	require.Nil(t, result)
	// inner chain remains empty — the STARTED append was refused by
	// the stub BEFORE inner.Append could run.
	require.Zero(t, fc.inner.Len())
}

// TestValidate_AuditChainCompletedFailure_Propagates — if the
// COMPLETED append fails, the error is surfaced and the result is
// not returned. An observer sees the STARTED event but no COMPLETED,
// which is the audit trail of a mid-path failure — exactly the
// observability the audit-event-before-surface rule promises.
func TestValidate_AuditChainCompletedFailure_Propagates(t *testing.T) {
	t.Parallel()
	f := newRecvFixtures(t)
	auditKID := ids.KeyID("recv-audit-g1")
	_, err := f.store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	fc := newFailingChain(2) // STARTED lands; COMPLETED fails.
	svc, err := NewValidationService(ServiceOptions{
		AuditChain:  fc,
		AuditSigner: f.store,
		AuditKeyID:  auditKID,
		Clock:       shared_time.NewFakeClock(f.inputs.Now),
	})
	require.NoError(t, err)

	result, err := svc.Validate(ValidateInputs{OperationalInputs: f.inputs})
	require.Error(t, err)
	require.Nil(t, result)

	// Exactly one event in the chain: STARTED.
	require.Equal(t, 1, fc.inner.Len())
	started, ok := fc.inner.EventAt(0)
	require.True(t, ok)
	require.Equal(t, audit_event.KindRecvValidationStarted, started.Kind)
}

// ---- context compile-time interface assertion ----------------------------

// Compile-time: ValidationService fulfils no special interface today
// but the service embeds its dependency types so a type change on
// chain.Chain or keys.Signer surfaces as a build error here. This
// keeps service_test.go honest against silent interface drift.
func TestValidationService_WellFormedConstruction(t *testing.T) {
	t.Parallel()
	sf := newServiceFixtures(t)
	_ = sf.service // referenced to prove the fixture wired successfully
	var _ keys.Signer = sf.recvFixtures.store
	var _ keys.Resolver = sf.recvFixtures.store

	// Session-object sanity: the fixtures build an ACTIVE session
	// before any sub-check runs — otherwise the happy-path suite above
	// would mask construction-time regressions.
	require.Equal(t, session_object.StateActive, sf.recvFixtures.inputs.Session.State)
	require.False(t, sf.recvFixtures.inputs.BootstrapManifest.BootstrapID.IsZero())
}
