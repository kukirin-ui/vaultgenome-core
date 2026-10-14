// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- test fixtures --------------------------------------------------------

type fixtures struct {
	svc         *Service
	ch          *chain.InMemoryChain
	store       *keys.InMemoryStore
	clock       *shared_time.FakeClock
	auditKID    ids.KeyID
	invalidated []invalidateCall
	zeroizes    int
}

type invalidateCall struct {
	SessionID ids.SessionID
	Reason    string
}

func newFixtures(t *testing.T) *fixtures {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(fc)

	auditKID := ids.KeyID("incident-audit-g1")
	_, err := store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	ch := chain.NewInMemoryChain()

	f := &fixtures{
		ch:       ch,
		store:    store,
		clock:    fc,
		auditKID: auditKID,
	}
	invalidator := SessionInvalidatorFunc(func(sid ids.SessionID, reason string) error {
		f.invalidated = append(f.invalidated, invalidateCall{SessionID: sid, Reason: reason})
		return nil
	})
	zeroizer := ZeroizerFunc(func() {
		f.zeroizes++
	})

	svc, err := NewService(ServiceOptions{
		AuditChain:         ch,
		AuditSigner:        store,
		AuditKeyID:         auditKID,
		Clock:              fc,
		SessionInvalidator: invalidator,
		Zeroizer:           zeroizer,
	})
	require.NoError(t, err)
	f.svc = svc
	return f
}

func goodTrigger() Trigger {
	return Trigger{
		SessionID:  ids.SessionID("session-abc"),
		ManifestID: ids.ManifestID("manifest-xyz"),
		Code:       "op.attestation_valid",
		Detail:     "attestation quote signature verification failed",
	}
}

// ---- constructor refusals -------------------------------------------------

func TestNewService_MissingAuditChain(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	_, err := NewService(ServiceOptions{
		AuditChain:         nil,
		AuditSigner:        f.store,
		AuditKeyID:         f.auditKID,
		Clock:              f.clock,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error { return nil }),
		Zeroizer:           ZeroizerFunc(func() {}),
	})
	require.Error(t, err)
	require.Equal(t, CodeMissingAuditChain, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewService_MissingAuditSigner(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	_, err := NewService(ServiceOptions{
		AuditChain:         f.ch,
		AuditSigner:        nil,
		AuditKeyID:         f.auditKID,
		Clock:              f.clock,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error { return nil }),
		Zeroizer:           ZeroizerFunc(func() {}),
	})
	require.Error(t, err)
	require.Equal(t, CodeMissingAuditSigner, shared_errors.CodeOf(err))
}

func TestNewService_MissingAuditKeyID(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	_, err := NewService(ServiceOptions{
		AuditChain:         f.ch,
		AuditSigner:        f.store,
		AuditKeyID:         "",
		Clock:              f.clock,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error { return nil }),
		Zeroizer:           ZeroizerFunc(func() {}),
	})
	require.Error(t, err)
	require.Equal(t, CodeMissingAuditKeyID, shared_errors.CodeOf(err))
}

func TestNewService_MissingClock(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	_, err := NewService(ServiceOptions{
		AuditChain:         f.ch,
		AuditSigner:        f.store,
		AuditKeyID:         f.auditKID,
		Clock:              nil,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error { return nil }),
		Zeroizer:           ZeroizerFunc(func() {}),
	})
	require.Error(t, err)
	require.Equal(t, CodeMissingClock, shared_errors.CodeOf(err))
}

func TestNewService_MissingSessionInvalidator(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	_, err := NewService(ServiceOptions{
		AuditChain:         f.ch,
		AuditSigner:        f.store,
		AuditKeyID:         f.auditKID,
		Clock:              f.clock,
		SessionInvalidator: nil,
		Zeroizer:           ZeroizerFunc(func() {}),
	})
	require.Error(t, err)
	require.Equal(t, CodeMissingSessionInvalidator, shared_errors.CodeOf(err))
}

func TestNewService_MissingZeroizer(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	_, err := NewService(ServiceOptions{
		AuditChain:         f.ch,
		AuditSigner:        f.store,
		AuditKeyID:         f.auditKID,
		Clock:              f.clock,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error { return nil }),
		Zeroizer:           nil,
	})
	require.Error(t, err)
	require.Equal(t, CodeMissingZeroizer, shared_errors.CodeOf(err))
}

func TestNewService_UsesDefaultAuditPrefixWhenEmpty(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	require.Equal(t, DefaultAuditIDPrefix, f.svc.auditPrefix)
}

func TestNewService_RespectsCustomAuditPrefix(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	customPrefix := "audit-inc-test-"
	svc, err := NewService(ServiceOptions{
		AuditChain:         f.ch,
		AuditSigner:        f.store,
		AuditKeyID:         f.auditKID,
		Clock:              f.clock,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error { return nil }),
		Zeroizer:           ZeroizerFunc(func() {}),
		AuditIDPrefix:      customPrefix,
	})
	require.NoError(t, err)
	require.Equal(t, customPrefix, svc.auditPrefix)
}

// ---- per-call refusals ----------------------------------------------------

func TestHandleAttestationFailure_RefusesMissingSessionID(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	trig := goodTrigger()
	trig.SessionID = ""
	_, err := f.svc.HandleAttestationFailure(trig)
	require.Error(t, err)
	require.Equal(t, CodeMissingSessionID, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, 0, f.ch.Len(), "no audit events on refused call")
	require.Empty(t, f.invalidated)
	require.Zero(t, f.zeroizes)
}

func TestHandleValidationHardFail_RefusesMissingCode(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	trig := goodTrigger()
	trig.Code = ""
	_, err := f.svc.HandleValidationHardFail(trig)
	require.Error(t, err)
	require.Equal(t, CodeMissingCode, shared_errors.CodeOf(err))
	require.Equal(t, 0, f.ch.Len(), "no audit events on refused call")
	require.Empty(t, f.invalidated)
	require.Zero(t, f.zeroizes)
}

func TestHandleAuditAppendFailure_RefusesMissingSessionID(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	trig := goodTrigger()
	trig.SessionID = ""
	_, err := f.svc.HandleAuditAppendFailure(trig)
	require.Error(t, err)
	require.Equal(t, CodeMissingSessionID, shared_errors.CodeOf(err))
	require.Equal(t, 0, f.ch.Len())
}

func TestHandleAuditAppendFailure_RefusesMissingCode(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	trig := goodTrigger()
	trig.Code = ""
	_, err := f.svc.HandleAuditAppendFailure(trig)
	require.Error(t, err)
	require.Equal(t, CodeMissingCode, shared_errors.CodeOf(err))
}

// ---- scenario happy paths -------------------------------------------------

func TestHandleAttestationFailure_HappyPath(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	trig := goodTrigger()
	trig.Code = shared_errors.CodeAttestationDenied
	trig.CauseError = shared_errors.Operational(shared_errors.CodeAttestationDenied, "quote signature invalid", nil)

	res, err := f.svc.HandleAttestationFailure(trig)
	require.NoError(t, err)
	require.NotNil(t, res)

	require.Equal(t, ScenarioAttestationFailure, res.Scenario)
	require.Equal(t, SeverityCritical, res.Severity)
	require.Equal(t, trig.SessionID, res.SessionID)
	require.Equal(t, trig.ManifestID, res.ManifestID)

	require.True(t, res.SessionInvalidated)
	require.Empty(t, res.InvalidationFailedCode)
	require.True(t, res.Zeroized, "critical severity must zeroize")

	require.NotEmpty(t, res.DetectedEventID)
	require.NotEmpty(t, res.TerminatedEventID)
	require.NotEqual(t, res.DetectedEventID, res.TerminatedEventID)

	// Chain: [DETECTED, TERMINATED], in order.
	require.Equal(t, 2, f.ch.Len())
	evt0, ok := f.ch.EventAt(0)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentDetected, evt0.Kind)
	require.Equal(t, res.DetectedEventID, evt0.EventID)

	evt1, ok := f.ch.EventAt(1)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentTerminated, evt1.Kind)
	require.Equal(t, res.TerminatedEventID, evt1.EventID)

	// Side effects ran exactly once, in order.
	require.Len(t, f.invalidated, 1)
	require.Equal(t, trig.SessionID, f.invalidated[0].SessionID)
	require.Equal(t, ScenarioAttestationFailure.String(), f.invalidated[0].Reason)
	require.Equal(t, 1, f.zeroizes)

	// Chain verifies under the same keystore.
	require.NoError(t, f.ch.Verify(f.store))
}

func TestHandleValidationHardFail_HappyPath_NoZeroize(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	trig := goodTrigger()
	trig.Code = "op.session_valid"
	trig.Detail = "session expired at validation time"

	res, err := f.svc.HandleValidationHardFail(trig)
	require.NoError(t, err)
	require.NotNil(t, res)

	require.Equal(t, ScenarioValidationHardFail, res.Scenario)
	require.Equal(t, SeverityError, res.Severity)
	require.True(t, res.SessionInvalidated)
	require.False(t, res.Zeroized, "error severity must NOT zeroize")

	require.Equal(t, 2, f.ch.Len())
	require.Len(t, f.invalidated, 1)
	require.Equal(t, 0, f.zeroizes, "validation hard-fail never triggers zeroize")

	require.NoError(t, f.ch.Verify(f.store))
}

func TestHandleAuditAppendFailure_HappyPath_NoZeroize(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	trig := goodTrigger()
	trig.Code = shared_errors.CodeChainGapDetected
	trig.CauseError = shared_errors.Integrity(shared_errors.CodeChainGapDetected, "follow-up append refused by chain", nil)

	res, err := f.svc.HandleAuditAppendFailure(trig)
	require.NoError(t, err)
	require.NotNil(t, res)

	require.Equal(t, ScenarioAuditAppendFailure, res.Scenario)
	require.Equal(t, SeverityError, res.Severity)
	require.True(t, res.SessionInvalidated)
	require.False(t, res.Zeroized)

	require.Equal(t, 2, f.ch.Len())
	require.Len(t, f.invalidated, 1)
	require.Equal(t, 0, f.zeroizes)

	evt1, ok := f.ch.EventAt(1)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentTerminated, evt1.Kind)
	require.Equal(t, trig.SessionID, evt1.SessionID)
	require.Equal(t, trig.ManifestID, evt1.ManifestID)

	require.NoError(t, f.ch.Verify(f.store))
}

// ---- side-effect ordering -------------------------------------------------

func TestHandleAttestationFailure_DetectedBeforeSideEffects(t *testing.T) {
	t.Parallel()
	// Use a spying invalidator that captures the chain's length at the
	// moment InvalidateSession is called. DETECTED MUST be on the chain
	// by that point; TERMINATED MUST NOT be.
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(fc)
	auditKID := ids.KeyID("incident-audit-g1")
	_, err := store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)
	ch := chain.NewInMemoryChain()

	var chainLenAtInvalidate int
	var chainLenAtZeroize int
	invalidator := SessionInvalidatorFunc(func(sid ids.SessionID, reason string) error {
		chainLenAtInvalidate = ch.Len()
		return nil
	})
	zeroizer := ZeroizerFunc(func() {
		chainLenAtZeroize = ch.Len()
	})

	svc, err := NewService(ServiceOptions{
		AuditChain:         ch,
		AuditSigner:        store,
		AuditKeyID:         auditKID,
		Clock:              fc,
		SessionInvalidator: invalidator,
		Zeroizer:           zeroizer,
	})
	require.NoError(t, err)

	_, err = svc.HandleAttestationFailure(goodTrigger())
	require.NoError(t, err)

	require.Equal(t, 1, chainLenAtInvalidate, "DETECTED must be on chain at invalidate time; TERMINATED must NOT be")
	require.Equal(t, 1, chainLenAtZeroize, "DETECTED must be on chain at zeroize time; TERMINATED must NOT be")
	require.Equal(t, 2, ch.Len(), "final chain length is 2 (DETECTED + TERMINATED)")
}

// ---- chain.Append failure survivorship ------------------------------------

// failingChain is a test double that fails on a configurable Append
// index. Other methods are no-ops suitable for error-path tests.
type failingChain struct {
	failOnIndex int // zero-based index of the Append call that fails
	calls       int
	events      []audit_event.AuditEvent
}

func (c *failingChain) Append(evt audit_event.AuditEvent, _ keys.Signer) (audit_event.AuditEvent, error) {
	idx := c.calls
	c.calls++
	if idx == c.failOnIndex {
		return audit_event.AuditEvent{}, shared_errors.Integrity(
			shared_errors.CodeChainGapDetected,
			"chain test double: append refused",
			nil,
		)
	}
	// Provide a deterministic EventID so Result comparisons are stable.
	if evt.EventID == "" {
		evt.EventID = ids.AuditEventID("fake-evt")
	}
	c.events = append(c.events, evt)
	return evt, nil
}

func (c *failingChain) Verify(keys.Resolver) error { return nil }
func (c *failingChain) Tip() []byte                { return make([]byte, audit_event.HashSize) }
func (c *failingChain) Len() int                   { return len(c.events) }
func (c *failingChain) EventAt(i int) (audit_event.AuditEvent, bool) {
	if i < 0 || i >= len(c.events) {
		return audit_event.AuditEvent{}, false
	}
	return c.events[i], true
}
func (c *failingChain) Events() []audit_event.AuditEvent { return c.events }

func TestHandleAttestationFailure_DetectedAppendFails_NoSideEffects(t *testing.T) {
	t.Parallel()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(fc)
	auditKID := ids.KeyID("incident-audit-g1")
	_, err := store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	fc0 := &failingChain{failOnIndex: 0}
	var invalidated, zeroized int
	svc, err := NewService(ServiceOptions{
		AuditChain:         fc0,
		AuditSigner:        store,
		AuditKeyID:         auditKID,
		Clock:              fc,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error { invalidated++; return nil }),
		Zeroizer:           ZeroizerFunc(func() { zeroized++ }),
	})
	require.NoError(t, err)

	_, err = svc.HandleAttestationFailure(goodTrigger())
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeChainGapDetected, shared_errors.CodeOf(err))
	require.Equal(t, 0, invalidated, "detection append refused → invalidator must NOT run")
	require.Equal(t, 0, zeroized, "detection append refused → zeroizer must NOT run")
	require.Equal(t, 0, fc0.Len())
}

func TestHandleAttestationFailure_TerminatedAppendFails_SideEffectsStillRan(t *testing.T) {
	t.Parallel()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(fc)
	auditKID := ids.KeyID("incident-audit-g1")
	_, err := store.GenerateSigning(auditKID, keys.PurposeSigningAudit)
	require.NoError(t, err)

	fc1 := &failingChain{failOnIndex: 1} // DETECTED append ok; TERMINATED refused.
	var invalidated, zeroized int
	svc, err := NewService(ServiceOptions{
		AuditChain:         fc1,
		AuditSigner:        store,
		AuditKeyID:         auditKID,
		Clock:              fc,
		SessionInvalidator: SessionInvalidatorFunc(func(ids.SessionID, string) error { invalidated++; return nil }),
		Zeroizer:           ZeroizerFunc(func() { zeroized++ }),
	})
	require.NoError(t, err)

	_, err = svc.HandleAttestationFailure(goodTrigger())
	require.Error(t, err, "terminated append refused → surface error")
	require.Equal(t, 1, invalidated, "DETECTED ok → invalidator ran")
	require.Equal(t, 1, zeroized, "DETECTED ok + critical severity → zeroizer ran")
	require.Equal(t, 1, fc1.Len(), "DETECTED survives on chain")
	first, ok := fc1.EventAt(0)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentDetected, first.Kind)
}

// ---- invalidator-error survivorship ---------------------------------------

func TestHandleValidationHardFail_InvalidatorClassifiedFailure_IsRecordedAndDoesNotAbort(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	// Replace the invalidator with one that returns a classified error.
	f.svc.invalidator = SessionInvalidatorFunc(func(ids.SessionID, string) error {
		return shared_errors.Integrity("session.registry_broken", "registry unreachable", nil)
	})

	res, err := f.svc.HandleValidationHardFail(goodTrigger())
	require.NoError(t, err, "invalidator errors are recorded, not short-circuiting")
	require.NotNil(t, res)
	require.False(t, res.SessionInvalidated)
	require.Equal(t, "session.registry_broken", res.InvalidationFailedCode)

	// TERMINATED still emitted (chain length 2) and chain verifies.
	require.Equal(t, 2, f.ch.Len())
	require.NoError(t, f.ch.Verify(f.store))
}

func TestHandleValidationHardFail_InvalidatorUncategorisedFailure_FallsBackToStableCode(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.svc.invalidator = SessionInvalidatorFunc(func(ids.SessionID, string) error {
		return stderrors.New("registry: network timeout")
	})

	res, err := f.svc.HandleValidationHardFail(goodTrigger())
	require.NoError(t, err)
	require.NotNil(t, res)
	require.False(t, res.SessionInvalidated)
	require.Equal(t, "incident.invalidator_failed", res.InvalidationFailedCode,
		"uncategorised invalidator failures must fall back to a stable code")
}

// ---- V2+ deferral ---------------------------------------------------------

func TestHandlePhysicalTamperSignal_ReturnsV2Deferred_NoSideEffects(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	res, err := f.svc.HandlePhysicalTamperSignal(goodTrigger())
	require.Error(t, err)
	require.Nil(t, res)
	require.Same(t, ErrIncidentV2Deferred, err, "V2+ must return the exact sentinel")
	require.True(t, IsV2Deferred(err))
	require.Equal(t, CodeIncidentV2Deferred, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))

	require.Equal(t, 0, f.ch.Len(), "V2+ emits no audit events")
	require.Empty(t, f.invalidated, "V2+ does not invalidate sessions")
	require.Zero(t, f.zeroizes, "V2+ does not zeroize")
}

func TestHandleSideChannelAnomaly_ReturnsV2Deferred_NoSideEffects(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	res, err := f.svc.HandleSideChannelAnomaly(goodTrigger())
	require.Error(t, err)
	require.Nil(t, res)
	require.Same(t, ErrIncidentV2Deferred, err)
	require.True(t, IsV2Deferred(err))

	require.Equal(t, 0, f.ch.Len())
	require.Empty(t, f.invalidated)
	require.Zero(t, f.zeroizes)
}

func TestIsV2Deferred_RecognisesWrappedError(t *testing.T) {
	t.Parallel()
	// Wrap the sentinel inside a classified error whose Code is the
	// V2-deferred code. IsV2Deferred should still return true via the
	// classified-code path (stderrors.Unwrap chains are not required).
	wrapped := shared_errors.Incident(CodeIncidentV2Deferred, "v2 deferred via wrapper", ErrIncidentV2Deferred)
	require.True(t, IsV2Deferred(wrapped))
}

func TestIsV2Deferred_RejectsUnrelatedError(t *testing.T) {
	t.Parallel()
	require.False(t, IsV2Deferred(nil))
	require.False(t, IsV2Deferred(stderrors.New("random")))
	require.False(t, IsV2Deferred(shared_errors.Operational("op.foo", "bar", nil)))
}

// ---- enum helpers ---------------------------------------------------------

func TestScenario_IsMVPCovered(t *testing.T) {
	t.Parallel()
	require.True(t, ScenarioAttestationFailure.IsMVPCovered())
	require.True(t, ScenarioValidationHardFail.IsMVPCovered())
	require.True(t, ScenarioAuditAppendFailure.IsMVPCovered())
	require.False(t, ScenarioPhysicalTamperSignal.IsMVPCovered())
	require.False(t, ScenarioSideChannelAnomaly.IsMVPCovered())
	require.False(t, Scenario("unknown").IsMVPCovered())
}

func TestSeverity_FixedPerScenario(t *testing.T) {
	t.Parallel()
	require.Equal(t, SeverityCritical, severityFor(ScenarioAttestationFailure))
	require.Equal(t, SeverityError, severityFor(ScenarioValidationHardFail))
	require.Equal(t, SeverityError, severityFor(ScenarioAuditAppendFailure))
	require.Equal(t, Severity(0), severityFor(ScenarioPhysicalTamperSignal))
	require.Equal(t, Severity(0), severityFor(ScenarioSideChannelAnomaly))
}

func TestSeverity_StringIsStableLowercase(t *testing.T) {
	t.Parallel()
	require.Equal(t, "info", SeverityInfo.String())
	require.Equal(t, "warn", SeverityWarn.String())
	require.Equal(t, "error", SeverityError.String())
	require.Equal(t, "critical", SeverityCritical.String())
	require.Equal(t, "unknown", Severity(99).String())
}

func TestScenario_StringIsStable(t *testing.T) {
	t.Parallel()
	require.Equal(t, "attestation_failure", ScenarioAttestationFailure.String())
	require.Equal(t, "validation_hard_fail", ScenarioValidationHardFail.String())
	require.Equal(t, "audit_append_failure", ScenarioAuditAppendFailure.String())
	require.Equal(t, "physical_tamper_signal", ScenarioPhysicalTamperSignal.String())
	require.Equal(t, "side_channel_anomaly", ScenarioSideChannelAnomaly.String())
}

// ---- monotonic IDs across repeated calls ----------------------------------

func TestHandle_MintsDistinctEventIDsAcrossCalls(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)

	res1, err := f.svc.HandleValidationHardFail(goodTrigger())
	require.NoError(t, err)
	res2, err := f.svc.HandleValidationHardFail(goodTrigger())
	require.NoError(t, err)

	require.NotEqual(t, res1.DetectedEventID, res2.DetectedEventID)
	require.NotEqual(t, res1.TerminatedEventID, res2.TerminatedEventID)
	require.NotEqual(t, res1.DetectedEventID, res2.TerminatedEventID)
	require.NotEqual(t, res1.TerminatedEventID, res2.DetectedEventID)

	// And the chain carries all four events.
	require.Equal(t, 4, f.ch.Len())
	require.NoError(t, f.ch.Verify(f.store))
}

// ---- payload shape (canonical-JSON) --------------------------------------

func TestDetectedPayload_CarriesCauseClassification(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	trig := goodTrigger()
	trig.CauseError = shared_errors.Integrity(shared_errors.CodeChainHashMismatch, "chain gap at tip+1", nil)

	_, err := f.svc.HandleValidationHardFail(trig)
	require.NoError(t, err)

	evt, ok := f.ch.EventAt(0)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentDetected, evt.Kind)
	// The payload is canonical-JSON; rather than re-decoding we check
	// for the presence of stable substrings. Canonical-JSON preserves
	// ordering so this is deterministic.
	bytes := string(evt.Payload)
	require.Contains(t, bytes, `"cause_category":"integrity"`)
	require.Contains(t, bytes, `"cause_code":"`+shared_errors.CodeChainHashMismatch+`"`)
	require.Contains(t, bytes, `"scenario":"validation_hard_fail"`)
	require.Contains(t, bytes, `"severity":"error"`)
	require.Contains(t, bytes, `"session_id":"`+string(trig.SessionID)+`"`)
}

func TestTerminatedPayload_CitesDetectedEventIDAndSideEffectFlags(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	res, err := f.svc.HandleAttestationFailure(goodTrigger())
	require.NoError(t, err)

	evt, ok := f.ch.EventAt(1)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentTerminated, evt.Kind)

	bytes := string(evt.Payload)
	require.Contains(t, bytes, `"detected_event_id":"`+string(res.DetectedEventID)+`"`)
	require.Contains(t, bytes, `"scenario":"attestation_failure"`)
	require.Contains(t, bytes, `"severity":"critical"`)
	require.Contains(t, bytes, `"session_invalidated":true`)
	require.Contains(t, bytes, `"zeroized":true`)
}

func TestTerminatedPayload_RecordsInvalidationFailureCode(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	f.svc.invalidator = SessionInvalidatorFunc(func(ids.SessionID, string) error {
		return shared_errors.Integrity("session.registry_broken", "registry unreachable", nil)
	})
	_, err := f.svc.HandleValidationHardFail(goodTrigger())
	require.NoError(t, err)

	evt, ok := f.ch.EventAt(1)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentTerminated, evt.Kind)

	bytes := string(evt.Payload)
	require.Contains(t, bytes, `"session_invalidated":false`)
	require.Contains(t, bytes, `"invalidation_failed_code":"session.registry_broken"`)
	require.Contains(t, bytes, `"zeroized":false`)
}

// ---- compile-time shape assertions ----------------------------------------

func TestInMemoryStore_SatisfiesZeroizer(t *testing.T) {
	t.Parallel()
	// Already asserted at package scope via `var _ Zeroizer =
	// (*keys.InMemoryStore)(nil)`. This test just reads the assertion
	// out loud so a grep for "Zeroizer" finds the intent.
	var z Zeroizer = keys.NewInMemoryStore(shared_time.NewFakeClock(time.Now()))
	_ = z
}
