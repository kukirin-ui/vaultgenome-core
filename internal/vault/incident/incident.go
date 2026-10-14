// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- scenario + severity enumeration --------------------------------------

// Scenario enumerates the R-15 incident kinds. The three MVP-covered
// values run the full termination flow; the two V2+ values return
// ErrIncidentV2Deferred.
type Scenario string

const (
	// ScenarioAttestationFailure — TEE attestation failed during an
	// active session. Critical: session invalidation + zeroization.
	// R-15 MVP scenario 1.
	ScenarioAttestationFailure Scenario = "attestation_failure"

	// ScenarioValidationHardFail — validation produced OverallVerdict
	// Fail on a release candidate. Error severity: session
	// invalidation, no zeroization (the keys were not compromised,
	// just the candidate failed policy). R-15 MVP scenario 2.
	ScenarioValidationHardFail Scenario = "validation_hard_fail"

	// ScenarioAuditAppendFailure — a subsequent audit-chain Append
	// refused after a prior Append in the same session succeeded.
	// Invariant #8 ("audit is first-class") requires the session to
	// refuse to continue. Error severity: session invalidation, no
	// zeroization. Stage G Iteration 3 (task #68) MVP scenario 3.
	ScenarioAuditAppendFailure Scenario = "audit_append_failure"

	// ScenarioPhysicalTamperSignal — an external tamper sensor fired
	// or a witness-log DetectFork trips. V2+ per patent P3 §[0017];
	// MVP returns ErrIncidentV2Deferred.
	ScenarioPhysicalTamperSignal Scenario = "physical_tamper_signal"

	// ScenarioSideChannelAnomaly — external observability flags an
	// anomalous access pattern (timing, volume, unusual hour). V2+
	// per patent P3 §[0017]; MVP returns ErrIncidentV2Deferred.
	ScenarioSideChannelAnomaly Scenario = "side_channel_anomaly"
)

// String returns the Scenario as a stable lowercase identifier.
func (s Scenario) String() string { return string(s) }

// IsMVPCovered reports whether the scenario has a real MVP handler
// (as opposed to a V2+ stub).
func (s Scenario) IsMVPCovered() bool {
	switch s {
	case ScenarioAttestationFailure,
		ScenarioValidationHardFail,
		ScenarioAuditAppendFailure:
		return true
	default:
		return false
	}
}

// Severity is the four-level incident ranking used to decide side
// effects. The mapping from Scenario to Severity is fixed by
// severityFor(); callers cannot override it — the severity of an
// R-15 scenario is a doctrine fact, not a configuration knob.
type Severity uint8

const (
	// SeverityInfo — informational. No session invalidation, no
	// zeroization. Reserved for future use; no MVP scenario maps to
	// Info today.
	SeverityInfo Severity = 1

	// SeverityWarn — warning. Session invalidation NOT required, but
	// the event is audit-bound. Reserved for future use.
	SeverityWarn Severity = 2

	// SeverityError — session invalidation required. No zeroization.
	// ValidationHardFail and AuditAppendFailure land here.
	SeverityError Severity = 3

	// SeverityCritical — session invalidation AND zeroization.
	// AttestationFailure lands here — a failed attestation means the
	// TEE's binding to the keys can no longer be trusted, so the
	// keys themselves must be wiped.
	SeverityCritical Severity = 4
)

// String returns the Severity as a stable lowercase identifier.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// severityFor returns the fixed Severity for scenario, or zero for
// unknown scenarios (which Handle* never surfaces — unknown scenarios
// are caught upstream by the enum switch in each handler).
func severityFor(scenario Scenario) Severity {
	switch scenario {
	case ScenarioAttestationFailure:
		return SeverityCritical
	case ScenarioValidationHardFail:
		return SeverityError
	case ScenarioAuditAppendFailure:
		return SeverityError
	default:
		// V2+ scenarios and unknowns: not used (V2+ short-circuits).
		return 0
	}
}

// ---- stable code constants ------------------------------------------------

const (
	// Construction-time refusals (Structural).
	CodeMissingAuditChain         = "incident.missing_audit_chain"
	CodeMissingAuditSigner        = "incident.missing_audit_signer"
	CodeMissingAuditKeyID         = "incident.missing_audit_key_id"
	CodeMissingClock              = "incident.missing_clock"
	CodeMissingSessionInvalidator = "incident.missing_session_invalidator"
	CodeMissingZeroizer           = "incident.missing_zeroizer"

	// Per-call refusals (Structural).
	CodeMissingSessionID = "incident.missing_session_id"
	CodeMissingCode      = "incident.missing_code"

	// V2+ deferral (Incident).
	CodeIncidentV2Deferred = "incident.v2_deferred"

	// Audit-payload refusals (Structural).
	CodePayloadEncodeFailed = "incident.payload_encode_failed"
)

// DefaultAuditIDPrefix prefixes the AuditEvent IDs minted by the
// Service. Production deployments may override via ServiceOptions to
// embed a deployment tag.
const DefaultAuditIDPrefix = "audit-incident-"

// ---- pluggable seams ------------------------------------------------------

// SessionInvalidator is the seam the Service uses to invalidate a
// SessionObject. Production wires this to the Session Registry in
// /internal/vault/session; tests may wire it to a fake.
//
// The reason string is a short, stable code (e.g. the scenario
// identifier) included in the subsequent SESSION_INVALIDATED audit
// event (owned by the Session Registry, not this package).
type SessionInvalidator interface {
	InvalidateSession(sessionID ids.SessionID, reason string) error
}

// SessionInvalidatorFunc adapts a function to SessionInvalidator.
type SessionInvalidatorFunc func(sessionID ids.SessionID, reason string) error

// InvalidateSession implements SessionInvalidator.
func (f SessionInvalidatorFunc) InvalidateSession(sessionID ids.SessionID, reason string) error {
	return f(sessionID, reason)
}

// Zeroizer is the seam the Service uses to wipe key material on
// Critical severity. keys.InMemoryStore satisfies this via its
// Zeroize() method; production wraps the same shape around the
// TEE-sealed store.
type Zeroizer interface {
	Zeroize()
}

// ZeroizerFunc adapts a function to Zeroizer.
type ZeroizerFunc func()

// Zeroize implements Zeroizer.
func (f ZeroizerFunc) Zeroize() { f() }

// Compile-time assertion that keys.InMemoryStore satisfies Zeroizer.
var _ Zeroizer = (*keys.InMemoryStore)(nil)

// ---- per-call trigger + result -------------------------------------------

// Trigger is the per-call context supplied to every Handle* method.
// It carries the session the incident affects, the optional manifest
// correlator, a stable machine-readable Code (cited by the DETECTED
// payload), a human-readable Detail, and the cause error if one is
// available (its category and code are recorded in the payload).
type Trigger struct {
	// SessionID identifies the session the incident affects. Required
	// on every Handle* call — an un-sessioned incident is a Service
	// usage bug.
	SessionID ids.SessionID

	// ManifestID optionally names the ReconstructionJobManifest in
	// flight when the incident was detected. Copied into the DETECTED
	// payload for correlation.
	ManifestID ids.ManifestID

	// Code is the stable machine-readable code the detector chose
	// (e.g. shared_errors.CodeAttestationDenied,
	// shared_errors.CodeChainHashMismatch, the Validation-hard-fail
	// code from the failing operational sub-check). Required.
	Code string

	// Detail is a short human-readable message for operator surfaces.
	// Optional. No PII or plaintext content — per invariant #7 this
	// field must not carry model plaintext or candidate bytes.
	Detail string

	// CauseError is the error the detector had in hand when it called
	// the Service. Optional. Its Category and Code are copied into
	// the DETECTED payload so an auditor can trace the chain of
	// classified errors across packages.
	CauseError error
}

// Result is returned to the caller after an MVP scenario handler
// runs. It provides both audit-event IDs (so the caller can cite the
// DETECTED event without re-reading the chain) and the side-effect
// flags.
type Result struct {
	Scenario Scenario
	Severity Severity

	SessionID  ids.SessionID
	ManifestID ids.ManifestID

	DetectedAt   time.Time
	TerminatedAt time.Time

	// DetectedEventID and TerminatedEventID are the sealed
	// AuditEvent.EventID values. Both are non-zero on a successful
	// Handle* call; DetectedEventID alone may survive on a partial
	// failure (see doc.go "Contract" section).
	DetectedEventID   ids.AuditEventID
	TerminatedEventID ids.AuditEventID

	// SessionInvalidated reports whether the SessionInvalidator
	// returned nil. False means invalidation itself failed; the
	// TERMINATED payload's InvalidationFailedCode carries the failure
	// code and the caller must treat the session as compromised.
	SessionInvalidated bool

	// InvalidationFailedCode is empty on success, non-empty if the
	// SessionInvalidator failed. Copied into the TERMINATED payload.
	InvalidationFailedCode string

	// Zeroized reports whether Zeroizer.Zeroize() was invoked.
	// Zeroize is a void method so we track intent, not success —
	// a working keystore wipes atomically or panics.
	Zeroized bool
}

// ---- V2+ deferral ---------------------------------------------------------

// errV2Deferred is the singleton classified error returned by V2+
// handlers. Classified as CategoryIncident with stable code
// incident.v2_deferred so callers can branch on either.
type errV2Deferred struct{}

func (e *errV2Deferred) Error() string {
	return "incident[" + CodeIncidentV2Deferred + "]: v2+ scenario handler not implemented in MVP"
}
func (e *errV2Deferred) Category() shared_errors.Category { return shared_errors.CategoryIncident }
func (e *errV2Deferred) Code() string                     { return CodeIncidentV2Deferred }
func (e *errV2Deferred) Unwrap() error                    { return nil }

// Compile-time assertion that *errV2Deferred satisfies the shared
// classified-Error interface.
var _ shared_errors.Error = (*errV2Deferred)(nil)

// ErrIncidentV2Deferred is the error V2+ handlers return. It is a
// classified error (CategoryIncident, Code=incident.v2_deferred) so
// callers can route on either the category or the code. Stable
// identity — every call to a V2+ handler returns the same pointer,
// so == comparison works.
var ErrIncidentV2Deferred = &errV2Deferred{}

// IsV2Deferred reports whether err is (or wraps) ErrIncidentV2Deferred.
// Preferred over == so callers don't have to care about wrapping.
func IsV2Deferred(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrIncidentV2Deferred {
		return true
	}
	return shared_errors.CodeOf(err) == CodeIncidentV2Deferred
}

// ---- service --------------------------------------------------------------

// ServiceOptions collects the construction-time dependencies.
// Every required field is checked in NewService — a missing field is
// a Structural refusal.
type ServiceOptions struct {
	// AuditChain is the release-side hash-chained audit log.
	// INCIDENT_DETECTED and INCIDENT_TERMINATED events are appended
	// here. Required non-nil.
	AuditChain chain.Chain

	// AuditSigner signs the AuditEvent records this service emits.
	// Bound to keys.PurposeSigningAudit.
	AuditSigner keys.Signer

	// AuditKeyID is the KeyID under which AuditSigner was registered.
	AuditKeyID ids.KeyID

	// Clock is the vault monotonic clock. Timestamps on DETECTED and
	// TERMINATED come from Clock.Now().
	Clock shared_time.Clock

	// SessionInvalidator is wired to the Session Registry. Required.
	SessionInvalidator SessionInvalidator

	// Zeroizer is wired to the keystore. Required — even
	// zeroization-free scenarios (Error severity) depend on the
	// injection being present so a Critical scenario that arrives
	// later in the same Service instance has a configured path.
	Zeroizer Zeroizer

	// AuditIDPrefix overrides the default audit-event ID prefix.
	// Empty means use DefaultAuditIDPrefix.
	AuditIDPrefix string
}

// Service is the IncidentCoordinationService implementation. One
// Service instance may handle many incidents — it holds no per-call
// state beyond a monotonic counter used to mint distinct AuditEventIDs.
type Service struct {
	mu sync.Mutex

	chain       chain.Chain
	auditSigner keys.Signer
	auditKID    ids.KeyID
	clock       shared_time.Clock

	invalidator SessionInvalidator
	zeroizer    Zeroizer

	auditPrefix string

	ctr uint64
}

// NewService constructs a Service. Missing dependencies are
// Structural refusals so a vault main that forgets to wire a seam
// fails loudly at startup rather than silently skipping a
// termination step.
func NewService(opts ServiceOptions) (*Service, error) {
	if opts.AuditChain == nil {
		return nil, shared_errors.Structural(
			CodeMissingAuditChain,
			"incident: audit_chain is required",
			nil,
		)
	}
	if opts.AuditSigner == nil {
		return nil, shared_errors.Structural(
			CodeMissingAuditSigner,
			"incident: audit_signer is required",
			nil,
		)
	}
	if opts.AuditKeyID.IsZero() {
		return nil, shared_errors.Structural(
			CodeMissingAuditKeyID,
			"incident: audit_key_id is required",
			nil,
		)
	}
	if opts.Clock == nil {
		return nil, shared_errors.Structural(
			CodeMissingClock,
			"incident: clock is required",
			nil,
		)
	}
	if opts.SessionInvalidator == nil {
		return nil, shared_errors.Structural(
			CodeMissingSessionInvalidator,
			"incident: session_invalidator is required",
			nil,
		)
	}
	if opts.Zeroizer == nil {
		return nil, shared_errors.Structural(
			CodeMissingZeroizer,
			"incident: zeroizer is required",
			nil,
		)
	}
	prefix := opts.AuditIDPrefix
	if prefix == "" {
		prefix = DefaultAuditIDPrefix
	}
	return &Service{
		chain:       opts.AuditChain,
		auditSigner: opts.AuditSigner,
		auditKID:    opts.AuditKeyID,
		clock:       opts.Clock,
		invalidator: opts.SessionInvalidator,
		zeroizer:    opts.Zeroizer,
		auditPrefix: prefix,
	}, nil
}

// ---- helpers --------------------------------------------------------------

// counterBytes renders a 64-bit counter in big-endian form for
// lexicographically sortable hex-encoded IDs.
func counterBytes(n uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(n & 0xFF)
		n >>= 8
	}
	return b[:]
}

// mintAuditEventID returns the next minted audit event ID with the
// given suffix (detected / terminated). Must be called under s.mu.
func (s *Service) mintAuditEventID(suffix string) ids.AuditEventID {
	s.ctr++
	return ids.AuditEventID(s.auditPrefix + suffix + "-" + hex.EncodeToString(counterBytes(s.ctr)))
}
