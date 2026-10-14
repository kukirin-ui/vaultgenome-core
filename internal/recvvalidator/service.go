// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package recvvalidator

import (
	"encoding/hex"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Stable validator codes. Emitted from service-level refusals; the
// per-sub-check codes live on the DimensionVerdict's Finding records.
const (
	CodeValidatorMissingBootstrapManifest = "recv_validator.missing_bootstrap_manifest"
	CodeValidatorMissingAuditChain        = "recv_validator.missing_audit_chain"
	CodeValidatorMissingAuditSigner       = "recv_validator.missing_audit_signer"
	CodeValidatorMissingAuditKeyID        = "recv_validator.missing_audit_key_id"
	CodeValidatorMissingResolver          = "recv_validator.missing_resolver"
	CodeValidatorMissingClock             = "recv_validator.missing_clock"
)

// DefaultAuditIDPrefix and DefaultResultIDPrefix prefix the
// receive-side validator's minted identifiers. Production deployments
// may override to embed a deployment tag.
const (
	DefaultAuditIDPrefix  = "audit-recv-val-"
	DefaultResultIDPrefix = "vr-recv-"
)

// ServiceOptions collects construction-time dependencies.
type ServiceOptions struct {
	// AuditChain is the receive-side hash-chained audit log.
	// RECV_VALIDATION_STARTED and RECV_VALIDATION_COMPLETED events
	// are appended here. The same chain the Orchestrator writes
	// DISCLOSURE_RECEIVED and RECONSTITUTION_DECIDED into — a single
	// receive-side ledger carries every receive-side decision.
	// Required non-nil.
	AuditChain chain.Chain

	// AuditSigner signs the AuditEvent records this service emits.
	// Bound to keys.PurposeSigningAudit.
	AuditSigner keys.Signer

	// AuditKeyID is the KeyID under which AuditSigner was registered.
	AuditKeyID ids.KeyID

	// Clock is the receive-side monotonic clock. Timestamps on
	// AuditEvent.OccurredAt and ValidationResult.ValidatedAt come
	// from Clock.Now().
	Clock shared_time.Clock

	// AuditIDPrefix / ResultIDPrefix override the default ID
	// prefixes. Empty means use the package default.
	AuditIDPrefix  string
	ResultIDPrefix string
}

// ValidationService is the Stage G orchestrator for the receive-side
// validator. One ValidationService can validate many reconstitution
// attempts — it holds no per-attempt state apart from a monotonic
// counter used to mint distinct AuditEventIDs and
// ValidationResultIDs.
type ValidationService struct {
	mu sync.Mutex

	chain       chain.Chain
	auditSigner keys.Signer
	auditKID    ids.KeyID
	clock       shared_time.Clock

	auditPrefix  string
	resultPrefix string

	ctr uint64
}

// NewValidationService constructs a ValidationService. All required
// ServiceOptions are checked here; a refusal is Structural.
func NewValidationService(opts ServiceOptions) (*ValidationService, error) {
	if opts.AuditChain == nil {
		return nil, shared_errors.Structural(
			CodeValidatorMissingAuditChain,
			"recvvalidator: audit_chain is required",
			nil,
		)
	}
	if opts.AuditSigner == nil {
		return nil, shared_errors.Structural(
			CodeValidatorMissingAuditSigner,
			"recvvalidator: audit_signer is required",
			nil,
		)
	}
	if opts.AuditKeyID.IsZero() {
		return nil, shared_errors.Structural(
			CodeValidatorMissingAuditKeyID,
			"recvvalidator: audit_key_id is required",
			nil,
		)
	}
	if opts.Clock == nil {
		return nil, shared_errors.Structural(
			CodeValidatorMissingClock,
			"recvvalidator: clock is required",
			nil,
		)
	}
	auditPrefix := opts.AuditIDPrefix
	if auditPrefix == "" {
		auditPrefix = DefaultAuditIDPrefix
	}
	resultPrefix := opts.ResultIDPrefix
	if resultPrefix == "" {
		resultPrefix = DefaultResultIDPrefix
	}
	return &ValidationService{
		chain:        opts.AuditChain,
		auditSigner:  opts.AuditSigner,
		auditKID:     opts.AuditKeyID,
		clock:        opts.Clock,
		auditPrefix:  auditPrefix,
		resultPrefix: resultPrefix,
	}, nil
}

// ValidateInputs bundles everything the validator needs to produce a
// verdict for one reconstitution attempt. It is a superset of
// OperationalInputs with no extra fields today, but kept as a distinct
// type so that future receive-side dimensions can be added (e.g. a
// reconstructed-model probe-battery input) without breaking the
// operational-only callers.
type ValidateInputs struct {
	OperationalInputs

	// Behavioral, when non-nil, drives the receive-side numerical
	// reconstruction-fidelity dimension: the reconstructed genome recomputes the
	// sealed reference fixtures and the determinism-ladder gate certifies the
	// result (EXACT/EQUIVALENT → pass; no door opens → fail-closed). Nil leaves
	// the behavioral dimension absent — operational-only, unchanged for existing
	// callers. This is the receive-side seam the doc comment above anticipated.
	Behavioral *BehavioralInputs
}

// BehavioralInputs carries the reconstruction-fidelity check for one genome:
// the sealed reference fixtures and the ordered determinism-ladder doors
// (recompute strategies) the destination should try. The doors are supplied by
// the caller (backed by the canonical kernels over the reassembled weights), so
// the validator stays free of any compute-backend dependency.
type BehavioralInputs struct {
	GenomeID  string
	Fixtures  []equivalence.Fixture
	Ladder    []reconstruction.Strategy
	Threshold float64 // behavioral pass threshold recorded in the verdict, in [0,1]
}

// Validate runs the six operational sub-checks, constructs the
// ValidationResult, and binds it into the receive-side audit chain
// by appending RECV_VALIDATION_STARTED before and
// RECV_VALIDATION_COMPLETED after. The returned result carries two
// EvidenceRefs — one per audit event — so cross-ledger observers can
// trace the verdict back to its audit anchors.
//
// The audit-event-before-surface discipline is enforced: the
// COMPLETED event is appended BEFORE the ValidationResult is
// returned to the caller. A Chain.Append failure at that step
// surfaces the error directly; the caller must treat the attempt as
// failed. The STARTED event is best-effort in the sense that a
// failure there aborts before any work is done — the caller simply
// retries or propagates the error.
func (s *ValidationService) Validate(in ValidateInputs) (*validation_result.ValidationResult, error) {
	if in.BootstrapManifest == nil {
		return nil, shared_errors.Structural(
			CodeValidatorMissingBootstrapManifest,
			"recvvalidator: bootstrap_manifest is required",
			nil,
		)
	}
	if in.Resolver == nil {
		return nil, shared_errors.Structural(
			CodeValidatorMissingResolver,
			"recvvalidator: resolver is required",
			nil,
		)
	}
	if in.Now.IsZero() {
		in.Now = s.clock.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	bm := in.BootstrapManifest
	now := in.Now.UTC()

	// ---- audit-event-before-work: RECV_VALIDATION_STARTED ----
	s.ctr++
	startedPayload, err := buildRecvValidationStartedPayload(bm)
	if err != nil {
		return nil, err
	}
	startedSkel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(s.auditPrefix + "start-" + hex.EncodeToString(counterBytes(s.ctr))),
		Kind:          audit_event.KindRecvValidationStarted,
		OccurredAt:    now,
		SessionID:     bm.SessionID,
		ManifestID:    bm.ManifestID,
		Payload:       startedPayload,
		SigningKeyID:  s.auditKID,
	}
	startedSealed, err := s.chain.Append(startedSkel, s.auditSigner)
	if err != nil {
		return nil, err
	}

	// ---- run the six receive-side operational sub-checks ----
	dim := RunOperational(in.OperationalInputs)
	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: dim,
	}
	// Optional receive-side behavioral dimension: numerical reconstruction
	// fidelity via the determinism-ladder gate. The descent tries each door and
	// gates it against the sealed fixtures; a healthy genome finds a door
	// (VerdictPass), a corrupted one opens none (VerdictFail → overall fail via
	// Aggregate → ReasonValidationFailed). Absent behavioral inputs leave the
	// result operational-only.
	if in.Behavioral != nil {
		res, err := reconstruction.Regenerate(in.Behavioral.GenomeID, in.Behavioral.Fixtures, in.Behavioral.Ladder)
		if err != nil {
			return nil, err
		}
		dims[validation_result.DimensionBehavioral] = reconstruction.LadderToDimensionVerdict(res, in.Behavioral.Threshold)
	}
	overall := Aggregate(dims)

	// ValidationResultID is minted after the sub-checks run so that
	// an observer inspecting the audit payloads can see the same
	// counter-derived suffix on both the STARTED and COMPLETED
	// events (the STARTED event pins BootstrapID but not a result
	// ID; the COMPLETED event pins both).
	s.ctr++
	vrid := ids.ValidationResultID(s.resultPrefix + bm.BootstrapID.String() + "-" + hex.EncodeToString(counterBytes(s.ctr)))

	// Completed-time timestamp: always at or after Now. Using the
	// clock here (as opposed to reusing `now`) makes it possible
	// for an observer to detect nonzero validator duration even in
	// fake-clock tests if the harness steps the clock between
	// Validate() and the chain.Append below.
	completedAt := s.clock.Now().UTC()
	if completedAt.Before(now) {
		completedAt = now
	}

	// ---- build ValidationResult (operational-only) ----
	result := &validation_result.ValidationResult{
		SchemaVersion:      validation_result.SchemaVersionCurrent,
		ValidationResultID: vrid,
		SessionID:          bm.SessionID,
		ManifestID:         bm.ManifestID,
		Dimensions:         dims,
		OverallVerdict:     overall,
		Evidence: []validation_result.EvidenceRef{
			{AuditEventID: startedSealed.EventID, Kind: string(audit_event.KindRecvValidationStarted)},
		},
		ValidatedAt: completedAt,
	}

	// ---- audit-event-before-surface: RECV_VALIDATION_COMPLETED ----
	s.ctr++
	completedPayload, err := buildRecvValidationCompletedPayload(bm, result)
	if err != nil {
		return nil, err
	}
	completedSkel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(s.auditPrefix + "done-" + hex.EncodeToString(counterBytes(s.ctr))),
		Kind:          audit_event.KindRecvValidationCompleted,
		OccurredAt:    completedAt,
		SessionID:     bm.SessionID,
		ManifestID:    bm.ManifestID,
		Payload:       completedPayload,
		SigningKeyID:  s.auditKID,
	}
	completedSealed, err := s.chain.Append(completedSkel, s.auditSigner)
	if err != nil {
		return nil, err
	}
	// Append the COMPLETED evidence ref after the chain append so the
	// result references the sealed EventID.
	result.Evidence = append(result.Evidence, validation_result.EvidenceRef{
		AuditEventID: completedSealed.EventID,
		Kind:         string(audit_event.KindRecvValidationCompleted),
	})

	// Static validator runs as a post-condition so a structural bug
	// in the service never surfaces a malformed ValidationResult.
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return result, nil
}

// ---- audit payload shapes -------------------------------------------------

// recvValidationStartedPayload is the canonical-JSON body of a
// RECV_VALIDATION_STARTED AuditEvent. It commits to the receive-side
// pre-flight binding: which BootstrapManifest is being validated,
// and under which session and policy version.
type recvValidationStartedPayload struct {
	BootstrapID   ids.BootstrapManifestID `json:"bootstrap_id"`
	ManifestID    ids.ManifestID          `json:"manifest_id"`
	SessionID     ids.SessionID           `json:"session_id"`
	PolicyVersion ids.PolicyVersion       `json:"policy_version"`
	GenomeID      ids.GenomeID            `json:"genome_id"`
}

func buildRecvValidationStartedPayload(bm *bootstrap_manifest.BootstrapManifest) ([]byte, error) {
	p := recvValidationStartedPayload{
		BootstrapID:   bm.BootstrapID,
		ManifestID:    bm.ManifestID,
		SessionID:     bm.SessionID,
		PolicyVersion: bm.PolicyVersion,
		GenomeID:      bm.GenomeID,
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"recvvalidator: audit payload encode failed (started)",
			err,
		)
	}
	return out, nil
}

// recvValidationCompletedPayload is the canonical-JSON body of a
// RECV_VALIDATION_COMPLETED AuditEvent. It commits to the terminal
// verdict, the per-dimension score for operational, and the
// ValidationResultID that the ReconstitutionDecision will cite.
type recvValidationCompletedPayload struct {
	BootstrapID        ids.BootstrapManifestID `json:"bootstrap_id"`
	ManifestID         ids.ManifestID          `json:"manifest_id"`
	SessionID          ids.SessionID           `json:"session_id"`
	ValidationResultID ids.ValidationResultID  `json:"validation_result_id"`
	OverallVerdict     string                  `json:"overall_verdict"`
	OperationalVerdict string                  `json:"operational_verdict"`
	OperationalScore   float64                 `json:"operational_score"`
	FindingCount       int                     `json:"finding_count"`
}

func buildRecvValidationCompletedPayload(bm *bootstrap_manifest.BootstrapManifest, vr *validation_result.ValidationResult) ([]byte, error) {
	opDim := vr.Dimensions[validation_result.DimensionOperational]
	p := recvValidationCompletedPayload{
		BootstrapID:        bm.BootstrapID,
		ManifestID:         bm.ManifestID,
		SessionID:          bm.SessionID,
		ValidationResultID: vr.ValidationResultID,
		OverallVerdict:     string(vr.OverallVerdict),
		OperationalVerdict: string(opDim.Verdict),
		OperationalScore:   opDim.Score,
		FindingCount:       len(opDim.Details),
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"recvvalidator: audit payload encode failed (completed)",
			err,
		)
	}
	return out, nil
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
