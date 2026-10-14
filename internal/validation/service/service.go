// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/behavioral"
	"github.com/vault-genome/vaultgenome-core/internal/validation/operational"
	"github.com/vault-genome/vaultgenome-core/internal/validation/semantic"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Stable refusal codes emitted by the release-side Service. Per-sub-check
// codes live on DimensionVerdict.Finding records, not here.
const (
	CodeServiceMissingAuditChain  = "val_service.missing_audit_chain"
	CodeServiceMissingAuditSigner = "val_service.missing_audit_signer"
	CodeServiceMissingAuditKeyID  = "val_service.missing_audit_key_id"
	CodeServiceMissingClock       = "val_service.missing_clock"
	CodeServiceMissingSessionID   = "val_service.missing_session_id"
	CodeServiceMissingManifestID  = "val_service.missing_manifest_id"

	// CodeServiceDimensionNotEvaluable: ValidateInputs.Evaluated names a
	// dimension this service always evaluates itself (operational), or
	// one that does not exist.
	CodeServiceDimensionNotEvaluable = "val_service.dimension_not_evaluable"
)

// DefaultAuditIDPrefix / DefaultResultIDPrefix prefix the release-side
// validator's minted identifiers. Distinct from the receive-side
// validator prefixes so that an observer inspecting a merged ledger
// can tell the two families apart without parsing payloads.
const (
	DefaultAuditIDPrefix  = "audit-rel-val-"
	DefaultResultIDPrefix = "vr-rel-"
)

// ServiceOptions collects construction-time dependencies.
type ServiceOptions struct {
	// AuditChain is the release-side hash-chained audit log. The four
	// validation audit events (STARTED / DIMENSION / FINDING /
	// COMPLETED) are appended here. Required.
	AuditChain chain.Chain

	// AuditSigner signs the AuditEvent records. Must be bound to
	// keys.PurposeSigningAudit.
	AuditSigner keys.Signer

	// AuditKeyID is the KeyID under which AuditSigner was registered.
	AuditKeyID ids.KeyID

	// Clock drives OccurredAt / ValidatedAt timestamps.
	Clock shared_time.Clock

	// AuditIDPrefix / ResultIDPrefix override the package defaults.
	AuditIDPrefix  string
	ResultIDPrefix string
}

// ValidationService composes the three dimension evaluators and the
// aggregator into a single entry point. It owns only the audit chain,
// the signer, and a monotonic counter used to mint distinct event IDs
// and result IDs. All per-validation state lives in Inputs.
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

// NewValidationService constructs a ValidationService. Missing
// dependencies refuse with Structural errors so the governance layer
// can distinguish a configuration defect from a candidate-level defect.
func NewValidationService(opts ServiceOptions) (*ValidationService, error) {
	if opts.AuditChain == nil {
		return nil, shared_errors.Structural(
			CodeServiceMissingAuditChain,
			"validation.service: audit_chain is required",
			nil,
		)
	}
	if opts.AuditSigner == nil {
		return nil, shared_errors.Structural(
			CodeServiceMissingAuditSigner,
			"validation.service: audit_signer is required",
			nil,
		)
	}
	if opts.AuditKeyID.IsZero() {
		return nil, shared_errors.Structural(
			CodeServiceMissingAuditKeyID,
			"validation.service: audit_key_id is required",
			nil,
		)
	}
	if opts.Clock == nil {
		return nil, shared_errors.Structural(
			CodeServiceMissingClock,
			"validation.service: clock is required",
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

// ValidateInputs bundles every per-request input the Service needs to
// produce a ValidationResult. Each sub-evaluator's own Inputs struct is
// embedded via a distinct field so tests can mutate one dimension
// without touching the others.
type ValidateInputs struct {
	SessionID  ids.SessionID
	ManifestID ids.ManifestID

	// Semantic is the candidate-vs-fixture byte-equality input.
	Semantic semantic.Inputs

	// Behavioral is the probe-suite input.
	Behavioral behavioral.Inputs

	// Operational is the six-sub-check input. Always evaluated; the
	// §5 short-circuit is applied BEFORE semantic/behavioral when
	// op=fail to satisfy §8(3)–(5) ("no semantic/behavioral when op
	// fails").
	Operational operational.Inputs

	// Evaluated carries semantic and behavioral verdicts produced by an
	// evaluator that ran the model — the equivalence gate over a genome's
	// sealed fixtures (ADR 0008, ADR 0015) — in place of the byte
	// evaluators above. A dimension present here is recorded, with its
	// evaluator's name and detail, exactly as a dimension this service
	// evaluates itself: one DIMENSION_EVALUATED event, one FINDING per
	// finding, the same aggregation. Operational cannot be supplied.
	Evaluated map[validation_result.Dimension]EvaluatedDimension
}

// EvaluatedDimension is a dimension verdict from an evaluator outside
// this package.
type EvaluatedDimension struct {
	// Evaluator names what produced the verdict, e.g. "equivalence-ladder".
	Evaluator string
	// Verdict is the dimension's verdict, score, threshold and findings.
	Verdict validation_result.DimensionVerdict
	// Detail is evaluator-specific JSON recorded verbatim in the
	// VALIDATION_DIMENSION_EVALUATED payload (the doors tried, the
	// per-fixture agreement, ...). Optional.
	Detail json.RawMessage
}

// Validate runs the full three-dimension validation flow.
//
// Ordering (strict, audit-first):
//
//  1. VALIDATION_STARTED — before any sub-check runs.
//  2. operational.Run() — produces the operational DimensionVerdict.
//     VALIDATION_DIMENSION_EVALUATED emitted with op payload.
//  3. If op=fail: SKIP semantic + behavioral — §5 short-circuit.
//     §8(3)–(5) require "no semantic/behavioral when op fails".
//  4. Otherwise: semantic.Run() + behavioral.Run() in deterministic
//     order. Each emits its own DIMENSION_EVALUATED event.
//  5. For each Finding in any DimensionVerdict: one VALIDATION_FINDING
//     audit event. Ordering: operational findings, then semantic,
//     then behavioral. Within a dimension the findings appear in the
//     order the evaluator reports them (evaluators are deterministic).
//  6. Aggregate() — pure function computes OverallVerdict.
//  7. Build ValidationResult with Evidence refs pointing at the
//     sealed audit events above.
//  8. VALIDATION_COMPLETED — AFTER the result is fully built and
//     BEFORE the result is surfaced to the caller (audit-event-
//     before-surface).
//  9. result.Validate() as a post-condition.
//
// A Chain.Append failure at any step aborts the flow with the underlying
// error. The caller must treat the attempt as failed and MUST NOT
// create a ReleaseDecision — per §9(4) un-evidenced decisions are not
// governed decisions.
func (s *ValidationService) Validate(in ValidateInputs) (*validation_result.ValidationResult, error) {
	if in.SessionID.IsZero() {
		return nil, shared_errors.Structural(
			CodeServiceMissingSessionID,
			"validation.service: session_id is required",
			nil,
		)
	}
	if in.ManifestID.IsZero() {
		return nil, shared_errors.Structural(
			CodeServiceMissingManifestID,
			"validation.service: manifest_id is required",
			nil,
		)
	}

	for dim := range in.Evaluated {
		if dim != validation_result.DimensionSemantic && dim != validation_result.DimensionBehavioral {
			return nil, shared_errors.Structural(
				CodeServiceDimensionNotEvaluable,
				"validation.service: only the semantic and behavioral dimensions take an outside verdict; got "+string(dim),
				nil,
			)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().UTC()

	// ---- 1. VALIDATION_STARTED (audit-event-before-work) --------------
	s.ctr++
	startedPayload, err := buildValidationStartedPayload(in, now)
	if err != nil {
		return nil, err
	}
	startedSkel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(s.auditPrefix + "start-" + hex.EncodeToString(counterBytes(s.ctr))),
		Kind:          audit_event.KindValidationStarted,
		OccurredAt:    now,
		SessionID:     in.SessionID,
		ManifestID:    in.ManifestID,
		Payload:       startedPayload,
		SigningKeyID:  s.auditKID,
	}
	startedSealed, err := s.chain.Append(startedSkel, s.auditSigner)
	if err != nil {
		return nil, err
	}
	evidence := []validation_result.EvidenceRef{
		{AuditEventID: startedSealed.EventID, Kind: string(audit_event.KindValidationStarted)},
	}

	// ---- 2. operational dimension ------------------------------------
	opDim := operational.Run(in.Operational)
	opEvt, err := s.emitDimension(validation_result.DimensionOperational, opDim, in, now)
	if err != nil {
		return nil, err
	}
	evidence = append(evidence, validation_result.EvidenceRef{
		AuditEventID: opEvt.EventID,
		Kind:         string(audit_event.KindValidationDimension),
	})

	dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: opDim,
	}

	// ---- 3-4. Conditional short-circuit -----------------------------
	// §5: operational=fail short-circuits. Per §8(3)–(5) the negative
	// tests EXPLICITLY require that semantic/behavioral are NOT
	// evaluated when operational fails. Enforce that here rather than
	// relying solely on Aggregate: the evidence trail must reflect the
	// skip.
	var semDim, behDim validation_result.DimensionVerdict
	var skippedSemBeh bool
	if opDim.Verdict == validation_result.VerdictPass {
		if ev, ok := in.Evaluated[validation_result.DimensionSemantic]; ok {
			semDim = ev.Verdict
		} else {
			semDim = semantic.Run(in.Semantic)
		}
		semEvt, err := s.emitDimension(validation_result.DimensionSemantic, semDim, in, now)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, validation_result.EvidenceRef{
			AuditEventID: semEvt.EventID,
			Kind:         string(audit_event.KindValidationDimension),
		})
		dims[validation_result.DimensionSemantic] = semDim

		if ev, ok := in.Evaluated[validation_result.DimensionBehavioral]; ok {
			behDim = ev.Verdict
		} else {
			behDim = behavioral.Run(in.Behavioral)
		}
		behEvt, err := s.emitDimension(validation_result.DimensionBehavioral, behDim, in, now)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, validation_result.EvidenceRef{
			AuditEventID: behEvt.EventID,
			Kind:         string(audit_event.KindValidationDimension),
		})
		dims[validation_result.DimensionBehavioral] = behDim
	} else {
		skippedSemBeh = true
	}

	// ---- 5. Per-finding events (after all dimensions, before final) -
	// Order: op findings, sem findings, beh findings — deterministic
	// ledger layout so an observer reading the chain can reconstruct
	// dimension-by-dimension diagnostics without having to parse the
	// DimensionVerdict payloads.
	for _, f := range opDim.Details {
		evt, err := s.emitFinding(validation_result.DimensionOperational, f, in, now)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, validation_result.EvidenceRef{
			AuditEventID: evt.EventID,
			Kind:         string(audit_event.KindValidationFinding),
		})
	}
	if !skippedSemBeh {
		for _, f := range semDim.Details {
			evt, err := s.emitFinding(validation_result.DimensionSemantic, f, in, now)
			if err != nil {
				return nil, err
			}
			evidence = append(evidence, validation_result.EvidenceRef{
				AuditEventID: evt.EventID,
				Kind:         string(audit_event.KindValidationFinding),
			})
		}
		for _, f := range behDim.Details {
			evt, err := s.emitFinding(validation_result.DimensionBehavioral, f, in, now)
			if err != nil {
				return nil, err
			}
			evidence = append(evidence, validation_result.EvidenceRef{
				AuditEventID: evt.EventID,
				Kind:         string(audit_event.KindValidationFinding),
			})
		}
	}

	// ---- 6. Aggregate ----------------------------------------------
	overall := Aggregate(dims)

	// ---- 7. Build ValidationResult ---------------------------------
	s.ctr++
	vrid := ids.ValidationResultID(s.resultPrefix + in.SessionID.String() + "-" + hex.EncodeToString(counterBytes(s.ctr)))

	completedAt := s.clock.Now().UTC()
	if completedAt.Before(now) {
		completedAt = now
	}

	result := &validation_result.ValidationResult{
		SchemaVersion:      validation_result.SchemaVersionCurrent,
		ValidationResultID: vrid,
		SessionID:          in.SessionID,
		ManifestID:         in.ManifestID,
		Dimensions:         dims,
		OverallVerdict:     overall,
		Evidence:           evidence,
		ValidatedAt:        completedAt,
	}

	// ---- 8. VALIDATION_COMPLETED (before surface) ------------------
	s.ctr++
	completedPayload, err := buildValidationCompletedPayload(in, result, skippedSemBeh)
	if err != nil {
		return nil, err
	}
	completedSkel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(s.auditPrefix + "done-" + hex.EncodeToString(counterBytes(s.ctr))),
		Kind:          audit_event.KindValidationCompleted,
		OccurredAt:    completedAt,
		SessionID:     in.SessionID,
		ManifestID:    in.ManifestID,
		Payload:       completedPayload,
		SigningKeyID:  s.auditKID,
	}
	completedSealed, err := s.chain.Append(completedSkel, s.auditSigner)
	if err != nil {
		return nil, err
	}
	result.Evidence = append(result.Evidence, validation_result.EvidenceRef{
		AuditEventID: completedSealed.EventID,
		Kind:         string(audit_event.KindValidationCompleted),
	})

	// ---- 9. Post-condition ----------------------------------------
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return result, nil
}

// emitDimension appends one VALIDATION_DIMENSION_EVALUATED event.
func (s *ValidationService) emitDimension(
	dim validation_result.Dimension,
	dv validation_result.DimensionVerdict,
	in ValidateInputs,
	occurredAt time.Time,
) (audit_event.AuditEvent, error) {
	s.ctr++
	payload, err := buildDimensionPayload(dim, dv, in)
	if err != nil {
		return audit_event.AuditEvent{}, err
	}
	skel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(s.auditPrefix + "dim-" + hex.EncodeToString(counterBytes(s.ctr))),
		Kind:          audit_event.KindValidationDimension,
		OccurredAt:    occurredAt,
		SessionID:     in.SessionID,
		ManifestID:    in.ManifestID,
		Payload:       payload,
		SigningKeyID:  s.auditKID,
	}
	return s.chain.Append(skel, s.auditSigner)
}

// emitFinding appends one VALIDATION_FINDING event.
func (s *ValidationService) emitFinding(
	dim validation_result.Dimension,
	f validation_result.Finding,
	in ValidateInputs,
	occurredAt time.Time,
) (audit_event.AuditEvent, error) {
	s.ctr++
	payload, err := buildFindingPayload(dim, f, in)
	if err != nil {
		return audit_event.AuditEvent{}, err
	}
	skel := audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       ids.AuditEventID(s.auditPrefix + "find-" + hex.EncodeToString(counterBytes(s.ctr))),
		Kind:          audit_event.KindValidationFinding,
		OccurredAt:    occurredAt,
		SessionID:     in.SessionID,
		ManifestID:    in.ManifestID,
		Payload:       payload,
		SigningKeyID:  s.auditKID,
	}
	return s.chain.Append(skel, s.auditSigner)
}

// ---- audit payload shapes ------------------------------------------------

type validationStartedPayload struct {
	SessionID  ids.SessionID  `json:"session_id"`
	ManifestID ids.ManifestID `json:"manifest_id"`
}

func buildValidationStartedPayload(in ValidateInputs, _ time.Time) ([]byte, error) {
	p := validationStartedPayload{
		SessionID:  in.SessionID,
		ManifestID: in.ManifestID,
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"validation.service: started payload encode failed",
			err,
		)
	}
	return out, nil
}

type validationDimensionPayload struct {
	SessionID  ids.SessionID   `json:"session_id"`
	ManifestID ids.ManifestID  `json:"manifest_id"`
	Dimension  string          `json:"dimension"`
	Verdict    string          `json:"verdict"`
	Score      float64         `json:"score"`
	Threshold  float64         `json:"threshold"`
	Findings   int             `json:"findings"`
	Evaluator  string          `json:"evaluator,omitempty"`
	Detail     json.RawMessage `json:"detail,omitempty"`
}

func buildDimensionPayload(
	dim validation_result.Dimension,
	dv validation_result.DimensionVerdict,
	in ValidateInputs,
) ([]byte, error) {
	p := validationDimensionPayload{
		SessionID:  in.SessionID,
		ManifestID: in.ManifestID,
		Dimension:  string(dim),
		Verdict:    string(dv.Verdict),
		Score:      dv.Score,
		Threshold:  dv.Threshold,
		Findings:   len(dv.Details),
	}
	if ev, ok := in.Evaluated[dim]; ok {
		p.Evaluator = ev.Evaluator
		if len(ev.Detail) > 0 && json.Valid(ev.Detail) {
			p.Detail = ev.Detail
		}
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"validation.service: dimension payload encode failed",
			err,
		)
	}
	return out, nil
}

type validationFindingPayload struct {
	SessionID  ids.SessionID  `json:"session_id"`
	ManifestID ids.ManifestID `json:"manifest_id"`
	Dimension  string         `json:"dimension"`
	Code       string         `json:"code"`
	Severity   string         `json:"severity"`
	Message    string         `json:"message"`
}

func buildFindingPayload(
	dim validation_result.Dimension,
	f validation_result.Finding,
	in ValidateInputs,
) ([]byte, error) {
	p := validationFindingPayload{
		SessionID:  in.SessionID,
		ManifestID: in.ManifestID,
		Dimension:  string(dim),
		Code:       f.Code,
		Severity:   string(f.Severity),
		Message:    f.Message,
	}
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"validation.service: finding payload encode failed",
			err,
		)
	}
	return out, nil
}

type validationCompletedPayload struct {
	SessionID           ids.SessionID          `json:"session_id"`
	ManifestID          ids.ManifestID         `json:"manifest_id"`
	ValidationResultID  ids.ValidationResultID `json:"validation_result_id"`
	OverallVerdict      string                 `json:"overall_verdict"`
	OperationalVerdict  string                 `json:"operational_verdict"`
	SemanticEvaluated   bool                   `json:"semantic_evaluated"`
	BehavioralEvaluated bool                   `json:"behavioral_evaluated"`
	SemanticVerdict     string                 `json:"semantic_verdict,omitempty"`
	BehavioralVerdict   string                 `json:"behavioral_verdict,omitempty"`
	TotalFindings       int                    `json:"total_findings"`
}

func buildValidationCompletedPayload(
	in ValidateInputs,
	vr *validation_result.ValidationResult,
	skippedSemBeh bool,
) ([]byte, error) {
	op := vr.Dimensions[validation_result.DimensionOperational]
	p := validationCompletedPayload{
		SessionID:           in.SessionID,
		ManifestID:          in.ManifestID,
		ValidationResultID:  vr.ValidationResultID,
		OverallVerdict:      string(vr.OverallVerdict),
		OperationalVerdict:  string(op.Verdict),
		SemanticEvaluated:   !skippedSemBeh,
		BehavioralEvaluated: !skippedSemBeh,
	}
	total := len(op.Details)
	if sem, ok := vr.Dimensions[validation_result.DimensionSemantic]; ok {
		p.SemanticVerdict = string(sem.Verdict)
		total += len(sem.Details)
	}
	if beh, ok := vr.Dimensions[validation_result.DimensionBehavioral]; ok {
		p.BehavioralVerdict = string(beh.Verdict)
		total += len(beh.Details)
	}
	p.TotalFindings = total
	out, err := crypto.CanonicalJSON(&p)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"validation.service: completed payload encode failed",
			err,
		)
	}
	return out, nil
}

// ---- helpers -------------------------------------------------------------

// counterBytes renders a 64-bit counter in big-endian form.
func counterBytes(n uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(n & 0xFF)
		n >>= 8
	}
	return b[:]
}
