// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package orchestration

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/release_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/operational"
	valservice "github.com/vault-genome/vaultgenome-core/internal/validation/service"
	"github.com/vault-genome/vaultgenome-core/internal/vault/disclosure"
	"github.com/vault-genome/vaultgenome-core/internal/vault/incident"
	"github.com/vault-genome/vaultgenome-core/internal/vault/intake"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/session"
	"github.com/vault-genome/vaultgenome-core/internal/vault/trust"
)

// The Authority runs the nine stages for one request at a time, as one
// Flow (ADR 0015). Every stage is the library's own decision-maker —
// intake, trust, the session issuer, the staged disclosure sequencer, the
// validation service, the incident service — driven in the order the
// transition table allows, with every decision appended to the audit
// chain BEFORE it takes effect, and every authority artifact signed under
// the authority key:
//
//	stage 1  Intake          REQUEST_RECEIVED           unstarted → request → trust
//	stage 2  Admit           TRUST_EVALUATED            trust → session | release
//	stage 3  IssueSession    SESSION_ISSUED             session → disclosure
//	stage 4  Disclose        DISCLOSURE_AUTHORIZED ×n   (sequencer)
//	stage 5  IssueManifest   MANIFEST_ISSUED            disclosure → external_compute
//	stage 6  CandidateReceived CANDIDATE_RECEIVED       external_compute → return → validation
//	stage 7  Validate        VALIDATION_*               validation → release
//	stage 8  Decide          RELEASE_DECIDED            release → audit
//	stage 9  Seal            (INCIDENT_*, SESSION_INVALIDATED on refusal)  audit → terminal
//
// A Flow that fails between stages is Aborted: an incident on the record,
// its session invalidated, the machine terminated. A log that cannot take
// a record stops the stage: the caller gets the error and nothing has
// changed.

// AuditPayloadSchema names the payloads the Authority writes itself.
const AuditPayloadSchema = "vault-genome/orchestration-audit/v1"

// CodeAuditUnavailable (Operational): the audit chain did not take a
// record, so the decision was not taken.
const CodeAuditUnavailable = "audit_unavailable"

// CodeFlowEnded (Structural): a stage was asked of a flow that is over.
const CodeFlowEnded = "orchestration.flow_ended"

// AuthorityOptions wires an Authority.
type AuthorityOptions struct {
	Clock shared_time.Clock

	// Signer, Sealer and Resolver hold the authority signing key and the
	// recipient sealing key (one keystore serves all three).
	Signer   keys.Signer
	Sealer   keys.Sealer
	Resolver keys.Resolver
	// AuthorityKeyID signs every authority artifact: attestation,
	// session, disclosure, manifest, decision.
	AuthorityKeyID ids.KeyID
	// RecipientKeyID is the sealing key disclosures are sealed to — the
	// one the compute worker holds.
	RecipientKeyID ids.KeyID

	// Audit is the chain every decision goes to, signed by AuditSigner
	// under AuditKeyID (PurposeSigningAudit).
	Audit       chain.Chain
	AuditSigner keys.Signer
	AuditKeyID  ids.KeyID

	// PolicyVersion is pinned into every session and checked at
	// validation (op.policy_alignment).
	PolicyVersion ids.PolicyVersion
	// Profiles are the policy profiles trust admits; StopList, if set,
	// is the operator's stop list trust consults (ADR 0010).
	Profiles []string
	StopList trust.StopListSource

	// Zeroizer is what a Critical incident wipes. Required.
	Zeroizer incident.Zeroizer

	// Intake tunes what intake remembers.
	Intake intake.Options

	// IDNonce distinguishes this process's minted ids from another's on
	// the same log. Random when empty.
	IDNonce string
}

// Authority drives Flows. One per vault process.
type Authority struct {
	clock        shared_time.Clock
	signer       keys.Signer
	sealer       keys.Sealer
	resolver     keys.Resolver
	authorityKID ids.KeyID
	recipientKID ids.KeyID
	chain        chain.Chain
	auditSigner  keys.Signer
	auditKID     ids.KeyID
	policy       ids.PolicyVersion
	nonce        string

	intake     *intake.Intake
	trust      *trust.Admission
	sessions   *session.Issuer
	validation *valservice.ValidationService
	incidents  *incident.Service

	mu      sync.Mutex
	counter uint64
	flows   map[ids.SessionID]*Flow // live flows by session, for the incident invalidator
}

// NewAuthority wires the stage drivers. Every option but Intake, StopList
// and IDNonce is required.
func NewAuthority(opts AuthorityOptions) (*Authority, error) {
	switch {
	case opts.Clock == nil:
		return nil, missing("clock")
	case opts.Signer == nil:
		return nil, missing("signer")
	case opts.Sealer == nil:
		return nil, missing("sealer")
	case opts.Resolver == nil:
		return nil, missing("resolver")
	case opts.AuthorityKeyID.IsZero():
		return nil, missing("authority_key_id")
	case opts.RecipientKeyID.IsZero():
		return nil, missing("recipient_key_id")
	case opts.Audit == nil:
		return nil, missing("audit chain")
	case opts.AuditSigner == nil:
		return nil, missing("audit signer")
	case opts.AuditKeyID.IsZero():
		return nil, missing("audit_key_id")
	case opts.PolicyVersion.IsZero():
		return nil, missing("policy_version")
	case opts.Zeroizer == nil:
		return nil, missing("zeroizer")
	}
	nonce := opts.IDNonce
	if nonce == "" {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, shared_errors.Operational(shared_errors.CodeResourceExhausted, "orchestration: mint id nonce", err)
		}
		nonce = hex.EncodeToString(b[:])
	}
	a := &Authority{
		clock: opts.Clock, signer: opts.Signer, sealer: opts.Sealer, resolver: opts.Resolver,
		authorityKID: opts.AuthorityKeyID, recipientKID: opts.RecipientKeyID,
		chain: opts.Audit, auditSigner: opts.AuditSigner, auditKID: opts.AuditKeyID,
		policy: opts.PolicyVersion, nonce: nonce, flows: map[ids.SessionID]*Flow{},
	}
	var err error
	if a.intake, err = intake.New(opts.Clock, opts.Intake); err != nil {
		return nil, err
	}
	if a.trust, err = trust.NewAdmission(opts.Clock, opts.Signer, opts.AuthorityKeyID, trust.Options{
		Profiles: opts.Profiles, StopList: opts.StopList, IDPrefix: "att-" + nonce + "-",
	}); err != nil {
		return nil, err
	}
	if a.sessions, err = session.NewIssuer(opts.Clock, opts.Signer, opts.Resolver, opts.AuthorityKeyID, opts.PolicyVersion,
		session.Options{IDPrefix: "ses-" + nonce + "-"}); err != nil {
		return nil, err
	}
	if a.validation, err = valservice.NewValidationService(valservice.ServiceOptions{
		AuditChain: opts.Audit, AuditSigner: opts.AuditSigner, AuditKeyID: opts.AuditKeyID, Clock: opts.Clock,
		AuditIDPrefix: "rp-val-" + nonce + "-", ResultIDPrefix: "vr-" + nonce + "-",
	}); err != nil {
		return nil, err
	}
	if a.incidents, err = incident.NewService(incident.ServiceOptions{
		AuditChain: opts.Audit, AuditSigner: opts.AuditSigner, AuditKeyID: opts.AuditKeyID, Clock: opts.Clock,
		SessionInvalidator: incident.SessionInvalidatorFunc(a.invalidateSession),
		Zeroizer:           opts.Zeroizer,
		AuditIDPrefix:      "rp-inc-" + nonce + "-",
	}); err != nil {
		return nil, err
	}
	return a, nil
}

func missing(what string) error {
	return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "orchestration: "+what+" is required", nil)
}

// PolicyVersion is the policy every session is pinned to.
func (a *Authority) PolicyVersion() ids.PolicyVersion { return a.policy }

// MintRequestID names a request the caller did not name.
func MintRequestID() (ids.RequestID, error) {
	id, err := randomID("req-")
	return ids.RequestID(id), err
}

func randomID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", shared_errors.Operational(shared_errors.CodeResourceExhausted, "orchestration: mint id", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

// emit appends one of the Authority's own events. A chain that refuses
// it is the audit_unavailable error every stage stops on.
func (a *Authority) emit(kind audit_event.Kind, payload any, reqID ids.RequestID, sessID ids.SessionID, manID ids.ManifestID) (ids.AuditEventID, error) {
	raw, err := crypto.CanonicalJSON(payload)
	if err != nil {
		return "", shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "orchestration: encode audit payload", err)
	}
	a.mu.Lock()
	a.counter++
	id := ids.AuditEventID(fmt.Sprintf("rp-flow-%s-%016x", a.nonce, a.counter))
	a.mu.Unlock()
	sealed, err := a.chain.Append(audit_event.AuditEvent{
		SchemaVersion: audit_event.SchemaVersionCurrent,
		EventID:       id,
		Kind:          kind,
		OccurredAt:    a.clock.Now().UTC(),
		RequestID:     reqID,
		SessionID:     sessID,
		ManifestID:    manID,
		Payload:       raw,
		SigningKeyID:  a.auditKID,
	}, a.auditSigner)
	if err != nil {
		return "", shared_errors.Operational(CodeAuditUnavailable,
			fmt.Sprintf("orchestration: the audit log did not record %s; the decision is not taken", kind), err)
	}
	return sealed.EventID, nil
}

// invalidateSession is the incident service's seam: the issuer flips the
// session, and the invalidation goes on the record correlated to its flow.
func (a *Authority) invalidateSession(sid ids.SessionID, reason string) error {
	if _, err := a.sessions.Invalidate(sid); err != nil {
		return err
	}
	a.mu.Lock()
	f := a.flows[sid]
	a.mu.Unlock()
	var reqID ids.RequestID
	var manID ids.ManifestID
	if f != nil {
		reqID = f.request.RequestID
		if f.manifest != nil {
			manID = f.manifest.ManifestID
		}
	}
	_, err := a.emit(audit_event.KindSessionInvalidated, sessionInvalidatedPayload{
		Schema: AuditPayloadSchema, SessionID: sid, Reason: reason,
	}, reqID, sid, manID)
	return err
}

// ---- payloads ------------------------------------------------------------

type requestReceivedPayload struct {
	Schema            string            `json:"schema"`
	RequestID         ids.RequestID     `json:"request_id"`
	GenomeID          ids.GenomeID      `json:"genome_id"`
	PolicyProfile     string            `json:"policy_profile"`
	RequesterIdentity string            `json:"requester_identity"`
	Contour           map[string]string `json:"contour,omitempty"`
	Detail            json.RawMessage   `json:"detail,omitempty"`
}

type trustEvaluatedPayload struct {
	Schema             string            `json:"schema"`
	Outcome            string            `json:"outcome"`
	Reason             string            `json:"reason"`
	Detail             string            `json:"detail,omitempty"`
	AttestationID      ids.AttestationID `json:"attestation_id"`
	TTLSeconds         float64           `json:"ttl_seconds"`
	PeerProvider       string            `json:"peer_provider,omitempty"`
	PeerMeasurementHex string            `json:"peer_measurement_hex,omitempty"`
	// PeerDetail is what the peer's verifier said beyond the measurement
	// (the platform, the GPUs and their evaluations), when it had more.
	PeerDetail *tee.AttestationDetail `json:"peer_detail,omitempty"`
	RemoteAddr string                 `json:"remote_addr,omitempty"`
	EvidenceAt *time.Time             `json:"evidence_at,omitempty"`
	StopSerial uint64                 `json:"stop_serial,omitempty"`
}

type sessionIssuedPayload struct {
	Schema        string            `json:"schema"`
	SessionID     ids.SessionID     `json:"session_id"`
	GenomeID      ids.GenomeID      `json:"genome_id"`
	PolicyVersion ids.PolicyVersion `json:"policy_version"`
	IssuedAt      time.Time         `json:"issued_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
}

type manifestIssuedPayload struct {
	Schema                 string             `json:"schema"`
	ManifestID             ids.ManifestID     `json:"manifest_id"`
	GenomeID               ids.GenomeID       `json:"genome_id"`
	DisclosureIDs          []ids.DisclosureID `json:"disclosure_ids"`
	ExpectedOutputKind     string             `json:"expected_output_kind"`
	ExpectedOutputMaxBytes uint64             `json:"expected_output_max_bytes"`
	RecipientKeyID         ids.KeyID          `json:"recipient_key_id"`
	Deadline               time.Time          `json:"deadline"`
	Detail                 json.RawMessage    `json:"detail,omitempty"`
}

type candidateReceivedPayload struct {
	Schema             string          `json:"schema"`
	OutputKind         string          `json:"output_kind"`
	Bytes              int             `json:"bytes"`
	SHA256             string          `json:"sha256"`
	ProducedAt         time.Time       `json:"produced_at"`
	WorkerSigningKeyID string          `json:"worker_signing_key_id"`
	Detail             json.RawMessage `json:"detail,omitempty"`
}

type releaseDecidedPayload struct {
	Schema             string                 `json:"schema"`
	DecisionID         ids.DecisionID         `json:"decision_id"`
	Release            bool                   `json:"release"`
	Reason             string                 `json:"reason"`
	ValidationResultID ids.ValidationResultID `json:"validation_result_id,omitempty"`
	OverallVerdict     string                 `json:"overall_verdict,omitempty"`
	AttestationID      ids.AttestationID      `json:"attestation_id,omitempty"`
}

type sessionInvalidatedPayload struct {
	Schema    string        `json:"schema"`
	SessionID ids.SessionID `json:"session_id"`
	Reason    string        `json:"reason"`
}

type incidentDetectedPayload struct {
	Schema   string `json:"schema"`
	Scenario string `json:"scenario"`
	Severity string `json:"severity"`
	Stage    string `json:"stage"`
	Category string `json:"category"`
	Code     string `json:"code"`
	Reason   string `json:"reason"`
}

// ---- flow ----------------------------------------------------------------

// Flow is one request's passage through the nine stages.
type Flow struct {
	a       *Authority
	machine *Machine

	mu          sync.Mutex
	request     recovery_request.RecoveryRequest
	trust       *trust.Decision
	session     *session_object.SessionObject
	disclosures []disclosure_message.DisclosureMessage
	disclosureE []ids.AuditEventID
	manifest    *rjm.ReconstructionJobManifest
	candidate   *CandidateRecord
	validation  *validation_result.ValidationResult
	decision    *release_decision.ReleaseDecision
	incident    *incident.Result
	abort       *AbortRecord
	auditTip    []byte
	ended       bool
}

// CandidateRecord is what the Authority records about a candidate the
// Return Path accepted: never the bytes, only their digest.
type CandidateRecord struct {
	OutputKind         string          `json:"output_kind"`
	Bytes              int             `json:"bytes"`
	SHA256             string          `json:"sha256"`
	ProducedAt         time.Time       `json:"produced_at"`
	WorkerSigningKeyID string          `json:"worker_signing_key_id"`
	Detail             json.RawMessage `json:"detail,omitempty"`
}

// AbortRecord is why a flow ended before its decision.
type AbortRecord struct {
	Stage    string `json:"stage"`
	Category string `json:"category"`
	Code     string `json:"code"`
	Reason   string `json:"reason"`
	Incident bool   `json:"incident"` // an INCIDENT_DETECTED was recorded
}

// Intake is stage 1: the request is admitted, on the record, and the
// machine moves to trust. detail is the caller's own JSON for the
// REQUEST_RECEIVED payload (what the request names, in the caller's
// terms). A refused request leaves nothing behind.
func (a *Authority) Intake(req recovery_request.RecoveryRequest, detail json.RawMessage) (*Flow, error) {
	if err := a.intake.Admit(req); err != nil {
		return nil, err
	}
	if len(detail) > 0 && !json.Valid(detail) {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "orchestration: intake detail is not JSON", nil)
	}
	if _, err := a.emit(audit_event.KindRequestReceived, requestReceivedPayload{
		Schema: AuditPayloadSchema, RequestID: req.RequestID, GenomeID: req.GenomeID, PolicyProfile: req.PolicyProfile,
		RequesterIdentity: req.RequesterIdentity, Contour: req.Contour, Detail: detail,
	}, req.RequestID, "", ""); err != nil {
		return nil, err
	}
	f := &Flow{a: a, machine: NewMachine(), request: req}
	now := a.clock.Now()
	if _, err := f.machine.Advance(TriggerRequestReceived, now); err != nil {
		return nil, err
	}
	if _, err := f.machine.Advance(TriggerRequestValidated, now); err != nil {
		return nil, err
	}
	return f, nil
}

// Request is the request this flow serves.
func (f *Flow) Request() recovery_request.RecoveryRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.request
}

// State is where the flow is.
func (f *Flow) State() State { return f.machine.State() }

func (f *Flow) mustBe(s State) error {
	if f.ended {
		return shared_errors.Structural(CodeFlowEnded, "orchestration: the flow has ended", nil)
	}
	if got := f.machine.State(); got != s {
		return shared_errors.Structural(CodeIllegalTransition,
			fmt.Sprintf("orchestration: stage needs state %s, flow is at %s", s, got), nil)
	}
	return nil
}

// Admit is stage 2: trust is decided for the attested peer, on the record,
// and the machine moves to session (allow) or straight to release (deny).
// ttl is the attestation's time-to-live. The decision — signed either way —
// is returned; Allowed says which way.
func (f *Flow) Admit(peer trust.Peer, ttl time.Duration) (trust.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mustBe(StateTrust); err != nil {
		return trust.Decision{}, err
	}
	d, err := f.a.trust.Evaluate(f.request, peer, ttl)
	if err != nil {
		return trust.Decision{}, err
	}
	p := trustEvaluatedPayload{
		Schema: AuditPayloadSchema, Outcome: string(d.Result.Outcome), Reason: d.Reason, Detail: d.Detail,
		AttestationID: d.Result.AttestationID, TTLSeconds: d.Result.TTL.Seconds(), PeerProvider: string(d.PeerProvider),
		PeerMeasurementHex: d.PeerMeasurementHex, PeerDetail: d.PeerDetail, RemoteAddr: peer.RemoteAddr, StopSerial: d.StopSerial,
	}
	if !peer.EvidenceAt.IsZero() {
		at := peer.EvidenceAt.UTC()
		p.EvidenceAt = &at
	}
	if _, err := f.a.emit(audit_event.KindTrustEvaluated, p, f.request.RequestID, "", ""); err != nil {
		return trust.Decision{}, err
	}
	trigger := TriggerAttestationAllow
	if !d.Allowed {
		trigger = TriggerAttestationDeny
	}
	if _, err := f.machine.Advance(trigger, f.a.clock.Now()); err != nil {
		return trust.Decision{}, err
	}
	f.trust = &d
	return d, nil
}

// IssueSession is stage 3: a signed SessionObject bound to the request
// and the genome, expiring after ttl, on the record. The machine moves to
// disclosure.
func (f *Flow) IssueSession(ttl time.Duration) (session_object.SessionObject, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mustBe(StateSession); err != nil {
		return session_object.SessionObject{}, err
	}
	s, err := f.a.sessions.Issue(session.IssueParams{RequestID: f.request.RequestID, GenomeID: f.request.GenomeID, TTL: ttl})
	if err != nil {
		return session_object.SessionObject{}, err
	}
	if _, err := f.a.emit(audit_event.KindSessionIssued, sessionIssuedPayload{
		Schema: AuditPayloadSchema, SessionID: s.SessionID, GenomeID: s.GenomeID, PolicyVersion: s.PolicyVersion,
		IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt,
	}, f.request.RequestID, s.SessionID, ""); err != nil {
		return session_object.SessionObject{}, err
	}
	if _, err := f.machine.Advance(TriggerSessionIssued, f.a.clock.Now()); err != nil {
		return session_object.SessionObject{}, err
	}
	f.session = &s
	f.a.mu.Lock()
	f.a.flows[s.SessionID] = f
	f.a.mu.Unlock()
	return s, nil
}

// Component is one unit of the disclosure sequence: a named plaintext
// the worker needs. Plaintext is zeroized by Disclose.
type Component struct {
	ID        ids.ComponentID
	Plaintext []byte
}

// Disclose is stage 4: every component is sealed to the recipient key
// under the session, signed, and on the record (DISCLOSURE_AUTHORIZED
// before each message is surfaced), through the staged sequencer. The
// messages are returned in order; the machine stays at disclosure until
// the manifest is issued.
func (f *Flow) Disclose(components []Component) ([]disclosure_message.DisclosureMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mustBe(StateDisclosure); err != nil {
		return nil, err
	}
	if f.disclosures != nil {
		return nil, shared_errors.Structural(CodeIllegalTransition, "orchestration: the flow already disclosed", nil)
	}
	issuer, err := disclosure.NewStagedIssuer(f.a.clock, f.a.signer, f.a.sealer, f.a.resolver,
		f.a.authorityKID, f.a.recipientKID, *f.session, f.a.policy, disclosure.StagedOptions{IDPrefix: "disc-"})
	if err != nil {
		return nil, err
	}
	seq, err := disclosure.NewStagedSequencer(issuer, f.a.clock, disclosure.SequencerOptions{
		AuditSink: f.a.chain, AuditSigner: f.a.auditSigner, AuditKeyID: f.a.auditKID,
		AuditIDPrefix: "rp-disc-" + f.a.nonce + "-", FinalizeOnError: true,
	})
	if err != nil {
		return nil, err
	}
	run := make([]disclosure.Component, 0, len(components))
	for _, c := range components {
		run = append(run, disclosure.Component{ID: c.ID, Plaintext: c.Plaintext, RecipientKeyID: f.a.recipientKID})
	}
	res, err := seq.Run(run)
	if err != nil {
		if shared_errors.CodeOf(err) == "" || res == nil {
			return nil, err
		}
		return nil, err
	}
	f.disclosures = res.Messages
	f.disclosureE = res.AuditEventIDs
	return append([]disclosure_message.DisclosureMessage(nil), res.Messages...), nil
}

// ManifestParams is what a manifest says beyond what the flow knows.
type ManifestParams struct {
	OutputKind rjm.OutputKind
	// MaxBytes is the exact output budget.
	MaxBytes uint64
	Deadline time.Time
	// Detail is the caller's JSON for the MANIFEST_ISSUED payload.
	Detail json.RawMessage
}

// IssueManifest is stage 5: the signed ReconstructionJobManifest naming
// the disclosures, on the record. The machine moves to external compute:
// the manifest is issued to be dispatched at once.
func (f *Flow) IssueManifest(p ManifestParams) (rjm.ReconstructionJobManifest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mustBe(StateDisclosure); err != nil {
		return rjm.ReconstructionJobManifest{}, err
	}
	if len(f.disclosures) == 0 {
		return rjm.ReconstructionJobManifest{}, shared_errors.Structural(CodeIllegalTransition, "orchestration: nothing was disclosed", nil)
	}
	if len(p.Detail) > 0 && !json.Valid(p.Detail) {
		return rjm.ReconstructionJobManifest{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "orchestration: manifest detail is not JSON", nil)
	}
	id, err := randomID("rjm-")
	if err != nil {
		return rjm.ReconstructionJobManifest{}, err
	}
	discIDs := make([]ids.DisclosureID, 0, len(f.disclosures))
	for _, d := range f.disclosures {
		discIDs = append(discIDs, d.DisclosureID)
	}
	now := f.a.clock.Now().UTC()
	m := rjm.ReconstructionJobManifest{
		SchemaVersion:          rjm.SchemaVersionCurrent,
		ManifestID:             ids.ManifestID(id),
		SessionID:              f.session.SessionID,
		GenomeID:               f.request.GenomeID,
		PolicyVersion:          f.a.policy,
		DisclosureIDs:          discIDs,
		ExpectedOutputKind:     p.OutputKind,
		ExpectedOutputMaxBytes: p.MaxBytes,
		RecipientKeyID:         f.a.recipientKID,
		Deadline:               p.Deadline.UTC(),
		IssuedAt:               now,
		SigningKeyID:           f.a.authorityKID,
	}
	if err := m.SignWith(f.a.signer); err != nil {
		return rjm.ReconstructionJobManifest{}, err
	}
	if err := m.Validate(); err != nil {
		return rjm.ReconstructionJobManifest{}, err
	}
	if _, err := f.a.emit(audit_event.KindManifestIssued, manifestIssuedPayload{
		Schema: AuditPayloadSchema, ManifestID: m.ManifestID, GenomeID: m.GenomeID, DisclosureIDs: discIDs,
		ExpectedOutputKind: string(m.ExpectedOutputKind), ExpectedOutputMaxBytes: m.ExpectedOutputMaxBytes,
		RecipientKeyID: m.RecipientKeyID, Deadline: m.Deadline, Detail: p.Detail,
	}, f.request.RequestID, m.SessionID, m.ManifestID); err != nil {
		return rjm.ReconstructionJobManifest{}, err
	}
	if _, err := f.machine.Advance(TriggerManifestDispatched, f.a.clock.Now()); err != nil {
		return rjm.ReconstructionJobManifest{}, err
	}
	f.manifest = &m
	return m, nil
}

// CandidateReceived is stage 6: a candidate the Return Path accepted —
// bound to the manifest, within budget, signed by a registered worker —
// on the record before it is judged. The machine moves through return to
// validation.
func (f *Flow) CandidateReceived(c CandidateRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mustBe(StateExternalCompute); err != nil {
		return err
	}
	if len(c.Detail) > 0 && !json.Valid(c.Detail) {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "orchestration: candidate detail is not JSON", nil)
	}
	if _, err := f.a.emit(audit_event.KindCandidateReceived, candidateReceivedPayload{
		Schema: AuditPayloadSchema, OutputKind: c.OutputKind, Bytes: c.Bytes, SHA256: c.SHA256,
		ProducedAt: c.ProducedAt.UTC(), WorkerSigningKeyID: c.WorkerSigningKeyID, Detail: c.Detail,
	}, f.request.RequestID, f.session.SessionID, f.manifest.ManifestID); err != nil {
		return err
	}
	now := f.a.clock.Now()
	if _, err := f.machine.Advance(TriggerCandidateReceived, now); err != nil {
		return err
	}
	if _, err := f.machine.Advance(TriggerReturnAccepted, now); err != nil {
		return err
	}
	f.candidate = &c
	return nil
}

// ValidateParams is what the caller evaluated about the candidate: the
// semantic and behavioral verdicts of the gate that ran the model, and
// whether the wire signalled tamper.
type ValidateParams struct {
	Evaluated       map[validation_result.Dimension]valservice.EvaluatedDimension
	TamperSignalled bool
}

// Validate is stage 7: the validation service runs the six operational
// sub-checks over the flow's own artifacts, records the gate's semantic
// and behavioral verdicts, aggregates, and puts every event on the record
// before the result is surfaced. The machine moves to release whatever
// the verdict.
func (f *Flow) Validate(p ValidateParams) (validation_result.ValidationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mustBe(StateValidation); err != nil {
		return validation_result.ValidationResult{}, err
	}
	vr, err := f.a.validation.Validate(valservice.ValidateInputs{
		SessionID:  f.session.SessionID,
		ManifestID: f.manifest.ManifestID,
		Operational: operational.Inputs{
			Attestation:     f.trust.Result,
			Session:         *f.session,
			Manifest:        *f.manifest,
			ActivePolicy:    f.a.policy,
			TamperSignalled: p.TamperSignalled,
			Now:             f.a.clock.Now().UTC(),
			Resolver:        f.a.resolver,
		},
		Evaluated: p.Evaluated,
	})
	if err != nil {
		return validation_result.ValidationResult{}, err
	}
	if _, err := f.machine.Advance(TriggerValidationCompleted, f.a.clock.Now()); err != nil {
		return validation_result.ValidationResult{}, err
	}
	f.validation = vr
	return *vr, nil
}

// Decide is stage 8: the RELEASE_DECIDED event first, then the signed
// ReleaseDecision citing it — release on a passing validation, refusal
// on a failing one, refusal citing the attestation when trust denied.
// The machine moves to audit.
func (f *Flow) Decide() (release_decision.ReleaseDecision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mustBe(StateRelease); err != nil {
		return release_decision.ReleaseDecision{}, err
	}
	id, err := randomID("dec-")
	if err != nil {
		return release_decision.ReleaseDecision{}, err
	}
	d := release_decision.ReleaseDecision{
		SchemaVersion: release_decision.SchemaVersionCurrent,
		DecisionID:    ids.DecisionID(id),
		SigningKeyID:  f.a.authorityKID,
	}
	p := releaseDecidedPayload{Schema: AuditPayloadSchema, DecisionID: d.DecisionID}
	var sessID ids.SessionID
	var manID ids.ManifestID
	switch {
	case f.trust != nil && !f.trust.Allowed:
		d.Reason, d.Release, d.AttestationID = release_decision.ReasonTrustDenied, false, f.trust.Result.AttestationID
		p.AttestationID = d.AttestationID
	case f.validation != nil:
		d.SessionID, d.ManifestID, d.ValidationResultID = f.validation.SessionID, f.validation.ManifestID, f.validation.ValidationResultID
		d.AttestationID = f.trust.Result.AttestationID
		sessID, manID = d.SessionID, d.ManifestID
		p.ValidationResultID, p.OverallVerdict, p.AttestationID = d.ValidationResultID, string(f.validation.OverallVerdict), d.AttestationID
		switch f.validation.OverallVerdict {
		case validation_result.VerdictPass:
			d.Reason, d.Release = release_decision.ReasonValidationPass, true
		case validation_result.VerdictConditionalFail:
			d.Reason, d.Release = release_decision.ReasonConditionalFailRequiresReview, false
		default:
			d.Reason, d.Release = release_decision.ReasonValidationFail, false
		}
	default:
		return release_decision.ReleaseDecision{}, shared_errors.Structural(CodeIllegalTransition, "orchestration: nothing to decide on", nil)
	}
	p.Release, p.Reason = d.Release, string(d.Reason)
	evt, err := f.a.emit(audit_event.KindReleaseDecided, p, f.request.RequestID, sessID, manID)
	if err != nil {
		return release_decision.ReleaseDecision{}, err
	}
	d.AuditEventID = evt
	d.DecidedAt = f.a.clock.Now().UTC()
	if err := d.SignWith(f.a.signer); err != nil {
		return release_decision.ReleaseDecision{}, err
	}
	if err := d.Validate(); err != nil {
		return release_decision.ReleaseDecision{}, err
	}
	if _, err := f.machine.Advance(TriggerDecisionSigned, f.a.clock.Now()); err != nil {
		return release_decision.ReleaseDecision{}, err
	}
	f.decision = &d
	return d, nil
}

// Seal is stage 9: the audit chain's tip after the decision is the
// flow's seal. A refusal after validation is the R-15 validation-hard-fail
// incident: INCIDENT_DETECTED, the session invalidated (on the record),
// INCIDENT_TERMINATED. The machine reaches its terminal state.
func (f *Flow) Seal() (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.mustBe(StateAudit); err != nil {
		return f.machine.State(), err
	}
	if f.decision.Release {
		f.finish()
		return f.machine.Advance(TriggerAuditSealedRelease, f.a.clock.Now())
	}
	if f.session != nil && f.validation != nil {
		code := string(f.decision.Reason)
		if fd := firstFinding(f.validation); fd != nil {
			code = fd.Code
		}
		res, err := f.a.incidents.HandleValidationHardFail(incident.Trigger{
			SessionID:  f.session.SessionID,
			ManifestID: f.manifest.ManifestID,
			Code:       code,
			Detail:     "release refused: " + string(f.decision.Reason),
		})
		if err != nil {
			return f.machine.State(), shared_errors.Operational(CodeAuditUnavailable, "orchestration: the incident was not recorded", err)
		}
		f.incident = res
	}
	f.finish()
	return f.machine.Advance(TriggerAuditSealedRefusal, f.a.clock.Now())
}

// finish takes the chain tip and releases the flow's session registration.
// Called under f.mu.
func (f *Flow) finish() {
	f.auditTip = f.a.chain.Tip()
	f.ended = true
	if f.session != nil {
		f.a.mu.Lock()
		delete(f.a.flows, f.session.SessionID)
		f.a.mu.Unlock()
	}
}

// Abort ends a flow that cannot reach its decision: stage names where,
// err says why. An Integrity or Incident failure is recorded as
// INCIDENT_DETECTED; a session, if one was issued, is invalidated on the
// record; the machine terminates on incident.detected. The returned error
// is an audit failure only — the abort itself is not refused.
func (f *Flow) Abort(stage string, err error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended {
		return nil
	}
	rec := AbortRecord{Stage: stage, Category: shared_errors.CategoryOf(err).String(), Code: shared_errors.CodeOf(err), Reason: err.Error()}
	var sessID ids.SessionID
	var manID ids.ManifestID
	if f.session != nil {
		sessID = f.session.SessionID
	}
	if f.manifest != nil {
		manID = f.manifest.ManifestID
	}
	var auditErr error
	switch shared_errors.CategoryOf(err) {
	case shared_errors.CategoryIntegrity, shared_errors.CategoryIncident:
		rec.Incident = true
		if _, e := f.a.emit(audit_event.KindIncidentDetected, incidentDetectedPayload{
			Schema: AuditPayloadSchema, Scenario: "return_path_failure", Severity: "error", Stage: stage,
			Category: rec.Category, Code: rec.Code, Reason: rec.Reason,
		}, f.request.RequestID, sessID, manID); e != nil {
			auditErr = e
		}
	}
	if f.session != nil {
		if e := f.a.invalidateSession(f.session.SessionID, "aborted at "+stage+": "+rec.Code); e != nil && auditErr == nil {
			auditErr = e
		}
	}
	f.abort = &rec
	f.finish()
	if !f.machine.State().IsTerminal() {
		if _, e := f.machine.Advance(TriggerIncidentDetected, f.a.clock.Now()); e != nil && auditErr == nil {
			auditErr = e
		}
	}
	return auditErr
}

func firstFinding(vr *validation_result.ValidationResult) *validation_result.Finding {
	for _, dim := range []validation_result.Dimension{validation_result.DimensionOperational, validation_result.DimensionSemantic, validation_result.DimensionBehavioral} {
		if dv, ok := vr.Dimensions[dim]; ok && len(dv.Details) > 0 {
			fd := dv.Details[0]
			return &fd
		}
	}
	return nil
}

// ---- view ----------------------------------------------------------------

// DisclosureView is a disclosure as the flow shows it: the envelope's
// identity and a digest of the sealed payload, never the payload.
type DisclosureView struct {
	DisclosureID  ids.DisclosureID `json:"disclosure_id"`
	ComponentID   ids.ComponentID  `json:"component_id"`
	SequenceIndex uint32           `json:"sequence_index"`
	PayloadSHA256 string           `json:"payload_sha256"`
	AuthorizedAt  time.Time        `json:"authorized_at"`
	AuditEventID  ids.AuditEventID `json:"audit_event_id,omitempty"`
}

// IncidentView is an incident the flow ended on.
type IncidentView struct {
	Scenario           string           `json:"scenario"`
	Severity           string           `json:"severity"`
	SessionInvalidated bool             `json:"session_invalidated"`
	DetectedEventID    ids.AuditEventID `json:"detected_event_id"`
	TerminatedEventID  ids.AuditEventID `json:"terminated_event_id"`
}

// View is a snapshot of the flow: its state, every transition taken, and
// every authority artifact it produced, signed, for an operator to verify
// offline.
type View struct {
	State       State                                 `json:"state"`
	Steps       []Step                                `json:"steps"`
	Request     recovery_request.RecoveryRequest      `json:"request"`
	Attestation *attestation_result.AttestationResult `json:"attestation,omitempty"`
	Session     *session_object.SessionObject         `json:"session,omitempty"`
	Disclosures []DisclosureView                      `json:"disclosures,omitempty"`
	Manifest    *rjm.ReconstructionJobManifest        `json:"manifest,omitempty"`
	Candidate   *CandidateRecord                      `json:"candidate,omitempty"`
	Validation  *validation_result.ValidationResult   `json:"validation,omitempty"`
	Decision    *release_decision.ReleaseDecision     `json:"decision,omitempty"`
	Incident    *IncidentView                         `json:"incident,omitempty"`
	Abort       *AbortRecord                          `json:"abort,omitempty"`
	AuditTip    string                                `json:"audit_tip,omitempty"`
}

// Snapshot renders the flow now.
func (f *Flow) Snapshot() View {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := View{State: f.machine.State(), Steps: f.machine.Steps(), Request: f.request}
	if f.trust != nil {
		att := f.trust.Result
		v.Attestation = &att
	}
	if f.session != nil {
		// The stored record may have been invalidated since issuance.
		s := *f.session
		if cur, ok := f.a.sessions.Lookup(s.SessionID); ok {
			s = cur
		}
		v.Session = &s
	}
	for i, d := range f.disclosures {
		dv := DisclosureView{DisclosureID: d.DisclosureID, ComponentID: d.ComponentID, SequenceIndex: d.SequenceIndex,
			PayloadSHA256: hex.EncodeToString(crypto.SHA256Slice(d.SealedPayload)), AuthorizedAt: d.AuthorizedAt}
		if i < len(f.disclosureE) {
			dv.AuditEventID = f.disclosureE[i]
		}
		v.Disclosures = append(v.Disclosures, dv)
	}
	if f.manifest != nil {
		m := *f.manifest
		v.Manifest = &m
	}
	if f.candidate != nil {
		c := *f.candidate
		v.Candidate = &c
	}
	if f.validation != nil {
		vr := *f.validation
		v.Validation = &vr
	}
	if f.decision != nil {
		d := *f.decision
		v.Decision = &d
	}
	if f.incident != nil {
		v.Incident = &IncidentView{Scenario: f.incident.Scenario.String(), Severity: f.incident.Severity.String(),
			SessionInvalidated: f.incident.SessionInvalidated, DetectedEventID: f.incident.DetectedEventID, TerminatedEventID: f.incident.TerminatedEventID}
	}
	if f.abort != nil {
		a := *f.abort
		v.Abort = &a
	}
	if len(f.auditTip) > 0 {
		v.AuditTip = hex.EncodeToString(f.auditTip)
	}
	return v
}

// SessionID is the flow's session, empty before one is issued.
func (f *Flow) SessionID() ids.SessionID {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.session == nil {
		return ""
	}
	return f.session.SessionID
}

// ManifestID is the flow's manifest, empty before one is issued.
func (f *Flow) ManifestID() ids.ManifestID {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.manifest == nil {
		return ""
	}
	return f.manifest.ManifestID
}

// Decision is the flow's decision, nil before one.
func (f *Flow) Decision() *release_decision.ReleaseDecision {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.decision == nil {
		return nil
	}
	d := *f.decision
	return &d
}

// Ended reports whether the flow is over (sealed or aborted).
func (f *Flow) Ended() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ended
}
