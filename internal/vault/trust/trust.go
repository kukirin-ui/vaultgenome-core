// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// Reasons an AttestationResult carries. They are stable strings auditors
// key off: the allow reason names the attested peer's TEE family; each
// deny reason names the policy that refused.
const (
	ReasonPeerAttested = "trust.peer_attested"

	ReasonOperatorStop       = "trust.operator_stop"
	ReasonMeasurementRevoked = "trust.measurement_revoked"
	ReasonProfileNotServed   = "trust.policy_profile_not_served"
	ReasonPeerMissing        = "trust.peer_missing"
)

// CodeStopListUnavailable (Operational): the operator's stop list could
// not be read or did not verify, so trust could not be decided. Nothing
// is admitted while it lasts.
const CodeStopListUnavailable = "trust.stop_list_unavailable"

// DefaultIDPrefix prefixes minted AttestationIDs.
const DefaultIDPrefix = "att-"

// Peer is the compute party whose Evidence the vault verified on the
// Return Path handshake: the one that would receive the disclosures.
type Peer struct {
	Provider    tee.Provider
	Measurement []byte
	RemoteAddr  string
	// EvidenceAt is when the peer's Evidence was verified (the session's
	// ReadyAt). Recorded in the decision; staleness is the caller's
	// pre-check (a stale session is closed, not admitted).
	EvidenceAt time.Time
	// Detail is what the verifier said beyond the measurement, carried
	// onto the decision's audit record; nil when there was nothing more.
	Detail *tee.AttestationDetail
}

// StopListSource returns the operator's current stop list (ADR 0010).
// A nil source means no operator stop is configured.
type StopListSource func() (revocation.List, error)

// Options configures an Admission.
type Options struct {
	// Profiles are the policy profiles this vault serves. A request
	// naming another profile is denied. Required non-empty.
	Profiles []string
	// StopList, when set, is consulted on every admission: a stop-all
	// list denies every request; a list revoking the peer's measurement
	// denies that peer.
	StopList StopListSource
	// IDPrefix prefixes minted AttestationIDs. Default "att-".
	IDPrefix string
	// DefaultTTL is the attestation's time-to-live when Evaluate is
	// given none. Default attestation_result.DefaultTTL.
	DefaultTTL time.Duration
}

// Admission is Trust Admission — stage 2 of the nine-stage flow. It
// consumes the request's policy profile and the attested peer, consults
// the operator's stop list, and produces a signed AttestationResult:
// allow, or deny with the reason on record. Trust is a gate, not a log:
// a deny short-circuits the flow at the state machine.
type Admission struct {
	mu sync.Mutex

	clock      shared_time.Clock
	signer     keys.Signer
	signingKID ids.KeyID
	profiles   map[string]struct{}
	stopList   StopListSource
	idPrefix   string
	defaultTTL time.Duration
	counter    uint64
}

// NewAdmission builds an Admission signing with signingKID (registered in
// signer under PurposeSigningAuthority).
func NewAdmission(clock shared_time.Clock, signer keys.Signer, signingKID ids.KeyID, opts Options) (*Admission, error) {
	if clock == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "vault/trust: clock is required", nil)
	}
	if signer == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "vault/trust: signer is required", nil)
	}
	if signingKID.IsZero() {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "vault/trust: signing_key_id is required", nil)
	}
	if len(opts.Profiles) == 0 {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "vault/trust: at least one served policy profile is required", nil)
	}
	profiles := make(map[string]struct{}, len(opts.Profiles))
	for _, p := range opts.Profiles {
		if p == "" {
			return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "vault/trust: an empty policy profile cannot be served", nil)
		}
		profiles[p] = struct{}{}
	}
	prefix := opts.IDPrefix
	if prefix == "" {
		prefix = DefaultIDPrefix
	}
	ttl := opts.DefaultTTL
	if ttl == 0 {
		ttl = attestation_result.DefaultTTL
	}
	if ttl < 0 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "vault/trust: default TTL must be positive", nil)
	}
	return &Admission{
		clock: clock, signer: signer, signingKID: signingKID, profiles: profiles,
		stopList: opts.StopList, idPrefix: prefix, defaultTTL: ttl,
	}, nil
}

// Decision is one trust admission: the signed AttestationResult and what
// an audit payload needs to say about it.
type Decision struct {
	Result attestation_result.AttestationResult
	// Allowed is Result.Outcome == allow.
	Allowed bool
	// Reason is the Reason constant that decided it.
	Reason string
	// Detail is the human-readable explanation (the stop list's own words,
	// the profile named, ...).
	Detail string
	// StopSerial is the serial of the stop list consulted, 0 without one.
	StopSerial uint64
	// PeerProvider and PeerMeasurementHex name the attested peer;
	// PeerDetail is what its verifier said beyond the measurement.
	PeerProvider       tee.Provider
	PeerMeasurementHex string
	PeerDetail         *tee.AttestationDetail
}

// Evaluate decides trust for req against peer. ttl is the attestation's
// time-to-live; 0 takes the default. The AttestationResult is signed and
// validated before it is returned; a deny carries its reason. An error
// means no decision could be taken (a malformed request, a stop list that
// could not be read, a signing failure).
func (a *Admission) Evaluate(req recovery_request.RecoveryRequest, peer Peer, ttl time.Duration) (Decision, error) {
	if err := req.Validate(); err != nil {
		return Decision{}, err
	}
	if ttl == 0 {
		ttl = a.defaultTTL
	}
	if ttl <= 0 {
		return Decision{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "vault/trust: ttl must be positive", nil)
	}

	d := Decision{PeerProvider: peer.Provider, PeerMeasurementHex: hex.EncodeToString(peer.Measurement), PeerDetail: peer.Detail}
	outcome := attestation_result.OutcomeAllow
	switch {
	case len(peer.Measurement) == 0:
		outcome, d.Reason, d.Detail = attestation_result.OutcomeDeny, ReasonPeerMissing, "no attested peer: the Return Path session carries no measurement"
	case a.stopList != nil:
		list, err := a.stopList()
		if err != nil {
			return Decision{}, shared_errors.Operational(CodeStopListUnavailable,
				"vault/trust: the operator's stop list could not be consulted; nothing is admitted", err)
		}
		d.StopSerial = list.Serial
		if denied, why := list.Denies(peer.Provider, peer.Measurement); denied {
			outcome, d.Detail = attestation_result.OutcomeDeny, why
			d.Reason = ReasonMeasurementRevoked
			if list.StopAll {
				d.Reason = ReasonOperatorStop
			}
		}
	}
	if outcome == attestation_result.OutcomeAllow {
		if _, served := a.profiles[req.PolicyProfile]; !served {
			outcome, d.Reason = attestation_result.OutcomeDeny, ReasonProfileNotServed
			d.Detail = fmt.Sprintf("policy profile %q is not served by this vault", req.PolicyProfile)
		}
	}
	if outcome == attestation_result.OutcomeAllow {
		d.Reason = ReasonPeerAttested
		d.Detail = fmt.Sprintf("peer attested with %s, measurement %s", peer.Provider, d.PeerMeasurementHex)
	}

	a.mu.Lock()
	a.counter++
	id := ids.AttestationID(fmt.Sprintf("%s%016x", a.idPrefix, a.counter))
	a.mu.Unlock()

	res := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: id,
		RequestID:     req.RequestID,
		Outcome:       outcome,
		Reason:        d.Reason,
		IssuedAt:      a.clock.Now().UTC(),
		TTL:           ttl,
		SigningKeyID:  a.signingKID,
	}
	if err := res.SignWith(a.signer); err != nil {
		return Decision{}, err
	}
	if err := res.Validate(); err != nil {
		return Decision{}, err
	}
	d.Result = res
	d.Allowed = outcome == attestation_result.OutcomeAllow
	return d, nil
}
