// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Default values used when Options leaves them unset.
const (
	DefaultTTL      = 5 * time.Minute
	DefaultIDPrefix = "sess-"
)

// Options configures an Issuer. Zero values fall back to package defaults.
type Options struct {
	// DefaultTTL is applied when IssueParams.TTL is 0. Defaults to
	// DefaultTTL (5m). Must be > 0 if set.
	DefaultTTL time.Duration

	// IDPrefix is prepended to the monotonic counter when generating
	// SessionIDs. Defaults to "sess-". Useful in tests for deterministic
	// prefixes per issuer.
	IDPrefix string
}

// Issuer issues, tracks, and invalidates TrustedSessions.
//
// # Doctrinal role
//
// /internal/vault/session is the authority that owns SessionObject
// lifecycle. Callers (Trust Admission on allow; Incident on tamper signal)
// delegate to the Issuer — they do not mutate SessionObjects directly.
//
// The Issuer is intentionally not a persistence layer: it keeps sessions
// in memory keyed by SessionID. Production would back this with bbolt
// sealed under the TEE's sealing key behind the same interface.
//
// Concurrency: all public methods hold a single mutex. Fine-grained locking
// is an optimization we're not buying yet.
type Issuer struct {
	mu sync.Mutex

	clock        shared_time.Clock
	signer       keys.Signer
	resolver     keys.Resolver
	signingKID   ids.KeyID
	activePolicy ids.PolicyVersion

	defaultTTL time.Duration
	idPrefix   string
	counter    uint64

	sessions map[ids.SessionID]session_object.SessionObject
}

// NewIssuer constructs an Issuer that signs with signingKID (which must be
// registered in signer under PurposeSigningAuthority) and pins activePolicy
// into every issued session. resolver is used by Verify for signature
// checks. clock is the monotonic time source.
//
// All of signer, resolver, clock must be non-nil; signingKID must be
// non-zero; activePolicy must be non-zero. These are invariants of the
// vault; violating them is a programming bug, not a runtime condition,
// and is surfaced as a structural error.
func NewIssuer(
	clock shared_time.Clock,
	signer keys.Signer,
	resolver keys.Resolver,
	signingKID ids.KeyID,
	activePolicy ids.PolicyVersion,
	opts Options,
) (*Issuer, error) {
	if clock == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: clock is required",
			nil,
		)
	}
	if signer == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: signer is required",
			nil,
		)
	}
	if resolver == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: resolver is required",
			nil,
		)
	}
	if signingKID.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: signing_key_id is required",
			nil,
		)
	}
	if activePolicy.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: active policy_version is required",
			nil,
		)
	}

	ttl := opts.DefaultTTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl <= 0 {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"vault/session: DefaultTTL must be positive",
			nil,
		)
	}

	prefix := opts.IDPrefix
	if prefix == "" {
		prefix = DefaultIDPrefix
	}

	return &Issuer{
		clock:        clock,
		signer:       signer,
		resolver:     resolver,
		signingKID:   signingKID,
		activePolicy: activePolicy,
		defaultTTL:   ttl,
		idPrefix:     prefix,
		sessions:     make(map[ids.SessionID]session_object.SessionObject),
	}, nil
}

// ActivePolicy returns the policy_version this Issuer pins into new
// sessions. Exposed for validators and audit emitters.
func (iss *Issuer) ActivePolicy() ids.PolicyVersion {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	return iss.activePolicy
}

// RotatePolicy swaps the active policy_version. Existing sessions are
// NOT re-issued or invalidated here — CheckPolicyAlignment will flag
// them at validation time, and the caller is responsible for deciding
// whether to invalidate in bulk.
func (iss *Issuer) RotatePolicy(next ids.PolicyVersion) error {
	if next.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: next policy_version must be non-zero",
			nil,
		)
	}
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.activePolicy = next
	return nil
}

// IssueParams bundles the caller-supplied inputs for a fresh session.
// PolicyVersion and SigningKeyID are not accepted here — they are
// authority concerns owned by the Issuer.
type IssueParams struct {
	// RequestID correlates the session back to the originating
	// RecoveryRequest. Required.
	RequestID ids.RequestID
	// GenomeID names the AI Genome the session will address. Required.
	GenomeID ids.GenomeID
	// TTL controls ExpiresAt = IssuedAt + TTL. Zero uses the Issuer's
	// DefaultTTL. Negative TTL is rejected.
	TTL time.Duration
}

// Issue produces a signed SessionObject bound to p.RequestID / p.GenomeID
// / the Issuer's active policy, with a freshly generated SessionID.
// The session is stored in the Issuer's in-memory map so subsequent
// Lookup/Invalidate can find it.
//
// The returned SessionObject is a defensive copy — mutating it does not
// affect the Issuer's stored record.
func (iss *Issuer) Issue(p IssueParams) (session_object.SessionObject, error) {
	if p.RequestID.IsZero() {
		return session_object.SessionObject{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: request_id required",
			nil,
		)
	}
	if p.GenomeID.IsZero() {
		return session_object.SessionObject{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: genome_id required",
			nil,
		)
	}
	if p.TTL < 0 {
		return session_object.SessionObject{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"vault/session: TTL must not be negative",
			nil,
		)
	}

	iss.mu.Lock()
	defer iss.mu.Unlock()

	ttl := p.TTL
	if ttl == 0 {
		ttl = iss.defaultTTL
	}

	now := iss.clock.Now().UTC()
	iss.counter++
	sid := ids.SessionID(fmt.Sprintf("%s%016d", iss.idPrefix, iss.counter))

	s := session_object.SessionObject{
		SchemaVersion: session_object.SchemaVersionCurrent,
		SessionID:     sid,
		RequestID:     p.RequestID,
		GenomeID:      p.GenomeID,
		PolicyVersion: iss.activePolicy,
		IssuedAt:      now,
		ExpiresAt:     now.Add(ttl),
		State:         session_object.StateActive,
		SigningKeyID:  iss.signingKID,
	}
	if err := s.SignWith(iss.signer); err != nil {
		return session_object.SessionObject{}, err
	}
	// Post-condition: session is now a well-formed, validatable record.
	if err := s.Validate(); err != nil {
		return session_object.SessionObject{}, err
	}

	iss.sessions[sid] = s
	return s, nil
}

// Lookup returns a copy of the stored session by ID. The bool is false
// if the session is unknown.
func (iss *Issuer) Lookup(sid ids.SessionID) (session_object.SessionObject, bool) {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	s, ok := iss.sessions[sid]
	return s, ok
}

// Invalidate transitions the named session to StateInvalidated and
// re-signs it. The re-signed SessionObject replaces the stored record
// and is returned.
//
// Invalidation is idempotent: invalidating an already-invalidated session
// is a no-op that returns the stored (already invalidated) record without
// re-signing. This keeps incident handlers free to fire more than once
// without producing chains of indistinguishable signed objects.
//
// An unknown session returns an authority-classified error: invalidating
// something the vault never issued is a contract violation by the caller.
func (iss *Issuer) Invalidate(sid ids.SessionID) (session_object.SessionObject, error) {
	iss.mu.Lock()
	defer iss.mu.Unlock()

	s, ok := iss.sessions[sid]
	if !ok {
		return session_object.SessionObject{}, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			"vault/session: unknown session_id",
			nil,
		)
	}
	if s.State == session_object.StateInvalidated {
		return s, nil
	}

	s.State = session_object.StateInvalidated
	s.Signature = nil
	if err := s.SignWith(iss.signer); err != nil {
		return session_object.SessionObject{}, err
	}
	if err := s.Validate(); err != nil {
		return session_object.SessionObject{}, err
	}

	iss.sessions[sid] = s
	return s, nil
}

// Verify runs the full set of runtime checks on s:
//
//  1. Static Validate().
//  2. Signature verification under PurposeSigningAuthority through the
//     Issuer's resolver.
//  3. State == active (anything else is a rejection — expired / suspended
//     / invalidated sessions have no authority).
//  4. ExpiresAt > clock.Now() (otherwise the session is expired regardless
//     of its stored State).
//
// A session that passes Verify is currently authoritative. A failure is
// classified per the first failed check: Structural for malformed input,
// Integrity for bad signature, Authority for expired/invalidated.
//
// Verify intentionally does NOT consult the Issuer's internal map — it
// verifies the object as-presented. An active session held by a caller
// may still pass Verify even if the vault has since invalidated the
// stored copy (because the caller is holding an older signed snapshot);
// deciding what to do with that divergence is an operational concern for
// the validator.
func (iss *Issuer) Verify(s session_object.SessionObject) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := s.VerifySignature(iss.resolver); err != nil {
		return err
	}
	if s.State != session_object.StateActive {
		return shared_errors.Authority(
			shared_errors.CodeSessionInvalidated,
			"vault/session: state is not 'active': "+string(s.State),
			nil,
		)
	}
	now := iss.clock.Now()
	if !now.Before(s.ExpiresAt) {
		return shared_errors.Authority(
			shared_errors.CodeSessionExpired,
			"vault/session: session expired at "+s.ExpiresAt.UTC().Format(time.RFC3339Nano),
			nil,
		)
	}
	return nil
}

// Count returns the number of sessions in the Issuer's in-memory store.
// Primarily for tests and metrics.
func (iss *Issuer) Count() int {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	return len(iss.sessions)
}
