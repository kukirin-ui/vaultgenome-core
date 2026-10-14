// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure

import (
	"encoding/hex"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// DefaultStagedIDPrefix is prepended to a monotonic counter when a
// StagedIssuer generates a DisclosureID. Production deployments may
// override to embed a deployment tag (e.g. "disc-eu1-").
const DefaultStagedIDPrefix = "disc-"

// StagedOptions configures a StagedIssuer. Zero values fall back to
// package defaults.
type StagedOptions struct {
	// IDPrefix is prepended to the monotonic counter when generating
	// DisclosureIDs. Defaults to DefaultStagedIDPrefix ("disc-").
	IDPrefix string
}

// StagedIssuer is the release-side operator that emits a MONOTONIC
// sequence of sealed DisclosureMessages for one TrustedSession.
//
// # Doctrinal role
//
// Staged disclosure is the rule: the full AI Genome is NEVER
// reassembled in one place. Every component emission carries its own
// DisclosureMessage, each one:
//
//   - numbered with a monotonic SequenceIndex (no gaps, no reuse),
//   - pinned to the session's PolicyVersion at issuance time,
//   - AES-256-GCM sealed under a session-scoped sealing key,
//   - authority-signed over the envelope metadata,
//   - audit-bound (every emission is one entry the audit chain can cite).
//
// The StagedIssuer REFUSES to authorize an emission if the active
// platform policy has drifted from the session's pinned
// PolicyVersion. This is the doctrinal "no policy drift past a live
// session" invariant — see docs/doctrine/open-decisions-resolved.md R-7.
//
// No plaintext genome bytes leave this package except through the
// GCM sealing function. The input plaintext slice is zeroized in
// place before Emit returns. Callers that want to zero it themselves
// remain free to do so — the extra pass here is defense in depth,
// not a replacement for caller discipline.
//
// Corresponds to P3 §[0018]. Canonical term: "Staged Disclosure" —
// docs/doctrine/terminology.md §3.
//
// # Concurrency
//
// All public methods hold a single mutex. Sequence-index monotonicity
// is the correctness property the lock protects; nothing about this
// implementation is performance-critical at the lock level.
type StagedIssuer struct {
	mu sync.Mutex

	clock    shared_time.Clock
	signer   keys.Signer
	sealer   keys.Sealer
	resolver keys.Resolver

	signingKID ids.KeyID
	sealingKID ids.KeyID

	session      session_object.SessionObject
	activePolicy ids.PolicyVersion

	idPrefix  string
	counter   uint32 // 0-based monotonic sequence index (next to issue)
	finalized bool   // set by Finalize; subsequent Emit refused
}

// NewStagedIssuer constructs a StagedIssuer bound to one session,
// one sealing key, and one signing authority key. The active policy
// is captured at construction time; it must match session.PolicyVersion
// or construction is refused — the whole point of Staged Disclosure
// is that a session is NEVER run under a policy different from the
// one it was issued under.
//
// session MUST be Active. Sessions in any other state (suspended,
// invalidated, expired) are not valid bases for disclosure — refused
// here with Authority classification.
//
// All of clock, signer, sealer, resolver are required and must be
// non-nil; signingKID and sealingKID must be non-zero. activePolicy
// must be non-zero and equal session.PolicyVersion.
func NewStagedIssuer(
	clock shared_time.Clock,
	signer keys.Signer,
	sealer keys.Sealer,
	resolver keys.Resolver,
	signingKID ids.KeyID,
	sealingKID ids.KeyID,
	session session_object.SessionObject,
	activePolicy ids.PolicyVersion,
	opts StagedOptions,
) (*StagedIssuer, error) {
	if clock == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: clock is required",
			nil,
		)
	}
	if signer == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: signer is required",
			nil,
		)
	}
	if sealer == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: sealer is required",
			nil,
		)
	}
	if resolver == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: resolver is required",
			nil,
		)
	}
	if signingKID.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: signing_key_id is required",
			nil,
		)
	}
	if sealingKID.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: sealing_key_id is required",
			nil,
		)
	}
	if activePolicy.IsZero() {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: active policy_version is required",
			nil,
		)
	}

	// Validate the session statically. Signature check is a separate
	// concern — the caller holds the session within its trust
	// boundary and is responsible for having verified it at admission.
	// We refuse here only on fields the authority cannot reason about
	// without the stored session.
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if session.State != session_object.StateActive {
		return nil, shared_errors.Authority(
			shared_errors.CodeSessionInvalidated,
			"staged_disclosure: session state is not 'active': "+string(session.State),
			nil,
		)
	}
	if session.PolicyVersion != activePolicy {
		return nil, shared_errors.Authority(
			shared_errors.CodePolicyDrifted,
			"staged_disclosure: active policy_version does not match session.policy_version",
			nil,
		)
	}

	prefix := opts.IDPrefix
	if prefix == "" {
		prefix = DefaultStagedIDPrefix
	}

	return &StagedIssuer{
		clock:        clock,
		signer:       signer,
		sealer:       sealer,
		resolver:     resolver,
		signingKID:   signingKID,
		sealingKID:   sealingKID,
		session:      session,
		activePolicy: activePolicy,
		idPrefix:     prefix,
	}, nil
}

// EmitParams bundles one component-emission request. Plaintext is the
// only plaintext surface in the entire Staged Disclosure API — it
// flows from caller → Seal → DisclosureMessage.SealedPayload → wire.
// Nothing else reads it. The slice is ZEROIZED IN PLACE before Emit
// returns, regardless of outcome.
type EmitParams struct {
	// ComponentID names the component being released. The pairing
	// (SessionID, ComponentID, SequenceIndex) must be unique across
	// the entire disclosure timeline — the vault's audit log relies
	// on this for replay-resistance.
	ComponentID ids.ComponentID

	// Plaintext is the raw component material. REQUIRED non-empty.
	// Zeroized in place before Emit returns (both happy and error
	// paths). Callers that need the bytes for further use should
	// copy before calling Emit.
	Plaintext []byte

	// RecipientKeyID identifies the external-compute binding key.
	// The sealed ciphertext is protected against any principal that
	// does not hold the private half of this key. REQUIRED non-zero.
	RecipientKeyID ids.KeyID
}

// Emit produces one signed, sealed DisclosureMessage and bumps the
// sequence counter. On any error, no message is emitted and the
// counter does NOT advance — this preserves the "no gaps" invariant.
//
// Plaintext zeroization is unconditional: whether Emit returns a
// message or an error, p.Plaintext is overwritten with zeros before
// return.
//
// Refusal cases (in order, first-match):
//
//  1. issuer finalized → Operational.
//  2. params missing / malformed → Structural.
//  3. session expired (clock-based) → Authority.
//  4. session.policy_version drifted from issuer.activePolicy → Authority,
//     CodePolicyDrifted. This is the invariant that makes Staged
//     Disclosure safe under policy rotation: a pinned session cannot
//     be continued past its policy.
//  5. sealing / signing / canonicalization failure → propagated as-is.
func (s *StagedIssuer) Emit(p EmitParams) (*disclosure_message.DisclosureMessage, error) {
	// Guarantee zeroization of the input plaintext no matter how we
	// exit this function. This is defense in depth — the caller
	// should also zero after their own bookkeeping.
	defer zeroBytes(p.Plaintext)

	if err := validateEmitParams(p); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.finalized {
		return nil, shared_errors.Operational(
			shared_errors.CodeIssuerFinalized,
			"staged_disclosure: issuer is finalized; no further emissions",
			nil,
		)
	}

	now := s.clock.Now().UTC()

	// Session expiry check — we don't re-verify the signature here
	// (constructor owned that) but we DO enforce TTL against the
	// current clock. A session expiring mid-sequence must halt
	// further emissions.
	if !now.Before(s.session.ExpiresAt) {
		return nil, shared_errors.Authority(
			shared_errors.CodeSessionExpired,
			"staged_disclosure: session expired",
			nil,
		)
	}
	if s.session.State != session_object.StateActive {
		return nil, shared_errors.Authority(
			shared_errors.CodeSessionInvalidated,
			"staged_disclosure: session state no longer active: "+string(s.session.State),
			nil,
		)
	}

	// Policy drift gate. The session was issued pinned to a specific
	// policy version; if the platform has rotated since, this session
	// cannot be continued. Caller is expected to rotate the session
	// out of band (re-admission) rather than trying to force emissions
	// through a drifted policy.
	if s.session.PolicyVersion != s.activePolicy {
		return nil, shared_errors.Authority(
			shared_errors.CodePolicyDrifted,
			"staged_disclosure: session.policy_version no longer matches active policy",
			nil,
		)
	}

	seqIndex := s.counter

	// Seal. AAD binds the envelope fields that identify this
	// emission's place in the session's timeline — SessionID,
	// ComponentID, SequenceIndex, PolicyVersion, RecipientKeyID.
	// An attacker splicing a ciphertext from a different emission
	// into this envelope would fail Open because the AAD bytes
	// differ across emissions by construction (SequenceIndex is
	// strictly monotonic).
	aad, err := disclosure_message.BuildRecipientAAD(
		s.session.SessionID,
		p.ComponentID,
		seqIndex,
		s.activePolicy,
		p.RecipientKeyID,
	)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext, err := s.sealer.Seal(s.sealingKID, p.Plaintext, aad)
	if err != nil {
		return nil, err
	}

	// Assemble the envelope. DisclosureID is derived from the prefix
	// + (SessionID, SequenceIndex) pair: this makes IDs traceable
	// back to a specific position in a specific session without
	// requiring a separate registry.
	disclosureID := ids.DisclosureID(
		s.idPrefix + s.session.SessionID.String() + "-" + hex.EncodeToString(seqIndexBytes(seqIndex)),
	)

	msg := &disclosure_message.DisclosureMessage{
		SchemaVersion:  disclosure_message.SchemaVersionCurrent,
		DisclosureID:   disclosureID,
		SessionID:      s.session.SessionID,
		ComponentID:    p.ComponentID,
		PolicyVersion:  s.activePolicy,
		SequenceIndex:  seqIndex,
		SealedPayload:  ciphertext,
		Nonce:          nonce,
		RecipientKeyID: p.RecipientKeyID,
		AuthorizedAt:   now,
		SigningKeyID:   s.signingKID,
	}
	if err := msg.SignWith(s.signer); err != nil {
		return nil, err
	}
	// Post-condition: the envelope we emit must be self-consistent.
	if err := msg.Validate(); err != nil {
		return nil, err
	}

	s.counter++
	return msg, nil
}

// Finalize closes the sequence. After Finalize, Emit refuses with
// Operational. Idempotent — calling Finalize twice is a no-op that
// returns nil.
//
// Finalize is explicitly NOT the only way to stop emissions: session
// expiry, invalidation, and policy drift also halt Emit. Finalize is
// the cooperative close — the authority signaling "I am done."
func (s *StagedIssuer) Finalize() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finalized = true
	return nil
}

// SequenceIndex returns the NEXT SequenceIndex Emit will issue. Zero
// before the first Emit. Exposed for orchestration & tests.
func (s *StagedIssuer) SequenceIndex() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counter
}

// IsFinalized reports whether Finalize has been called.
func (s *StagedIssuer) IsFinalized() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finalized
}

// SessionID returns the session this issuer is bound to. Exposed for
// audit-event producers.
func (s *StagedIssuer) SessionID() ids.SessionID {
	return s.session.SessionID
}

// ---- helpers --------------------------------------------------------------

// AAD for the GCM seal is produced by
// disclosure_message.BuildRecipientAAD. That function is the single
// source of truth for the five-field AAD shape; both the release side
// (this file) and the receive side (/internal/reassembly/) call it.
// Keeping it in the contract package enforces doctrine invariant #1:
// receive-side code never imports release-side authority packages.

// validateEmitParams is the pre-lock structural gate on EmitParams.
// Split out so Emit's happy-path flow stays readable.
func validateEmitParams(p EmitParams) error {
	if p.ComponentID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: component_id required",
			nil,
		)
	}
	if len(p.Plaintext) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: plaintext required (empty emissions are meaningless)",
			nil,
		)
	}
	if p.RecipientKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"staged_disclosure: recipient_key_id required",
			nil,
		)
	}
	return nil
}

// zeroBytes overwrites b with zeros. Noop on nil / empty slice.
// Extracted so the Emit function is self-documenting about its
// zeroization commitment.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// seqIndexBytes renders a uint32 in big-endian form. The result is
// hex-encoded into the DisclosureID — fixed width so IDs sort
// lexicographically by sequence.
func seqIndexBytes(n uint32) []byte {
	return []byte{
		byte(n >> 24),
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	}
}
