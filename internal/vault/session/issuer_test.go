// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// harness bundles a fake-clock keystore and a ready-to-use Issuer.
type harness struct {
	clock  *shared_time.FakeClock
	store  *keys.InMemoryStore
	kid    ids.KeyID
	policy ids.PolicyVersion
	iss    *Issuer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	fc := shared_time.NewFakeClock(now)
	store := keys.NewInMemoryStore(fc)

	kid := ids.KeyID("vault-auth-1")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	policy := ids.PolicyVersion("policy-v1")
	iss, err := NewIssuer(fc, store, store, kid, policy, Options{})
	require.NoError(t, err)

	return &harness{clock: fc, store: store, kid: kid, policy: policy, iss: iss}
}

// -------- constructor --------

func TestNewIssuer_RejectsMissingDeps(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	fc := shared_time.NewFakeClock(now)
	store := keys.NewInMemoryStore(fc)
	kid := ids.KeyID("vault-auth-1")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	policy := ids.PolicyVersion("policy-v1")

	_, err = NewIssuer(nil, store, store, kid, policy, Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = NewIssuer(fc, nil, store, kid, policy, Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = NewIssuer(fc, store, nil, kid, policy, Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = NewIssuer(fc, store, store, ids.KeyID(""), policy, Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = NewIssuer(fc, store, store, kid, ids.PolicyVersion(""), Options{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestNewIssuer_RejectsNegativeDefaultTTL(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	fc := shared_time.NewFakeClock(now)
	store := keys.NewInMemoryStore(fc)
	kid := ids.KeyID("vault-auth-1")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	_, err = NewIssuer(fc, store, store, kid, ids.PolicyVersion("policy-v1"), Options{DefaultTTL: -1 * time.Second})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// -------- Issue --------

func TestIssuer_Issue_Succeeds(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	s, err := h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("req-0001"),
		GenomeID:  ids.GenomeID("genome-alpha"),
	})
	require.NoError(t, err)
	require.Equal(t, session_object.StateActive, s.State)
	require.Equal(t, h.policy, s.PolicyVersion)
	require.Equal(t, h.kid, s.SigningKeyID)
	require.False(t, s.SessionID.IsZero())
	require.NotEmpty(t, s.Signature)
	require.Equal(t, DefaultTTL, s.ExpiresAt.Sub(s.IssuedAt))

	// Signature must verify under the same resolver.
	require.NoError(t, s.VerifySignature(h.store))
	// Static validation must pass.
	require.NoError(t, s.Validate())
	// And Verify — which layers state + TTL — must pass.
	require.NoError(t, h.iss.Verify(s))

	// Stored in the Issuer's map.
	require.Equal(t, 1, h.iss.Count())
	stored, ok := h.iss.Lookup(s.SessionID)
	require.True(t, ok)
	require.Equal(t, s.SessionID, stored.SessionID)
	require.Equal(t, s.Signature, stored.Signature)
}

func TestIssuer_Issue_UsesCustomTTL(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s, err := h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("req-0001"),
		GenomeID:  ids.GenomeID("genome-alpha"),
		TTL:       90 * time.Second,
	})
	require.NoError(t, err)
	require.Equal(t, 90*time.Second, s.ExpiresAt.Sub(s.IssuedAt))
}

func TestIssuer_Issue_GeneratesUniqueIDs(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	p := IssueParams{
		RequestID: ids.RequestID("req-0001"),
		GenomeID:  ids.GenomeID("genome-alpha"),
	}
	s1, err := h.iss.Issue(p)
	require.NoError(t, err)
	s2, err := h.iss.Issue(p)
	require.NoError(t, err)
	require.NotEqual(t, s1.SessionID, s2.SessionID)
}

func TestIssuer_Issue_RejectsMissingInputs(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	_, err := h.iss.Issue(IssueParams{GenomeID: ids.GenomeID("g")})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = h.iss.Issue(IssueParams{RequestID: ids.RequestID("r")})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("r"),
		GenomeID:  ids.GenomeID("g"),
		TTL:       -time.Second,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// -------- Verify --------

func TestIssuer_Verify_RejectsExpired(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s, err := h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("req-0001"),
		GenomeID:  ids.GenomeID("genome-alpha"),
		TTL:       1 * time.Minute,
	})
	require.NoError(t, err)

	h.clock.Step(2 * time.Minute) // past ExpiresAt

	err = h.iss.Verify(s)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSessionExpired, shared_errors.CodeOf(err))
}

func TestIssuer_Verify_RejectsTamperedSignature(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s, err := h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("req-0001"),
		GenomeID:  ids.GenomeID("genome-alpha"),
	})
	require.NoError(t, err)

	// Mutate a field after signing — signature must no longer verify.
	s.GenomeID = ids.GenomeID("genome-beta")

	err = h.iss.Verify(s)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// -------- Invalidate --------

func TestIssuer_Invalidate_TransitionsAndReSigns(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s, err := h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("req-0001"),
		GenomeID:  ids.GenomeID("genome-alpha"),
	})
	require.NoError(t, err)
	origSig := append([]byte(nil), s.Signature...)

	inv, err := h.iss.Invalidate(s.SessionID)
	require.NoError(t, err)
	require.Equal(t, session_object.StateInvalidated, inv.State)
	require.NotEqual(t, origSig, inv.Signature, "invalidated session must have a fresh signature")

	// New state is a well-formed, verifiable, static-valid session.
	require.NoError(t, inv.Validate())
	require.NoError(t, inv.VerifySignature(h.store))

	// But Verify rejects it because State != active.
	err = h.iss.Verify(inv)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSessionInvalidated, shared_errors.CodeOf(err))

	// Stored record reflects the new state.
	stored, ok := h.iss.Lookup(s.SessionID)
	require.True(t, ok)
	require.Equal(t, session_object.StateInvalidated, stored.State)
}

func TestIssuer_Invalidate_Idempotent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s, err := h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("req-0001"),
		GenomeID:  ids.GenomeID("genome-alpha"),
	})
	require.NoError(t, err)

	first, err := h.iss.Invalidate(s.SessionID)
	require.NoError(t, err)

	second, err := h.iss.Invalidate(s.SessionID)
	require.NoError(t, err)

	// Same signature — idempotent invalidation does not re-sign.
	require.Equal(t, first.Signature, second.Signature)
	require.Equal(t, session_object.StateInvalidated, second.State)
}

func TestIssuer_Invalidate_UnknownSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, err := h.iss.Invalidate(ids.SessionID("no-such-session"))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

// -------- RotatePolicy --------

func TestIssuer_RotatePolicy_AppliesToFutureIssues(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	before, err := h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("req-0001"),
		GenomeID:  ids.GenomeID("genome-alpha"),
	})
	require.NoError(t, err)
	require.Equal(t, h.policy, before.PolicyVersion)

	nextPolicy := ids.PolicyVersion("policy-v2")
	require.NoError(t, h.iss.RotatePolicy(nextPolicy))
	require.Equal(t, nextPolicy, h.iss.ActivePolicy())

	after, err := h.iss.Issue(IssueParams{
		RequestID: ids.RequestID("req-0002"),
		GenomeID:  ids.GenomeID("genome-alpha"),
	})
	require.NoError(t, err)
	require.Equal(t, nextPolicy, after.PolicyVersion)

	// The already-issued 'before' session continues to verify
	// cryptographically — it's just pinned to an older policy.
	require.NoError(t, before.VerifySignature(h.store))
}

func TestIssuer_RotatePolicy_RejectsEmpty(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	err := h.iss.RotatePolicy(ids.PolicyVersion(""))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}
