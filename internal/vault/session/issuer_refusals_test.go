// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

func params() IssueParams {
	return IssueParams{RequestID: ids.RequestID("req-1"), GenomeID: ids.GenomeID("gen:abc")}
}

// TestIssuer_Issue_SignerRefusalStoresNothing proves that a session the
// signer will not sign — the key is registered for another purpose — is
// never issued or stored, and the refusal is the key store's own.
func TestIssuer_Issue_SignerRefusalStoresNothing(t *testing.T) {
	t.Parallel()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(fc)
	kid := ids.KeyID("audit-not-authority")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)
	iss, err := NewIssuer(fc, store, store, kid, ids.PolicyVersion("policy-v1"), Options{})
	require.NoError(t, err, "the key is checked at signing time, not at construction")

	s, err := iss.Issue(params())
	require.Error(t, err)
	require.Equal(t, session_object.SessionObject{}, s)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.Empty(t, iss.sessions, "a refused issue stores nothing")
}

// TestIssuer_Issue_ZeroClockFailsPostCondition proves the issuer's own
// post-condition: a clock that reads the zero time yields a session with
// no issued_at, which the static validator refuses, so nothing is stored.
func TestIssuer_Issue_ZeroClockFailsPostCondition(t *testing.T) {
	t.Parallel()
	fc := shared_time.NewFakeClock(time.Time{})
	store := keys.NewInMemoryStore(fc)
	kid := ids.KeyID("vault-auth-1")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	iss, err := NewIssuer(fc, store, store, kid, ids.PolicyVersion("policy-v1"), Options{})
	require.NoError(t, err)

	s, err := iss.Issue(params())
	require.Error(t, err)
	require.Equal(t, session_object.SessionObject{}, s)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Contains(t, err.Error(), "issued_at required")
	require.Empty(t, iss.sessions)
}

// withdrawnSigner signs the first n requests and refuses every later one,
// as a key store does once its signing key has been withdrawn.
type withdrawnSigner struct {
	keys.Signer
	left int
}

var errKeyWithdrawn = errors.New("keys: signing key withdrawn")

func (w *withdrawnSigner) Sign(kid ids.KeyID, purpose keys.Purpose, msg []byte) ([]byte, error) {
	if w.left == 0 {
		return nil, errKeyWithdrawn
	}
	w.left--
	return w.Signer.Sign(kid, purpose, msg)
}

// TestIssuer_Invalidate_ReSignRefusalLeavesSessionActive proves that when
// the invalidated record cannot be re-signed, the error is surfaced and
// the stored session stays the active, still-verifiable original rather
// than an unsigned invalidated one.
func TestIssuer_Invalidate_ReSignRefusalLeavesSessionActive(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	signer := &withdrawnSigner{Signer: h.store, left: 1}
	iss, err := NewIssuer(h.clock, signer, h.store, h.kid, h.policy, Options{})
	require.NoError(t, err)
	issued, err := iss.Issue(params())
	require.NoError(t, err)

	s, err := iss.Invalidate(issued.SessionID)
	require.ErrorIs(t, err, errKeyWithdrawn)
	require.Equal(t, session_object.SessionObject{}, s)

	stored, ok := iss.Lookup(issued.SessionID)
	require.True(t, ok)
	require.Equal(t, session_object.StateActive, stored.State)
	require.Equal(t, issued, stored)
	require.NoError(t, iss.Verify(stored))
}

// TestIssuer_Verify_RefusesMalformedSessions proves Verify runs the static
// validator first: a session missing required fields is a structural
// refusal before any signature or state check.
func TestIssuer_Verify_RefusesMalformedSessions(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	issued, err := h.iss.Issue(params())
	require.NoError(t, err)

	cases := map[string]struct {
		mutate func(s *session_object.SessionObject)
		code   string
	}{
		"zero value":        {func(s *session_object.SessionObject) { *s = session_object.SessionObject{} }, shared_errors.CodeSchemaVersionUnsupported},
		"no request id":     {func(s *session_object.SessionObject) { s.RequestID = "" }, shared_errors.CodeRequiredFieldMissing},
		"expires at issue":  {func(s *session_object.SessionObject) { s.ExpiresAt = s.IssuedAt }, shared_errors.CodeCrossFieldInconsistent},
		"unknown state":     {func(s *session_object.SessionObject) { s.State = "frozen" }, shared_errors.CodeFieldValueInvalid},
		"missing signature": {func(s *session_object.SessionObject) { s.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := issued
			tc.mutate(&s)
			err := h.iss.Verify(s)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
		})
	}
}
