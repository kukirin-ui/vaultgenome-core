// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// failingIDGen refuses the id it is told to refuse.
type failingIDGen struct {
	fakeIDGen
	requestErr  error
	decisionErr error
}

func (g *failingIDGen) NewRequestID() (ids.RequestID, error) {
	if g.requestErr != nil {
		return "", g.requestErr
	}
	return g.fakeIDGen.NewRequestID()
}

func (g *failingIDGen) NewDecisionID() (ids.DecisionID, error) {
	if g.decisionErr != nil {
		return "", g.decisionErr
	}
	return g.fakeIDGen.NewDecisionID()
}

// countingSigner signs through the store until its n-th call, which it
// refuses, the way a signing service that went away mid-flow would.
type countingSigner struct {
	keys.Signer
	calls  int
	failAt int
}

func (s *countingSigner) Sign(kid ids.KeyID, purpose keys.Purpose, msg []byte) ([]byte, error) {
	s.calls++
	if s.calls == s.failAt {
		return nil, shared_errors.Operational("signer_offline", "signer offline", nil)
	}
	return s.Signer.Sign(kid, purpose, msg)
}

// erroringPolicy cannot evaluate at all, as a policy backed by a store
// that is down would.
type erroringPolicy struct{ err error }

func (p erroringPolicy) AuthorizeKeyRelease(tee.Provider, []byte, ids.DecisionID, []ids.KeyID) (PolicyVerdict, error) {
	return PolicyVerdict{}, p.err
}

func (erroringPolicy) PolicyVersion() string { return "erroring-v1" }

// Every failure between the handshake and the token stops the flow at
// its own stage: what was decided before it stays on the record, what
// comes after is never done, and no token leaves.
func TestCoordinateRestore_StopsAtTheFailingStage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		arrange    func(f *fixture, c *Coordinator)
		category   shared_errors.Category
		code       string
		want       string
		events     int
		handshakes int
	}{
		{
			name:     "request id generation",
			arrange:  func(f *fixture, c *Coordinator) { c.idGenerator = &failingIDGen{requestErr: errors.New("rng down")} },
			category: shared_errors.CategoryStructural, code: shared_errors.CodeFieldValueInvalid, want: "request id generation failed",
			events: 0, handshakes: 0,
		},
		{
			name:     "handshake signing key unknown",
			arrange:  func(f *fixture, c *Coordinator) { c.signingKID = "no-such-key" },
			category: shared_errors.CategoryAuthority, code: shared_errors.CodeRequiredFieldMissing, want: "unknown kid",
			events: 1, handshakes: 0,
		},
		{
			name:     "handshake signer offline",
			arrange:  func(f *fixture, c *Coordinator) { c.keySigner = &countingSigner{Signer: f.keyStore, failAt: 1} },
			category: shared_errors.CategoryOperational, code: "signer_offline", want: "signer offline",
			events: 1, handshakes: 0,
		},
		{
			name: "attestation record refused",
			arrange: func(f *fixture, c *Coordinator) {
				f.auditChain.failKind = audit_event.KindCrossCloudAttestationVerified
			},
			category: shared_errors.CategoryUnknown, code: "", want: "emit failed",
			events: 1, handshakes: 1,
		},
		{
			name: "policy cannot evaluate",
			arrange: func(f *fixture, c *Coordinator) {
				c.policy = erroringPolicy{err: shared_errors.Operational("policy_store_down", "policy store down", nil)}
			},
			category: shared_errors.CategoryOperational, code: "policy_store_down", want: "policy store down",
			events: 2, handshakes: 1,
		},
		{
			name:     "token id generation",
			arrange:  func(f *fixture, c *Coordinator) { c.idGenerator = &failingIDGen{decisionErr: errors.New("rng down")} },
			category: shared_errors.CategoryStructural, code: shared_errors.CodeFieldValueInvalid, want: "token id generation failed",
			events: 2, handshakes: 1,
		},
		{
			name:     "key release record refused",
			arrange:  func(f *fixture, c *Coordinator) { f.auditChain.failKind = audit_event.KindKeyReleaseAuthorized },
			category: shared_errors.CategoryUnknown, code: "", want: "emit failed",
			events: 2, handshakes: 1,
		},
		{
			name:     "token signer offline",
			arrange:  func(f *fixture, c *Coordinator) { c.keySigner = &countingSigner{Signer: f.keyStore, failAt: 2} },
			category: shared_errors.CategoryOperational, code: "signer_offline", want: "signer offline",
			events: 3, handshakes: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := makeFixture(t)
			c := *f.coord
			tc.arrange(f, &c)
			res, err := c.CoordinateRestore(context.Background(), validRequest(f))
			require.Error(t, err)
			require.Equal(t, tc.category, shared_errors.CategoryOf(err), "%v", err)
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.ErrorContains(t, err, tc.want)
			require.Len(t, f.auditChain.events, tc.events)
			require.Len(t, f.transport.sentHandshakes, tc.handshakes)
			require.Empty(t, f.transport.sentTokens, "no token leaves a flow that did not finish")
			require.Empty(t, res.TokenID)

			// The result names what was recorded before the failure.
			if tc.events >= 1 {
				require.Equal(t, ids.AuditEventID("audit-1"), res.HandshakeAuditID)
				require.NotEmpty(t, res.HandshakeRequestID)
			} else {
				require.Empty(t, res.HandshakeAuditID)
			}
			if tc.events >= 2 {
				require.Equal(t, ids.AuditEventID("audit-2"), res.AttestationAuditID)
				require.Equal(t, []byte(f.destMeasure[:]), res.DestinationMeasurement)
			} else {
				require.Empty(t, res.AttestationAuditID)
			}
			if tc.events >= 3 {
				require.Equal(t, ids.AuditEventID("audit-3"), res.KeyReleaseAuditID)
			} else {
				require.Empty(t, res.KeyReleaseAuditID)
			}
		})
	}
}

// Only sealing keys cross clouds. A key offered under another purpose is
// refused after attestation and policy, before anything is wrapped, and
// the refusal names the offending entry.
func TestCoordinateRestore_RefusesKeysThatAreNotSealingKeys(t *testing.T) {
	t.Parallel()
	for _, purpose := range []uint8{0, 1, 2, 4} {
		f := makeFixture(t)
		req := validRequest(f)
		req.KeysToRelease[1].Purpose = purpose
		res, err := f.coord.CoordinateRestore(context.Background(), req)
		require.Error(t, err, "purpose %d", purpose)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
		require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
		require.ErrorContains(t, err, "KeysToRelease[1].Purpose must be PurposeSealing")
		require.Len(t, f.auditChain.events, 2, "handshake and attestation are on the record, no authorisation")
		require.Equal(t, audit_event.KindCrossCloudAttestationVerified, f.auditChain.events[1].Kind)
		require.Empty(t, f.transport.sentTokens)
		require.Empty(t, res.KeyReleaseAuditID)
		require.Equal(t, []byte(f.destMeasure[:]), res.DestinationMeasurement)
	}
	require.Equal(t, uint8(keys.PurposeSealing), krt.PurposeSealing, "the token's sealing purpose is the keystore's")
}

// A release recorded for a TEE family this coordinator has no verifier
// for cannot be confirmed: nothing is fetched and nothing is recorded.
func TestConfirmRestore_RefusesAReleaseForAnUnknownTEEFamily(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	rel := released(t, f)
	rel.DestinationKind = tee.ProviderGCPSEVSNP
	fetch := &fakeReceipts{}
	f.coord.receipts = fetch
	before := len(f.auditChain.events)

	res, err := f.coord.ConfirmRestore(context.Background(), ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"})
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "not registered")
	require.Empty(t, fetch.asked, "no receipt is fetched for a family that cannot be verified")
	require.Len(t, f.auditChain.events, before)
	require.Empty(t, res.AuditID)
}

// An allow list is keyed by TEE family; an entry with no family is a
// configuration mistake the constructor refuses.
func TestAllowListPolicy_ConstructorRefusesAnEmptyProvider(t *testing.T) {
	t.Parallel()
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{"": {make([]byte, 32)}})
	require.Nil(t, p)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "empty Provider key")
}
