// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

type harness struct {
	clock  *shared_time.FakeClock
	store  *keys.InMemoryStore
	kid    ids.KeyID
	req    recovery_request.RecoveryRequest
	peer   Peer
	opPriv ed25519.PrivateKey
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clock := shared_time.NewFakeClock(time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(clock)
	kid := ids.KeyID("vault-auth")
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return &harness{
		clock: clock, store: store, kid: kid, opPriv: priv,
		req: recovery_request.RecoveryRequest{
			SchemaVersion: recovery_request.SchemaVersionCurrent, RequestID: "req-1", GenomeID: "genome-1",
			PolicyProfile: "gate", RequesterIdentity: "operator:test", CreatedAt: clock.Now(),
		},
		peer: Peer{Provider: tee.ProviderGCPSEVSNP, Measurement: make([]byte, 48), RemoteAddr: "127.0.0.1:1", EvidenceAt: clock.Now()},
	}
}

func (h *harness) admission(t *testing.T, opts Options) *Admission {
	t.Helper()
	if opts.Profiles == nil {
		opts.Profiles = []string{"gate"}
	}
	a, err := NewAdmission(h.clock, h.store, h.kid, opts)
	require.NoError(t, err)
	return a
}

func (h *harness) stopList(t *testing.T, serial uint64, stopAll bool, revoked map[string][]string) StopListSource {
	t.Helper()
	l, err := revocation.Sign(revocation.List{
		Schema: "vault-genome/revocation/v1", Serial: serial, IssuedAt: h.clock.Now(), StopAll: stopAll,
		RevokedMeasurements: revoked, Reason: "drill", SigningKeyID: "operator-1",
	}, h.opPriv)
	require.NoError(t, err)
	return func() (revocation.List, error) { return l, nil }
}

func TestEvaluate_AllowsAPinnedPeerWithASignedAttestation(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := h.admission(t, Options{})
	d, err := a.Evaluate(h.req, h.peer, 0)
	require.NoError(t, err)
	require.True(t, d.Allowed)
	require.Equal(t, ReasonPeerAttested, d.Reason)
	require.Equal(t, attestation_result.OutcomeAllow, d.Result.Outcome)
	require.Equal(t, attestation_result.DefaultTTL, d.Result.TTL)
	require.Equal(t, h.req.RequestID, d.Result.RequestID)
	require.NoError(t, d.Result.VerifySignature(h.store))
	require.Equal(t, tee.ProviderGCPSEVSNP, d.PeerProvider)
	require.Len(t, d.PeerMeasurementHex, 96)

	// Ids are minted, distinct, and a custom TTL is honoured.
	d2, err := a.Evaluate(h.req, h.peer, 90*time.Second)
	require.NoError(t, err)
	require.NotEqual(t, d.Result.AttestationID, d2.Result.AttestationID)
	require.Equal(t, 90*time.Second, d2.Result.TTL)
}

func TestEvaluate_DeniesWithTheReasonOnRecord(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	t.Run("profile not served", func(t *testing.T) {
		a := h.admission(t, Options{Profiles: []string{"other"}})
		d, err := a.Evaluate(h.req, h.peer, 0)
		require.NoError(t, err)
		require.False(t, d.Allowed)
		require.Equal(t, ReasonProfileNotServed, d.Reason)
		require.Equal(t, attestation_result.OutcomeDeny, d.Result.Outcome)
		require.Equal(t, ReasonProfileNotServed, d.Result.Reason)
		require.NoError(t, d.Result.VerifySignature(h.store))
	})
	t.Run("no attested peer", func(t *testing.T) {
		a := h.admission(t, Options{})
		d, err := a.Evaluate(h.req, Peer{}, 0)
		require.NoError(t, err)
		require.False(t, d.Allowed)
		require.Equal(t, ReasonPeerMissing, d.Reason)
	})
	t.Run("operator stop in force", func(t *testing.T) {
		a := h.admission(t, Options{StopList: h.stopList(t, 7, true, nil)})
		d, err := a.Evaluate(h.req, h.peer, 0)
		require.NoError(t, err)
		require.False(t, d.Allowed)
		require.Equal(t, ReasonOperatorStop, d.Reason)
		require.EqualValues(t, 7, d.StopSerial)
		require.Contains(t, d.Detail, "operator stop in force")
	})
	t.Run("measurement revoked", func(t *testing.T) {
		revoked := map[string][]string{string(tee.ProviderGCPSEVSNP): {hex.EncodeToString(h.peer.Measurement)}}
		a := h.admission(t, Options{StopList: h.stopList(t, 8, false, revoked)})
		d, err := a.Evaluate(h.req, h.peer, 0)
		require.NoError(t, err)
		require.False(t, d.Allowed)
		require.Equal(t, ReasonMeasurementRevoked, d.Reason)

		// Another measurement passes the same list.
		other := h.peer
		other.Measurement = append([]byte(nil), h.peer.Measurement...)
		other.Measurement[0] = 1
		d, err = a.Evaluate(h.req, other, 0)
		require.NoError(t, err)
		require.True(t, d.Allowed)
	})
}

func TestEvaluate_CannotDecideWithoutTheStopListOrAValidRequest(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := h.admission(t, Options{StopList: func() (revocation.List, error) { return revocation.List{}, errors.New("unreadable") }})
	_, err := a.Evaluate(h.req, h.peer, 0)
	require.Error(t, err)
	require.Equal(t, CodeStopListUnavailable, shared_errors.CodeOf(err))

	a = h.admission(t, Options{})
	bad := h.req
	bad.PolicyProfile = ""
	_, err = a.Evaluate(bad, h.peer, 0)
	require.Error(t, err)
	_, err = a.Evaluate(h.req, h.peer, -time.Second)
	require.Error(t, err)
}

func TestNewAdmission_RefusesMissingDeps(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	_, err := NewAdmission(nil, h.store, h.kid, Options{Profiles: []string{"gate"}})
	require.Error(t, err)
	_, err = NewAdmission(h.clock, nil, h.kid, Options{Profiles: []string{"gate"}})
	require.Error(t, err)
	_, err = NewAdmission(h.clock, h.store, "", Options{Profiles: []string{"gate"}})
	require.Error(t, err)
	_, err = NewAdmission(h.clock, h.store, h.kid, Options{})
	require.Error(t, err)
	_, err = NewAdmission(h.clock, h.store, h.kid, Options{Profiles: []string{""}})
	require.Error(t, err)
}

// What the peer's verifier said beyond the measurement rides on the
// decision, allow or deny, for the audit record.
func TestEvaluate_CarriesThePeersDetailOntoTheDecision(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := h.admission(t, Options{})
	peer := h.peer
	peer.Provider = tee.ProviderAzureCGPU
	peer.Detail = &tee.AttestationDetail{Provider: tee.ProviderAzureCGPU, Product: "Genoa",
		GPUs: []tee.GPUVerdict{{Key: "GPU-0", HWModel: "GH100", Issuer: "own evaluation"}}}

	d, err := a.Evaluate(h.req, peer, 0)
	require.NoError(t, err)
	require.True(t, d.Allowed)
	require.Equal(t, peer.Detail, d.PeerDetail)

	denied := h.admission(t, Options{StopList: h.stopList(t, 3, true, nil)})
	d, err = denied.Evaluate(h.req, peer, 0)
	require.NoError(t, err)
	require.False(t, d.Allowed)
	require.Equal(t, peer.Detail, d.PeerDetail, "a denial says what was seen too")

	d, err = a.Evaluate(h.req, h.peer, 0)
	require.NoError(t, err)
	require.Nil(t, d.PeerDetail, "a peer with nothing beyond the measurement carries none")
}
