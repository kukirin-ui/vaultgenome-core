// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package revocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

var measured = make([]byte, 48) // an SEV-SNP-sized measurement

func operatorKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func signed(t *testing.T, priv ed25519.PrivateKey, l List) []byte {
	t.Helper()
	if l.IssuedAt.IsZero() {
		l.IssuedAt = time.Date(2026, 9, 14, 21, 0, 0, 0, time.UTC)
	}
	if l.SigningKeyID == "" {
		l.SigningKeyID = "operator-1"
	}
	s, err := Sign(l, priv)
	require.NoError(t, err)
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	return raw
}

func TestSignParse_RoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := operatorKey(t)
	raw := signed(t, priv, List{Serial: 3, RevokedMeasurements: map[string][]string{"gcp-sev-snp": {hex.EncodeToString(measured)}}, Reason: "host compromised"})
	l, err := Parse(raw, pub, "operator-1")
	require.NoError(t, err)
	require.Equal(t, uint64(3), l.Serial)
	require.Equal(t, Schema, l.Schema)
}

// Only the operator's key, and only the list exactly as signed.
func TestParse_RefusesWhatTheOperatorDidNotSign(t *testing.T) {
	t.Parallel()
	pub, priv := operatorKey(t)
	otherPub, otherPriv := operatorKey(t)
	good := signed(t, priv, List{Serial: 2, StopAll: true, Reason: "drill"})

	var flipped map[string]any
	require.NoError(t, json.Unmarshal(good, &flipped))
	flipped["stop_all"] = false // someone lifts the stop without the key
	lifted, err := json.Marshal(flipped)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		raw []byte
		pub ed25519.PublicKey
		kid string
	}{
		"edited after signing":   {lifted, pub, "operator-1"},
		"another operator's key": {signed(t, otherPriv, List{Serial: 2}), pub, "operator-1"},
		"wrong trusted key":      {good, otherPub, "operator-1"},
		"other signer id":        {good, pub, "operator-2"},
		"unknown field":          {[]byte(strings.Replace(string(good), `"schema"`, `"extra":1,"schema"`, 1)), pub, "operator-1"},
		"not json":               {[]byte("stop"), pub, "operator-1"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(tc.raw, tc.pub, tc.kid)
			require.Error(t, err)
		})
	}
}

func TestSign_RefusesMalformedLists(t *testing.T) {
	t.Parallel()
	_, priv := operatorKey(t)
	at := time.Now()
	for name, l := range map[string]List{
		"serial 0":         {IssuedAt: at, SigningKeyID: "k"},
		"no issue time":    {Serial: 1, SigningKeyID: "k"},
		"no signer":        {Serial: 1, IssuedAt: at},
		"other schema":     {Schema: "v0", Serial: 1, IssuedAt: at, SigningKeyID: "k"},
		"unknown provider": {Serial: 1, IssuedAt: at, SigningKeyID: "k", RevokedMeasurements: map[string][]string{"my-enclave": {hex.EncodeToString(measured)}}},
		"not hex":          {Serial: 1, IssuedAt: at, SigningKeyID: "k", RevokedMeasurements: map[string][]string{"gcp-sev-snp": {"zz"}}},
		"truncated":        {Serial: 1, IssuedAt: at, SigningKeyID: "k", RevokedMeasurements: map[string][]string{"gcp-sev-snp": {hex.EncodeToString(measured[:20])}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Sign(l, priv)
			require.Error(t, err)
		})
	}
}

func TestDenies(t *testing.T) {
	t.Parallel()
	m := hex.EncodeToString(measured)
	revoked := List{Serial: 4, RevokedMeasurements: map[string][]string{"gcp-sev-snp": {m}}, Reason: "host compromised"}

	denied, why := revoked.Denies(tee.ProviderGCPSEVSNP, measured)
	require.True(t, denied)
	require.Contains(t, why, "revocation serial 4")
	require.Contains(t, why, "host compromised")

	denied, _ = revoked.Denies(tee.ProviderGCPSEVSNP, make([]byte, 32))
	require.False(t, denied, "another measurement is not revoked")
	denied, _ = revoked.Denies(tee.ProviderSimulated, measured)
	require.False(t, denied, "revocation is per provider")

	stop := List{Serial: 5, StopAll: true}
	denied, why = stop.Denies(tee.ProviderSimulated, make([]byte, 32))
	require.True(t, denied)
	require.Contains(t, why, "operator stop in force")
	require.Contains(t, why, "no reason given")
}

type countingPolicy struct{ calls int }

func (p *countingPolicy) AuthorizeKeyRelease(tee.Provider, []byte, ids.DecisionID, []ids.KeyID) (kms.PolicyVerdict, error) {
	p.calls++
	return kms.PolicyVerdict{Authorized: true, Reason: "allow-list match"}, nil
}
func (p *countingPolicy) PolicyVersion() string { return "xcc-2026-09-14" }

// The operator list is consulted first; what it refuses never reaches the
// allow-list.
func TestGate(t *testing.T) {
	t.Parallel()
	inner := &countingPolicy{}
	g := NewGate(inner, List{Serial: 9, StopAll: true, Reason: "drill"})
	v, err := g.AuthorizeKeyRelease(tee.ProviderSimulated, make([]byte, 32), "dec", []ids.KeyID{"k"})
	require.NoError(t, err)
	require.False(t, v.Authorized)
	require.Zero(t, inner.calls)
	require.Equal(t, "xcc-2026-09-14;revocation=9", g.PolicyVersion())
	require.Equal(t, uint64(9), g.Serial())

	g = NewGate(inner, List{Serial: 10})
	v, err = g.AuthorizeKeyRelease(tee.ProviderSimulated, make([]byte, 32), "dec", []ids.KeyID{"k"})
	require.NoError(t, err)
	require.True(t, v.Authorized)
	require.Equal(t, 1, inner.calls)
}

func event(kind audit_event.Kind, policyVersion string) audit_event.AuditEvent {
	payload, _ := json.Marshal(map[string]string{"policy_version": policyVersion})
	return audit_event.AuditEvent{Kind: kind, Payload: payload}
}

// Putting an older list back cannot undo a stop: the audit log remembers
// the newest serial any decision was made under.
func TestCheckNotRolledBack(t *testing.T) {
	t.Parallel()
	events := []audit_event.AuditEvent{
		event(audit_event.KindCrossCloudHandshakeInitiated, "ignored;revocation=99"),
		event(audit_event.KindKeyReleaseAuthorized, "v1;revocation=3"),
		event(audit_event.KindKeyReleaseDenied, "v1;revocation=7"),
		event(audit_event.KindKeyReleaseAuthorized, "v1-without-a-list"),
		{Kind: audit_event.KindKeyReleaseDenied, Payload: []byte("not json")},
	}
	require.Equal(t, uint64(7), HighestSerial(events))
	require.ErrorContains(t, CheckNotRolledBack(List{Serial: 6}, events), "rollback refused")
	require.NoError(t, CheckNotRolledBack(List{Serial: 7}, events))
	require.NoError(t, CheckNotRolledBack(List{Serial: 8}, events))
	require.Zero(t, HighestSerial(nil))
}
