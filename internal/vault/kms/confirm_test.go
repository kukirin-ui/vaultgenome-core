// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// fakeReceipts serves one signed receipt, as a destination would.
type fakeReceipts struct {
	signed receipt.Signed
	err    error
	asked  []ids.KeyID
}

func (f *fakeReceipts) FetchRestoreReceipt(_ context.Context, _ string, kid ids.KeyID) (receipt.Signed, error) {
	f.asked = append(f.asked, kid)
	return f.signed, f.err
}

// released runs a real release through the fixture and returns what the
// audit log recorded for it.
func released(t *testing.T, f *fixture) AuthorizedRelease {
	t.Helper()
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.NoError(t, err)
	rel, err := FindAuthorizedRelease(auditEvents(f), validRequest(f).DecisionID)
	require.NoError(t, err)
	return rel
}

func auditEvents(f *fixture) []audit_event.AuditEvent {
	out := make([]audit_event.AuditEvent, 0, len(f.auditChain.events))
	for i, e := range f.auditChain.events {
		out = append(out, audit_event.AuditEvent{EventID: ids.AuditEventID(fmt.Sprintf("audit-%d", i+1)), Kind: e.Kind, Payload: e.Payload, RequestID: e.RequestID})
	}
	return out
}

// receiptFor is the receipt an honest destination signs after restoring
// the genome keyed kid under rel.
func receiptFor(rel AuthorizedRelease, kid ids.KeyID) receipt.Receipt {
	at := stdtime.Date(2026, 9, 15, 3, 0, 0, 0, stdtime.UTC)
	return receipt.Receipt{
		Schema:                 receipt.Schema,
		KeyID:                  string(kid),
		DecisionID:             string(rel.DecisionID),
		RequestID:              string(rel.RequestID),
		TokenID:                string(rel.TokenID),
		DestinationKind:        string(rel.DestinationKind),
		DestinationMeasurement: hex.EncodeToString(rel.DestinationMeasurement),
		BundleSHA256:           strings.Repeat("ab", 32),
		Generation:             1,
		ContentKind:            "dir",
		PayloadSHA256:          "sha256:" + strings.Repeat("cd", 32),
		TreeSHA256:             strings.Repeat("ef", 32),
		Files:                  3,
		Bytes:                  4096,
		KeyReceivedAt:          at,
		RestoredAt:             at.Add(stdtime.Second),
		RestoreSeconds:         0.8,
	}
}

func sign(t *testing.T, r receipt.Receipt, p tee.Producer) receipt.Signed {
	t.Helper()
	s, err := receipt.Sign(r, p)
	require.NoError(t, err)
	return s
}

func expected() *ExpectedGenome {
	return &ExpectedGenome{
		BundleSHA256:  strings.Repeat("ab", 32),
		PayloadSHA256: "sha256:" + strings.Repeat("cd", 32),
		TreeSHA256:    strings.Repeat("ef", 32),
	}
}

// The destination's word, signed by the TEE the key went to and naming
// the same release, is recorded as the restore's completion.
func TestConfirmRestore_RecordsAVerifiedReceipt(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	rel := released(t, f)
	require.Equal(t, []ids.KeyID{"dek-1", "dek-2"}, rel.KeyIDs)
	fetch := &fakeReceipts{signed: sign(t, receiptFor(rel, "dek-1"), f.destProducer)}
	f.coord.receipts = fetch

	res, err := f.coord.ConfirmRestore(context.Background(), ConfirmRequest{
		Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1", Expect: expected(),
	})
	require.NoError(t, err)
	require.True(t, res.MatchedOperatorBundle)
	require.Equal(t, []ids.KeyID{"dek-1"}, fetch.asked)

	last := f.auditChain.events[len(f.auditChain.events)-1]
	require.Equal(t, audit_event.KindCrossCloudRestoreCompleted, last.Kind)
	require.Equal(t, rel.RequestID, last.RequestID)
	var p restoreConfirmedPayload
	require.NoError(t, json.Unmarshal(last.Payload, &p))
	require.Equal(t, rel.DecisionID, p.DecisionID)
	require.Equal(t, rel.TokenID, p.TokenID)
	require.Equal(t, ids.KeyID("dek-1"), p.KeyID)
	require.Equal(t, strings.Repeat("ef", 32), p.TreeSHA256)
	require.Equal(t, res.ReceiptSHA256, p.ReceiptSHA256)
	require.Len(t, p.EvidenceSHA256, 32)
	require.True(t, p.MatchedOperatorBundle)
	require.Equal(t, string(rel.AuditID), p.ReleaseAuditID)

	// Without the operator's bundle it still confirms, and says so.
	res, err = f.coord.ConfirmRestore(context.Background(), ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"})
	require.NoError(t, err)
	require.False(t, res.MatchedOperatorBundle)
}

// Anything that does not add up is refused, and nothing is recorded.
func TestConfirmRestore_RefusesWhatDoesNotMatchTheRelease(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	rel := released(t, f)
	impostor, err := tee.NewSimulated([]byte("impostor"), make([]byte, 32))
	require.NoError(t, err)
	eventsBefore := len(f.auditChain.events)

	edit := func(mutate func(r *receipt.Receipt)) receipt.Signed {
		r := receiptFor(rel, "dek-1")
		mutate(&r)
		return sign(t, r, f.destProducer)
	}
	otherRelease := rel
	otherRelease.DestinationMeasurement = make([]byte, 32)

	for name, tc := range map[string]struct {
		req      ConfirmRequest
		signed   receipt.Signed
		fetchErr error
		category shared_errors.Category
		want     string
	}{
		"key not released": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-9"},
			receipt.Signed{}, nil, shared_errors.CategoryAuthority, "was not released"},
		"another TEE signed it": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"},
			sign(t, receiptFor(rel, "dek-1"), impostor), nil, shared_errors.CategoryIntegrity, "receipt refused"},
		"released elsewhere": {ConfirmRequest{Release: otherRelease, DestinationEndpoint: "https://dest", KeyID: "dek-1"},
			sign(t, receiptFor(rel, "dek-1"), f.destProducer), nil, shared_errors.CategoryIntegrity, "the key was released to"},
		"other decision": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"},
			edit(func(r *receipt.Receipt) { r.DecisionID = "dec-other" }), nil, shared_errors.CategoryIntegrity, "decision_id"},
		"other token": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"},
			edit(func(r *receipt.Receipt) { r.TokenID = "tok-other" }), nil, shared_errors.CategoryIntegrity, "token_id"},
		"other request": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"},
			edit(func(r *receipt.Receipt) { r.RequestID = "req-other" }), nil, shared_errors.CategoryIntegrity, "request_id"},
		"other key": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"},
			edit(func(r *receipt.Receipt) { r.KeyID = "dek-2" }), nil, shared_errors.CategoryIntegrity, "key_id"},
		"other genome": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1", Expect: expected()},
			edit(func(r *receipt.Receipt) { r.TreeSHA256 = strings.Repeat("00", 32) }), nil, shared_errors.CategoryIntegrity, "tree_sha256"},
		"other bundle": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1", Expect: expected()},
			edit(func(r *receipt.Receipt) { r.BundleSHA256 = strings.Repeat("11", 32) }), nil, shared_errors.CategoryIntegrity, "bundle_sha256"},
		"destination down": {ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"},
			receipt.Signed{}, shared_errors.Operational(shared_errors.CodeResourceExhausted, "restore not complete", nil), shared_errors.CategoryOperational, "restore not complete"},
		"no endpoint": {ConfirmRequest{Release: rel, KeyID: "dek-1"},
			receipt.Signed{}, nil, shared_errors.CategoryStructural, "DestinationEndpoint"},
		"no release": {ConfirmRequest{DestinationEndpoint: "https://dest", KeyID: "dek-1"},
			receipt.Signed{}, nil, shared_errors.CategoryStructural, "incomplete"},
	} {
		t.Run(name, func(t *testing.T) {
			c := *f.coord
			c.receipts = &fakeReceipts{signed: tc.signed, err: tc.fetchErr}
			_, err := c.ConfirmRestore(context.Background(), tc.req)
			require.ErrorContains(t, err, tc.want)
			require.True(t, shared_errors.Is(err, tc.category), "category of %v", err)
		})
	}
	require.Len(t, f.auditChain.events, eventsBefore, "a refused confirmation records nothing")

	_, err = f.coord.ConfirmRestore(context.Background(), ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"})
	require.ErrorContains(t, err, "no ReceiptFetcher")
}

func TestConfirmRestore_ReportsAnAuditFailure(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	rel := released(t, f)
	f.coord.receipts = &fakeReceipts{signed: sign(t, receiptFor(rel, "dek-1"), f.destProducer)}
	f.auditChain.failKind = audit_event.KindCrossCloudRestoreCompleted
	_, err := f.coord.ConfirmRestore(context.Background(), ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1"})
	require.ErrorContains(t, err, "emit failed")
}

func TestFindAuthorizedRelease(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	first := released(t, f)
	second := released(t, f) // the same decision released again
	require.NotEqual(t, first.RequestID, second.RequestID)
	require.Equal(t, second.RequestID, func() ids.RequestID {
		r, err := FindAuthorizedRelease(auditEvents(f), validRequest(f).DecisionID)
		require.NoError(t, err)
		return r.RequestID
	}(), "the latest release of a decision")

	_, err := FindAuthorizedRelease(auditEvents(f), "dec-never")
	require.True(t, shared_errors.Is(err, shared_errors.CategoryAuthority))

	bad := []audit_event.AuditEvent{{EventID: "e1", Kind: audit_event.KindKeyReleaseAuthorized, Payload: []byte("{")}}
	_, err = FindAuthorizedRelease(bad, "dec")
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestHTTPTransport_FetchRestoreReceipt(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	good := sign(t, receiptFor(AuthorizedRelease{
		DecisionID: "d", RequestID: "r", TokenID: "t", DestinationKind: tee.ProviderSimulated,
		DestinationMeasurement: f.destMeasure,
	}, "genome-x"), f.destProducer)
	var gotAuth, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotKey = r.Header.Get("Authorization"), r.URL.Query().Get("key_id")
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/genome/receipt", r.URL.Path)
		switch gotKey {
		case "genome-x":
			_ = json.NewEncoder(w).Encode(good)
		case "busy":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"restore not complete"}`))
		default:
			_, _ = w.Write([]byte(`{"receipt":""}`))
		}
	}))
	defer srv.Close()
	tr := NewHTTPTransport(HTTPTransportConfig{HTTPClient: srv.Client(), BearerToken: "tok-123", RequestTimeout: 5 * stdtime.Second})

	s, err := tr.FetchRestoreReceipt(context.Background(), srv.URL+"/", "genome-x")
	require.NoError(t, err)
	require.Equal(t, good, s)
	require.Equal(t, "Bearer tok-123", gotAuth)

	_, err = tr.FetchRestoreReceipt(context.Background(), srv.URL, "busy")
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational), "a restore in progress is retried: %v", err)

	_, err = tr.FetchRestoreReceipt(context.Background(), srv.URL, "empty")
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))

	_, err = tr.FetchRestoreReceipt(context.Background(), "http://127.0.0.1:1", "genome-x")
	require.Error(t, err)
	require.False(t, errors.Is(err, context.Canceled))
}

// A source can require the destination to have proved the model works.
func TestConfirmRestore_RequiresAGateVerdict(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	rel := released(t, f)
	confirm := func(g *receipt.Gate, require string) (ConfirmResult, error) {
		r := receiptFor(rel, "dek-1")
		r.Gate = g
		c := *f.coord
		c.receipts = &fakeReceipts{signed: sign(t, r, f.destProducer)}
		return c.ConfirmRestore(context.Background(), ConfirmRequest{Release: rel, DestinationEndpoint: "https://dest", KeyID: "dek-1", RequireGate: require})
	}
	eq := &receipt.Gate{Level: receipt.GateEquivalent, Door: "native float", Fixtures: 16, MaxAbsErr: 1e-4, Atol: 1e-2, Rtol: 1e-3}

	res, err := confirm(eq, receipt.GateEquivalent)
	require.NoError(t, err)
	require.Equal(t, receipt.GateEquivalent, res.Receipt.Gate.Level)
	last := f.auditChain.events[len(f.auditChain.events)-1]
	var p restoreConfirmedPayload
	require.NoError(t, json.Unmarshal(last.Payload, &p))
	require.Equal(t, receipt.GateEquivalent, p.Gate.Level)
	require.Equal(t, receipt.GateEquivalent, p.RequiredGate)

	before := len(f.auditChain.events)
	_, err = confirm(eq, receipt.GateExact)
	require.ErrorContains(t, err, "gate verdict EQUIVALENT; EXACT or better is required")
	_, err = confirm(nil, receipt.GateEquivalent)
	require.ErrorContains(t, err, "no gate verdict")
	_, err = confirm(&receipt.Gate{Level: receipt.GateFail, Fixtures: 16, MaxAbsErr: 7}, receipt.GateEquivalent)
	require.ErrorContains(t, err, "gate verdict FAIL")
	_, err = confirm(eq, "MAYBE")
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.Len(t, f.auditChain.events, before, "refused confirmations record nothing")
}
