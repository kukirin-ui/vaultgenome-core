// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// errQuoteDown is what the failing producer returns from Quote.
var errQuoteDown = errors.New("attestation device unavailable")

// failingQuoteProducer reports the real simulated measurement but cannot
// produce Evidence, which is what a destination whose attestation device
// is down looks like to the Receiver.
type failingQuoteProducer struct {
	inner *tee.Simulated
}

func (p failingQuoteProducer) Quote(tee.Nonce) (tee.Evidence, error) { return nil, errQuoteDown }
func (p failingQuoteProducer) Measurement() tee.Measurement          { return p.inner.Measurement() }

// TestHandleHandshakeRequest_QuoteFailureReleasesTheKey proves a local
// Quote failure is reported as an outage, that the half-registered
// handshake key is forgotten rather than left to block the request ID,
// and that the same request can be answered once the device is back.
func TestHandleHandshakeRequest_QuoteFailureReleasesTheKey(t *testing.T) {
	t.Parallel()
	var inner *tee.Simulated
	f := makeReceiverFixture(t, func(c *Config) {
		inner = c.LocalTEE.(*tee.Simulated)
		c.LocalTEE = failingQuoteProducer{inner: inner}
	})
	req := signedHandshake(t, f.source, f.sourceKID, "xcc-req-test-1", tee.ProviderSimulated, mustRandomBytes(t, tee.NonceMinBytes))

	resp, err := f.receiver.HandleHandshakeRequest(req)
	require.ErrorIs(t, err, errQuoteDown)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational), "got %v", err)
	require.Equal(t, shared_errors.CodeResourceExhausted, shared_errors.CodeOf(err))
	require.Empty(t, resp.RecipientPublicKey)
	require.Zero(t, f.receiver.Outstanding(), "the key minted for the failed handshake must be forgotten")

	// Forgetting an ID that is no longer outstanding is harmless.
	f.receiver.forget("xcc-req-test-1")
	require.Zero(t, f.receiver.Outstanding())

	// With the device back, the very same request is answered: the
	// failed attempt did not burn the request ID as a replay.
	f.receiver.localTEE = inner
	resp, err = f.receiver.HandleHandshakeRequest(req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Evidence)
	require.Equal(t, 1, f.receiver.Outstanding())
}

// TestHandleKeyReleaseToken_OnDeliveryIsToldAboutAcceptedTokens proves
// the delivery callback runs once per accepted token, before the call
// returns, with the token's identifiers, every delivered key ID and
// the receiver clock's time; and that it does not run for a refused
// token.
func TestHandleKeyReleaseToken_OnDeliveryIsToldAboutAcceptedTokens(t *testing.T) {
	t.Parallel()
	var deliveries []Delivery
	f := makeReceiverFixture(t, func(c *Config) {
		c.OnDelivery = func(d Delivery) { deliveries = append(deliveries, d) }
	})

	pub := f.handshake(t, "xcc-req-test-1")
	refused := f.signedToken(t, tokenSpec{decisionID: "dec-other", recipientPub: pub, keys: oneKey(t)})
	_, err := f.receiver.HandleKeyReleaseToken(refused)
	requireIntegrity(t, err)
	require.Empty(t, deliveries, "a refused token is not a delivery")

	pub = f.handshake(t, "xcc-req-test-1")
	tok := f.signedToken(t, tokenSpec{recipientPub: pub, keys: map[ids.KeyID][]byte{
		ids.KeyID("dek-1"): mustRandomBytes(t, 32),
		ids.KeyID("dek-2"): mustRandomBytes(t, 32),
	}})
	n, err := f.receiver.HandleKeyReleaseToken(tok)
	require.NoError(t, err)
	require.Equal(t, 2, n)

	require.Len(t, deliveries, 1)
	d := deliveries[0]
	require.Equal(t, tok.DecisionID, d.DecisionID)
	require.Equal(t, tok.RequestID, d.RequestID)
	require.Equal(t, tok.TokenID, d.TokenID)
	require.ElementsMatch(t, []ids.KeyID{"dek-1", "dek-2"}, d.KeyIDs)
	require.Equal(t, f.clock.Now().UTC(), d.At)
}

// TestClassifiedErrorStatus_And_CategoryString pins the HTTP status and
// the wire category name for every error class the handler can emit,
// including an unclassified error and the nil sentinel.
func TestClassifiedErrorStatus_And_CategoryString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCat    string
	}{
		{"structural", shared_errors.Structural("c", "m", nil), http.StatusBadRequest, "structural"},
		{"authority", shared_errors.Authority("c", "m", nil), http.StatusForbidden, "authority"},
		{"integrity", shared_errors.Integrity("c", "m", nil), http.StatusUnprocessableEntity, "integrity"},
		{"operational", shared_errors.Operational("c", "m", nil), http.StatusServiceUnavailable, "operational"},
		{"incident", shared_errors.Incident("c", "m", nil), http.StatusServiceUnavailable, "incident"},
		{"wrapped keeps its class", errors.Join(errors.New("ctx"), shared_errors.Authority("c", "m", nil)), http.StatusForbidden, "authority"},
		{"unclassified", errors.New("plain"), http.StatusInternalServerError, "unknown"},
		{"nil", nil, http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.wantStatus, classifiedErrorStatus(tc.err))
			require.Equal(t, tc.wantCat, categoryString(tc.err))
		})
	}
}
