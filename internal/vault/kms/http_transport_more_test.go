// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/require"
	cchr "github.com/vault-genome/vaultgenome-core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Without a client of its own the transport uses the standard one; with
// one it keeps what it was given, token and timeout included.
func TestNewHTTPTransport_KeepsWhatItIsGiven(t *testing.T) {
	t.Parallel()
	tx := NewHTTPTransport(HTTPTransportConfig{})
	require.Same(t, http.DefaultClient, tx.httpClient)
	require.Empty(t, tx.bearerToken)
	require.Zero(t, tx.timeout)

	own := &http.Client{Timeout: stdtime.Second}
	tx = NewHTTPTransport(HTTPTransportConfig{HTTPClient: own, BearerToken: "tok", RequestTimeout: 3 * stdtime.Second})
	require.Same(t, own, tx.httpClient)
	require.Equal(t, "tok", tx.bearerToken)
	require.Equal(t, 3*stdtime.Second, tx.timeout)
}

// An endpoint that is not a URL is refused before any connection is
// attempted, on every path the transport serves.
func TestHTTPTransport_RefusesAnEndpointThatIsNotAURL(t *testing.T) {
	t.Parallel()
	tx := NewHTTPTransport(HTTPTransportConfig{HTTPClient: &http.Client{Timeout: 200 * stdtime.Millisecond}})
	const bad = "http://[::1]:not-a-port"
	calls := map[string]func() error{
		"handshake": func() error {
			_, err := tx.SendHandshakeRequest(context.Background(), bad, cchr.CrossCloudHandshakeRequest{})
			return err
		},
		"token":   func() error { return tx.SendKeyReleaseToken(context.Background(), bad, krt.KeyReleaseToken{}) },
		"receipt": func() error { _, err := tx.FetchRestoreReceipt(context.Background(), bad, "dek-1"); return err },
	}
	for name, call := range calls {
		err := call()
		require.Error(t, err, name)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), name)
		require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err), name)
		require.ErrorContains(t, err, "build request failed", name)
	}
}

// A 200 whose body is not the handshake answer is a structural refusal:
// the transport does not guess at Evidence.
func TestHTTPTransport_RefusesAHandshakeAnswerThatIsNotJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>not the handshake</html>"))
	}))
	t.Cleanup(srv.Close)
	tx := NewHTTPTransport(HTTPTransportConfig{HTTPClient: srv.Client()})
	resp, err := tx.SendHandshakeRequest(context.Background(), srv.URL, cchr.CrossCloudHandshakeRequest{})
	require.Empty(t, resp.Evidence)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "decode response failed")
}

// A destination that announces more body than it sends is an operational
// failure to retry, not an answer.
func TestHTTPTransport_ReportsATruncatedAnswer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		require.True(t, ok)
		conn, _, err := hj.Hijack()
		require.NoError(t, err)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"evidence\":"))
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	tx := NewHTTPTransport(HTTPTransportConfig{HTTPClient: srv.Client()})
	err := tx.SendKeyReleaseToken(context.Background(), srv.URL, krt.KeyReleaseToken{})
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeResourceExhausted, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "read response body failed")
}

// A long error body is quoted up to 256 characters; an envelope whose
// category is not one of ours is classified by its status instead.
func TestClassifyHTTPError_SnippetAndUnknownCategory(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 300)
	err := classifyHTTPError(http.StatusBadGateway, []byte("  "+long+"  "), "https://x")
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.ErrorContains(t, err, strings.Repeat("x", 256)+"...")
	require.NotContains(t, err.Error(), strings.Repeat("x", 257))

	exact := strings.Repeat("y", 256)
	err = classifyHTTPError(http.StatusBadGateway, []byte(exact), "https://x")
	require.ErrorContains(t, err, exact)
	require.NotContains(t, err.Error(), "...")

	err = classifyHTTPError(http.StatusForbidden, []byte(`{"error":{"category":"cosmic","code":"c1","message":"m"}}`), "https://x")
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeAttestationDenied, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "HTTP 403")

	err = classifyHTTPError(http.StatusUnprocessableEntity, []byte(`{"error":{"category":"integrity","message":"no code"}}`), "https://x")
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err), "an envelope without a code is classified by status")
}
