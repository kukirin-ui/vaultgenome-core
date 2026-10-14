// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/require"
	cchr "github.com/vault-genome/vaultgenome-core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func TestJoinEndpoint(t *testing.T) {
	t.Parallel()
	cases := []struct{ base, path, want string }{
		{"https://example.com", "/v1/x", "https://example.com/v1/x"},
		{"https://example.com/", "/v1/x", "https://example.com/v1/x"},
		{"https://example.com", "v1/x", "https://example.com/v1/x"},
		{"https://example.com/", "v1/x", "https://example.com/v1/x"},
		{"https://example.com:8443", "/v1/x", "https://example.com:8443/v1/x"},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, joinEndpoint(tc.base, tc.path))
	}
}

func TestClassifyHTTPError_StructuredEnvelope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		category    string
		expectedCat shared_errors.Category
	}{
		{"structural", shared_errors.CategoryStructural},
		{"authority", shared_errors.CategoryAuthority},
		{"operational", shared_errors.CategoryOperational},
		{"integrity", shared_errors.CategoryIntegrity},
		{"incident", shared_errors.CategoryIncident},
	}
	for _, tc := range cases {
		t.Run(tc.category, func(t *testing.T) {
			body, err := json.Marshal(map[string]interface{}{
				"error": map[string]string{
					"category": tc.category,
					"code":     "test_code",
					"message":  "test message",
				},
			})
			require.NoError(t, err)
			err = classifyHTTPError(http.StatusBadRequest, body, "https://x")
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, tc.expectedCat))
			require.Equal(t, "test_code", shared_errors.CodeOf(err))
		})
	}
}

func TestClassifyHTTPError_FallbackHeuristics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status      int
		expectedCat shared_errors.Category
	}{
		{http.StatusUnauthorized, shared_errors.CategoryAuthority},
		{http.StatusForbidden, shared_errors.CategoryAuthority},
		{http.StatusBadRequest, shared_errors.CategoryStructural},
		{http.StatusUnprocessableEntity, shared_errors.CategoryIntegrity},
		{http.StatusInternalServerError, shared_errors.CategoryOperational},
		{http.StatusServiceUnavailable, shared_errors.CategoryOperational},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			err := classifyHTTPError(tc.status, []byte("plain body"), "https://x")
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, tc.expectedCat))
		})
	}
}

func TestHTTPTransport_NetworkError_ReturnsOperational(t *testing.T) {
	t.Parallel()
	// Pointing at a closed port gives a connection refused.
	tx := NewHTTPTransport(HTTPTransportConfig{
		HTTPClient:     &http.Client{Timeout: 200 * stdtime.Millisecond},
		BearerToken:    "",
		RequestTimeout: 200 * stdtime.Millisecond,
	})
	req := cchr.CrossCloudHandshakeRequest{}
	_, err := tx.SendHandshakeRequest(context.Background(), "http://127.0.0.1:1", req)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
}

func TestHTTPTransport_BearerHeaderAttached(t *testing.T) {
	t.Parallel()
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"evidence":         []byte{1, 2, 3},
			"measurement_hint": []byte{4, 5, 6},
		})
	}))
	t.Cleanup(srv.Close)

	tx := NewHTTPTransport(HTTPTransportConfig{
		HTTPClient:  srv.Client(),
		BearerToken: "secret-2026",
	})
	// Build a syntactically-valid handshake (server doesn't validate
	// in this test — we only care about auth header propagation).
	nonce := bytes.Repeat([]byte{0x42}, tee.NonceMinBytes)
	req := cchr.CrossCloudHandshakeRequest{
		SchemaVersion:       cchr.SchemaVersionCurrent,
		RequestID:           ids.RequestID("x"),
		DecisionID:          ids.DecisionID("d"),
		DestinationTEEKind:  tee.ProviderSimulated,
		DestinationEndpoint: srv.URL,
		HandshakeNonce:      nonce,
		InitiatedAt:         stdtime.Now(),
		SigningKeyID:        ids.KeyID("k"),
		Signature:           []byte{0xAA},
		AuditEventID:        ids.AuditEventID("a"),
	}
	_, err := tx.SendHandshakeRequest(context.Background(), srv.URL, req)
	require.NoError(t, err)
	require.Equal(t, "Bearer secret-2026", sawAuth)
}

func TestHTTPTransport_RequestTimeout(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stdtime.Sleep(500 * stdtime.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	tx := NewHTTPTransport(HTTPTransportConfig{
		HTTPClient:     srv.Client(),
		RequestTimeout: 50 * stdtime.Millisecond,
	})
	_, err := tx.SendHandshakeRequest(context.Background(), srv.URL, cchr.CrossCloudHandshakeRequest{})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
}

func TestHTTPTransport_EmptyEvidenceRejected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"evidence":         []byte{},
			"measurement_hint": []byte{4, 5, 6},
		})
	}))
	t.Cleanup(srv.Close)
	tx := NewHTTPTransport(HTTPTransportConfig{HTTPClient: srv.Client()})
	_, err := tx.SendHandshakeRequest(context.Background(), srv.URL, cchr.CrossCloudHandshakeRequest{})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestHTTPTransport_TokenSendNetworkError(t *testing.T) {
	t.Parallel()
	tx := NewHTTPTransport(HTTPTransportConfig{
		HTTPClient:     &http.Client{Timeout: 200 * stdtime.Millisecond},
		RequestTimeout: 200 * stdtime.Millisecond,
	})
	err := tx.SendKeyReleaseToken(context.Background(), "http://127.0.0.1:1", krt.KeyReleaseToken{})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
}
