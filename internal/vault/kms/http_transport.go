// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	cchr "github.com/vault-genome/vaultgenome-core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// HTTPTransport is a production implementation of the Transport
// interface that delivers handshakes and tokens to a destination's
// HTTP endpoint. JSON bodies; Bearer auth optional.
//
// # Endpoints
//
// HTTPTransport posts to two paths under the supplied destination
// endpoint base URL:
//
//	POST <endpoint>/v1/crosscloud/handshake
//	POST <endpoint>/v1/crosscloud/token
//
// The destination's HTTP handler is implemented by
// /internal/bootstrap/crosscloud.HTTPHandler — the symmetric peer
// that wraps a *crosscloud.Receiver.
//
// # Auth
//
// If BearerToken is non-empty, every request carries an
// "Authorization: Bearer <token>" header. The destination's handler
// checks the token in constant time. Empty token = no transport-
// layer auth (the cryptographic signatures on the wire payloads
// remain the primary authenticator; bearer-token is defence-in-depth
// for transport-layer DoS resistance).
//
// # TLS
//
// HTTPTransport uses the http.Client passed in via Config. For
// production deployments, the operator wires an *http.Client with
// mTLS configured against an operator-supplied CA bundle. For local
// dev / testing, http.DefaultClient (or an httptest.Server-backed
// client) is sufficient.
type HTTPTransport struct {
	httpClient  *http.Client
	bearerToken string
	timeout     time.Duration
}

// HTTPTransportConfig bundles HTTPTransport's dependencies.
type HTTPTransportConfig struct {
	// HTTPClient is the http.Client used for all requests. If nil,
	// http.DefaultClient is used. Production deployments supply a
	// client wired with mTLS.
	HTTPClient *http.Client

	// BearerToken is appended to every request as Authorization:
	// Bearer <token>. Empty = no transport-layer auth.
	BearerToken string

	// RequestTimeout caps individual handshake / token round trips.
	// Zero = no timeout (defer to context cancellation).
	RequestTimeout time.Duration
}

// NewHTTPTransport constructs a ready-to-use HTTPTransport.
func NewHTTPTransport(cfg HTTPTransportConfig) *HTTPTransport {
	c := cfg.HTTPClient
	if c == nil {
		c = http.DefaultClient
	}
	return &HTTPTransport{
		httpClient:  c,
		bearerToken: cfg.BearerToken,
		timeout:     cfg.RequestTimeout,
	}
}

// SendHandshakeRequest dispatches a signed handshake request to
// <endpoint>/v1/crosscloud/handshake and parses the destination's
// reply (Evidence, MeasurementHint, RecipientPublicKey).
func (t *HTTPTransport) SendHandshakeRequest(
	ctx context.Context,
	endpoint string,
	req cchr.CrossCloudHandshakeRequest,
) (HandshakeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return HandshakeResponse{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.HTTPTransport.SendHandshakeRequest: marshal request failed",
			err,
		)
	}

	url := joinEndpoint(endpoint, "/v1/crosscloud/handshake")
	respBody, err := t.postJSON(ctx, url, body)
	if err != nil {
		return HandshakeResponse{}, err
	}

	var wire httpHandshakeResponse
	if err := json.Unmarshal(respBody, &wire); err != nil {
		return HandshakeResponse{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.HTTPTransport.SendHandshakeRequest: decode response failed",
			err,
		)
	}
	if len(wire.Evidence) == 0 {
		return HandshakeResponse{}, shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			"kms.HTTPTransport.SendHandshakeRequest: empty Evidence in response",
			nil,
		)
	}
	return HandshakeResponse(wire), nil
}

// SendKeyReleaseToken dispatches a signed token to
// <endpoint>/v1/crosscloud/token.
func (t *HTTPTransport) SendKeyReleaseToken(
	ctx context.Context,
	endpoint string,
	token krt.KeyReleaseToken,
) error {
	body, err := json.Marshal(token)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.HTTPTransport.SendKeyReleaseToken: marshal token failed",
			err,
		)
	}
	url := joinEndpoint(endpoint, "/v1/crosscloud/token")
	_, err = t.postJSON(ctx, url, body)
	return err
}

// FetchRestoreReceipt fetches the destination's signed receipt for the
// restore of the genome keyed kid: GET
// <endpoint>/v1/genome/receipt?key_id=<kid>. A restore that has not
// finished answers 409, returned as an Operational error to retry.
func (t *HTTPTransport) FetchRestoreReceipt(ctx context.Context, endpoint string, kid ids.KeyID) (receipt.Signed, error) {
	u := joinEndpoint(endpoint, "/v1/genome/receipt") + "?key_id=" + url.QueryEscape(string(kid))
	body, err := t.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return receipt.Signed{}, err
	}
	var s receipt.Signed
	if err := json.Unmarshal(body, &s); err != nil || len(s.Receipt) == 0 || len(s.Evidence) == 0 {
		return receipt.Signed{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.HTTPTransport.FetchRestoreReceipt: the destination's answer is not a signed receipt",
			err,
		)
	}
	return s, nil
}

// postJSON is the shared POST + classified-error helper.
func (t *HTTPTransport) postJSON(ctx context.Context, url string, body []byte) ([]byte, error) {
	return t.do(ctx, http.MethodPost, url, body)
}

func (t *HTTPTransport) do(ctx context.Context, method, url string, body []byte) ([]byte, error) {
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"kms.HTTPTransport: build request failed",
			err,
		)
	}
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.Header.Set("Accept", "application/json")
	if t.bearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+t.bearerToken)
	}

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			fmt.Sprintf("kms.HTTPTransport: %s %s failed", method, url),
			err,
		)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"kms.HTTPTransport: read response body failed",
			err,
		)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, classifyHTTPError(resp.StatusCode, respBody, url)
	}
	return respBody, nil
}

// httpHandshakeResponse is the wire shape the destination's HTTP
// handler returns for /v1/crosscloud/handshake. Carries the same
// fields as kms.HandshakeResponse, JSON-encoded.
type httpHandshakeResponse struct {
	Evidence           []byte `json:"evidence"`
	MeasurementHint    []byte `json:"measurement_hint,omitempty"`
	RecipientPublicKey []byte `json:"recipient_public_key,omitempty"`
}

// classifyHTTPError maps a non-2xx HTTP response into the project's
// error taxonomy. The destination may return a structured
// classified-error JSON body; if so, we preserve the category and
// code. Otherwise we fall back to status-code heuristics.
func classifyHTTPError(status int, body []byte, url string) error {
	// Try to decode the destination's classified error envelope.
	type classifiedEnvelope struct {
		Error struct {
			Category string `json:"category"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		} `json:"error"`
	}
	var env classifiedEnvelope
	if json.Unmarshal(body, &env) == nil && env.Error.Code != "" {
		msg := fmt.Sprintf("kms.HTTPTransport: destination %s returned %d (%s/%s): %s",
			url, status, env.Error.Category, env.Error.Code, env.Error.Message)
		switch strings.ToLower(env.Error.Category) {
		case "structural":
			return shared_errors.Structural(env.Error.Code, msg, nil)
		case "authority":
			return shared_errors.Authority(env.Error.Code, msg, nil)
		case "operational":
			return shared_errors.Operational(env.Error.Code, msg, nil)
		case "integrity":
			return shared_errors.Integrity(env.Error.Code, msg, nil)
		case "incident":
			return shared_errors.Incident(env.Error.Code, msg, nil)
		}
	}

	// Fallback: status-code heuristics.
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 256 {
		snippet = snippet[:256] + "..."
	}
	msg := fmt.Sprintf("kms.HTTPTransport: destination %s returned HTTP %d: %s", url, status, snippet)
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return shared_errors.Authority(shared_errors.CodeAttestationDenied, msg, nil)
	case status == http.StatusBadRequest:
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, msg, nil)
	case status == http.StatusUnprocessableEntity:
		return shared_errors.Integrity(shared_errors.CodeSignatureInvalid, msg, nil)
	default:
		return shared_errors.Operational(shared_errors.CodeResourceExhausted, msg, nil)
	}
}

// joinEndpoint joins a base endpoint URL and a path, normalising
// trailing/leading slashes to avoid "//" duplication.
func joinEndpoint(base, path string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}
