// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/crosscloud"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// wireError is the classified envelope the handler writes on refusal.
type wireError struct {
	Error struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Message  string `json:"message"`
	} `json:"error"`
}

// postRaw sends body to path on the fixture's server and decodes the
// error envelope, if any.
func postRaw(t *testing.T, f *httpFixture, path string, body io.Reader, headers map[string]string) (int, wireError) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.server.URL+path, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := f.server.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var env wireError
	if resp.StatusCode != http.StatusOK {
		require.NoError(t, json.Unmarshal(raw, &env), "body: %s", raw)
		require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	}
	return resp.StatusCode, env
}

// newHTTPFixtureWithRegistrar mirrors newHTTPFixture but lets the test
// pick the destination registrar and tune the receiver configuration.
func newHTTPFixtureWithRegistrar(t *testing.T, registrar crosscloud.KeyRegistrar, tune func(*crosscloud.Config)) *httpFixture {
	t.Helper()
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))
	sourceKeystore := keys.NewInMemoryStore(clock)
	sourceKID := ids.KeyID("source-auth-1")
	_, err := sourceKeystore.GenerateSigning(sourceKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	destSeed := make([]byte, 32)
	_, err = rand.Read(destSeed)
	require.NoError(t, err)
	destProducer, err := tee.NewSimulated([]byte("vault-genome-http-test"), destSeed)
	require.NoError(t, err)
	destMeasure := destProducer.Measurement()
	destMeasureBytes := make([]byte, 32)
	copy(destMeasureBytes, destMeasure[:])

	cfg := crosscloud.Config{
		SourceAuthorityKeys: sourceKeystore,
		LocalTEE:            destProducer,
		Kind:                tee.ProviderSimulated,
		Registrar:           registrar,
		Clock:               clock,
	}
	if tune != nil {
		tune(&cfg)
	}
	receiver, err := crosscloud.NewReceiver(cfg)
	require.NoError(t, err)
	handler, err := crosscloud.NewHTTPHandler(crosscloud.HTTPHandlerConfig{Receiver: receiver})
	require.NoError(t, err)
	mux := http.NewServeMux()
	for path, h := range handler.Routes() {
		mux.HandleFunc(path, h)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &httpFixture{
		server:           server,
		sourceKeystore:   sourceKeystore,
		sourceKID:        sourceKID,
		destProducer:     destProducer,
		destMeasure:      destMeasure,
		destMeasureBytes: destMeasureBytes,
	}
}

// handshakeRaw runs an honest handshake over raw HTTP and returns the
// recipient key the destination presented.
func handshakeRaw(t *testing.T, f *httpFixture) []byte {
	t.Helper()
	nonce := make([]byte, tee.NonceMinBytes)
	_, _ = rand.Read(nonce)
	body, err := json.Marshal(signedHandshakeForHTTP(t, f, nonce))
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, f.server.URL+"/v1/crosscloud/handshake", bytes.NewReader(body))
	require.NoError(t, err)
	resp, err := f.server.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var wire struct {
		RecipientPublicKey []byte `json:"recipient_public_key"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&wire))
	require.NotEmpty(t, wire.RecipientPublicKey)
	return wire.RecipientPublicKey
}

// errRegistrar refuses every registration with the configured error.
type errRegistrar struct{ err error }

func (r errRegistrar) RegisterSealing(ids.KeyID, []byte) error { return r.err }

// errReader fails on the first read, standing in for a client that
// drops the connection mid-body.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// TestNewHTTPHandler_RequiresReceiver proves the handler cannot be built
// without the receiver it fronts.
func TestNewHTTPHandler_RequiresReceiver(t *testing.T) {
	t.Parallel()
	h, err := crosscloud.NewHTTPHandler(crosscloud.HTTPHandlerConfig{})
	require.Nil(t, h)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

// TestHTTPToken_RequestRefusals proves the token route refuses the
// wrong method, a missing bearer token and an unparseable body with the
// documented status and envelope, before any token logic runs.
func TestHTTPToken_RequestRefusals(t *testing.T) {
	t.Parallel()

	t.Run("wrong method", func(t *testing.T) {
		t.Parallel()
		f := newHTTPFixture(t, "")
		resp, err := f.server.Client().Get(f.server.URL + "/v1/crosscloud/token")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		require.Equal(t, http.MethodPost, resp.Header.Get("Allow"))
		var env wireError
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		require.Equal(t, "structural", env.Error.Category)
		require.Equal(t, shared_errors.CodeFieldValueInvalid, env.Error.Code)
	})

	t.Run("bearer missing", func(t *testing.T) {
		t.Parallel()
		f := newHTTPFixture(t, "secret-bearer-2026-05-09")
		status, env := postRaw(t, f, "/v1/crosscloud/token", strings.NewReader("{}"), nil)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "authority", env.Error.Category)
		require.Equal(t, shared_errors.CodeAttestationDenied, env.Error.Code)
		require.Contains(t, env.Error.Message, "bearer token missing or invalid")
	})

	t.Run("bearer wrong", func(t *testing.T) {
		t.Parallel()
		f := newHTTPFixture(t, "secret-bearer-2026-05-09")
		status, env := postRaw(t, f, "/v1/crosscloud/token", strings.NewReader("{}"), map[string]string{"Authorization": "Bearer nope"})
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "authority", env.Error.Category)
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()
		f := newHTTPFixture(t, "")
		status, env := postRaw(t, f, "/v1/crosscloud/token", strings.NewReader("{not json"), nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "structural", env.Error.Category)
		require.Equal(t, shared_errors.CodeFieldValueInvalid, env.Error.Code)
		require.Contains(t, env.Error.Message, "invalid JSON body")
	})

	t.Run("structurally invalid token", func(t *testing.T) {
		t.Parallel()
		f := newHTTPFixture(t, "")
		status, env := postRaw(t, f, "/v1/crosscloud/token", strings.NewReader("{}"), nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "structural", env.Error.Category)
		require.Contains(t, env.Error.Message, "key_release_token")
	})
}

// TestHTTPHandshake_InvalidJSONEnvelope proves the handshake route
// reports an unparseable body with the structural envelope.
func TestHTTPHandshake_InvalidJSONEnvelope(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	status, env := postRaw(t, f, "/v1/crosscloud/handshake", strings.NewReader("[1,2"), nil)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "structural", env.Error.Category)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, env.Error.Code)
	require.Contains(t, env.Error.Message, "invalid JSON body")
}

// TestHTTP_BodyReadFailure proves both routes report a body that
// cannot be read as an operational refusal, without touching the
// receiver.
func TestHTTP_BodyReadFailure(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	receiver, err := crosscloud.NewReceiver(crosscloud.Config{
		SourceAuthorityKeys: f.sourceKeystore,
		LocalTEE:            f.destProducer,
		Kind:                tee.ProviderSimulated,
		Registrar:           keys.NewInMemoryStore(shared_time.NewFakeClock(stdtime.Now())),
	})
	require.NoError(t, err)
	handler, err := crosscloud.NewHTTPHandler(crosscloud.HTTPHandlerConfig{Receiver: receiver})
	require.NoError(t, err)

	for path, h := range handler.Routes() {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, path, errReader{})
			rec := httptest.NewRecorder()
			h(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			var env wireError
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
			require.Equal(t, "operational", env.Error.Category)
			require.Equal(t, shared_errors.CodeResourceExhausted, env.Error.Code)
			require.Contains(t, env.Error.Message, "read body failed")
			require.Zero(t, receiver.Outstanding())
		})
	}
}

// TestHTTP_BodyTooLarge proves a body over the 4 MiB ceiling is refused
// as structural before it is parsed.
func TestHTTP_BodyTooLarge(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	const maxBody = 4 * 1024 * 1024
	huge := bytes.Repeat([]byte("x"), maxBody+1)
	status, env := postRaw(t, f, "/v1/crosscloud/handshake", bytes.NewReader(huge), nil)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "structural", env.Error.Category)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, env.Error.Code)
	require.Contains(t, env.Error.Message, "request body too large")
}

// TestHTTPHandshake_StructuralRefusalIs400 proves a well-formed request
// for another TEE family comes back as a structural 400.
func TestHTTPHandshake_StructuralRefusalIs400(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	nonce := make([]byte, tee.NonceMinBytes)
	_, _ = rand.Read(nonce)
	req := signedHandshakeForHTTP(t, f, nonce)
	req.DestinationTEEKind = tee.ProviderAWSNitro
	req.Signature = []byte{0x00}
	require.NoError(t, req.SignWith(f.sourceKeystore))
	body, err := json.Marshal(req)
	require.NoError(t, err)
	status, env := postRaw(t, f, "/v1/crosscloud/handshake", bytes.NewReader(body), nil)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "structural", env.Error.Category)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, env.Error.Code)
}

// TestHTTPHandshake_OperationalRefusalIs503 proves an exhausted
// handshake table surfaces as a 503 with the operational envelope.
func TestHTTPHandshake_OperationalRefusalIs503(t *testing.T) {
	t.Parallel()
	f := newHTTPFixtureWithRegistrar(t, keys.NewInMemoryStore(shared_time.NewFakeClock(stdtime.Now())), func(c *crosscloud.Config) { c.MaxPending = 1 })
	handshakeRaw(t, f)

	nonce := make([]byte, tee.NonceMinBytes)
	_, _ = rand.Read(nonce)
	second := signedHandshakeForHTTP(t, f, nonce)
	second.RequestID = ids.RequestID("xcc-http-req-2")
	second.Signature = []byte{0x00}
	require.NoError(t, second.SignWith(f.sourceKeystore))
	body, err := json.Marshal(second)
	require.NoError(t, err)
	status, env := postRaw(t, f, "/v1/crosscloud/handshake", bytes.NewReader(body), nil)
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, "operational", env.Error.Category)
	require.Equal(t, shared_errors.CodeResourceExhausted, env.Error.Code)
}

// TestHTTPToken_RegistrarErrorStatus proves the keystore's own error
// class decides the token route's status: authority refusals are 403,
// incidents 503, and an unclassified failure is a 500 reported as
// "unknown".
func TestHTTPToken_RegistrarErrorStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCat    string
		wantCode   string
	}{
		{"authority", shared_errors.Authority(shared_errors.CodeAttestationDenied, "keystore refuses", nil), http.StatusForbidden, "authority", shared_errors.CodeAttestationDenied},
		{"incident", shared_errors.Incident(shared_errors.CodeTamperSignal, "keystore tampered", nil), http.StatusServiceUnavailable, "incident", shared_errors.CodeTamperSignal},
		{"unclassified", errors.New("disk on fire"), http.StatusInternalServerError, "unknown", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newHTTPFixtureWithRegistrar(t, errRegistrar{err: tc.err}, nil)
			dek := make([]byte, 32)
			_, _ = rand.Read(dek)
			tok := signedTokenForHTTP(t, f, handshakeRaw(t, f), map[ids.KeyID][]byte{ids.KeyID("http-dek-1"): dek})
			body, err := json.Marshal(tok)
			require.NoError(t, err)
			status, env := postRaw(t, f, "/v1/crosscloud/token", bytes.NewReader(body), nil)
			require.Equal(t, tc.wantStatus, status)
			require.Equal(t, tc.wantCat, env.Error.Category)
			require.Equal(t, tc.wantCode, env.Error.Code)
			require.Contains(t, env.Error.Message, tc.err.Error())
			require.Contains(t, env.Error.Message, `registering wrapped[0] (kid "http-dek-1")`)
		})
	}
}

// TestHTTPToken_RegisteredCountOnWire proves a successful delivery
// answers with the number of keys registered.
func TestHTTPToken_RegisteredCountOnWire(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, "")
	dek1 := make([]byte, 32)
	_, _ = rand.Read(dek1)
	dek2 := make([]byte, 32)
	_, _ = rand.Read(dek2)
	tok := signedTokenForHTTP(t, f, handshakeRaw(t, f), map[ids.KeyID][]byte{
		ids.KeyID("http-dek-1"): dek1,
		ids.KeyID("http-dek-2"): dek2,
	})
	body, err := json.Marshal(tok)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, f.server.URL+"/v1/crosscloud/token", bytes.NewReader(body))
	require.NoError(t, err)
	resp, err := f.server.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var wire struct {
		Registered int `json:"registered"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&wire))
	require.Equal(t, 2, wire.Registered)
	for _, kid := range []ids.KeyID{"http-dek-1", "http-dek-2"} {
		_, _, err := f.destKeystore.Seal(kid, []byte("ping"), nil)
		require.NoError(t, err)
	}
}
