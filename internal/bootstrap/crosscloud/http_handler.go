// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	cchr "github.com/vault-genome/vaultgenome-core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// HTTPHandler wraps a Receiver in an HTTP request handler suitable
// for mounting into the destination's acp-bootstrap daemon HTTP
// server. It implements two routes:
//
//	POST /v1/crosscloud/handshake — accepts a CrossCloudHandshakeRequest,
//	                               returns {evidence, measurement_hint,
//	                               recipient_public_key}.
//	POST /v1/crosscloud/token     — accepts a KeyReleaseToken,
//	                               returns {registered: int}.
//
// All responses are JSON. Errors carry the project's classified
// envelope:
//
//	{"error":{"category":"...","code":"...","message":"..."}}
//
// Auth: if BearerToken is non-empty, every request must carry
// "Authorization: Bearer <token>" matched in constant time. Empty =
// no transport-layer auth (cryptographic signatures on the wire
// payloads remain the primary authenticator).
type HTTPHandler struct {
	receiver    *Receiver
	bearerToken string
	log         *slog.Logger
}

// HTTPHandlerConfig bundles HTTPHandler dependencies.
type HTTPHandlerConfig struct {
	Receiver    *Receiver
	BearerToken string
	Logger      *slog.Logger
}

// NewHTTPHandler returns a ready-to-use HTTPHandler.
func NewHTTPHandler(cfg HTTPHandlerConfig) (*HTTPHandler, error) {
	if cfg.Receiver == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"crosscloud.NewHTTPHandler: Receiver required",
			nil,
		)
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &HTTPHandler{
		receiver:    cfg.Receiver,
		bearerToken: cfg.BearerToken,
		log:         log,
	}, nil
}

// Routes returns the (path, handler) pairs callers can register on a
// net/http.ServeMux:
//
//	mux := http.NewServeMux()
//	for path, h := range handler.Routes() {
//	    mux.HandleFunc(path, h)
//	}
func (h *HTTPHandler) Routes() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"/v1/crosscloud/handshake": h.HandleHandshake,
		"/v1/crosscloud/token":     h.HandleToken,
	}
}

// HandleHandshake services POST /v1/crosscloud/handshake.
func (h *HTTPHandler) HandleHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !h.checkBearer(r) {
		writeClassifiedError(w, http.StatusUnauthorized, shared_errors.Authority(
			shared_errors.CodeAttestationDenied,
			"crosscloud.HandleHandshake: bearer token missing or invalid",
			nil,
		))
		return
	}

	body, err := readBody(r)
	if err != nil {
		writeClassifiedError(w, http.StatusBadRequest, err)
		return
	}

	var req cchr.CrossCloudHandshakeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeClassifiedError(w, http.StatusBadRequest, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crosscloud.HandleHandshake: invalid JSON body",
			err,
		))
		return
	}

	resp, err := h.receiver.HandleHandshakeRequest(req)
	if err != nil {
		h.log.Warn("crosscloud handshake rejected", slog.String("err", err.Error()))
		writeClassifiedError(w, classifiedErrorStatus(err), err)
		return
	}

	keyHash := sha256OfBytes(resp.RecipientPublicKey)
	h.log.Info("crosscloud handshake answered",
		slog.String("request_id", logSafe(string(req.RequestID))),
		slog.String("decision_id", logSafe(string(req.DecisionID))),
		slog.String("recipient_key_sha256", hex.EncodeToString(keyHash[:])),
	)
	wire := struct {
		Evidence           []byte `json:"evidence"`
		MeasurementHint    []byte `json:"measurement_hint,omitempty"`
		RecipientPublicKey []byte `json:"recipient_public_key"`
	}{
		Evidence:           resp.Evidence,
		MeasurementHint:    resp.MeasurementHint,
		RecipientPublicKey: resp.RecipientPublicKey,
	}
	writeJSON(w, http.StatusOK, wire)
}

// HandleToken services POST /v1/crosscloud/token.
func (h *HTTPHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if !h.checkBearer(r) {
		writeClassifiedError(w, http.StatusUnauthorized, shared_errors.Authority(
			shared_errors.CodeAttestationDenied,
			"crosscloud.HandleToken: bearer token missing or invalid",
			nil,
		))
		return
	}

	body, err := readBody(r)
	if err != nil {
		writeClassifiedError(w, http.StatusBadRequest, err)
		return
	}

	var token krt.KeyReleaseToken
	if err := json.Unmarshal(body, &token); err != nil {
		writeClassifiedError(w, http.StatusBadRequest, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crosscloud.HandleToken: invalid JSON body",
			err,
		))
		return
	}

	registered, err := h.receiver.HandleKeyReleaseToken(token)
	if err != nil {
		h.log.Warn("crosscloud token rejected",
			slog.String("err", err.Error()),
			slog.Int("registered_partial", registered),
		)
		writeClassifiedError(w, classifiedErrorStatus(err), err)
		return
	}
	h.log.Info("crosscloud token accepted",
		slog.String("token_id", logSafe(string(token.TokenID))),
		slog.String("request_id", logSafe(string(token.RequestID))),
		slog.String("decision_id", logSafe(string(token.DecisionID))),
		slog.Int("registered_keys", registered),
	)
	writeJSON(w, http.StatusOK, struct {
		Registered int `json:"registered"`
	}{Registered: registered})
}

func (h *HTTPHandler) checkBearer(r *http.Request) bool {
	if h.bearerToken == "" {
		return true
	}
	got := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(got, prefix) {
		return false
	}
	tok := got[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(tok), []byte(h.bearerToken)) == 1
}

func readBody(r *http.Request) ([]byte, error) {
	const maxBody = 4 * 1024 * 1024 // 4 MiB ceiling — token bodies are small
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return nil, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"crosscloud: read body failed",
			err,
		)
	}
	if len(body) > maxBody {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"crosscloud: request body too large",
			nil,
		)
	}
	return body, nil
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeClassifiedError(w, http.StatusMethodNotAllowed, shared_errors.Structural(
		shared_errors.CodeFieldValueInvalid,
		"method not allowed",
		nil,
	))
}

// writeClassifiedError serialises a project-classified error into
// the wire envelope the source HTTPTransport understands.
func writeClassifiedError(w http.ResponseWriter, status int, err error) {
	cat := categoryString(err)
	code := shared_errors.CodeOf(err)
	msg := err.Error()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"category": cat,
			"code":     code,
			"message":  msg,
		},
	})
}

// classifiedErrorStatus maps a project error category to an HTTP
// status code.
func classifiedErrorStatus(err error) int {
	switch {
	case shared_errors.Is(err, shared_errors.CategoryStructural):
		return http.StatusBadRequest
	case shared_errors.Is(err, shared_errors.CategoryAuthority):
		return http.StatusForbidden
	case shared_errors.Is(err, shared_errors.CategoryIntegrity):
		return http.StatusUnprocessableEntity
	case shared_errors.Is(err, shared_errors.CategoryOperational):
		return http.StatusServiceUnavailable
	case shared_errors.Is(err, shared_errors.CategoryIncident):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func categoryString(err error) string {
	switch {
	case shared_errors.Is(err, shared_errors.CategoryStructural):
		return "structural"
	case shared_errors.Is(err, shared_errors.CategoryAuthority):
		return "authority"
	case shared_errors.Is(err, shared_errors.CategoryIntegrity):
		return "integrity"
	case shared_errors.Is(err, shared_errors.CategoryOperational):
		return "operational"
	case shared_errors.Is(err, shared_errors.CategoryIncident):
		return "incident"
	default:
		// Honour a sentinel "no error" case — should not happen on
		// the writeClassifiedError path but defend regardless.
		if errors.Is(err, nil) {
			return ""
		}
		return "unknown"
	}
}

// logSafe keeps a request-supplied identifier on one log line: a carriage
// return or newline inside it would otherwise let a caller forge a record
// in the daemon's log (CodeQL go/log-injection).
func logSafe(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}
