// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/intake"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
)

// HTTPAPIServer is the operator-facing REST API in front of the
// JobQueue. It owns one net/http.Server and one *metrics.Registry-
// bound set of counters.
//
// Routes:
//
//	POST /v1/jobs         → 202 + {job_id, request_id, state, genome}
//	GET  /v1/jobs/{id}    → 200 + JobView
//
// A job is a gate job (ADR 0013) and a RecoveryRequest into the
// nine-stage flow (ADR 0015): its body names a sealed genome in
// genome.bundle_dir; sagvd opens it, keeps its references, admits the
// request at intake — on the record as REQUEST_RECEIVED before the job
// exists — and queues it. Trust, session, disclosure, manifest, the
// candidate, validation and the release decision follow when a worker
// connects; GET /v1/jobs/{id} shows every stage and every signed
// artifact.
//
// All other paths / methods are 404 / 405. Responses are JSON-only
// (Content-Type: application/json) so SDKs do not have to handle two
// response shapes. Errors carry a classified payload
// {"error":{"category","code","message"}} so the Python SDK can map
// them back onto the same taxonomy the Return Path wire uses.
//
// Authentication: if HTTPAPIConfig.BearerToken is non-empty, every
// request must carry "Authorization: Bearer <token>" with a
// constant-time-matching token. Empty token = no auth — only safe
// for loopback demos.
type HTTPAPIServer struct {
	cfg       HTTPAPIConfig
	runtime   RuntimeConfig
	queue     *JobQueue
	genomes   *genomeJobs              // nil: gate jobs are not configured
	authority *orchestration.Authority // nil only with genomes nil
	clock     shared_time.Clock
	log       *slog.Logger

	listener net.Listener
	server   *http.Server
	metrics  *httpMetrics
}

// httpMetrics is the set of counters the REST API drives. Registered
// once at construction; exposed via the /metrics endpoint on the
// health HTTP server (same Registry is shared).
type httpMetrics struct {
	requests      *metrics.Counter // labels: route, status
	jobsSubmitted *metrics.Counter // unlabeled
}

// NewHTTPAPIServer wires a ready-to-Start server. The caller is
// expected to have already called cfg.Validate(); a non-host:port
// listen address here is a programmer error.
//
// genomes may be nil (genome.bundle_dir not configured): then POST
// /v1/jobs refuses every submission with gate_jobs_disabled. With
// genomes, authority is required: a job is a request admitted into the
// flow, on the record, before it is queued.
func NewHTTPAPIServer(
	cfg HTTPAPIConfig,
	runtime RuntimeConfig,
	queue *JobQueue,
	genomes *genomeJobs,
	authority *orchestration.Authority,
	clock shared_time.Clock,
	registry *metrics.Registry,
	logger *slog.Logger,
) (*HTTPAPIServer, error) {
	if queue == nil {
		return nil, errors.New("sagvd: HTTPAPIServer requires non-nil JobQueue")
	}
	if genomes != nil && authority == nil {
		return nil, errors.New("sagvd: HTTPAPIServer requires the orchestration authority (an audit log) when gate jobs are enabled")
	}
	if clock == nil {
		clock = shared_time.NewSystemClock()
	}
	if registry == nil {
		return nil, errors.New("sagvd: HTTPAPIServer requires non-nil metrics.Registry")
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &HTTPAPIServer{
		cfg:       cfg,
		runtime:   runtime,
		queue:     queue,
		genomes:   genomes,
		authority: authority,
		clock:     clock,
		log:       logger,
		metrics: &httpMetrics{
			requests: registry.NewCounter(
				"sagvd_http_requests_total",
				"Total HTTP requests to the operator REST API, labelled by route and status.",
			),
			jobsSubmitted: registry.NewCounter(
				"sagvd_jobs_submitted_total",
				"Total jobs accepted via POST /v1/jobs.",
			),
		},
	}
	return s, nil
}

// Start binds the listener (if a ListenAddress is configured) and
// launches the serving goroutine. Empty ListenAddress is a no-op:
// the REST API is disabled and in-process callers must drive the
// JobQueue directly (tests, loopback demos).
func (s *HTTPAPIServer) Start() error {
	if s.cfg.ListenAddress == "" {
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("sagvd: HTTP API listen %q: %w", s.cfg.ListenAddress, err)
	}
	s.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/jobs", s.withInstrumentation("/v1/jobs", s.withAuth(s.handleJobsCollection)))
	mux.HandleFunc("/v1/jobs/", s.withInstrumentation("/v1/jobs/{id}", s.withAuth(s.handleJobByID)))

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: s.runtime.HTTPReadHeaderTimeout(),
		WriteTimeout:      s.runtime.HTTPWriteTimeout(),
		// IdleTimeout is generous; operator REST clients may keep
		// connections alive between polls of GET /v1/jobs/{id}.
		IdleTimeout: 60 * time.Second,
	}
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("sagvd: HTTP API server exited with error", "err", err)
		}
	}()
	return nil
}

// Addr returns the bound host:port (useful in tests where the
// configured ListenAddress ends in :0). Returns the configured
// ListenAddress verbatim when the server is not bound.
func (s *HTTPAPIServer) Addr() string {
	if s.listener == nil {
		return s.cfg.ListenAddress
	}
	return s.listener.Addr().String()
}

// Close shuts the HTTP server down with Server.Shutdown, honouring
// ctx's deadline. Safe to call on a never-Started server.
func (s *HTTPAPIServer) Close(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// ---- handlers ------------------------------------------------------------

// handleJobsCollection accepts POST /v1/jobs. GET on the collection
// is not currently supported — listing queued jobs is a later feature
// (pagination, filtering, ownership). The operator knows the job IDs
// they submitted.
func (s *HTTPAPIServer) handleJobsCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	s.submitJob(w, r)
}

// handleJobByID accepts GET /v1/jobs/{id}. Anything else on the
// path is 404/405.
func (s *HTTPAPIServer) handleJobByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
	// strings.TrimPrefix leaves a trailing slash or a nested path
	// visible; both are invalid here.
	if id == "" || strings.ContainsRune(id, '/') {
		writeError(w, http.StatusNotFound, "structural", "not_found", "unknown resource")
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	view, ok := s.queue.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "structural", "job_not_found",
			"no job with id "+id)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// submitRequest is the body shape POST /v1/jobs accepts: which sealed
// genome to bring back, how long the worker has, and how the request
// names itself to the flow.
type submitRequest struct {
	// Genome names a bundle in genome.bundle_dir and, unless its escrow
	// envelope is beside it, its key file.
	Genome genomeRef `json:"genome"`

	// DeadlineSecondsFromNow is how long the worker has to restore the
	// model and answer, from the moment the job is handed to it; 0 takes
	// runtime.default_job_deadline_seconds, which is also the ceiling.
	DeadlineSecondsFromNow int `json:"deadline_seconds_from_now,omitempty"`

	// RequestID names the RecoveryRequest. Minted (req-<hex>) when
	// empty; a request_id already admitted is refused (409).
	RequestID string `json:"request_id,omitempty"`

	// PolicyProfile is the policy envelope the request asks for. The
	// daemon serves "gate" (the default); any other is denied at Trust
	// Admission, on the record.
	PolicyProfile string `json:"policy_profile,omitempty"`

	// RequesterIdentity names who asks. Default "operator:rest".
	RequesterIdentity string `json:"requester_identity,omitempty"`

	// Contour is the request's own key/value context (jurisdiction,
	// role, ...), carried verbatim on the RecoveryRequest and its audit
	// record. Optional; at most 16 entries.
	Contour map[string]string `json:"contour,omitempty"`
}

// Defaults of a submitted request.
const (
	DefaultRequesterIdentity = "operator:rest"
	maxContourEntries        = 16
	maxRequestField          = 128
)

// requestIDRE is what a caller may name a request: letters, digits and
// a few separators, starting with a letter or digit.
var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// maxSubmitBodyBytes bounds a POST /v1/jobs body: it names files, it
// does not carry them.
const maxSubmitBodyBytes = 64 << 10

// submitResponse is what POST /v1/jobs returns on success.
type submitResponse struct {
	JobID     string     `json:"job_id"`
	RequestID string     `json:"request_id"`
	State     string     `json:"state"`
	Genome    GenomeView `json:"genome"`
}

// submitJob parses the body, inspects the named genome — opens the
// bundle, keeps the references, clears the plaintext — admits the
// request at intake (REQUEST_RECEIVED on the record) and enqueues it.
// Returns 202 Accepted on success.
func (s *HTTPAPIServer) submitJob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSubmitBodyBytes)

	var req submitRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "structural", "decode_body",
			"decode request body: "+err.Error())
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "structural", "trailing_data",
			"request body contains trailing data after JSON object")
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, shared_errors.CategoryOf(err).String(),
			shared_errors.CodeOf(err), err.Error())
		return
	}
	if s.genomes == nil {
		writeError(w, http.StatusServiceUnavailable, "structural", CodeGateJobsDisabled,
			"gate jobs are not configured: set genome.bundle_dir")
		return
	}

	// Deadline defaulting + ceiling check. A submitter asking for
	// longer than the configured ceiling is Structurally rejected
	// so that operator-configured SLO bounds are ground truth.
	deadlineSecs := req.DeadlineSecondsFromNow
	if deadlineSecs == 0 {
		deadlineSecs = s.runtime.DefaultJobDeadlineSeconds
	}
	if deadlineSecs > s.runtime.DefaultJobDeadlineSeconds {
		writeError(w, http.StatusBadRequest, "structural", "deadline_exceeds_ceiling",
			fmt.Sprintf("deadline_seconds_from_now %d exceeds ceiling %d",
				deadlineSecs, s.runtime.DefaultJobDeadlineSeconds))
		return
	}
	if deadlineSecs <= 0 {
		writeError(w, http.StatusBadRequest, "structural", "deadline_invalid",
			"deadline_seconds_from_now must be > 0")
		return
	}
	deadline := time.Duration(deadlineSecs) * time.Second

	info, err := s.genomes.inspect(req.Genome)
	if err != nil {
		writeError(w, statusForBuildError(err), shared_errors.CategoryOf(err).String(),
			shared_errors.CodeOf(err), err.Error())
		return
	}
	jobID, err := NewJobID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "operational", shared_errors.CodeResourceExhausted, err.Error())
		return
	}

	// Stage 1: the RecoveryRequest, admitted at intake and on the record
	// before it is queued. A job the log did not take is not a job.
	rr, err := req.recoveryRequest(info, s.clock.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "operational", shared_errors.CodeResourceExhausted, err.Error())
		return
	}
	detail, _ := json.Marshal(struct {
		JobID           string `json:"job_id"`
		Bundle          string `json:"bundle"`
		BundleSHA256    string `json:"bundle_sha256"`
		PayloadSHA256   string `json:"payload_sha256"`
		KeySource       string `json:"key_source"`
		Generation      uint64 `json:"generation"`
		Base            string `json:"base"`
		BaseDigest      string `json:"base_digest"`
		Fixtures        int    `json:"fixtures"`
		Critical        int    `json:"critical"`
		ShippedFiles    int    `json:"shipped_files"`
		ShippedBytes    int64  `json:"shipped_bytes"`
		OutputBudget    uint64 `json:"output_budget_bytes"`
		DeadlineSeconds int    `json:"deadline_seconds"`
	}{jobID, info.View.Bundle, info.View.BundleSHA256, info.View.PayloadSHA256, info.View.KeySource, info.View.Generation,
		info.View.Base, info.View.BaseDigest, info.View.Fixtures, info.View.Critical, info.View.Files, info.View.Bytes, info.Budget, deadlineSecs})
	flow, err := s.authority.Intake(rr, detail)
	if err != nil {
		status := http.StatusBadRequest
		switch shared_errors.CodeOf(err) {
		case intake.CodeDuplicateRequest:
			status = http.StatusConflict
		case orchestration.CodeAuditUnavailable:
			status = http.StatusServiceUnavailable
			s.log.Error("sagvd audit log refused a request", "job_id", jobID, "request_id", logSafe(rr.RequestID.String()), "err", err)
		}
		writeError(w, status, shared_errors.CategoryOf(err).String(), shared_errors.CodeOf(err), err.Error())
		return
	}
	view, err := s.queue.Submit(jobID, flow, info, deadline)
	if err != nil {
		writeError(w, http.StatusBadRequest, shared_errors.CategoryOf(err).String(),
			shared_errors.CodeOf(err), err.Error())
		return
	}
	s.metrics.jobsSubmitted.Inc()
	s.log.Info("sagvd gate job accepted",
		"job_id", jobID,
		"request_id", logSafe(rr.RequestID.String()),
		"policy_profile", logSafe(rr.PolicyProfile),
		"requester", logSafe(rr.RequesterIdentity),
		"genome_id", logSafe(info.GenomeID),
		"bundle", logSafe(info.View.Bundle),
		"key_source", info.View.KeySource,
		"fixtures", info.View.Fixtures,
		"shipped_bytes", info.View.Bytes,
		"output_budget_bytes", info.Budget,
		"deadline_seconds", deadlineSecs,
	)
	writeJSON(w, http.StatusAccepted, submitResponse{
		JobID: jobID, RequestID: rr.RequestID.String(), State: view.State, Genome: info.View,
	})
}

// recoveryRequest is the RecoveryRequest a submission makes: the genome
// the bundle holds, the profile and identity named (or their defaults),
// and the bundle named as contour.
func (r submitRequest) recoveryRequest(info genomeInfo, now time.Time) (recovery_request.RecoveryRequest, error) {
	reqID := ids.RequestID(r.RequestID)
	if reqID.IsZero() {
		minted, err := orchestration.MintRequestID()
		if err != nil {
			return recovery_request.RecoveryRequest{}, err
		}
		reqID = minted
	}
	profile := r.PolicyProfile
	if profile == "" {
		profile = PolicyProfileGate
	}
	identity := r.RequesterIdentity
	if identity == "" {
		identity = DefaultRequesterIdentity
	}
	contour := map[string]string{"bundle": info.View.Bundle, "key_source": info.View.KeySource}
	for k, v := range r.Contour {
		contour[k] = v
	}
	return recovery_request.RecoveryRequest{
		SchemaVersion:     recovery_request.SchemaVersionCurrent,
		RequestID:         reqID,
		GenomeID:          ids.GenomeID(info.GenomeID),
		PolicyProfile:     profile,
		RequesterIdentity: identity,
		Contour:           contour,
		CreatedAt:         now,
	}, nil
}

// statusForBuildError maps a gate-job inspection error to an HTTP
// status: what the caller named is 4xx, what the vault cannot do is
// 5xx.
func statusForBuildError(err error) int {
	switch shared_errors.CodeOf(err) {
	case CodeGenomeNotFound, CodeGenomeInvalid, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeFieldValueInvalid:
		return http.StatusBadRequest
	case CodeGenomeKeyInvalid:
		return http.StatusForbidden
	case CodeGenomeTooLarge:
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}

// validate runs structural checks on the parsed body before any file
// is touched.
func (r submitRequest) validate() error {
	var errs []error
	if strings.TrimSpace(r.Genome.Bundle) == "" {
		errs = append(errs, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome.bundle required", nil))
	}
	if r.DeadlineSecondsFromNow < 0 {
		errs = append(errs, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"deadline_seconds_from_now must be >= 0", nil))
	}
	if r.RequestID != "" && !requestIDRE.MatchString(r.RequestID) {
		errs = append(errs, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"request_id: letters, digits, '.', '_', ':', '-'; at most 128 characters", nil))
	}
	for name, v := range map[string]string{"policy_profile": r.PolicyProfile, "requester_identity": r.RequesterIdentity} {
		if !printableField(v) {
			errs = append(errs, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				name+": printable characters only, at most 128", nil))
		}
	}
	if len(r.Contour) > maxContourEntries {
		errs = append(errs, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("contour: at most %d entries", maxContourEntries), nil))
	}
	for k, v := range r.Contour {
		if k == "" || !printableField(k) || !printableField(v) {
			errs = append(errs, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"contour: keys and values are printable, non-empty keys, at most 128 characters", nil))
			break
		}
	}
	return errors.Join(errs...)
}

// printableField accepts a short string of printable characters (an
// empty one included), so what a caller names reads back as one line.
func printableField(s string) bool {
	if len(s) > maxRequestField {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// ---- middleware ----------------------------------------------------------

// withAuth enforces the optional Bearer token on every write
// endpoint. If the configured token is empty, auth is a no-op.
func (s *HTTPAPIServer) withAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.BearerToken == "" {
			h(w, r)
			return
		}
		got := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(got, prefix) {
			writeError(w, http.StatusUnauthorized, "authority", "auth_missing",
				"missing Bearer credentials")
			return
		}
		token := got[len(prefix):]
		// Constant-time comparison: prevents timing side-channels
		// from revealing the token to a probing client.
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.BearerToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "authority", "auth_invalid",
				"invalid Bearer credentials")
			return
		}
		h(w, r)
	}
}

// withInstrumentation records one http_requests_total{route,status}
// sample per handled request. Status is captured via a thin
// ResponseWriter wrapper; we do not use httptest.ResponseRecorder in
// production because it buffers the whole body — we only need the
// final status code.
func (s *HTTPAPIServer) withInstrumentation(route string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		h(rec, r)
		status := rec.Status()
		s.metrics.requests.Inc(
			metrics.Label{Name: "route", Value: route},
			metrics.Label{Name: "status", Value: strconv.Itoa(status)},
		)
	}
}

// statusRecorder wraps http.ResponseWriter to capture the status
// code WriteHeader was called with. If WriteHeader is never called
// the net/http default (200) is reported via the Write fallback.
type statusRecorder struct {
	http.ResponseWriter
	status int32
}

// WriteHeader records the first code passed; subsequent calls are
// ignored (net/http itself warns on double-WriteHeader — we match
// that behaviour by only remembering the first code).
func (s *statusRecorder) WriteHeader(code int) {
	atomic.CompareAndSwapInt32(&s.status, 0, int32(code))
	s.ResponseWriter.WriteHeader(code)
}

// Write implicitly flushes headers with 200 when WriteHeader has
// not yet been called. We mirror that so Status() reports 200 in
// that case — not 0.
func (s *statusRecorder) Write(b []byte) (int, error) {
	atomic.CompareAndSwapInt32(&s.status, 0, http.StatusOK)
	return s.ResponseWriter.Write(b)
}

// Status returns the recorded status code, defaulting to 200 if
// neither WriteHeader nor Write was ever called.
func (s *statusRecorder) Status() int {
	v := int(atomic.LoadInt32(&s.status))
	if v == 0 {
		return http.StatusOK
	}
	return v
}

// ---- helpers -------------------------------------------------------------

// writeJSON marshals v and writes it with status + Content-Type.
// Marshalling errors are rare (only map-key or circular cases) and
// are surfaced as a 500 so operators see the cause.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w,
			`{"error":{"category":"operational","code":"marshal_failed","message":"response marshal failed"}}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError writes a classified error response. The payload shape
// is stable for SDK consumption: {"error":{category,code,message}}.
func writeError(w http.ResponseWriter, status int, category, code, message string) {
	type envelope struct {
		Error struct {
			Category string `json:"category"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		} `json:"error"`
	}
	var env envelope
	env.Error.Category = category
	env.Error.Code = code
	env.Error.Message = message
	writeJSON(w, status, env)
}

// writeMethodNotAllowed sends 405 with a classified error envelope
// and sets the Allow header to allowed, per RFC 9110 §15.5.5.
func writeMethodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "structural", "method_not_allowed",
		"method not allowed; allowed="+allowed)
}
