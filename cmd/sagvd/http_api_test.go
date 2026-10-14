// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/intake"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
)

// --- test fixtures --------------------------------------------------------

// testHTTPFixture bundles every piece a handler-level test needs:
// a live HTTPAPIServer, the queue behind it, the authority and audit
// log it admits requests through, and a client that talks to its bound
// listener. Cleanup closes the server.
type testHTTPFixture struct {
	server *HTTPAPIServer
	queue  *JobQueue
	client *http.Client
	base   string
	dir    string     // genome.bundle_dir
	genome testGenome // a sealed genome in dir
	audit  *returnPathAudit
	ta     *testAuthority
}

// newTestFixture starts an HTTPAPIServer listening on 127.0.0.1:0
// (OS-assigned port) with the given bearer token, over a bundle dir
// holding one sealed genome. Empty token means auth is disabled.
func newTestFixture(t *testing.T, bearer string) *testHTTPFixture {
	return newTestFixtureWith(t, bearer, true)
}

func newTestFixtureWith(t *testing.T, bearer string, gateJobs bool) *testHTTPFixture {
	t.Helper()

	clock := shared_time.NewSystemClock()
	queue := NewJobQueue(clock, 50*time.Millisecond)
	registry := metrics.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := HTTPAPIConfig{
		ListenAddress: "127.0.0.1:0",
		BearerToken:   bearer,
	}
	runtime := RuntimeConfig{
		HTTPReadHeaderTimeoutSeconds: 5,
		HTTPWriteTimeoutSeconds:      10,
		DefaultJobDeadlineSeconds:    60,
		MaxPayloadBytes:              1 << 20,
	}
	dir := t.TempDir()
	sealed := sealTestGenome(t, dir, genomeOptions{})
	fx := &testHTTPFixture{
		queue:  queue,
		client: &http.Client{Timeout: 5 * time.Second},
		dir:    dir,
		genome: sealed,
	}
	var genomes *genomeJobs
	if gateJobs {
		full := DefaultConfig()
		full.Genome.BundleDir = dir
		full.Runtime = runtime
		genomes = newGenomeJobs(full, clock, nil)
		fx.audit, _ = newTestAudit(t)
		fx.ta = newTestAuthority(t, fx.audit)
	}
	var authority *orchestration.Authority
	if fx.ta != nil {
		authority = fx.ta.authority
	}
	srv, err := NewHTTPAPIServer(cfg, runtime, queue, genomes, authority, clock, registry, logger)
	if err != nil {
		t.Fatalf("NewHTTPAPIServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Close(shutCtx)
	})
	fx.server = srv
	fx.base = "http://" + srv.Addr()
	return fx
}

// --- tests: happy path ----------------------------------------------------

// submitBody is what clients POST to /v1/jobs in these tests.
type submitBody struct {
	Genome                 map[string]string `json:"genome"`
	DeadlineSecondsFromNow int               `json:"deadline_seconds_from_now,omitempty"`
	RequestID              string            `json:"request_id,omitempty"`
	PolicyProfile          string            `json:"policy_profile,omitempty"`
	RequesterIdentity      string            `json:"requester_identity,omitempty"`
	Contour                map[string]string `json:"contour,omitempty"`
}

func (b submitBody) marshal(t *testing.T) []byte {
	t.Helper()
	bs, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal submit body: %v", err)
	}
	return bs
}

// goodSubmit returns a body that names the fixture's sealed genome.
// Individual tests clone and mutate.
func (fx *testHTTPFixture) goodSubmit() submitBody {
	return submitBody{
		Genome:                 map[string]string{"bundle": fx.genome.Bundle, "key_file": fx.genome.KeyFile},
		DeadlineSecondsFromNow: 30,
	}
}

func (fx *testHTTPFixture) post(t *testing.T, body []byte) (*http.Response, []byte) {
	t.Helper()
	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func TestHTTPAPI_PostJobs_HappyPath(t *testing.T) {
	fx := newTestFixture(t, "")

	resp, body := fx.post(t, fx.goodSubmit().marshal(t))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d want 202 (body=%s)", resp.StatusCode, body)
	}
	var out submitResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.JobID) != 32 || !strings.HasPrefix(out.RequestID, "req-") || out.State != "trust" {
		t.Fatalf("response lacks identities: %+v", out)
	}
	if out.Genome.KeyID != fx.genome.KeyID || out.Genome.Fixtures != 3 || out.Genome.KeySource != "key_file" {
		t.Fatalf("genome view: %+v", out.Genome)
	}
	view, ok := fx.queue.Get(out.JobID)
	if !ok {
		t.Fatal("queue missing submitted job")
	}
	if view.Genome == nil || view.Genome.KeyID != fx.genome.KeyID || view.Gate != nil || view.Result != nil {
		t.Fatalf("queued view: %+v", view)
	}
	if view.RequestID != out.RequestID || view.State != "trust" || view.ManifestID != "" || view.SessionID != "" {
		t.Fatalf("queued view identities: %+v", view)
	}
	if view.Flow == nil || len(view.Flow.Steps) != 2 || view.Flow.Request.GenomeID.String() != fx.genome.KeyID ||
		view.Flow.Request.PolicyProfile != PolicyProfileGate || view.Flow.Request.RequesterIdentity != DefaultRequesterIdentity ||
		view.Flow.Request.Contour["bundle"] != fx.genome.Bundle {
		t.Fatalf("queued view flow: %+v", view.Flow)
	}
	if view.ExpectedOutputKind != "bytes/fixed-length" {
		t.Fatalf("expected_output_kind = %q", view.ExpectedOutputKind)
	}
}

// What the caller names — request_id, profile, identity, contour — is
// what the flow carries; a request_id is admitted once.
func TestHTTPAPI_PostJobs_NamesTheRequest(t *testing.T) {
	fx := newTestFixture(t, "")
	body := fx.goodSubmit()
	body.RequestID = "req-ops:2026-09-16.1"
	body.PolicyProfile = "gate"
	body.RequesterIdentity = "operator:alice"
	body.Contour = map[string]string{"jurisdiction": "eu"}

	resp, data := fx.post(t, body.marshal(t))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d want 202 (%s)", resp.StatusCode, data)
	}
	var out submitResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.RequestID != body.RequestID {
		t.Fatalf("request_id = %q want %q", out.RequestID, body.RequestID)
	}
	view, _ := fx.queue.Get(out.JobID)
	if r := view.Flow.Request; r.RequesterIdentity != "operator:alice" || r.Contour["jurisdiction"] != "eu" || r.Contour["bundle"] != fx.genome.Bundle {
		t.Fatalf("request carried: %+v", r)
	}

	// The same request_id again: refused as a duplicate, not queued.
	resp, data = fx.post(t, body.marshal(t))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate request_id: status = %d want 409 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != intake.CodeDuplicateRequest {
		t.Fatalf("code = %s", env.Error.Code)
	}
	if got := fx.queue.Depth(); got != 1 {
		t.Fatalf("depth = %d want 1", got)
	}

	// An unknown profile is admitted here — intake is structural — and
	// denied later at trust, on the record.
	body.RequestID = ""
	body.PolicyProfile = "sovereign-x"
	if resp, data = fx.post(t, body.marshal(t)); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unknown profile at intake: status = %d want 202 (%s)", resp.StatusCode, data)
	}
}

func TestHTTPAPI_GetJobByID_HappyPath(t *testing.T) {
	fx := newTestFixture(t, "")

	_, body := fx.post(t, fx.goodSubmit().marshal(t))
	var submitted submitResponse
	if err := json.Unmarshal(body, &submitted); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}

	resp, err := fx.client.Get(fx.base + "/v1/jobs/" + submitted.JobID)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d want 200 (body=%s)", resp.StatusCode, body)
	}
	var view JobView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.ID != submitted.JobID || view.Status != JobStatusQueued || view.State != "trust" || view.RequestID != submitted.RequestID {
		t.Fatalf("view: %+v", view)
	}
	if view.Genome == nil || view.Genome.Bundle != fx.genome.Bundle {
		t.Fatalf("view.Genome = %+v", view.Genome)
	}
}

func TestHTTPAPI_GetJobByID_NotFound(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, err := fx.client.Get(fx.base + "/v1/jobs/" + strings.Repeat("0", 32))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d want 404", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "job_not_found" {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

// --- tests: validation ----------------------------------------------------

func TestHTTPAPI_PostJobs_RejectsWhatItCannotBuild(t *testing.T) {
	fx := newTestFixture(t, "")
	otherDir := t.TempDir()
	foreign := sealTestGenome(t, otherDir, genomeOptions{name: "foreign"})
	if err := os.Rename(filepath.Join(otherDir, foreign.KeyFile), filepath.Join(fx.dir, "foreign.key")); err != nil {
		t.Fatal(err)
	}
	big := map[string]string{}
	for i := 0; i <= maxContourEntries; i++ {
		big[strings.Repeat("k", i+1)] = "v"
	}
	cases := []struct {
		name     string
		mut      func(*submitBody)
		status   int
		category string
		code     string
	}{
		{"no genome", func(b *submitBody) { b.Genome = nil }, 400, "structural", "required_field_missing"},
		{"no bundle", func(b *submitBody) { delete(b.Genome, "bundle") }, 400, "structural", "required_field_missing"},
		{"bundle is a path", func(b *submitBody) { b.Genome["bundle"] = "../" + fx.genome.Bundle }, 400, "structural", "field_value_invalid"},
		{"bundle absent", func(b *submitBody) { b.Genome["bundle"] = "absent.genome" }, 400, "structural", CodeGenomeNotFound},
		{"key absent", func(b *submitBody) { b.Genome["key_file"] = "absent.key" }, 400, "structural", CodeGenomeNotFound},
		{"wrong key", func(b *submitBody) { b.Genome["key_file"] = "foreign.key" }, 403, "authority", CodeGenomeKeyInvalid},
		{"no key and no escrow", func(b *submitBody) { delete(b.Genome, "key_file") }, 400, "structural", CodeGenomeNotFound},
		{"negative deadline", func(b *submitBody) { b.DeadlineSecondsFromNow = -1 }, 400, "structural", "field_value_invalid"},
		{"deadline above ceiling", func(b *submitBody) { b.DeadlineSecondsFromNow = 3600 }, 400, "structural", "deadline_exceeds_ceiling"},
		{"request_id with a slash", func(b *submitBody) { b.RequestID = "a/b" }, 400, "structural", "field_value_invalid"},
		{"request_id too long", func(b *submitBody) { b.RequestID = strings.Repeat("a", 129) }, 400, "structural", "field_value_invalid"},
		{"identity with a newline", func(b *submitBody) { b.RequesterIdentity = "a\nb" }, 400, "structural", "field_value_invalid"},
		{"contour too big", func(b *submitBody) { b.Contour = big }, 400, "structural", "field_value_invalid"},
		{"contour empty key", func(b *submitBody) { b.Contour = map[string]string{"": "v"} }, 400, "structural", "field_value_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fx.goodSubmit()
			tc.mut(&body)
			resp, data := fx.post(t, body.marshal(t))
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d want %d (body=%s)", resp.StatusCode, tc.status, data)
			}
			env := decodeErrorEnvelope(t, bytes.NewReader(data))
			if env.Error.Category != tc.category || env.Error.Code != tc.code {
				t.Fatalf("error = %s/%s want %s/%s (%s)", env.Error.Category, env.Error.Code, tc.category, tc.code, env.Error.Message)
			}
		})
	}
	if got := fx.queue.Depth(); got != 0 {
		t.Fatalf("refused submissions enqueued work: depth %d", got)
	}
	if n := fx.audit.Len(); n != 0 {
		t.Fatalf("refused submissions were recorded: %d events", n)
	}
}

func TestHTTPAPI_PostJobs_RejectsUnknownFieldsAndOversizedBodies(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, data := fx.post(t, []byte(`{"genome":{"bundle":"x.genome"},"payload_base64":"aGk="}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d want 400 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != "decode_body" {
		t.Fatalf("code = %s (want decode_body)", env.Error.Code)
	}
	resp, data = fx.post(t, []byte(`{"genome":{"bundle":"x.genome"}} {}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d want 400 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != "trailing_data" {
		t.Fatalf("code = %s (want trailing_data)", env.Error.Code)
	}
	huge := []byte(`{"genome":{"bundle":"` + strings.Repeat("a", maxSubmitBodyBytes) + `"}}`)
	resp, _ = fx.post(t, huge)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body: status = %d want 400", resp.StatusCode)
	}
}

// A request is on the audit record before it is queued, under its own
// id; a log that cannot take it refuses the job.
func TestHTTPAPI_PostJobs_IsOnTheRecordFirst(t *testing.T) {
	fx := newTestFixture(t, "")
	_, body := fx.post(t, fx.goodSubmit().marshal(t))
	var out submitResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	events := fx.audit.chain.Events()
	if len(events) != 1 || events[0].Kind != "REQUEST_RECEIVED" || string(events[0].RequestID) != out.RequestID {
		t.Fatalf("audit log after one job: %+v", events)
	}
	payload := string(events[0].Payload)
	for _, want := range []string{`"job_id":"` + out.JobID + `"`, `"genome_id":"` + fx.genome.KeyID + `"`, `"policy_profile":"gate"`, `"output_budget_bytes":`, `"deadline_seconds":30`} {
		if !strings.Contains(payload, want) {
			t.Fatalf("REQUEST_RECEIVED payload lacks %s: %s", want, payload)
		}
	}

	if err := fx.audit.Close(); err != nil {
		t.Fatal(err)
	}
	resp, data := fx.post(t, fx.goodSubmit().marshal(t))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d want 503 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != CodeAuditUnavailable {
		t.Fatalf("code = %s", env.Error.Code)
	}
	if got := fx.queue.Depth(); got != 1 {
		t.Fatalf("a job the log did not take was queued: depth %d", got)
	}
}

func TestHTTPAPI_RequiresTheAuthorityWithGateJobs(t *testing.T) {
	clock := shared_time.NewSystemClock()
	full := DefaultConfig()
	full.Genome.BundleDir = t.TempDir()
	genomes := newGenomeJobs(full, clock, nil)
	_, err := NewHTTPAPIServer(HTTPAPIConfig{}, full.Runtime, NewJobQueue(clock, time.Second), genomes, nil, clock, metrics.NewRegistry(), nil)
	if err == nil {
		t.Fatal("gate jobs without an authority (an audit log) were accepted")
	}
}

func TestHTTPAPI_PostJobs_GateJobsDisabledIs503(t *testing.T) {
	fx := newTestFixtureWith(t, "", false)
	resp, data := fx.post(t, fx.goodSubmit().marshal(t))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d want 503 (%s)", resp.StatusCode, data)
	}
	if env := decodeErrorEnvelope(t, bytes.NewReader(data)); env.Error.Code != CodeGateJobsDisabled {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

// --- tests: method/path routing ------------------------------------------

func TestHTTPAPI_GetJobsCollection_405(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, err := fx.client.Get(fx.base + "/v1/jobs")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q want POST", got)
	}
}

func TestHTTPAPI_PostJobByID_405(t *testing.T) {
	fx := newTestFixture(t, "")
	resp, err := fx.client.Post(fx.base+"/v1/jobs/someid",
		"application/json", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d want 405", resp.StatusCode)
	}
}

// --- tests: bearer auth --------------------------------------------------

func TestHTTPAPI_Auth_MissingCredsIs401(t *testing.T) {
	fx := newTestFixture(t, "top-secret-token")
	resp, err := fx.client.Post(fx.base+"/v1/jobs", "application/json",
		bytes.NewReader(fx.goodSubmit().marshal(t)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "auth_missing" {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

func TestHTTPAPI_Auth_WrongTokenIs401(t *testing.T) {
	fx := newTestFixture(t, "top-secret-token")
	req, _ := http.NewRequest("POST", fx.base+"/v1/jobs",
		bytes.NewReader(fx.goodSubmit().marshal(t)))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := fx.client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401", resp.StatusCode)
	}
	env := decodeErrorEnvelope(t, resp.Body)
	if env.Error.Code != "auth_invalid" {
		t.Fatalf("code = %s", env.Error.Code)
	}
}

func TestHTTPAPI_Auth_RightTokenAccepted(t *testing.T) {
	fx := newTestFixture(t, "top-secret-token")
	req, _ := http.NewRequest("POST", fx.base+"/v1/jobs",
		bytes.NewReader(fx.goodSubmit().marshal(t)))
	req.Header.Set("Authorization", "Bearer top-secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := fx.client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d want 202 (body=%s)", resp.StatusCode, body)
	}
}

func TestHTTPAPI_Auth_GetRequiresToo(t *testing.T) {
	fx := newTestFixture(t, "top-secret-token")
	resp, err := fx.client.Get(fx.base + "/v1/jobs/anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d want 401 for unauthenticated GET", resp.StatusCode)
	}
}

// --- tests: server lifecycle ----------------------------------------------

func TestHTTPAPI_EmptyListenIsNoOp(t *testing.T) {
	cfg := HTTPAPIConfig{ListenAddress: ""}
	runtime := DefaultConfig().Runtime
	clock := shared_time.NewSystemClock()

	srv, err := NewHTTPAPIServer(cfg, runtime, NewJobQueue(clock, runtime.QueuePoll()), nil, nil, clock, metrics.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("NewHTTPAPIServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start empty-listen: %v", err)
	}
	if addr := srv.Addr(); addr != "" {
		t.Fatalf("Addr on empty-listen server = %q want empty", addr)
	}
	if err := srv.Close(context.Background()); err != nil {
		t.Fatalf("Close empty-listen: %v", err)
	}
}

// --- shared helpers -------------------------------------------------------

type errorEnvelope struct {
	Error struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Message  string `json:"message"`
	} `json:"error"`
}

func decodeErrorEnvelope(t *testing.T, r io.Reader) errorEnvelope {
	t.Helper()
	var env errorEnvelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error.Category == "" || env.Error.Code == "" {
		t.Fatalf("error envelope missing category/code: %+v", env)
	}
	return env
}
