// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/validation/reconstruction"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
)

// ---- public status / types -----------------------------------------------

// JobStatus is the lifecycle phase of a submitted job.
type JobStatus string

const (
	// JobStatusQueued — accepted by POST /v1/jobs (intake), waiting for
	// a worker to connect.
	JobStatusQueued JobStatus = "queued"

	// JobStatusRunning — the flow is being driven for this job: trust,
	// session, disclosure, the JobRequest on the wire, the candidate
	// awaited and judged.
	JobStatusRunning JobStatus = "running"

	// JobStatusSucceeded — the flow reached a release decision with
	// release=true; GET /v1/jobs/{id} surfaces the bytes.
	JobStatusSucceeded JobStatus = "succeeded"

	// JobStatusFailed — the flow refused release or ended before a
	// decision. GET /v1/jobs/{id} surfaces {category, code, message}.
	JobStatusFailed JobStatus = "failed"
)

// JobError captures a classified error produced during serving. The
// shape matches what shared_errors yields so operators can correlate
// a 500 on the REST API with a metric label and an audit-chain entry.
type JobError struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// newJobError classifies err through shared_errors and returns the
// wire-ready JobError.
func newJobError(err error) JobError {
	if err == nil {
		return JobError{}
	}
	return JobError{
		Category: shared_errors.CategoryOf(err).String(),
		Code:     shared_errors.CodeOf(err),
		Message:  err.Error(),
	}
}

// Job is one gate job tracked by sagvd: a request admitted into the
// nine-stage flow, the genome it names, and its outcome.
//
// Lifecycle: Queued (intake) → Running (dispatched to a worker) →
// Succeeded or Failed. Terminal states are immutable; no re-queue on
// failure. A job whose worker's Evidence proved too old at dispatch goes
// back to the head of the queue (Requeue) without having started.
type Job struct {
	// ID is a 16-byte hex-encoded random identifier minted before intake,
	// so the audit record of a job names it.
	ID string

	// Status is the current lifecycle phase.
	Status JobStatus

	// Flow is the job's passage through the nine stages (ADR 0015). It
	// is admitted at submission (stage 1) and driven by the dispatcher.
	Flow *orchestration.Flow

	// Info is what the authority keeps about the genome the job named:
	// its view, the references that judge the answer, the answer's exact
	// budget. Never plaintext.
	Info genomeInfo

	// DeadlineFor is how long the worker has from dispatch.
	DeadlineFor time.Duration

	// Deadline is when the worker's answer is due; set at dispatch.
	Deadline time.Time

	// SubmittedAt records when POST /v1/jobs accepted the job.
	SubmittedAt time.Time

	// StartedAt records when the dispatcher picked this job up.
	// Zero until transition to Running.
	StartedAt time.Time

	// CompletedAt records when the dispatcher wrote the terminal
	// outcome. Zero until transition to Succeeded or Failed.
	CompletedAt time.Time

	// Candidate holds the worker's output once release was authorised.
	// Zero-valued otherwise: a refused answer is never surfaced.
	Candidate returnpath.CandidateOutput

	// WorkerSigningKeyID records the kid under which the
	// CandidateOutputFrame was signed, once one arrived.
	WorkerSigningKeyID string

	// Err is the classified error for Failed jobs; zero JobError
	// otherwise.
	Err JobError

	// GateResult is the ladder's verdict once the answer was judged; nil
	// until then.
	GateResult *GateView

	// Top1 is the top-1 agreement once the answer was judged.
	Top1 *equivalence.Top1Report
}

// JobView is the JSON-serialisable projection GET /v1/jobs/{id}
// returns: the job's status, the genome it named, the gate's verdict,
// and the flow — every stage taken and every signed artifact, for an
// operator to verify against the keys `sagvd identity` prints.
type JobView struct {
	ID                 string                  `json:"job_id"`
	RequestID          string                  `json:"request_id"`
	Status             JobStatus               `json:"status"`
	State              string                  `json:"state"`
	SubmittedAt        time.Time               `json:"submitted_at"`
	StartedAt          *time.Time              `json:"started_at,omitempty"`
	CompletedAt        *time.Time              `json:"completed_at,omitempty"`
	ManifestID         string                  `json:"manifest_id,omitempty"`
	SessionID          string                  `json:"session_id,omitempty"`
	ExpectedOutputKind string                  `json:"expected_output_kind"`
	Deadline           *time.Time              `json:"deadline,omitempty"`
	Result             *CandidateView          `json:"result,omitempty"`
	Error              *JobError               `json:"error,omitempty"`
	Genome             *GenomeView             `json:"genome,omitempty"`
	Gate               *GateView               `json:"gate,omitempty"`
	Top1               *equivalence.Top1Report `json:"top1,omitempty"`
	Flow               *orchestration.View     `json:"flow,omitempty"`
}

// CandidateView is the subset of a released CandidateOutput the REST
// API surfaces. Bytes are hex-encoded so the payload is transport-safe
// JSON.
type CandidateView struct {
	OutputKind         string    `json:"output_kind"`
	BytesHex           string    `json:"bytes_hex"`
	ByteCount          int       `json:"byte_count"`
	ProducedAt         time.Time `json:"produced_at"`
	WorkerSigningKeyID string    `json:"worker_signing_key_id"`
}

// toView renders a Job into its JSON-safe projection. Defensive copies
// of the bytes slice so callers cannot mutate queue state.
func (j *Job) toView() JobView {
	view := JobView{
		ID:                 j.ID,
		Status:             j.Status,
		SubmittedAt:        j.SubmittedAt,
		ExpectedOutputKind: string(rjm.OutputKindBytesFixedLength),
	}
	if j.Flow != nil {
		snap := j.Flow.Snapshot()
		view.RequestID = snap.Request.RequestID.String()
		view.State = snap.State.String()
		view.ManifestID = j.Flow.ManifestID().String()
		view.SessionID = j.Flow.SessionID().String()
		view.Flow = &snap
	}
	if !j.StartedAt.IsZero() {
		t := j.StartedAt
		view.StartedAt = &t
	}
	if !j.CompletedAt.IsZero() {
		t := j.CompletedAt
		view.CompletedAt = &t
	}
	if !j.Deadline.IsZero() {
		t := j.Deadline
		view.Deadline = &t
	}
	if j.Status == JobStatusSucceeded {
		view.Result = &CandidateView{
			OutputKind:         string(j.Candidate.OutputKind),
			BytesHex:           hex.EncodeToString(j.Candidate.Bytes),
			ByteCount:          len(j.Candidate.Bytes),
			ProducedAt:         j.Candidate.ProducedAt,
			WorkerSigningKeyID: j.WorkerSigningKeyID,
		}
	}
	if j.Status == JobStatusFailed {
		err := j.Err
		view.Error = &err
	}
	g := j.Info.View
	view.Genome = &g
	if j.GateResult != nil {
		g := *j.GateResult
		g.Attempts = append([]reconstruction.Attempt(nil), j.GateResult.Attempts...)
		view.Gate = &g
	}
	if j.Top1 != nil {
		t := *j.Top1
		t.Results = append([]equivalence.Top1Result(nil), j.Top1.Results...)
		view.Top1 = &t
	}
	return view
}

// ---- queue ---------------------------------------------------------------

// JobQueue is a mutex-guarded in-memory FIFO of pending Jobs plus a
// map of every job ever seen (for GET /v1/jobs/{id} lookups).
//
// Scope / lifetime: process-local. A restart loses queued jobs; this
// is acceptable because gate jobs are idempotent and operators resubmit
// (the audit log keeps what was decided). A bbolt-backed durable queue
// lands with the broader persistence layer.
//
// Concurrency: safe for concurrent use. Next blocks until either a job
// is available or the context is cancelled.
type JobQueue struct {
	mu sync.Mutex
	// jobs is every job the queue has ever seen, indexed by ID.
	// Jobs stay in the map after completion so GET /v1/jobs/{id}
	// still works. A TTL sweep lands with persistence.
	jobs map[string]*Job
	// pending is the FIFO order of queued job IDs. When a job
	// transitions out of Queued, it is removed from pending but
	// stays in jobs.
	pending []string

	clock shared_time.Clock
	// pollInterval bounds how often Next() re-checks under its
	// lock. Operators can tune this via Runtime.QueuePollMs.
	pollInterval time.Duration
}

// NewJobQueue constructs a fresh queue. clock may be nil (SystemClock
// is substituted). pollInterval must be > 0 — callers typically pass
// cfg.Runtime.QueuePoll().
func NewJobQueue(clock shared_time.Clock, pollInterval time.Duration) *JobQueue {
	if clock == nil {
		clock = shared_time.NewSystemClock()
	}
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}
	return &JobQueue{
		jobs:         make(map[string]*Job),
		clock:        clock,
		pollInterval: pollInterval,
	}
}

// NewJobID mints a job id ahead of submission, so the audit record of
// a job can name it before the job exists.
func NewJobID() (string, error) {
	id, err := newJobID()
	if err != nil {
		return "", fmt.Errorf("sagvd: allocate job id: %w", err)
	}
	return id, nil
}

// Submit enqueues an admitted job under its pre-minted id (NewJobID):
// the flow intake produced, the genome it named, and how long the worker
// will have. An id already in the queue is refused.
func (q *JobQueue) Submit(id string, flow *orchestration.Flow, info genomeInfo, deadline time.Duration) (JobView, error) {
	if id == "" {
		return JobView{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "sagvd: job id required", nil)
	}
	if flow == nil {
		return JobView{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "sagvd: a job needs its flow", nil)
	}
	if deadline <= 0 {
		return JobView{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: a job needs a positive deadline", nil)
	}
	if info.Gate == nil || info.Budget == 0 {
		return JobView{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "sagvd: a job needs its genome's references and budget", nil)
	}
	now := q.clock.Now().UTC()
	j := &Job{
		ID:          id,
		Status:      JobStatusQueued,
		Flow:        flow,
		Info:        info,
		DeadlineFor: deadline,
		SubmittedAt: now,
	}
	q.mu.Lock()
	if _, dup := q.jobs[id]; dup {
		q.mu.Unlock()
		return JobView{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "sagvd: job id already queued", nil)
	}
	q.jobs[id] = j
	q.pending = append(q.pending, id)
	view := j.toView() // render under the lock; Next may flip j.Status concurrently
	q.mu.Unlock()
	return view, nil
}

// Get returns the view for a job by ID. The bool is false if no such
// job exists.
func (q *JobQueue) Get(id string) (JobView, bool) {
	q.mu.Lock()
	j, ok := q.jobs[id]
	if !ok {
		q.mu.Unlock()
		return JobView{}, false
	}
	view := j.toView()
	q.mu.Unlock()
	return view, true
}

// Depth reports the count of pending (not-yet-dispatched) jobs. Used
// by the queue_depth gauge.
func (q *JobQueue) Depth() int {
	q.mu.Lock()
	n := len(q.pending)
	q.mu.Unlock()
	return n
}

// ErrQueueClosed is returned from Next when the context is cancelled.
var ErrQueueClosed = errors.New("sagvd: job queue: context done")

// Next blocks until a queued job is available, marks it Running, and
// returns a copy of it (the flow is shared; the queue's own record is
// only written through the queue). On ctx.Done returns ErrQueueClosed.
//
// Polling model: Next acquires the mutex, checks the head of the
// pending slice, and either returns immediately or releases the lock
// and sleeps for pollInterval before retrying.
func (q *JobQueue) Next(ctx context.Context) (Job, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Job{}, ErrQueueClosed
		}
		q.mu.Lock()
		if len(q.pending) > 0 {
			id := q.pending[0]
			q.pending = q.pending[1:]
			j, ok := q.jobs[id]
			if !ok {
				// Should never happen: we keep them in sync, but a
				// belt-and-suspenders check keeps the invariant
				// visible to future maintainers.
				q.mu.Unlock()
				continue
			}
			j.Status = JobStatusRunning
			j.StartedAt = q.clock.Now().UTC()
			cp := *j
			q.mu.Unlock()
			return cp, nil
		}
		q.mu.Unlock()

		// Lockless wait for the next poll tick or ctx cancellation.
		select {
		case <-ctx.Done():
			return Job{}, ErrQueueClosed
		case <-time.After(q.pollInterval):
		}
	}
}

// Requeue puts a running job back at the head of the queue, untouched:
// the worker it was about to go to must attest again first.
func (q *JobQueue) Requeue(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok || j.Status != JobStatusRunning {
		return
	}
	j.Status = JobStatusQueued
	j.StartedAt = time.Time{}
	q.pending = append([]string{id}, q.pending...)
}

// MarkDispatched records when the worker's answer is due, once the
// JobRequest is about to leave the vault.
func (q *JobQueue) MarkDispatched(id string, deadline time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if j, ok := q.jobs[id]; ok {
		j.Deadline = deadline.UTC()
	}
}

// CompleteGated records a judged job's outcome: the ladder's verdict and
// the top-1 agreement, and with a nil err the worker's output as the
// released result; with err the job failed on that classified error,
// the verdicts still on record and the output withheld.
func (q *JobQueue) CompleteGated(id string, out returnpath.CandidateOutput, workerKID string, gate GateView, top1 *equivalence.Top1Report, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok {
		return
	}
	j.CompletedAt = q.clock.Now().UTC()
	j.GateResult = &gate
	j.Top1 = top1
	j.WorkerSigningKeyID = workerKID
	if err != nil {
		j.Status = JobStatusFailed
		j.Err = newJobError(err)
		return
	}
	j.Status = JobStatusSucceeded
	j.Candidate = out
}

// CompleteFailure records a classified failure. err is mapped through
// newJobError.
func (q *JobQueue) CompleteFailure(id string, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	j, ok := q.jobs[id]
	if !ok {
		return
	}
	j.Status = JobStatusFailed
	j.CompletedAt = q.clock.Now().UTC()
	j.Err = newJobError(err)
}

// newJobID returns a 32-char hex ID (16 random bytes). Collisions are
// cryptographically improbable within a single process lifetime.
func newJobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
