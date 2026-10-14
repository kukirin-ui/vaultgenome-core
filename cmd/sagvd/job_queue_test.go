// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

// testClock is a controllable clock so tests can assert that
// SubmittedAt / StartedAt / CompletedAt carry the expected values.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Since(t time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// assertClockSatisfiesInterface is a compile-time guard that the
// testClock satisfies shared_time.Clock. Without this, a future
// interface-method addition would fail silently at test runtime
// rather than at compile time.
var _ shared_time.Clock = (*testClock)(nil)

const testGenomeID = "genome-0123456789ab-g0-0123456789ab"

// submit queues a fresh job under a minted id with a flow admitted for
// it.
func submit(t *testing.T, q *JobQueue, ta *testAuthority, requestID string) (string, JobView) {
	t.Helper()
	id, err := NewJobID()
	if err != nil {
		t.Fatal(err)
	}
	view, err := q.Submit(id, ta.flow(t, requestID, testGenomeID), testInfo(testGenomeID), aMinute)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return id, view
}

func TestJobQueue_SubmitQueuesTheFlow(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 50*time.Millisecond)
	ta := newTestAuthority(t, nil)

	id, view := submit(t, q, ta, "req-1")
	if len(id) != 32 {
		t.Fatalf("id len = %d want 32", len(id))
	}
	if view.Status != JobStatusQueued || view.ID != id || view.RequestID != "req-1" || view.State != "trust" {
		t.Fatalf("queued view: %+v", view)
	}
	if !view.SubmittedAt.Equal(clock.Now()) {
		t.Fatalf("view.SubmittedAt = %v want %v", view.SubmittedAt, clock.Now())
	}
	if view.StartedAt != nil || view.Deadline != nil || view.ManifestID != "" || view.SessionID != "" {
		t.Fatalf("a queued job has no start, deadline, manifest or session: %+v", view)
	}
	if view.Genome == nil || view.Genome.KeyID != testGenomeID || view.Gate != nil || view.Result != nil {
		t.Fatalf("queued view genome/gate: %+v", view)
	}
	if view.Flow == nil || view.Flow.Request.RequestID != "req-1" || len(view.Flow.Steps) != 2 {
		t.Fatalf("queued view flow: %+v", view.Flow)
	}
	if view.ExpectedOutputKind != string(rjm.OutputKindBytesFixedLength) {
		t.Fatalf("expected_output_kind = %q", view.ExpectedOutputKind)
	}
	if q.Depth() != 1 {
		t.Fatalf("Depth = %d want 1", q.Depth())
	}
}

func TestJobQueue_SubmitRefusesWhatItCannotCarry(t *testing.T) {
	q := NewJobQueue(nil, 50*time.Millisecond)
	ta := newTestAuthority(t, nil)
	flow := ta.flow(t, "req-2", testGenomeID)
	for name, tc := range map[string]struct {
		id       string
		info     genomeInfo
		deadline time.Duration
	}{
		"no id":        {"", testInfo(testGenomeID), aMinute},
		"no gate":      {"a", genomeInfo{Budget: 1}, aMinute},
		"no budget":    {"b", genomeInfo{Gate: &gateSpec{}}, aMinute},
		"no deadline":  {"c", testInfo(testGenomeID), 0},
		"bad deadline": {"d", testInfo(testGenomeID), -time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := q.Submit(tc.id, flow, tc.info, tc.deadline); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := q.Submit("e", nil, testInfo(testGenomeID), aMinute); err == nil {
		t.Fatal("a job without a flow was accepted")
	}
	if q.Depth() != 0 {
		t.Fatalf("Depth = %d want 0 after refused submits", q.Depth())
	}

	// An id is queued once.
	if _, err := q.Submit("dup", flow, testInfo(testGenomeID), aMinute); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Submit("dup", flow, testInfo(testGenomeID), aMinute); err == nil {
		t.Fatal("a job id was queued twice")
	}
}

func TestJobQueue_Next_PopsFIFOAndReturnsTheJob(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 10*time.Millisecond)
	ta := newTestAuthority(t, nil)

	ids := make([]string, 3)
	for i := range ids {
		ids[i], _ = submit(t, q, ta, fmt.Sprintf("req-%d", i))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i, want := range ids {
		job, err := q.Next(ctx)
		if err != nil {
			t.Fatalf("Next[%d]: %v", i, err)
		}
		if job.ID != want {
			t.Fatalf("Next[%d] id = %s want %s (not FIFO)", i, job.ID, want)
		}
		if job.Flow == nil || job.Flow.Request().RequestID.String() != fmt.Sprintf("req-%d", i) || job.Info.Budget != 666 || job.DeadlineFor != aMinute {
			t.Fatalf("Next[%d] job = %+v", i, job)
		}
		view, ok := q.Get(job.ID)
		if !ok {
			t.Fatalf("Get after Next: job missing")
		}
		if view.Status != JobStatusRunning || view.StartedAt == nil {
			t.Fatalf("after Next: %+v", view)
		}
	}
	if q.Depth() != 0 {
		t.Fatalf("Depth after drain = %d want 0", q.Depth())
	}
}

func TestJobQueue_Next_BlocksUntilSubmit(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 20*time.Millisecond)
	ta := newTestAuthority(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type nextResult struct {
		id  string
		err error
	}
	done := make(chan nextResult, 1)
	go func() {
		job, err := q.Next(ctx)
		done <- nextResult{job.ID, err}
	}()

	// Give Next a chance to spin through at least one empty poll.
	time.Sleep(50 * time.Millisecond)
	submitted, _ := submit(t, q, ta, "req-wait")

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("Next err: %v", res.err)
		}
		if res.id != submitted {
			t.Fatalf("Next returned %s want %s", res.id, submitted)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Next did not unblock within 1s after Submit")
	}
}

func TestJobQueue_Next_ContextCancelReturnsErrQueueClosed(t *testing.T) {
	q := NewJobQueue(nil, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := q.Next(ctx)
	if !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Next err = %v want ErrQueueClosed", err)
	}
}

// A job whose worker must attest again goes back to the head of the
// queue untouched; dispatch records the deadline.
func TestJobQueue_RequeueAndDispatch(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 10*time.Millisecond)
	ta := newTestAuthority(t, nil)
	first, _ := submit(t, q, ta, "req-first")
	second, _ := submit(t, q, ta, "req-second")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	job, err := q.Next(ctx)
	if err != nil || job.ID != first {
		t.Fatalf("Next: %v %+v", err, job)
	}
	q.Requeue(first)
	view, _ := q.Get(first)
	if view.Status != JobStatusQueued || view.StartedAt != nil || q.Depth() != 2 {
		t.Fatalf("requeued: %+v depth %d", view, q.Depth())
	}
	job, err = q.Next(ctx)
	if err != nil || job.ID != first {
		t.Fatalf("a requeued job keeps its place: got %s want %s", job.ID, first)
	}
	q.Requeue("no-such-id") // no panic
	q.Requeue(second)       // not running: untouched
	if q.Depth() != 1 {
		t.Fatalf("Depth = %d want 1", q.Depth())
	}

	due := clock.Now().Add(aMinute)
	q.MarkDispatched(first, due)
	view, _ = q.Get(first)
	if view.Deadline == nil || !view.Deadline.Equal(due) {
		t.Fatalf("deadline not recorded: %+v", view.Deadline)
	}
}

func TestJobQueue_CompleteGated_RecordsVerdictsAndWithholdsRefusedOutput(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)}
	q := NewJobQueue(clock, 10*time.Millisecond)
	ta := newTestAuthority(t, nil)
	id, _ := submit(t, q, ta, "req-gate")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := q.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}

	clock.advance(100 * time.Millisecond)
	out := returnpath.CandidateOutput{ManifestID: "m", SessionID: "s", OutputKind: rjm.OutputKindBytesFixedLength, Bytes: []byte("{}"), ProducedAt: clock.Now()}
	top1 := &equivalence.Top1Report{Total: 3, Agreed: 3, Results: []equivalence.Top1Result{{ID: "fx-000", Agree: true}}}
	q.CompleteGated(id, out, "worker-kid-1", GateView{Level: "EXACT", Door: "pinned replay", Fixtures: 3}, top1, nil)
	view, _ := q.Get(id)
	if view.Status != JobStatusSucceeded || view.Result == nil || view.Result.WorkerSigningKeyID != "worker-kid-1" || view.Result.ByteCount != 2 {
		t.Fatalf("released job: %+v", view)
	}
	if view.Gate == nil || view.Gate.Level != "EXACT" || view.Top1 == nil || view.Top1.Agreed != 3 || view.CompletedAt == nil {
		t.Fatalf("released job view lacks its verdicts: %+v", view)
	}
	view.Top1.Results[0].ID = "edited"
	if again, _ := q.Get(id); again.Top1.Results[0].ID != "fx-000" {
		t.Fatal("the view shares the queue's top-1 results")
	}

	// Judged and refused: failed, with the verdicts still on record, the
	// worker that answered named, and the output withheld.
	id2, _ := submit(t, q, ta, "req-gate-2")
	if _, err := q.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}
	q.CompleteGated(id2, out, "worker-kid-1", GateView{Level: "FAIL", Fixtures: 3}, top1,
		shared_errors.Operational(CodeGateFailed, "missed", nil))
	view, _ = q.Get(id2)
	if view.Status != JobStatusFailed || view.Error == nil || view.Error.Code != CodeGateFailed || view.Result != nil {
		t.Fatalf("refused gate job: %+v", view)
	}
	if view.Gate == nil || view.Gate.Level != "FAIL" {
		t.Fatalf("refused gate job view lacks the verdict: %+v", view)
	}
	q.CompleteGated("no-such-id", out, "k", GateView{}, nil, nil) // no panic
}

func TestJobQueue_CompleteFailure_RecordsClassifiedError(t *testing.T) {
	q := NewJobQueue(nil, 10*time.Millisecond)
	ta := newTestAuthority(t, nil)
	id, _ := submit(t, q, ta, "req-fail")

	failErr := shared_errors.Authority("worker_rejected_job", "queue_test: simulated reject", nil)
	q.CompleteFailure(id, failErr)

	view, ok := q.Get(id)
	if !ok {
		t.Fatal("Get missing")
	}
	if view.Status != JobStatusFailed || view.Error == nil || view.Error.Category != "authority" || view.Error.Code != "worker_rejected_job" {
		t.Fatalf("failed job: %+v", view)
	}
	q.CompleteFailure("no-such-id", errors.New("dummy")) // no panic
	if _, ok := q.Get("no-such-id"); ok {
		t.Fatal("Get on missing id returned ok=true")
	}
}

func TestJobQueue_DefaultPollInterval(t *testing.T) {
	q := NewJobQueue(nil, 0)
	if q.pollInterval != 250*time.Millisecond {
		t.Fatalf("pollInterval = %v want 250ms (default)", q.pollInterval)
	}
}

func TestJobQueue_Concurrent_SubmitAndNext(t *testing.T) {
	// Submit N jobs from one goroutine while M Next goroutines drain.
	// All IDs must be returned exactly once, with no deadlock.
	const N = 100
	const M = 4

	q := NewJobQueue(nil, 5*time.Millisecond)
	ta := newTestAuthority(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var submittedMu sync.Mutex
	submitted := make([]string, 0, N)
	go func() {
		for i := 0; i < N; i++ {
			id, err := NewJobID()
			if err != nil {
				t.Errorf("NewJobID: %v", err)
				return
			}
			if _, err := q.Submit(id, ta.flow(t, fmt.Sprintf("req-c-%d", i), testGenomeID), testInfo(testGenomeID), aMinute); err != nil {
				t.Errorf("Submit[%d]: %v", i, err)
				return
			}
			submittedMu.Lock()
			submitted = append(submitted, id)
			submittedMu.Unlock()
		}
	}()

	gotCh := make(chan string, N)
	var wg sync.WaitGroup
	for g := 0; g < M; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				job, err := q.Next(ctx)
				if err != nil {
					return
				}
				gotCh <- job.ID
			}
		}()
	}

	got := make(map[string]bool, N)
	for i := 0; i < N; i++ {
		select {
		case id := <-gotCh:
			if got[id] {
				t.Errorf("id %s delivered twice", id)
			}
			got[id] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("only drained %d/%d jobs within 3s", i, N)
		}
	}
	cancel()
	wg.Wait()

	if len(got) != N {
		t.Fatalf("got %d unique ids want %d", len(got), N)
	}
}
