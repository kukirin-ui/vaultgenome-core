// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/client"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/server"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	"github.com/vault-genome/vaultgenome-core/internal/genome/gatejob"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/incident"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
)

// daemonFixture is a sagvd Daemon wired in process — its keys, its
// simulated TEE and the pin of a worker's, its audit log, its authority —
// with a sealed genome in its bundle dir and a fake worker that dials
// the Return Path and answers as a restored model would.
type daemonFixture struct {
	t         *testing.T
	clock     shared_time.Clock
	cfg       Config
	mat       *materials
	audit     *returnPathAudit
	authority *orchestration.Authority
	queue     *JobQueue
	genomes   *genomeJobs
	daemon    *Daemon
	registry  *metrics.Registry
	dir       string
	sealed    testGenome

	vaultSim, workerSim *tee.Simulated
	workerStore         *keys.InMemoryStore

	// stop cancels the daemon's context: the test's hand on shutdown.
	stop context.CancelFunc
}

func newDaemonFixture(t *testing.T, mutate func(*Config)) *daemonFixture {
	t.Helper()
	clock := shared_time.NewSystemClock()
	f := &daemonFixture{t: t, clock: clock, dir: t.TempDir(), registry: metrics.NewRegistry()}

	// The vault's keys: the authority signing key and the session-sealing
	// key the workers hold.
	store := keys.NewInMemoryStore(clock)
	authKID := ids.KeyID("authority-test-1")
	authVK, err := store.RegisterSigningFromSeed(authKID, keys.PurposeSigningAuthority, bytes.Repeat([]byte{7}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	sealKID := testRegisterSealing(t, store)

	// Two simulated TEEs, each pinned by the other.
	f.vaultSim, err = tee.NewSimulated([]byte("sagvd-flow-test-v1"), bytes.Repeat([]byte{0xA1}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	f.workerSim, err = tee.NewSimulated([]byte("worker-flow-test-v1"), bytes.Repeat([]byte{0xB2}, crypto.Ed25519SeedSize))
	require.NoError(t, err)

	// The worker's keys: its registered signing key, and the same sealing
	// material as the vault.
	f.workerStore = keys.NewInMemoryStore(clock)
	workerVK, err := f.workerStore.RegisterSigningFromSeed("worker-1", keys.PurposeSigningAuthority, bytes.Repeat([]byte{0xC3}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	testRegisterSealing(t, f.workerStore)

	f.mat = &materials{
		Store: store, AuthoritySigningKeyID: authKID, AuthoritySigningPublicKey: authVK.PublicKey, SessionSealingKeyID: sealKID,
		Producer: f.vaultSim, Provider: tee.ProviderSimulated,
		Verifier: tee.NewSimulatedVerifier(f.workerSim.PublicKey(), f.workerSim.Measurement()), PeerProvider: tee.ProviderSimulated,
		WorkerResolver: server.NewPublicKeyResolver(map[ids.KeyID]keys.VerifyingKey{"worker-1": workerVK}),
	}

	f.cfg = DefaultConfig()
	f.cfg.Vault.ListenAddress = "127.0.0.1:0"
	f.cfg.Vault.TLS.Enabled = false
	f.cfg.Genome.BundleDir = f.dir
	f.cfg.Runtime.JobTimeoutSeconds = 10
	f.cfg.Runtime.HandshakeTimeoutSeconds = 3
	f.cfg.Runtime.QueuePollMs = 10
	f.cfg.Runtime.MaxPayloadBytes = 1 << 20
	f.cfg.Runtime.DefaultJobDeadlineSeconds = 60
	if mutate != nil {
		mutate(&f.cfg)
	}
	f.sealed = sealTestGenome(t, f.dir, genomeOptions{})
	f.genomes = newGenomeJobs(f.cfg, clock, nil)
	f.audit, _ = newTestAuditWith(t, f.registry)
	f.authority, err = orchestration.NewAuthority(orchestration.AuthorityOptions{
		Clock: clock, Signer: store, Sealer: store, Resolver: store, AuthorityKeyID: authKID, RecipientKeyID: sealKID,
		Audit: f.audit.Chain(), AuditSigner: f.audit.Signer(), AuditKeyID: f.audit.KeyID(),
		PolicyVersion: ids.PolicyVersion(f.cfg.PolicyVersion()), Profiles: []string{PolicyProfileGate},
		Zeroizer: incident.ZeroizerFunc(func() {}),
	})
	require.NoError(t, err)
	f.queue = NewJobQueue(clock, f.cfg.Runtime.QueuePoll())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.daemon, err = NewDaemon(f.cfg, f.mat, f.queue, f.genomes, f.audit, clock, logger, f.registry)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	f.stop = cancel
	done := make(chan error, 1)
	go func() { done <- f.daemon.Run(ctx) }()
	require.Eventually(t, func() bool { return f.daemon.Addr() != f.cfg.Vault.ListenAddress }, 5*time.Second, 10*time.Millisecond, "daemon did not bind")
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("daemon did not stop")
		}
		f.daemon.Shutdown()
	})
	return f
}

// submit admits a request for the fixture's genome under profile and
// queues it, as POST /v1/jobs does.
func (f *daemonFixture) submit(profile string) string {
	f.t.Helper()
	info, err := f.genomes.inspect(genomeRef{Bundle: f.sealed.Bundle, KeyFile: f.sealed.KeyFile})
	require.NoError(f.t, err)
	reqID, err := orchestration.MintRequestID()
	require.NoError(f.t, err)
	flow, err := f.authority.Intake(recovery_request.RecoveryRequest{
		SchemaVersion: recovery_request.SchemaVersionCurrent, RequestID: reqID, GenomeID: ids.GenomeID(info.GenomeID),
		PolicyProfile: profile, RequesterIdentity: "operator:test", CreatedAt: f.clock.Now(),
	}, nil)
	require.NoError(f.t, err)
	id, err := NewJobID()
	require.NoError(f.t, err)
	_, err = f.queue.Submit(id, flow, info, time.Minute)
	require.NoError(f.t, err)
	return id
}

// reconstructorFunc is a worker backend made of one function.
type reconstructorFunc func(man rjm.ReconstructionJobManifest, comps []worker.ComponentMaterial) ([]byte, error)

func (fn reconstructorFunc) Reconstruct(_ context.Context, man rjm.ReconstructionJobManifest, comps []worker.ComponentMaterial) (returnpath.CandidateOutput, error) {
	out, err := fn(man, comps)
	if err != nil {
		return returnpath.CandidateOutput{}, err
	}
	return returnpath.CandidateOutput{ManifestID: man.ManifestID, SessionID: man.SessionID, OutputKind: man.ExpectedOutputKind, Bytes: out, ProducedAt: time.Now().UTC()}, nil
}

// worker dials the daemon as acp-compute does — the 4-frame handshake
// with the worker's simulated TEE, the disclosures opened with the
// session-sealing key — and answers one job with answer's bytes. It
// returns ServeOneJob's outcome.
func (f *daemonFixture) worker(ctx context.Context, answer func(genomeID string) []byte) error {
	f.t.Helper()
	conn, err := net.Dial("tcp", f.daemon.Addr())
	require.NoError(f.t, err)
	return f.workerConn(ctx, conn, func(genomeID string) ([]byte, error) { return answer(genomeID), nil })
}

// workerConn is worker over a connection the caller dialed (plain or
// TLS); reconstruct answers the job, or refuses it with an error.
func (f *daemonFixture) workerConn(ctx context.Context, conn net.Conn, reconstruct func(genomeID string) ([]byte, error)) error {
	f.t.Helper()
	sess, err := client.Dial(client.SessionConfig{
		Conn: conn, Producer: f.workerSim, Verifier: tee.NewSimulatedVerifier(f.vaultSim.PublicKey(), f.vaultSim.Measurement()), Clock: f.clock,
		Reconstructor: reconstructorFunc(func(_ rjm.ReconstructionJobManifest, comps []worker.ComponentMaterial) ([]byte, error) {
			desc, err := gatejob.DecodeDescriptor(comps[0].Plaintext)
			if err != nil {
				return nil, err
			}
			return reconstruct(desc.GenomeID)
		}),
		Signer: f.workerStore, SigningKeyID: "worker-1", Opener: client.KeyStoreOpener{Sealer: f.workerStore}, HandshakeTimeout: 3 * time.Second,
	})
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = sess.Close() }()
	return sess.ServeOneJob(ctx)
}

// waitJob polls the queue until the job reaches want.
func (f *daemonFixture) waitJob(id, want string) JobView {
	f.t.Helper()
	var view JobView
	require.Eventually(f.t, func() bool {
		v, ok := f.queue.Get(id)
		view = v
		return ok && string(v.Status) == want
	}, 15*time.Second, 20*time.Millisecond, "job %s did not reach %s", id, want)
	return view
}

func (f *daemonFixture) kinds() []string {
	events := f.audit.chain.Events()
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, string(e.Kind))
	}
	return out
}

func (f *daemonFixture) metric(name string) string {
	var buf bytes.Buffer
	require.NoError(f.t, f.registry.WriteMetricsTo(&buf))
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if bytes.HasPrefix(line, []byte(name)) {
			return string(line)
		}
	}
	return ""
}

var flowKinds = []string{"REQUEST_RECEIVED", "TRUST_EVALUATED", "SESSION_ISSUED",
	"DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED",
	"MANIFEST_ISSUED", "CANDIDATE_RECEIVED", "VALIDATION_STARTED",
	"VALIDATION_DIMENSION_EVALUATED", "VALIDATION_DIMENSION_EVALUATED", "VALIDATION_DIMENSION_EVALUATED"}

// The daemon takes a job through the nine stages in process: the fake
// worker attests, receives the disclosures, answers; the release is
// authorised, signed and on the record. Then a request the vault does not
// serve is denied at trust — a signed refusal, no session.
func TestDaemon_DrivesTheNineStagesInProcess(t *testing.T) {
	f := newDaemonFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	id := f.submit(PolicyProfileGate)
	require.NoError(t, f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, nil) }))
	view := f.waitJob(id, "succeeded")

	require.Equal(t, "release_authorized", view.State)
	require.NotNil(t, view.Result)
	require.Equal(t, f.sealed.rightOutput(t, nil), mustHex(t, view.Result.BytesHex))
	require.Equal(t, "worker-1", view.Result.WorkerSigningKeyID)
	require.NotNil(t, view.Gate)
	require.Equal(t, "EXACT", view.Gate.Level)
	require.Equal(t, "authority-test-1", view.Gate.SignerKeyID)
	require.NotNil(t, view.Top1)
	require.Equal(t, 3, view.Top1.Agreed)
	require.NotNil(t, view.Deadline)
	fl := view.Flow
	require.NotNil(t, fl)
	require.Len(t, fl.Steps, 10)
	require.Len(t, fl.Disclosures, 5)
	require.NotNil(t, fl.Decision)
	require.True(t, fl.Decision.Release)
	require.NoError(t, fl.Decision.VerifySignature(f.mat.Store))
	require.NoError(t, fl.Manifest.VerifySignature(f.mat.Store))
	require.NoError(t, fl.Session.VerifySignature(f.mat.Store))
	require.NoError(t, fl.Attestation.VerifySignature(f.mat.Store))
	require.Equal(t, fl.Manifest.ManifestID.String(), view.ManifestID)
	require.Equal(t, fl.Session.SessionID.String(), view.SessionID)

	want := append(append([]string{}, flowKinds...), "VALIDATION_COMPLETED", "RELEASE_DECIDED")
	require.Equal(t, want, f.kinds())
	require.NoError(t, f.audit.chain.Verify(f.audit.keys))
	require.Equal(t, `sagvd_release_decisions_total{decision="release"} 1`, f.metric(`sagvd_release_decisions_total{decision="release"}`))
	require.Equal(t, `sagvd_jobs_completed_total{outcome="success"} 1`, f.metric(`sagvd_jobs_completed_total{outcome="success"}`))
	require.Equal(t, `sagvd_gate_verdicts_total{level="EXACT"} 1`, f.metric(`sagvd_gate_verdicts_total{level="EXACT"}`))

	// A profile the vault does not serve: admitted at intake, denied at
	// trust when a worker is ready, decided and sealed without a session.
	before := len(f.kinds())
	id2 := f.submit("sovereign-x")
	err := f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, nil) })
	require.ErrorContains(t, err, "Shutdown before any JobRequest", "the worker is sent away without a job")
	view = f.waitJob(id2, "failed")
	require.Equal(t, CodeTrustDenied, view.Error.Code)
	require.Equal(t, "authority", view.Error.Category)
	require.Equal(t, "incident_terminated", view.State)
	require.Nil(t, view.Result)
	require.Nil(t, view.Flow.Session)
	require.Equal(t, "deny", string(view.Flow.Attestation.Outcome))
	require.Equal(t, "trust.policy_profile_not_served", view.Flow.Attestation.Reason)
	require.False(t, view.Flow.Decision.Release)
	require.Equal(t, "trust_denied", string(view.Flow.Decision.Reason))
	require.Equal(t, view.Flow.Attestation.AttestationID, view.Flow.Decision.AttestationID)
	require.Equal(t, []string{"REQUEST_RECEIVED", "TRUST_EVALUATED", "RELEASE_DECIDED"}, f.kinds()[before:])
	require.Equal(t, `sagvd_release_decisions_total{decision="trust_denied"} 1`, f.metric(`sagvd_release_decisions_total{decision="trust_denied"}`))
}

// A model that misses its references is refused: a signed release=false,
// the session closed as an incident, the answer withheld. An answer that
// is not an answer aborts the flow as an integrity incident. A bundle
// that changed between submission and dispatch aborts it at disclosure.
func TestDaemon_RefusesAndAbortsOnTheRecord(t *testing.T) {
	f := newDaemonFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	id := f.submit(PolicyProfileGate)
	require.NoError(t, f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, map[[2]int]float32{{1, 2}: 0.5}) }))
	view := f.waitJob(id, "failed")
	require.Equal(t, CodeGateFailed, view.Error.Code)
	require.Nil(t, view.Result, "a refused answer is withheld")
	require.Equal(t, "FAIL", view.Gate.Level)
	require.Equal(t, "incident_terminated", view.State)
	require.False(t, view.Flow.Decision.Release)
	require.Equal(t, "validation_fail", string(view.Flow.Decision.Reason))
	require.Equal(t, "validation_hard_fail", view.Flow.Incident.Scenario)
	require.Equal(t, "invalidated", string(view.Flow.Session.State))
	want := append(append([]string{}, flowKinds...), "VALIDATION_FINDING", "VALIDATION_FINDING", "VALIDATION_FINDING",
		"VALIDATION_COMPLETED", "RELEASE_DECIDED", "INCIDENT_DETECTED", "SESSION_INVALIDATED", "INCIDENT_TERMINATED")
	require.Equal(t, want, f.kinds())
	require.Equal(t, `sagvd_release_decisions_total{decision="refuse"} 1`, f.metric(`sagvd_release_decisions_total{decision="refuse"}`))

	// Not an answer: the candidate is on record, then the flow aborts.
	before := len(f.kinds())
	id2 := f.submit(PolicyProfileGate)
	require.NoError(t, f.worker(ctx, func(string) []byte { return []byte("not a gate output") }))
	view = f.waitJob(id2, "failed")
	require.Equal(t, CodeGateOutputInvalid, view.Error.Code)
	require.Equal(t, "integrity", view.Error.Category)
	require.Equal(t, "incident_terminated", view.State)
	require.NotNil(t, view.Flow.Abort)
	require.Equal(t, "judge", view.Flow.Abort.Stage)
	require.True(t, view.Flow.Abort.Incident)
	require.Nil(t, view.Flow.Decision)
	tail := f.kinds()[before:]
	require.Equal(t, []string{"CANDIDATE_RECEIVED", "INCIDENT_DETECTED", "SESSION_INVALIDATED"}, tail[len(tail)-3:])

	// The bundle is not the one the job named: the session was issued,
	// nothing was disclosed.
	before = len(f.kinds())
	id3 := f.submit(PolicyProfileGate)
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, f.sealed.Bundle), []byte("no longer the bundle"), 0o644))
	require.Error(t, f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, nil) }), "the worker gets no job")
	view = f.waitJob(id3, "failed")
	require.Equal(t, CodeGenomeInvalid, view.Error.Code)
	require.Equal(t, "disclose", view.Flow.Abort.Stage)
	require.False(t, view.Flow.Abort.Incident)
	require.Equal(t, "invalidated", string(view.Flow.Session.State))
	require.Equal(t, []string{"REQUEST_RECEIVED", "TRUST_EVALUATED", "SESSION_ISSUED", "SESSION_INVALIDATED"}, f.kinds()[before:])
	require.NoError(t, f.audit.chain.Verify(f.audit.keys))
}

// A worker whose Evidence is older than runtime.evidence_max_age when a
// job is ready for it is told to attest again; the job keeps its place
// and the next attested session gets it.
func TestDaemon_StaleEvidenceIsToldToAttestAgain(t *testing.T) {
	f := newDaemonFixture(t, func(c *Config) { c.Runtime.EvidenceMaxAgeSeconds = 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The worker attests and waits for a job that arrives too late.
	stale := make(chan error, 1)
	go func() { stale <- f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, nil) }) }()
	require.Eventually(t, func() bool { return f.metric("sagvd_sessions_opened_total") == "sagvd_sessions_opened_total 1" }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(1500 * time.Millisecond)
	id := f.submit(PolicyProfileGate)
	select {
	case err := <-stale:
		require.Error(t, err, "the stale worker is sent away without a job")
	case <-time.After(10 * time.Second):
		t.Fatal("the stale worker was not sent away")
	}
	view, ok := f.queue.Get(id)
	require.True(t, ok)
	require.Equal(t, JobStatusQueued, view.Status, "the job kept its place")
	require.Equal(t, []string{"REQUEST_RECEIVED", "TRUST_EVALUATED"}, f.kinds())
	require.Contains(t, string(f.audit.chain.Events()[1].Payload), `"code":"evidence_stale"`)

	// A fresh session gets it.
	require.NoError(t, f.worker(ctx, func(string) []byte { return f.sealed.rightOutput(t, nil) }))
	view = f.waitJob(id, "succeeded")
	require.Equal(t, "release_authorized", view.State)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
