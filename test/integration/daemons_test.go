//go:build integration

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	workerSigningKID = "acp-compute-worker-demo"
	vaultDescriptor  = "sagvd-phase1-demo-v1"
	workerDescriptor = "acp-compute-phase1-demo-v1"
	jobOutputKind    = "bytes/fixed-length"

	startupTimeout = 30 * time.Second
	jobTimeout     = 60 * time.Second
)

// bins holds the binaries TestMain builds once per run.
var bins struct {
	sagvd, worker, bootstrap, acpctl, keygen, fakedoor string
}

func TestMain(m *testing.M) {
	code, err := buildAndRun(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func buildAndRun(m *testing.M) (int, error) {
	root, err := moduleRoot()
	if err != nil {
		return 0, err
	}
	dir, err := os.MkdirTemp("", "acp-integration-bin-")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	bins.sagvd = filepath.Join(dir, "sagvd")
	bins.worker = filepath.Join(dir, "acp-compute")
	bins.bootstrap = filepath.Join(dir, "acp-bootstrap")
	bins.acpctl = filepath.Join(dir, "acpctl")
	bins.keygen = filepath.Join(dir, "keygen")
	bins.fakedoor = filepath.Join(dir, "fakedoor")
	for _, b := range []struct{ out, dir, pkg string }{
		{bins.sagvd, root, "./cmd/sagvd"},
		{bins.worker, root, "./cmd/acp-compute"},
		{bins.bootstrap, root, "./cmd/acp-bootstrap"},
		{bins.acpctl, root, "./cmd/acpctl"},
		{bins.keygen, filepath.Join(root, "deploy", "compose", "keygen"), "."},
		{bins.fakedoor, root, "./test/integration/fakedoor"},
	} {
		cmd := exec.Command("go", "build", "-o", b.out, b.pkg)
		cmd.Dir = b.dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return 0, fmt.Errorf("go build %s: %w\n%s", b.pkg, err, out)
		}
	}
	return m.Run(), nil
}

// moduleRoot walks up from the working directory to the core module root.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && bytes.HasPrefix(data, []byte("module github.com/vault-genome/vaultgenome-core\n")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("core module root not found above working directory")
		}
		dir = parent
	}
}

// ---- tests ------------------------------------------------------------------

// A gate job submitted over the authenticated REST API names a sealed
// genome; sagvd opens it, ships its model side sealed over mutual TLS to
// a worker that proves its pinned TEE identity, the worker restores the
// model through its door and answers, and sagvd holds the answer to the
// sealed references: the job succeeds with a signed EXACT verdict.
func TestLiveDaemons_JobRoundTripOverMTLS(t *testing.T) {
	secrets := keygen(t)
	v := startVault(t, secrets)
	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")

	sealed := v.sealGenome(t, "gen-0", true)
	id, accepted := v.submitGenome(t, sealed)
	if accepted.Genome.KeyID != sealed.keyID || accepted.Genome.Fixtures != 3 || accepted.Genome.KeySource != "key_file" {
		t.Fatalf("accepted genome view: %+v", accepted.Genome)
	}
	job := v.waitJob(t, id, "succeeded", jobTimeout)
	if job.Result == nil || job.Result.ByteCount == 0 {
		t.Fatalf("succeeded job carries no result: %+v", job)
	}
	if job.Result.WorkerSigningKeyID != workerSigningKID {
		t.Fatalf("result signed by %q, want %q", job.Result.WorkerSigningKeyID, workerSigningKID)
	}
	if job.Result.OutputKind != jobOutputKind {
		t.Fatalf("output kind %q, want %q", job.Result.OutputKind, jobOutputKind)
	}
	raw, err := hex.DecodeString(job.Result.BytesHex)
	if err != nil || len(raw) != job.Result.ByteCount {
		t.Fatalf("result bytes_hex inconsistent with byte_count=%d (decode err %v)", job.Result.ByteCount, err)
	}
	if !bytes.Contains(raw, []byte(`"schema":"vault-genome/gate-output/v1"`)) || !bytes.Contains(raw, []byte(sealed.keyID)) {
		t.Fatalf("result is not a gate output for %s: %s", sealed.keyID, raw)
	}
	if job.Gate == nil || job.Gate.Level != "EXACT" || job.Gate.Door != "pinned replay" || job.Gate.Rung != 0 || job.Gate.Fixtures != 3 {
		t.Fatalf("gate verdict: %+v", job.Gate)
	}
	if job.Gate.SignedVerdict == nil || len(job.Gate.SignedVerdict.Signature) == 0 || job.Gate.SignerKeyID != "sagvd-authority-demo" {
		t.Fatalf("the verdict is not signed by the authority: %+v", job.Gate)
	}
	if job.Gate.SignedVerdict.Verdict.NExact != 3 || job.Gate.SignedVerdict.Verdict.GenomeID != sealed.keyID {
		t.Fatalf("signed verdict: %+v", job.Gate.SignedVerdict.Verdict)
	}
	if job.Genome == nil || job.Genome.KeyID != sealed.keyID {
		t.Fatalf("job view lacks its genome: %+v", job.Genome)
	}
	if got := v.counter(t, `sagvd_jobs_completed_total{outcome="success"}`); got < 1 {
		t.Fatalf("sagvd_jobs_completed_total{outcome=\"success\"} = %d, want >= 1", got)
	}
	if got := v.counter(t, `sagvd_gate_verdicts_total{level="EXACT"}`); got < 1 {
		t.Fatalf("sagvd_gate_verdicts_total{level=\"EXACT\"} = %d, want >= 1", got)
	}
	if got := v.counter(t, `sagvd_sessions_opened_total`); got < 1 {
		t.Fatalf("sagvd_sessions_opened_total = %d, want >= 1", got)
	}
	if got := v.counter(t, `sagvd_audit_events_total{kind="VALIDATION_COMPLETED"}`); got != 1 {
		t.Fatalf("sagvd_audit_events_total{kind=\"VALIDATION_COMPLETED\"} = %d, want 1", got)
	}
	if got := v.counter(t, `sagvd_release_decisions_total{decision="release"}`); got != 1 {
		t.Fatalf("sagvd_release_decisions_total{decision=\"release\"} = %d, want 1", got)
	}

	// The job view shows the whole flow: every stage taken, the signed
	// artifacts, the release decision.
	if job.RequestID != accepted.RequestID || job.State != "release_authorized" || job.ManifestID == "" || job.SessionID == "" {
		t.Fatalf("job view identities: %+v", job)
	}
	f := job.Flow
	if f == nil || f.State != "release_authorized" || len(f.Steps) != 10 || len(f.Disclosures) != 5 {
		t.Fatalf("job view flow: %+v", f)
	}
	if f.Attestation == nil || f.Attestation.Outcome != "allow" || f.Session == nil || f.Session.State != "active" ||
		f.Validation == nil || f.Validation.OverallVerdict != "pass" {
		t.Fatalf("job view flow artifacts: %+v", f)
	}
	if f.Decision == nil || !f.Decision.Release || f.Decision.Reason != "validation_pass" || f.Decision.AuditEventID == "" || len(f.Decision.Signature) == 0 || len(f.AuditTip) != 64 {
		t.Fatalf("job view decision: %+v", f.Decision)
	}

	// Every decision is on the record, in order, correlated to the
	// request, and the log verifies under the audit key the vault
	// publishes.
	kinds, events := v.auditLogAfterStop(t)
	want := append(append([]string{}, flowKinds...), "VALIDATION_COMPLETED", "RELEASE_DECIDED")
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("audit kinds %v, want %v", kinds, want)
	}
	for i, e := range events {
		if e.RequestID != accepted.RequestID && e.Kind != "DISCLOSURE_AUTHORIZED" && !strings.HasPrefix(e.Kind, "VALIDATION_") {
			t.Fatalf("event %d %s is not correlated to the request: %+v", i, e.Kind, e)
		}
		if i >= 3 && e.SessionID != job.SessionID {
			t.Fatalf("event %d %s is not correlated to the session: %+v", i, e.Kind, e)
		}
		if i >= 8 && e.Kind != "DISCLOSURE_AUTHORIZED" && e.ManifestID != job.ManifestID {
			t.Fatalf("event %d %s is not correlated to the manifest: %+v", i, e.Kind, e)
		}
	}
	trust, done, decided := events[1], lastOfKind(t, events, "VALIDATION_COMPLETED"), lastOfKind(t, events, "RELEASE_DECIDED")
	if !strings.Contains(string(trust.Payload), `"outcome":"allow"`) || !strings.Contains(string(done.Payload), `"overall_verdict":"pass"`) ||
		!strings.Contains(string(decided.Payload), `"release":true`) || !strings.Contains(string(decided.Payload), `"reason":"validation_pass"`) {
		t.Fatalf("audit payloads: trust %s / completed %s / decided %s", trust.Payload, done.Payload, decided.Payload)
	}
	if !strings.Contains(string(events[12].Payload), `"evaluator":"top1-agreement"`) || !strings.Contains(string(events[13].Payload), `"evaluator":"equivalence-ladder"`) ||
		!strings.Contains(string(events[13].Payload), `"level":"EXACT"`) {
		t.Fatalf("dimension payloads: semantic %s / behavioral %s", events[12].Payload, events[13].Payload)
	}
	if decided.Payload == nil || f.Decision.AuditEventID == "" {
		t.Fatalf("decision not evidenced: %s", decided.Payload)
	}
}

// A genome whose sealed references the restored model does not reproduce
// fails its gate: the job fails on the record's terms, the verdict on the
// job says FAIL at every door, and nothing is signed.
func TestLiveDaemons_GateRefusesAModelThatMissesItsReferences(t *testing.T) {
	secrets := keygen(t)
	v := startVault(t, secrets)
	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")

	sealed := v.sealGenome(t, "gen-wrong", false)
	id, _ := v.submitGenome(t, sealed)
	job := v.waitJob(t, id, "failed", jobTimeout)
	if job.Error == nil || job.Error.Code != "gate_failed" || job.Error.Category != "operational" {
		t.Fatalf("failed job error: %+v", job.Error)
	}
	if job.Gate == nil || job.Gate.Level != "FAIL" || len(job.Gate.Attempts) != 2 || job.Gate.SignedVerdict != nil {
		t.Fatalf("gate verdict: %+v", job.Gate)
	}
	if job.Result != nil {
		t.Fatalf("a refused model must not be a result: %+v", job.Result)
	}
	if got := v.counter(t, `sagvd_gate_verdicts_total{level="FAIL"}`); got < 1 {
		t.Fatalf("sagvd_gate_verdicts_total{level=\"FAIL\"} = %d, want >= 1", got)
	}
	if got := v.counter(t, `sagvd_jobs_completed_total{outcome="reject"}`); got < 1 {
		t.Fatalf("sagvd_jobs_completed_total{outcome=\"reject\"} = %d, want >= 1", got)
	}

	// A wrong key opens nothing: refused at submission, never queued.
	other := v.sealGenome(t, "gen-other", true)
	body, err := json.Marshal(map[string]any{"genome": map[string]string{"bundle": sealed.bundle, "key_file": other.keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	status, resp := v.do(t, http.MethodPost, "/v1/jobs", v.token, body)
	if status != http.StatusForbidden || !bytes.Contains(resp, []byte("genome_key_invalid")) {
		t.Fatalf("wrong key: status %d body %s", status, resp)
	}

	// The refusal is a decision: the flow ends on a signed release=false,
	// the session is closed as an incident.
	if job.State != "incident_terminated" || job.Flow == nil || job.Flow.Decision == nil || job.Flow.Decision.Release ||
		job.Flow.Decision.Reason != "validation_fail" || job.Flow.Incident == nil || job.Flow.Incident.Scenario != "validation_hard_fail" ||
		job.Flow.Session == nil || job.Flow.Session.State != "invalidated" {
		t.Fatalf("refused job flow: state %s %+v", job.State, job.Flow)
	}

	// On the record: the findings before the failed verdict, the refusal
	// decided, the incident closed — and no job for the refused
	// submission.
	kinds, events := v.auditLogAfterStop(t)
	want := append(append([]string{}, flowKinds...), "VALIDATION_FINDING", "VALIDATION_FINDING", "VALIDATION_FINDING",
		"VALIDATION_COMPLETED", "RELEASE_DECIDED", "INCIDENT_DETECTED", "SESSION_INVALIDATED", "INCIDENT_TERMINATED")
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("audit kinds %v, want %v", kinds, want)
	}
	done, decided := lastOfKind(t, events, "VALIDATION_COMPLETED"), lastOfKind(t, events, "RELEASE_DECIDED")
	if !strings.Contains(string(done.Payload), `"overall_verdict":"fail"`) || !strings.Contains(string(done.Payload), `"behavioral_verdict":"fail"`) {
		t.Fatalf("VALIDATION_COMPLETED payload: %s", done.Payload)
	}
	if !strings.Contains(string(decided.Payload), `"release":false`) || !strings.Contains(string(decided.Payload), `"reason":"validation_fail"`) {
		t.Fatalf("RELEASE_DECIDED payload: %s", decided.Payload)
	}
}

// With key escrow the bundle directory holds no key at all: the sealer
// encapsulated the genome's key to the authority, and sagvd opens the
// envelope with its escrow key to build the job.
func TestLiveDaemons_EscrowedGenomeNeedsNoKeyFile(t *testing.T) {
	secrets := keygen(t)
	escrowKey := filepath.Join(t.TempDir(), "escrow.key")
	escrowPub := filepath.Join(t.TempDir(), "escrow.pem")
	acpctl(t, "escrow", "keygen", "--out", escrowKey, "--pub", escrowPub)
	v := startVaultWith(t, secrets, func(cfg map[string]any) {
		cfg["genome"].(map[string]any)["key_escrow_path"] = escrowKey
	})
	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")

	dir := writeModelGenome(t, true)
	bundle := filepath.Join(v.bundleDir, "escrowed.genome")
	acpctl(t, "genome", "seal", "--content-dir", dir, "--output", bundle, "--escrow-to", escrowPub)
	entries, err := os.ReadDir(v.bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			t.Fatalf("a key file in the bundle dir: %s", e.Name())
		}
	}
	body, err := json.Marshal(map[string]any{"genome": map[string]string{"bundle": "escrowed.genome"}})
	if err != nil {
		t.Fatal(err)
	}
	status, resp := v.do(t, http.MethodPost, "/v1/jobs", v.token, body)
	if status != http.StatusAccepted {
		t.Fatalf("POST /v1/jobs: status %d body %s", status, resp)
	}
	var accepted submitView
	if err := json.Unmarshal(resp, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Genome.KeySource != "escrow" {
		t.Fatalf("key source %q, want escrow", accepted.Genome.KeySource)
	}
	job := v.waitJob(t, accepted.JobID, "succeeded", jobTimeout)
	if job.Gate == nil || job.Gate.Level != "EXACT" {
		t.Fatalf("gate verdict: %+v", job.Gate)
	}
}

// The REST API refuses callers without the bearer token or with a wrong
// one, on both the write and the read endpoint.
func TestLiveDaemons_RESTRejectsMissingOrWrongToken(t *testing.T) {
	v := startVault(t, keygen(t))
	body := jobBody(t, v.sealGenome(t, "gen-auth", true))
	for _, tc := range []struct {
		name, token, wantCode string
	}{
		{"missing token", "", "auth_missing"},
		{"wrong token", strings.Repeat("0", 64), "auth_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, resp := v.do(t, http.MethodPost, "/v1/jobs", tc.token, body)
			if status != http.StatusUnauthorized || !bytes.Contains(resp, []byte(tc.wantCode)) {
				t.Fatalf("POST /v1/jobs: status %d body %s, want 401 %s", status, resp, tc.wantCode)
			}
			if status, resp = v.do(t, http.MethodGet, "/v1/jobs/any-id", tc.token, nil); status != http.StatusUnauthorized {
				t.Fatalf("GET /v1/jobs/{id}: status %d body %s, want 401", status, resp)
			}
		})
	}
	if got := v.counter(t, `sagvd_jobs_submitted_total`); got != 0 {
		t.Fatalf("unauthenticated requests enqueued work: sagvd_jobs_submitted_total = %d", got)
	}
}

// The Return Path completes a TLS session only for a client certificate
// issued by the deployment CA; the server counts every refusal.
func TestLiveDaemons_ReturnPathRequiresTrustedClientCert(t *testing.T) {
	secrets := keygen(t)
	v := startVault(t, secrets)
	roots := certPool(t, filepath.Join(secrets, "shared", "tls", "ca.crt"))
	foreign := keygen(t) // an independent CA the vault does not trust
	foreignPair, err := tls.LoadX509KeyPair(
		filepath.Join(foreign, "acp-compute", "tls", "client.crt"),
		filepath.Join(foreign, "acp-compute", "tls", "client.key"))
	if err != nil {
		t.Fatal(err)
	}

	before := v.counter(t, `sagvd_handshake_failures_total{phase="tls"}`)
	for _, tc := range []struct {
		name  string
		certs []tls.Certificate
	}{
		{"no client certificate", nil},
		{"client certificate from a foreign CA", []tls.Certificate{foreignPair}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tlsProbe(v.vaultAddr, &tls.Config{
				RootCAs: roots, ServerName: "localhost", Certificates: tc.certs, MinVersion: tls.VersionTLS13,
			})
			var ne net.Error
			if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
				t.Fatalf("Return Path accepted the TLS session (err=%v)", err)
			}
		})
	}
	waitFor(t, 5*time.Second, "server-side TLS refusals counted", func() bool {
		return v.counter(t, `sagvd_handshake_failures_total{phase="tls"}`) >= before+2
	})
}

// A worker holding a valid mTLS client certificate and the session
// sealing key — but not the pinned TEE key — is refused at the Return
// Path handshake and never handed work. The job is held, not lost: the
// pinned worker receives it afterwards.
func TestLiveDaemons_UnpinnedWorkerIsRefusedWork(t *testing.T) {
	secrets := keygen(t)
	rogueTEE := keygen(t)
	v := startVault(t, secrets)

	rogue, rogueHealth := v.startWorker(t, "rogue-worker", workerIdentity{tlsFrom: secrets, teeFrom: rogueTEE})
	waitReady(t, rogue, rogueHealth+"/healthz")

	before := v.counter(t, `sagvd_handshake_failures_total{phase="handshake"}`)
	id, _ := v.submitGenome(t, v.sealGenome(t, "gen-held", true))
	waitFor(t, 20*time.Second, "rogue worker refused at the Return Path handshake", func() bool {
		return v.counter(t, `sagvd_handshake_failures_total{phase="handshake"}`) > before
	})
	if job := v.job(t, id); job.Status != "queued" {
		t.Fatalf("job reached %q while only an unpinned worker was connected, want queued", job.Status)
	}
	if got := v.counter(t, `sagvd_sessions_opened_total`); got != 0 {
		t.Fatalf("a Return Path session opened for the unpinned worker (sessions_opened_total = %d)", got)
	}

	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")
	job := v.waitJob(t, id, "succeeded", jobTimeout)
	if job.Result == nil || job.Result.WorkerSigningKeyID != workerSigningKID {
		t.Fatalf("held job not delivered by the pinned worker: %+v", job)
	}

	// The refusal is on the record, ahead of the admission.
	if took, killed := rogue.stop(); killed {
		t.Fatalf("rogue worker had to be killed after %s", took)
	}
	kinds, events := v.auditLogAfterStop(t)
	var denied, allowed int
	for i, e := range events {
		if e.Kind != "TRUST_EVALUATED" {
			continue
		}
		switch {
		case strings.Contains(string(e.Payload), `"outcome":"deny"`):
			denied++
			if e.SessionID != "" {
				t.Fatalf("a refused peer is not a job: %+v", e)
			}
		case strings.Contains(string(e.Payload), `"outcome":"allow"`):
			allowed++
			if denied == 0 {
				t.Fatalf("admission before any refusal at event %d: %v", i, kinds)
			}
		}
	}
	if denied == 0 || allowed != 1 {
		t.Fatalf("trust decisions on record: %d denied, %d allowed (%v)", denied, allowed, kinds)
	}
}

// The operator's stop list reaches gate jobs at Trust Admission (ADR 0010,
// 0015): with a stop-all in force, the attested worker's next job is denied
// — a signed refusal citing the attestation, on the record, no session, no
// disclosure.
func TestLiveDaemons_OperatorStopDeniesAtTrust(t *testing.T) {
	secrets := keygen(t)
	opDir := t.TempDir()
	opSeed, opPub, list := filepath.Join(opDir, "operator.seed"), filepath.Join(opDir, "operator.pem"), filepath.Join(opDir, "stop.json")
	acpctl(t, "stop", "keygen", "-out", opSeed, "-pub", opPub)
	acpctl(t, "stop", "issue", "-key", opSeed, "-kid", "operator-1", "-serial", "1", "-out", list)
	v := startVaultWith(t, secrets, func(cfg map[string]any) {
		cfg["operator_stop"] = map[string]any{"kid": "operator-1", "public_key_path": opPub, "list_path": list}
	})
	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")

	// Nothing stopped: the job goes through.
	sealed := v.sealGenome(t, "gen-stop", true)
	id, _ := v.submitGenome(t, sealed)
	v.waitJob(t, id, "succeeded", jobTimeout)

	// The operator stops every release; the next job is denied at trust.
	stopped := filepath.Join(opDir, "stop-2.json")
	acpctl(t, "stop", "issue", "-key", opSeed, "-kid", "operator-1", "-serial", "2", "-all", "-reason", "drill", "-out", stopped)
	if err := os.Rename(stopped, list); err != nil {
		t.Fatal(err)
	}
	id2, accepted := v.submitGenome(t, sealed)
	job := v.waitJob(t, id2, "failed", jobTimeout)
	if job.Error == nil || job.Error.Code != "trust_denied" || job.Error.Category != "authority" || !strings.Contains(job.Error.Message, "operator stop in force") {
		t.Fatalf("denied job error: %+v", job.Error)
	}
	f := job.Flow
	if job.State != "incident_terminated" || f == nil || f.Attestation == nil || f.Attestation.Outcome != "deny" || f.Attestation.Reason != "trust.operator_stop" {
		t.Fatalf("denied job attestation: state %s %+v", job.State, f)
	}
	if f.Decision == nil || f.Decision.Release || f.Decision.Reason != "trust_denied" || f.Decision.AttestationID == "" || len(f.Decision.Signature) == 0 || f.Session != nil || len(f.Disclosures) != 0 {
		t.Fatalf("denied job decision: %+v", f)
	}
	if got := v.counter(t, `sagvd_release_decisions_total{decision="trust_denied"}`); got != 1 {
		t.Fatalf("sagvd_release_decisions_total{decision=\"trust_denied\"} = %d, want 1", got)
	}

	// On the record: the request, the denial naming the stop list's
	// serial, the refusal — and nothing after it.
	kinds, events := v.auditLogAfterStop(t)
	if n := len(kinds); n < 3 || strings.Join(kinds[n-3:], ",") != "REQUEST_RECEIVED,TRUST_EVALUATED,RELEASE_DECIDED" {
		t.Fatalf("audit kinds %v, want …,REQUEST_RECEIVED,TRUST_EVALUATED,RELEASE_DECIDED", kinds)
	}
	deny, decided := events[len(events)-2], events[len(events)-1]
	if deny.RequestID != accepted.RequestID || !strings.Contains(string(deny.Payload), `"outcome":"deny"`) ||
		!strings.Contains(string(deny.Payload), `"reason":"trust.operator_stop"`) || !strings.Contains(string(deny.Payload), `"stop_serial":2`) {
		t.Fatalf("TRUST_EVALUATED payload: %+v", deny)
	}
	if !strings.Contains(string(decided.Payload), `"release":false`) || !strings.Contains(string(decided.Payload), `"reason":"trust_denied"`) || decided.SessionID != "" {
		t.Fatalf("RELEASE_DECIDED payload: %+v", decided)
	}
}

// Both daemons honour SIGTERM promptly while a Return Path session is
// open and idle — the state in which the worker sits blocked reading the
// next JobRequest. net.Conn reads do not observe context cancellation, so
// without the context-bound connection close the worker ignored SIGTERM
// in this state until the job deadline.
func TestLiveDaemons_ShutdownIsPromptWhileSessionIdle(t *testing.T) {
	secrets := keygen(t)
	v := startVault(t, secrets)
	w, health := v.startWorker(t, "acp-compute", workerIdentity{tlsFrom: secrets, teeFrom: secrets})
	waitReady(t, w, health+"/healthz")
	waitFor(t, 20*time.Second, "worker idle in an open Return Path session", func() bool {
		return v.counter(t, `sagvd_sessions_opened_total`) >= 1
	})
	for _, p := range []*proc{w, v.proc} {
		if took, killed := p.stop(); killed || took > 5*time.Second {
			t.Fatalf("%s took %s to honour SIGTERM (killed=%v), want < 5s",
				p.name, took.Round(time.Millisecond), killed)
		}
	}
}

// sagvd refuses to start when a listener reachable from the network
// would be unauthenticated. The check runs before any socket is bound.
func TestSagvd_RefusesUnauthenticatedNetworkExposure(t *testing.T) {
	secrets := keygen(t)
	for _, tc := range []struct {
		name   string
		mutate func(cfg map[string]any)
		want   string
	}{
		{
			name: "plaintext Return Path on all interfaces",
			mutate: func(cfg map[string]any) {
				vault := cfg["vault"].(map[string]any)
				vault["listen_address"] = fmt.Sprintf("0.0.0.0:%d", freePort(t))
				vault["tls"] = map[string]any{"enabled": false}
			},
			want: "vault.tls.enabled required",
		},
		{
			name: "REST API without a token on all interfaces",
			mutate: func(cfg map[string]any) {
				api := cfg["http_api"].(map[string]any)
				api["listen_address"] = fmt.Sprintf("0.0.0.0:%d", freePort(t))
				delete(api, "bearer_token_file")
			},
			want: "bearer_token or bearer_token_file required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := vaultConfig(secrets, loopback(t), loopback(t), loopback(t))
			tc.mutate(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, bins.sagvd, "-config", writeJSON(t, "sagvd.json", cfg)).CombinedOutput()
			if err == nil || ctx.Err() != nil {
				t.Fatalf("sagvd did not refuse the config (err=%v, ctx=%v)\n%s", err, ctx.Err(), out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("refusal does not name the problem %q:\n%s", tc.want, out)
			}
		})
	}
}

// ---- deployment helpers -----------------------------------------------------

// keygen provisions a fresh secrets tree (seeds, sealing key, mTLS PKI,
// API token) with the real deploy/compose/keygen binary.
func keygen(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "secrets")
	if b, err := exec.Command(bins.keygen, "-out", out, "-quiet").CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v\n%s", err, b)
	}
	return out
}

// vault is one running sagvd plus the addresses to reach it.
type vault struct {
	secrets   string
	token     string
	vaultAddr string
	apiURL    string
	healthURL string
	bundleDir string // genome.bundle_dir
	auditLog  string // audit.log_path
	proc      *proc
}

func vaultConfig(secrets, vaultAddr, apiAddr, healthAddr string) map[string]any {
	return vaultConfigWithGenomes(secrets, vaultAddr, apiAddr, healthAddr, "")
}

func vaultConfigWithGenomes(secrets, vaultAddr, apiAddr, healthAddr, bundleDir string) map[string]any {
	return vaultConfigWithAudit(secrets, vaultAddr, apiAddr, healthAddr, bundleDir, "")
}

// vaultConfigWithAudit is vaultConfigWithGenomes with the Return Path
// audit log at auditLog; gate jobs need one.
func vaultConfigWithAudit(secrets, vaultAddr, apiAddr, healthAddr, bundleDir, auditLog string) map[string]any {
	sec := func(p ...string) string { return filepath.Join(append([]string{secrets}, p...)...) }
	genome := map[string]any{"gate": map[string]any{"atol": 1e-2, "rtol": 1e-3, "max_non_critical_outliers": 0}}
	if bundleDir != "" {
		genome["bundle_dir"] = bundleDir
	}
	audit := map[string]any{}
	if auditLog != "" {
		audit["log_path"] = auditLog
	}
	return map[string]any{
		"genome": genome,
		"audit":  audit,
		"vault": map[string]any{
			"listen_address": vaultAddr,
			"tls": map[string]any{
				"enabled":     true,
				"server_cert": sec("sagvd", "tls", "server.crt"),
				"server_key":  sec("sagvd", "tls", "server.key"),
				"client_cas":  sec("shared", "tls", "ca.crt"),
			},
		},
		"http_api": map[string]any{
			"listen_address":    apiAddr,
			"bearer_token_file": sec("sagvd", "api_token"),
		},
		"tee": map[string]any{
			"workload_descriptor": vaultDescriptor,
			"seed_path":           sec("sagvd", "tee_seed"),
			"insecure_simulation": true,
			"peer": map[string]any{
				"public_key_path":  sec("sagvd", "peer_worker_pubkey"),
				"measurement_path": sec("sagvd", "peer_worker_measurement"),
			},
		},
		"keys": map[string]any{
			"authority_signing": map[string]any{"kid": "sagvd-authority-demo", "seed_path": sec("sagvd", "authority_signing_seed")},
			"audit_signing":     map[string]any{"kid": "sagvd-audit-demo", "seed_path": sec("sagvd", "audit_signing_seed")},
			"session_sealing":   map[string]any{"kid": "session-sealing-demo", "material_path": sec("shared", "sealing.key")},
		},
		"workers": map[string]any{"registry_path": sec("shared", "workers.json")},
		"runtime": map[string]any{
			"job_timeout_seconds":              60,
			"handshake_timeout_seconds":        10,
			"queue_poll_ms":                    50,
			"http_read_header_timeout_seconds": 5,
			"http_write_timeout_seconds":       30,
			"default_job_deadline_seconds":     60,
			"max_payload_bytes":                4 << 20,
		},
		"health": map[string]any{"listen_address": healthAddr},
		"log":    map[string]any{"level": "debug", "format": "json"},
	}
}

// startVault runs sagvd with mTLS on the Return Path and a bearer token
// on the REST API, on loopback, with an empty genome.bundle_dir, and
// waits for /readyz.
func startVault(t *testing.T, secrets string) *vault {
	t.Helper()
	return startVaultWith(t, secrets, nil)
}

// startVaultWith is startVault with a hook over the config before it is
// written.
func startVaultWith(t *testing.T, secrets string, mutate func(cfg map[string]any)) *vault {
	t.Helper()
	tok, err := os.ReadFile(filepath.Join(secrets, "sagvd", "api_token"))
	if err != nil {
		t.Fatal(err)
	}
	vaultAddr, apiAddr, healthAddr := loopback(t), loopback(t), loopback(t)
	v := &vault{
		secrets:   secrets,
		token:     strings.TrimSpace(string(tok)),
		vaultAddr: vaultAddr,
		apiURL:    "http://" + apiAddr,
		healthURL: "http://" + healthAddr,
		bundleDir: t.TempDir(),
		auditLog:  filepath.Join(t.TempDir(), "returnpath-audit.db"),
	}
	cfg := vaultConfigWithAudit(secrets, vaultAddr, apiAddr, healthAddr, v.bundleDir, v.auditLog)
	if mutate != nil {
		mutate(cfg)
	}
	v.proc = startProc(t, "sagvd", bins.sagvd, "-config", writeJSON(t, "sagvd.json", cfg))
	waitReady(t, v.proc, v.healthURL+"/readyz")
	return v
}

// workerIdentity chooses where a worker's credentials come from, so a
// test can combine a legitimate mTLS certificate with a foreign TEE key.
type workerIdentity struct {
	tlsFrom string // secrets tree providing the mTLS client certificate
	teeFrom string // secrets tree providing the TEE seed and signing seed
}

// startWorker runs acp-compute against v. The worker always trusts v's
// CA, pins v's TEE key and measurement, and holds v's session sealing
// key; id picks its own client certificate and TEE identity. It returns
// the process and the worker's health base URL.
func (v *vault) startWorker(t *testing.T, name string, id workerIdentity) (*proc, string) {
	t.Helper()
	healthAddr := loopback(t)
	cfg := map[string]any{
		"vault": map[string]any{
			"address": v.vaultAddr,
			"tls": map[string]any{
				"enabled":     true,
				"client_cert": filepath.Join(id.tlsFrom, "acp-compute", "tls", "client.crt"),
				"client_key":  filepath.Join(id.tlsFrom, "acp-compute", "tls", "client.key"),
				"ca_bundle":   filepath.Join(v.secrets, "shared", "tls", "ca.crt"),
				"server_name": "localhost",
			},
		},
		"tee": map[string]any{
			"workload_descriptor": workerDescriptor,
			"seed_path":           filepath.Join(id.teeFrom, "acp-compute", "tee_seed"),
			"insecure_simulation": true,
			"peer": map[string]any{
				"public_key_path":  filepath.Join(v.secrets, "acp-compute", "peer_vault_pubkey"),
				"measurement_path": filepath.Join(v.secrets, "acp-compute", "peer_vault_measurement"),
			},
		},
		"keys": map[string]any{
			"worker_signing":  map[string]any{"kid": workerSigningKID, "seed_path": filepath.Join(id.teeFrom, "acp-compute", "worker_signing_seed")},
			"session_sealing": map[string]any{"kid": "session-sealing-demo", "material_path": filepath.Join(v.secrets, "shared", "sealing.key")},
		},
		"genome": map[string]any{
			"door": map[string]any{"command": []string{bins.fakedoor}, "timeout_seconds": 30},
		},
		"runtime": map[string]any{
			"job_timeout_seconds":       60,
			"handshake_timeout_seconds": 10,
			"dial_backoff_initial_ms":   100,
			"dial_backoff_max_ms":       1000,
			"idle_between_jobs_ms":      50,
		},
		"health": map[string]any{"listen_address": healthAddr},
		"log":    map[string]any{"level": "debug", "format": "json"},
	}
	p := startProc(t, name, bins.worker, "-config", writeJSON(t, name+".json", cfg))
	return p, "http://" + healthAddr
}

// ---- REST helpers -----------------------------------------------------------

type jobView struct {
	ID         string `json:"job_id"`
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	State      string `json:"state"`
	ManifestID string `json:"manifest_id"`
	SessionID  string `json:"session_id"`
	Flow       *struct {
		State       string `json:"state"`
		Steps       []any  `json:"steps"`
		Disclosures []any  `json:"disclosures"`
		Attestation *struct {
			Outcome string `json:"outcome"`
			Reason  string `json:"reason"`
		} `json:"attestation"`
		Session *struct {
			State string `json:"state"`
		} `json:"session"`
		Validation *struct {
			OverallVerdict string `json:"overall_verdict"`
		} `json:"validation"`
		Decision *struct {
			Release       bool   `json:"release"`
			Reason        string `json:"reason"`
			AuditEventID  string `json:"audit_event_id"`
			AttestationID string `json:"attestation_id"`
			Signature     []byte `json:"signature"`
		} `json:"decision"`
		Incident *struct {
			Scenario string `json:"scenario"`
		} `json:"incident"`
		AuditTip string `json:"audit_tip"`
	} `json:"flow"`
	Result *struct {
		OutputKind         string `json:"output_kind"`
		BytesHex           string `json:"bytes_hex"`
		ByteCount          int    `json:"byte_count"`
		WorkerSigningKeyID string `json:"worker_signing_key_id"`
	} `json:"result"`
	Error *struct {
		Category string `json:"category"`
		Code     string `json:"code"`
		Message  string `json:"message"`
	} `json:"error"`
	Genome *genomeView `json:"genome"`
	Gate   *struct {
		Level         string `json:"level"`
		Door          string `json:"door"`
		Rung          int    `json:"rung"`
		Fixtures      int    `json:"fixtures"`
		Attempts      []any  `json:"attempts"`
		SignerKeyID   string `json:"signer_key_id"`
		SignedVerdict *struct {
			Verdict struct {
				Level    string `json:"level"`
				GenomeID string `json:"genome_id"`
				NExact   int    `json:"n_exact"`
			} `json:"verdict"`
			Signature []byte `json:"signature"`
		} `json:"signed_verdict"`
	} `json:"gate"`
}

type genomeView struct {
	Bundle    string `json:"bundle"`
	KeyID     string `json:"key_id"`
	KeySource string `json:"key_source"`
	Fixtures  int    `json:"fixtures"`
}

// submitView is what POST /v1/jobs returns.
type submitView struct {
	JobID     string     `json:"job_id"`
	RequestID string     `json:"request_id"`
	State     string     `json:"state"`
	Genome    genomeView `json:"genome"`
}

// sealedGenome is a genome sealed into the vault's bundle dir.
type sealedGenome struct {
	bundle, keyFile, keyID string
}

// doorValue is the arithmetic the fake door computes (see fakedoor/main.go).
func doorValue(inputIDs []int, idx int) float32 {
	sum := 0
	for _, id := range inputIDs {
		sum += id
	}
	return float32(sum) + float32(idx)*0.5
}

// writeModelGenome writes a model genome as the vg_genome worker does:
// genome.json, adapter/, fixtures.json with prompts, data/. With right
// references the fake door reproduces the fixtures exactly; otherwise the
// references are off by more than the gate's tolerance.
func writeModelGenome(t *testing.T, rightReferences bool) string {
	t.Helper()
	dir := t.TempDir()
	prompts := []struct {
		id   string
		ids  []int
		topk []int
	}{
		{"fx-000", []int{3, 5, 8}, []int{7, 1, 4}},
		{"fx-001", []int{4, 4}, []int{0, 9, 2}},
		{"fx-002", []int{12}, []int{5, 6, 1}},
	}
	var fixtures []map[string]any
	for i, p := range prompts {
		b := make([]byte, 4*len(p.topk))
		for j, idx := range p.topk {
			v := doorValue(p.ids, idx)
			if !rightReferences {
				v += 0.25
			}
			binary.LittleEndian.PutUint32(b[4*j:], math.Float32bits(v))
		}
		fixtures = append(fixtures, map[string]any{
			"id": p.id, "critical": i < 2, "prompt": "prompt " + p.id, "input_ids": p.ids, "topk_index": p.topk,
			"expected": map[string]any{"dtype": "f32", "shape": []int{len(p.topk)}, "raw_b64": base64.StdEncoding.EncodeToString(b)},
			"greedy":   map[string]any{"ids": []int{1}, "text": "x"},
		})
	}
	fixturesJSON, err := json.Marshal(map[string]any{"schema": "vault-genome/lora-fixtures/v1", "top_k": 3, "new_tokens": 1, "fixtures": fixtures})
	if err != nil {
		t.Fatal(err)
	}
	weights := make([]byte, 5000)
	if _, err := rand.Read(weights); err != nil {
		t.Fatal(err)
	}
	wSum, fxSum := sha256.Sum256(weights), sha256.Sum256(fixturesJSON)
	genomeJSON, err := json.Marshal(map[string]any{
		"schema": "vault-genome/lora-genome/v1", "created_at": "2026-09-15T00:00:00Z",
		"base": map[string]any{"name": "tiny-llama", "manifest": map[string]any{
			"files": map[string]string{"model.safetensors": "sha256:" + strings.Repeat("01", 32)}, "digest": "sha256:" + strings.Repeat("02", 32)}},
		"adapter":  map[string]any{"dir": "adapter", "format": "peft-lora", "r": 8, "alpha": 16.0, "targets": []string{"q_proj", "v_proj"}, "parameters": 100, "weights_sha256": "sha256:" + hex.EncodeToString(wSum[:])},
		"recipe":   map[string]any{"data": "data/train.jsonl", "steps": 2, "seed": 7, "threads": 1, "losses": []float64{1, 0.5}},
		"fixtures": map[string]any{"file": "fixtures.json", "sha256": "sha256:" + hex.EncodeToString(fxSum[:]), "count": 3, "critical": 2, "top_k": 3},
		"runtime":  map[string]any{"torch": "2.7.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel, data := range map[string][]byte{
		"genome.json":                       genomeJSON,
		"adapter/adapter_config.json":       []byte(`{"peft_type":"LORA","r":8,"lora_alpha":16.0,"target_modules":["q_proj","v_proj"]}`),
		"adapter/adapter_model.safetensors": weights,
		"fixtures.json":                     fixturesJSON,
		"data/train.jsonl":                  []byte(`{"prompt":"p","completion":"c"}` + "\n"),
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// sealGenome seals a model genome into the vault's bundle dir with acpctl
// and returns how a job names it.
func (v *vault) sealGenome(t *testing.T, name string, rightReferences bool) sealedGenome {
	t.Helper()
	dir := writeModelGenome(t, rightReferences)
	g := sealedGenome{bundle: name + ".genome", keyFile: name + ".key"}
	var sealed struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "genome", "seal", "--content-dir", dir,
		"--output", filepath.Join(v.bundleDir, g.bundle), "--key-out", filepath.Join(v.bundleDir, g.keyFile), "--json")), &sealed); err != nil {
		t.Fatal(err)
	}
	g.keyID = sealed.KeyID
	return g
}

func jobBody(t *testing.T, g sealedGenome) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"genome":                    map[string]string{"bundle": g.bundle, "key_file": g.keyFile},
		"deadline_seconds_from_now": 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// do sends one REST request; an empty token sends no Authorization header.
func (v *vault) do(t *testing.T, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, v.apiURL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func (v *vault) submitGenome(t *testing.T, g sealedGenome) (string, submitView) {
	t.Helper()
	status, body := v.do(t, http.MethodPost, "/v1/jobs", v.token, jobBody(t, g))
	if status != http.StatusAccepted {
		t.Fatalf("POST /v1/jobs: status %d body %s, want 202", status, body)
	}
	var r submitView
	if err := json.Unmarshal(body, &r); err != nil || r.JobID == "" {
		t.Fatalf("POST /v1/jobs: no job_id in %s (%v)", body, err)
	}
	return r.JobID, r
}

func (v *vault) job(t *testing.T, id string) jobView {
	t.Helper()
	status, body := v.do(t, http.MethodGet, "/v1/jobs/"+id, v.token, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /v1/jobs/%s: status %d body %s", id, status, body)
	}
	var j jobView
	if err := json.Unmarshal(body, &j); err != nil {
		t.Fatalf("decode job view: %v (%s)", err, body)
	}
	return j
}

// waitJob polls until the job reaches want, failing fast if it lands in
// a different terminal state.
func (v *vault) waitJob(t *testing.T, id, want string, timeout time.Duration) jobView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		j := v.job(t, id)
		switch {
		case j.Status == want:
			return j
		case j.Status == "succeeded" || j.Status == "failed":
			t.Fatalf("job %s reached %q, want %q: %+v", id, j.Status, want, j)
		case time.Now().After(deadline):
			t.Fatalf("job %s still %q after %s, want %q", id, j.Status, timeout, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// auditEvent is what `acpctl audit query --json` prints per event.
type auditEvent struct {
	Kind       string          `json:"kind"`
	RequestID  string          `json:"request_id"`
	SessionID  string          `json:"session_id"`
	ManifestID string          `json:"manifest_id"`
	Payload    json.RawMessage `json:"payload"`
}

// flowKinds is the audit record of one gate job driven through the nine
// stages (ADR 0015) up to its validation: the request, trust, the session,
// one disclosure per component (a descriptor and four files), the
// manifest, the candidate, and the three-dimension validation.
var flowKinds = []string{"REQUEST_RECEIVED", "TRUST_EVALUATED", "SESSION_ISSUED",
	"DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED", "DISCLOSURE_AUTHORIZED",
	"MANIFEST_ISSUED", "CANDIDATE_RECEIVED", "VALIDATION_STARTED",
	"VALIDATION_DIMENSION_EVALUATED", "VALIDATION_DIMENSION_EVALUATED", "VALIDATION_DIMENSION_EVALUATED"}

// lastOfKind returns the last event of kind k, failing when there is none.
func lastOfKind(t *testing.T, events []auditEvent, k string) auditEvent {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Kind == k {
			return events[i]
		}
	}
	t.Fatalf("no %s event on record", k)
	return auditEvent{}
}

// auditLogAfterStop stops the vault (its bbolt log is held open while it
// runs), verifies the Return Path audit log with the audit key `sagvd
// identity` publishes, and returns its events in order.
func (v *vault) auditLogAfterStop(t *testing.T) ([]string, []auditEvent) {
	t.Helper()
	if took, killed := v.proc.stop(); killed {
		t.Fatalf("sagvd had to be killed after %s", took)
	}
	cfgPath := filepath.Join(t.TempDir(), "sagvd-identity.json")
	cfg := vaultConfigWithAudit(v.secrets, v.vaultAddr, "", "", v.bundleDir, v.auditLog)
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	id := identityOf(t, bins.sagvd, cfgPath)
	pem := filepath.Join(t.TempDir(), "audit.pem")
	if id["audit_public_key_pem"] == "" {
		t.Fatalf("sagvd identity publishes no audit key: %v", id)
	}
	if err := os.WriteFile(pem, []byte(id["audit_public_key_pem"]), 0o600); err != nil {
		t.Fatal(err)
	}
	var verified struct {
		OK         bool   `json:"ok"`
		EventCount int    `json:"event_count"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal([]byte(acpctl(t, "audit", "verify", "--audit", v.auditLog, "--audit-pubkey", pem, "--audit-kid", "sagvd-audit-demo", "--json")), &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.OK {
		t.Fatalf("audit log does not verify: %s", verified.Error)
	}
	var events []auditEvent
	for _, line := range strings.Split(strings.TrimSpace(acpctl(t, "audit", "query", "--audit", v.auditLog, "--json")), "\n") {
		if line == "" {
			continue
		}
		var e auditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit query line %q: %v", line, err)
		}
		events = append(events, e)
	}
	if len(events) != verified.EventCount {
		t.Fatalf("audit query listed %d events, verify counted %d", len(events), verified.EventCount)
	}
	kinds := make([]string, len(events))
	for i, e := range events {
		kinds[i] = e.Kind
	}
	return kinds, events
}

// counter reads one series from sagvd's Prometheus exposition; an absent
// series reads as zero.
func (v *vault) counter(t *testing.T, series string) uint64 {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(v.healthURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), series+" "); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				t.Fatalf("parse %s: %v", series, err)
			}
			return n
		}
	}
	return 0
}

// ---- TLS helpers ------------------------------------------------------------

func certPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("no certificates in %s", path)
	}
	return pool
}

// tlsProbe completes a client handshake and one read. Under TLS 1.3 the
// server's client-authentication verdict arrives after the client
// finishes its side of the handshake, so a refusal surfaces on the first
// read as a TLS alert. A read timeout means the server accepted the
// session and is waiting for the Return Path handshake.
func tlsProbe(addr string, cfg *tls.Config) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	return err
}

// ---- process helpers --------------------------------------------------------

// proc is one running daemon with its combined output captured.
type proc struct {
	name   string
	cmd    *exec.Cmd
	log    *syncBuffer
	exited chan struct{}
	err    error // set before exited is closed
}

func startProc(t *testing.T, name, bin string, args ...string) *proc {
	t.Helper()
	p := &proc{name: name, log: &syncBuffer{}, exited: make(chan struct{})}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Stdout = p.log
	p.cmd.Stderr = p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		// Every daemon must honour SIGTERM: orchestrators (compose,
		// Kubernetes) send it and escalate to SIGKILL on a timeout.
		if took, killed := p.stop(); killed {
			t.Errorf("%s ignored SIGTERM for %s and had to be killed", p.name, took.Round(time.Millisecond))
		}
		if t.Failed() {
			t.Logf("---- %s output ----\n%s", p.name, p.log.String())
		}
	})
	return p
}

// stop sends SIGTERM (the daemons' graceful-shutdown path) and escalates
// to SIGKILL after 10 s. It reports how long the process took to exit and
// whether it had to be killed.
func (p *proc) stop() (time.Duration, bool) {
	select {
	case <-p.exited:
		return 0, false
	default:
	}
	start := time.Now()
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
		return time.Since(start), false
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
		return time.Since(start), true
	}
}

// waitReady polls url until it answers 200, failing fast if p exits.
func waitReady(t *testing.T, p *proc, url string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-p.exited:
			t.Fatalf("%s exited before %s answered: %v\n%s", p.name, url, p.err, p.log.String())
		default:
		}
		if resp, err := client.Get(url); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: %s not ready within %s\n%s", p.name, url, startupTimeout, p.log.String())
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", timeout, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// loopback reserves a free 127.0.0.1 port and returns host:port.
func loopback(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("127.0.0.1:%d", freePort(t))
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func writeJSON(t *testing.T, name string, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// syncBuffer is a goroutine-safe io.Writer collecting process output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
