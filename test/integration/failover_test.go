//go:build integration

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Continuity Drill, live and local (ADR 0012): the primary's sentinel
// (`acpctl sentinel watch`) keeps a model genome sealed as it trains; the
// release authority (`sagvd failover`) watches its outbox under the
// operator's signed failover policy; the standby (`acp-bootstrap`) holds a
// replica of the outbox and waits. When the primary is attacked, or dies,
// the authority releases the last trustworthy genome's escrowed key to the
// standby — and nowhere else — and confirms the standby restored it and
// proved the model works.

// failoverReport is what `sagvd failover` prints.
type failoverReport struct {
	Status  string `json:"status"`
	Error   string `json:"error"`
	Trigger struct {
		Kind    string `json:"kind"`
		Tripped []struct {
			Wire   string `json:"wire"`
			Target string `json:"target"`
		} `json:"tripped"`
		PrimaryMeasurementHex string `json:"primary_measurement_hex"`
	} `json:"trigger"`
	Decision struct {
		Decision   string `json:"decision"`
		Reason     string `json:"reason"`
		DecisionID string `json:"decision_id"`
	} `json:"decision"`
	Ignored  []string `json:"ignored"`
	SetAside []struct {
		File   string `json:"file"`
		Reason string `json:"reason"`
	} `json:"set_aside"`
	Genome *struct {
		Generation uint64 `json:"generation"`
		KeyID      string `json:"key_id"`
	} `json:"genome"`
	Release *struct {
		PolicyVersion string `json:"policy_version"`
	} `json:"release"`
	Restore *struct {
		Gate *struct {
			Level string `json:"level"`
		} `json:"gate"`
		RequiredGate string `json:"required_gate"`
	} `json:"restore"`
	Timing *struct {
		RPOSeconds      float64 `json:"rpo_seconds"`
		DetectSeconds   float64 `json:"detect_seconds"`
		FailoverSeconds float64 `json:"failover_seconds"`
		RTOSeconds      float64 `json:"rto_seconds"`
	} `json:"timing"`
	AuditChainLength int `json:"audit_chain_length"`
}

type failoverRig struct {
	x         *xcc
	state     string
	outbox    string
	restored  string
	canary    string
	srcCfg    string
	escrowPEM string
	seed      string
	policy    string
	// teeSeed and teeDescriptor name the primary's simulated TEE when the
	// rig attests (ADR 0017); empty otherwise.
	teeSeed, teeDescriptor string
}

// rigOptions shape a rig: the primary attested by a (simulated) TEE and
// pinned in the policy, and a grace on `stopped`.
type rigOptions struct {
	attested     bool
	stoppedGrace string
}

// newFailoverRig provisions the three machines: the primary's state, key and
// canary; the standby, gating with a door that answers as the right model;
// the authority with an escrow key sealed to its (simulated) TEE; and the
// operator's policy.
func newFailoverRig(t *testing.T, timeout string, opts ...rigOptions) *failoverRig {
	t.Helper()
	var o rigOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	x := newXCC(t)
	r := &failoverRig{x: x, outbox: filepath.Join(t.TempDir(), "outbox"), restored: t.TempDir()}
	if err := os.MkdirAll(r.outbox, 0o755); err != nil {
		t.Fatal(err)
	}
	var rightResp []byte
	r.state, rightResp = modelGenomeDir(t, "AADAPwAAAMA=", "AACAPgAAQEA=") // [1.5, -2], [0.25, 3]
	right := filepath.Join(x.dir, "right.json")
	if err := os.WriteFile(right, rightResp, 0o644); err != nil {
		t.Fatal(err)
	}
	door := filepath.Join(x.dir, "door.sh")
	if err := os.WriteFile(door, []byte("#!/bin/sh\ncat >/dev/null\ncat "+right+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.canary = filepath.Join(t.TempDir(), "canary")
	writeSecret(t, r.canary, []byte("no process reads this"))

	// The standby replicates the primary's outbox; here it reads it in place.
	destCfg := x.destinationConfig(t, "standby", map[string]any{
		"genome": map[string]any{"bundle_dir": r.outbox, "restore_dir": r.restored, "rescan_seconds": 1,
			"gate": map[string]any{"command": []string{door, "{genome}"}, "atol": 1e-3, "rtol": 1e-3, "required": true}},
	})
	id := identityOf(t, bins.bootstrap, destCfg)
	x.startDestination(t, destCfg)

	// The authority's escrow key: made in its own process and written
	// sealed to its TEE (ADR 0016); the public half goes to the primary.
	cfg := x.sourceConfig(t, id, id["measurement_hex"])
	escrowSealed := filepath.Join(x.dir, "escrow.sealed")
	var provisioned struct {
		EscrowKey string `json:"escrow_key"`
		TEE       string `json:"tee"`
	}
	if out, err := runJSON(t, &provisioned, bins.sagvd, "escrow-provision", "-config", cfg, "-out", escrowSealed, "-pub", filepath.Join(x.dir, "escrow-local.pem")); err != nil || provisioned.TEE != "simulated" {
		t.Fatalf("escrow-provision: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c["crosscloud"].(map[string]any)["key_escrow_path"] = escrowSealed
	r.srcCfg = writeJSON(t, "sagvd-failover.json", c)
	authority := identityOf(t, bins.sagvd, r.srcCfg)
	if authority["key_escrow_tag"] != provisioned.EscrowKey || authority["key_escrow_storage"] != "sealed:simulated" {
		t.Fatalf("identity %+v, want escrow key %s sealed", authority, provisioned.EscrowKey)
	}
	r.escrowPEM = filepath.Join(t.TempDir(), "escrow.pem")
	writeSecret(t, r.escrowPEM, []byte(authority["key_escrow_public_key_pem"]))

	// The primary's sentinel key, and the operator's policy pinning it.
	r.seed = filepath.Join(t.TempDir(), "sentinel.seed")
	pub := filepath.Join(t.TempDir(), "sentinel.pem")
	acpctl(t, "sentinel", "keygen", "--out", r.seed, "--pub", pub)
	r.policy = filepath.Join(x.dir, "failover.json")
	issue := []string{"failover", "issue", "--key", x.operatorSeed, "--kid", "operator-1", "--serial", "1",
		"--sentinel-pub", pub, "--standby-kind", "simulated", "--standby-endpoint", x.endpoint,
		"--standby-measurement", id["measurement_hex"], "--heartbeat-timeout", timeout,
		"--require-gate", "EQUIVALENT", "--reason", "drill", "--out", r.policy}
	if o.stoppedGrace != "" {
		issue = append(issue, "--stopped-grace", o.stoppedGrace)
	}
	if o.attested {
		// The primary's TEE, simulated: its identity is what the operator
		// pins, and the sentinel attests every record with it.
		r.teeSeed = filepath.Join(t.TempDir(), "primary-tee.seed")
		writeSecret(t, r.teeSeed, []byte(strings.Repeat("p", 32)))
		r.teeDescriptor = "primary-drill-v1"
		var primary struct {
			TEE            string `json:"tee"`
			MeasurementHex string `json:"measurement_hex"`
			AttestorPEM    string `json:"attestor_public_key_pem"`
		}
		if out, err := runJSON(t, &primary, bins.acpctl, "sentinel", "identity", "--tee", "simulated", "--tee-seed", r.teeSeed, "--workload-descriptor", r.teeDescriptor); err != nil {
			t.Fatalf("sentinel identity: %v\n%s", err, out)
		}
		attestorPub := filepath.Join(x.dir, "primary-attestor.pem")
		writeSecret(t, attestorPub, []byte(primary.AttestorPEM))
		issue = append(issue, "--primary-kind", primary.TEE, "--primary-measurement", primary.MeasurementHex, "--primary-attestor-pub", attestorPub)
	}
	acpctl(t, issue...)
	if out := acpctl(t, "failover", "verify", "--in", r.policy, "--pubkey", x.operatorPEM, "--kid", "operator-1"); !strings.Contains(out, "stands") {
		t.Fatalf("failover verify: %s", out)
	}
	return r
}

func (r *failoverRig) sentinel(t *testing.T) *proc {
	t.Helper()
	args := []string{"sentinel", "watch", "--content-dir", r.state, "--outbox", r.outbox,
		"--escrow-to", r.escrowPEM, "--key", r.seed, "--tripwire", r.canary, "--interval", "200ms", "--settle", "300ms"}
	if r.teeSeed != "" {
		args = append(args, "--tee", "simulated", "--tee-seed", r.teeSeed, "--workload-descriptor", r.teeDescriptor)
	}
	return startProc(t, "sentinel", bins.acpctl, args...)
}

func (r *failoverRig) executor(t *testing.T, report string) *proc {
	t.Helper()
	return startProc(t, "sagvd failover", bins.sagvd, "failover", "-config", r.srcCfg, "-policy", r.policy,
		"-outbox", r.outbox, "-poll", "200ms", "-confirm-wait", "60s", "-report", report)
}

// records counts the seal records in the outbox.
func (r *failoverRig) records(t *testing.T) int {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(r.outbox, "gen-*.seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	return len(m)
}

func exitCode(p *proc) int {
	<-p.exited
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		return ee.ExitCode()
	}
	if p.err != nil {
		return -1
	}
	return 0
}

func readReport(t *testing.T, p *proc, path string) failoverReport {
	t.Helper()
	select {
	case <-p.exited:
	case <-time.After(jobTimeout):
		t.Fatalf("sagvd failover did not finish\n%s", p.log.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no report: %v\n%s", err, p.log.String())
	}
	var rep failoverReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("report: %v\n%s", err, raw)
	}
	return rep
}

// The intrusion drill: the canary is touched and the model tampered with;
// the sentinel stops sealing and reports; the authority fails over to the
// last genome sealed before the intrusion.
func TestLiveFailover_CompromiseToStandby(t *testing.T) {
	r := newFailoverRig(t, "30s")
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)

	// Training goes on: a new adapter, sealed as generation 1.
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("lora weights, epoch 2"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "generation 1", func() bool { return r.records(t) >= 2 })

	// The intrusion.
	writeSecret(t, r.canary, []byte("read by an intruder"))
	if code := exitCode(primary); code != 3 {
		t.Fatalf("sentinel exited %d, want 3 (compromised)\n%s", code, primary.log.String())
	}
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep := readReport(t, authority, report)
	if code := exitCode(authority); code != 0 || rep.Status != "restored" {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep, authority.log.String())
	}
	if rep.Trigger.Kind != "compromise-report" || len(rep.Trigger.Tripped) != 1 || rep.Trigger.Tripped[0].Target != r.canary {
		t.Fatalf("trigger %+v", rep.Trigger)
	}
	if rep.Genome == nil || rep.Genome.Generation != 1 {
		t.Fatalf("genome %+v, want generation 1", rep.Genome)
	}
	if rep.Restore == nil || rep.Restore.Gate == nil || rep.Restore.Gate.Level != "EXACT" || rep.Restore.RequiredGate != "EQUIVALENT" {
		t.Fatalf("restore %+v", rep.Restore)
	}
	if !strings.HasSuffix(rep.Release.PolicyVersion, ";failover=1;revocation=1") {
		t.Fatalf("policy version %q", rep.Release.PolicyVersion)
	}
	restored, err := os.ReadFile(filepath.Join(r.restored, rep.Genome.KeyID, "adapter", "adapter_model.safetensors"))
	if err != nil || string(restored) != "lora weights, epoch 2" {
		t.Fatalf("the standby restored %q (%v)", restored, err)
	}
	// On record: the decision, the release (3 events), the confirmation.
	if ok, events, _ := r.x.auditVerify(t); !ok || events != 5 || rep.AuditChainLength != 5 {
		t.Fatalf("audit log: ok=%v events=%d report=%d, want 5", ok, events, rep.AuditChainLength)
	}
	t.Logf("failover: detect %.2fs, failover %.2fs, RTO %.2fs, RPO %.2fs", rep.Timing.DetectSeconds, rep.Timing.FailoverSeconds, rep.Timing.RTOSeconds, rep.Timing.RPOSeconds)

	// The policy is spent: moving again takes a new one.
	var again failoverReport
	out, err := runJSON(t, &again, bins.sagvd, "failover", "-config", r.srcCfg, "-policy", r.policy, "-outbox", r.outbox)
	if err == nil || !strings.Contains(out, "already carried out") {
		t.Fatalf("a spent policy ran again: %v\n%s", err, out)
	}
}

// The crash drill: the primary is killed outright and writes nothing more;
// its heartbeat stops rising, and the authority fails over once the
// policy's timeout has passed.
func TestLiveFailover_KilledPrimary(t *testing.T) {
	r := newFailoverRig(t, "3s")
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)
	time.Sleep(time.Second) // the authority sees the heartbeat rise

	if err := primary.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-primary.exited

	rep := readReport(t, authority, report)
	if code := exitCode(authority); code != 0 || rep.Status != "restored" || rep.Trigger.Kind != "heartbeat-timeout" || rep.Genome.Generation != 0 {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep, authority.log.String())
	}
	if rep.Timing.DetectSeconds < 3 {
		t.Fatalf("failed over %.2fs after the last heartbeat, inside the 3s timeout", rep.Timing.DetectSeconds)
	}
	t.Logf("failover: detect %.2fs, failover %.2fs, RTO %.2fs, RPO %.2fs", rep.Timing.DetectSeconds, rep.Timing.FailoverSeconds, rep.Timing.RTOSeconds, rep.Timing.RPOSeconds)
}

// The primary attested (ADR 0017): its records carry its TEE's report, the
// policy pins its measurement, and the drill runs as before — the decision
// naming the primary. Then the seed is stolen and used off the chip: a
// rogue sentinel's records are ignored, the silence is a trigger, and
// nothing in the rogue outbox is trusted, so the second policy declines.
func TestLiveFailover_AttestedPrimary(t *testing.T) {
	r := newFailoverRig(t, "3s", rigOptions{attested: true})
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("lora weights, epoch 2"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, "generation 1", func() bool { return r.records(t) >= 2 })
	writeSecret(t, r.canary, []byte("read by an intruder"))
	if code := exitCode(primary); code != 3 {
		t.Fatalf("sentinel exited %d, want 3 (compromised)\n%s", code, primary.log.String())
	}
	rep := readReport(t, authority, report)
	if code := exitCode(authority); code != 0 || rep.Status != "restored" || rep.Trigger.Kind != "compromise-report" || rep.Genome == nil || rep.Genome.Generation != 1 {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep, authority.log.String())
	}
	if rep.Trigger.PrimaryMeasurementHex == "" {
		t.Fatalf("the trigger names no primary measurement: %+v", rep.Trigger)
	}
	if ok, events, _ := r.x.auditVerify(t); !ok || events != 5 {
		t.Fatalf("audit log: ok=%v events=%d", ok, events)
	}

	// The seed stolen, the chip not. The thief copies the outbox to a
	// machine of their own (another simulated TEE), drops the compromise
	// report, and runs a sentinel there with the stolen seed: it seals a
	// generation 2 of its own and heartbeats, every record attested by the
	// wrong chip. A second policy pins the primary as before. The rogue's
	// records are ignored, the silence after the primary's last genuine
	// word is the trigger, nothing past that word is trusted, and the
	// quarantine declines the rest: no key moves.
	rogueOutbox := filepath.Join(t.TempDir(), "rogue-outbox")
	copyDir(t, r.outbox, rogueOutbox)
	if err := os.Remove(filepath.Join(rogueOutbox, "compromise.json")); err != nil {
		t.Fatal(err)
	}
	var p1 struct {
		Primary struct {
			Measurements []string `json:"measurements"`
		} `json:"primary"`
		Standby struct {
			Measurements []string `json:"measurements"`
		} `json:"standby"`
	}
	raw, err := os.ReadFile(r.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &p1); err != nil {
		t.Fatal(err)
	}
	policy2 := filepath.Join(r.x.dir, "failover-2.json")
	acpctl(t, "failover", "issue", "--key", r.x.operatorSeed, "--kid", "operator-1", "--serial", "2",
		"--sentinel-pub", sentinelPubOf(t, r.seed), "--standby-kind", "simulated", "--standby-endpoint", r.x.endpoint,
		"--standby-measurement", p1.Standby.Measurements[0], "--no-compromise-trigger", "--heartbeat-timeout", "2s", "--quarantine", "24h",
		"--primary-kind", "simulated", "--primary-measurement", p1.Primary.Measurements[0], "--primary-attestor-pub", filepath.Join(r.x.dir, "primary-attestor.pem"),
		"--require-gate", "EQUIVALENT", "--reason", "a stolen seed off the pinned chip", "--out", policy2)
	report2 := filepath.Join(t.TempDir(), "rogue-report.json")
	second := startProc(t, "sagvd failover (rogue)", bins.sagvd, "failover", "-config", r.srcCfg, "-policy", policy2,
		"-outbox", rogueOutbox, "-poll", "200ms", "-confirm-wait", "10s", "-report", report2)
	waitFor(t, 20*time.Second, "the second executor watching the genuine heartbeat", func() bool {
		return strings.Contains(second.log.String(), `"state":"watching"`)
	})
	if err := os.WriteFile(filepath.Join(r.state, "adapter", "adapter_model.safetensors"), []byte("weights of the thief"), 0o644); err != nil {
		t.Fatal(err)
	}
	rogueTEE := filepath.Join(t.TempDir(), "rogue-tee.seed")
	writeSecret(t, rogueTEE, []byte(strings.Repeat("r", 32)))
	rogue := startProc(t, "rogue sentinel", bins.acpctl, "sentinel", "watch", "--content-dir", r.state, "--outbox", rogueOutbox,
		"--escrow-to", r.escrowPEM, "--key", r.seed, "--interval", "200ms", "--settle", "0s",
		"--tee", "simulated", "--tee-seed", rogueTEE, "--workload-descriptor", "the-thief's-machine")
	waitFor(t, 20*time.Second, "the rogue's generation 2", func() bool { _, err := os.Stat(filepath.Join(rogueOutbox, "gen-000002.seal.json")); return err == nil })
	rep2 := readReport(t, second, report2)
	_ = rogue.cmd.Process.Kill()
	<-rogue.exited
	if code := exitCode(second); code != 3 || rep2.Status != "declined" || rep2.Trigger.Kind != "heartbeat-timeout" {
		t.Fatalf("rogue: sagvd failover exited %d: %+v\n%s", code, rep2, second.log.String())
	}
	if rep2.Trigger.PrimaryMeasurementHex != rep.Trigger.PrimaryMeasurementHex {
		t.Fatalf("the trigger was attested by %q, want the primary's %q", rep2.Trigger.PrimaryMeasurementHex, rep.Trigger.PrimaryMeasurementHex)
	}
	// Refused either way: the wrong measurement under the verifier, or a
	// measurement the policy does not pin.
	refused := false
	for _, note := range rep2.Ignored {
		if strings.Contains(note, "does not pin as the primary") || strings.Contains(note, "attestation does not verify") {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("the rogue's attested records were not refused: %v", rep2.Ignored)
	}
	pastTheWord := false
	for _, r := range rep2.SetAside {
		if r.File == "gen-000002.seal.json" && strings.Contains(r.Reason, "after generation 1") {
			pastTheWord = true
		}
	}
	if !pastTheWord || !strings.Contains(rep2.Decision.Reason, "no genome in the verified chain") {
		t.Fatalf("set aside %+v; declined for %q", rep2.SetAside, rep2.Decision.Reason)
	}
	if ok, events, _ := r.x.auditVerify(t); !ok || events != 6 {
		t.Fatalf("audit log after the decline: ok=%v events=%d, want 6 (one more FAILOVER_DECIDED)", ok, events)
	}
}

// A sentinel stopped by its operator stands the authority down for the
// policy's grace, no longer: not back in time, the primary fails over.
func TestLiveFailover_StoppedOverdue(t *testing.T) {
	r := newFailoverRig(t, "30s", rigOptions{stoppedGrace: "2s"})
	primary := r.sentinel(t)
	waitFor(t, 20*time.Second, "generation 0", func() bool { return r.records(t) >= 1 })
	report := filepath.Join(t.TempDir(), "report.json")
	authority := r.executor(t, report)
	time.Sleep(time.Second)
	if err := primary.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(primary); code != 0 {
		t.Fatalf("sentinel exited %d on SIGINT, want 0 (stopped)\n%s", code, primary.log.String())
	}
	rep := readReport(t, authority, report)
	if code := exitCode(authority); code != 0 || rep.Status != "restored" || rep.Trigger.Kind != "stopped-overdue" || rep.Genome.Generation != 0 {
		t.Fatalf("sagvd failover exited %d: %+v\n%s", code, rep, authority.log.String())
	}
	if !strings.Contains(authority.log.String(), "standing down for") {
		t.Fatalf("the authority did not stand down first\n%s", authority.log.String())
	}
}

// sentinelPubOf writes the PEM public half of a sentinel seed.
func sentinelPubOf(t *testing.T, seed string) string {
	t.Helper()
	var id struct {
		PEM string `json:"sentinel_public_key_pem"`
	}
	teeSeed := filepath.Join(t.TempDir(), "tee.seed")
	writeSecret(t, teeSeed, []byte(strings.Repeat("x", 32)))
	if out, err := runJSON(t, &id, bins.acpctl, "sentinel", "identity", "--tee", "simulated", "--tee-seed", teeSeed, "--key", seed); err != nil {
		t.Fatalf("sentinel identity: %v\n%s", err, out)
	}
	p := filepath.Join(t.TempDir(), "sentinel.pem")
	writeSecret(t, p, []byte(id.PEM))
	return p
}

// copyDir copies the regular files of src into dst.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
