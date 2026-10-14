//go:build integration

// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Live cross-cloud key release: `sagvd crosscloud-restore` (the source
// authority) and `acp-bootstrap` (the destination) run as real processes
// and talk over TLS 1.3 with client certificates and a bearer token. The
// DEK crosses the wire only encapsulated to an X25519 key the destination
// TEE generated for that handshake and bound into its Evidence (ADR 0009).

const destinationDescriptor = "acp-bootstrap-destination-v1"

// xcc is one provisioned source/destination pair. Trust is exchanged the
// way docs/operator/06_cross_cloud_restore.md tells an operator to: each
// side prints its identity with the `identity` subcommand and the other
// side pins what it printed.
type xcc struct {
	secrets      string // keygen tree: sagvd authority seed, PKI
	dir          string // destination material written by the test
	token        string // bearer token both sides share
	authorityPEM string // path of the authority key the destination pins
	auditPEM     string // path of the audit key an auditor verifies the log with
	auditLog     string // the source's durable cross-cloud audit log
	operatorSeed string // the operator's stop-signing key (kept off the release host in real life)
	operatorPEM  string // its public half, which the source pins
	stopList     string // the stop list the source reads
	endpoint     string // https://127.0.0.1:port of acp-bootstrap
	health       string
	dest         *proc
	releases     int
}

// identityOf runs `<bin> identity -config cfg` and decodes its JSON.
func identityOf(t *testing.T, bin, cfg string) map[string]string {
	t.Helper()
	out, err := exec.Command(bin, "identity", "-config", cfg).Output()
	if err != nil {
		t.Fatalf("%s identity: %v", filepath.Base(bin), err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatalf("%s identity output is not JSON: %v\n%s", filepath.Base(bin), err, out)
	}
	id := make(map[string]string, len(raw))
	for k, v := range raw {
		id[k] = fmt.Sprint(v)
	}
	return id
}

// newXCC provisions both sides: a keygen tree for the source authority,
// the destination's bearer token, and the destination's pinned copy of
// the authority key as printed by `sagvd identity`.
func newXCC(t *testing.T) *xcc {
	t.Helper()
	x := &xcc{secrets: keygen(t), dir: t.TempDir()}
	x.token = hex.EncodeToString(randomBytes(t, 32))
	writeSecret(t, filepath.Join(x.dir, "api_token"), []byte(x.token+"\n"))

	src := writeJSON(t, "sagvd-identity.json", vaultConfig(x.secrets, loopback(t), loopback(t), loopback(t)))
	id := identityOf(t, bins.sagvd, src)
	if id["authority_kid"] != "sagvd-authority-demo" {
		t.Fatalf("sagvd identity: authority_kid %q", id["authority_kid"])
	}
	x.authorityPEM = filepath.Join(x.dir, "authority.pem")
	writeSecret(t, x.authorityPEM, []byte(id["authority_public_key_pem"]))
	if id["audit_kid"] != "sagvd-audit-demo" || id["audit_public_key_pem"] == "" {
		t.Fatalf("sagvd identity does not print the audit key: %v", id)
	}
	x.auditPEM = filepath.Join(x.dir, "audit.pem")
	writeSecret(t, x.auditPEM, []byte(id["audit_public_key_pem"]))
	x.auditLog = filepath.Join(x.dir, "xcc-audit.db")

	// The operator creates a stop key and a first list that stops nothing.
	x.operatorSeed = filepath.Join(x.dir, "operator.seed")
	x.operatorPEM = filepath.Join(x.dir, "operator.pem")
	x.stopList = filepath.Join(x.dir, "stop.json")
	acpctl(t, "stop", "keygen", "-out", x.operatorSeed, "-pub", x.operatorPEM)
	x.issueStop(t, "1")
	return x
}

// acpctl runs the operator CLI and fails the test if it fails.
func acpctl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(bins.acpctl, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("acpctl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// issueStop has the operator sign a new stop list over the current one.
func (x *xcc) issueStop(t *testing.T, serial string, extra ...string) {
	t.Helper()
	args := append([]string{"stop", "issue", "-key", x.operatorSeed, "-kid", "operator-1", "-serial", serial, "-out", x.stopList}, extra...)
	acpctl(t, args...)
}

// auditVerify runs `acpctl audit verify` over the source's audit log, as
// an auditor would, and returns its report.
func (x *xcc) auditVerify(t *testing.T) (ok bool, events int, tip string) {
	t.Helper()
	out, err := exec.Command(bins.acpctl, "audit", "verify", "--audit", x.auditLog,
		"--audit-pubkey", x.auditPEM, "--audit-kid", "sagvd-audit-demo", "--json").Output()
	var res struct {
		OK         bool   `json:"ok"`
		EventCount int    `json:"event_count"`
		Tip        string `json:"tip"`
		Error      string `json:"error"`
	}
	if jerr := json.Unmarshal(out, &res); jerr != nil {
		t.Fatalf("acpctl audit verify: %v / %v\n%s", err, jerr, out)
	}
	if res.Error != "" {
		t.Logf("acpctl audit verify: %s", res.Error)
	}
	return res.OK && err == nil, res.EventCount, res.Tip
}

// destinationConfig writes an acp-bootstrap config with TLS 1.3, mTLS
// against the deployment CA and a bearer token, whose TEE runs on a
// fresh seed; it returns the config path. extra adds top-level sections.
func (x *xcc) destinationConfig(t *testing.T, name string, extra ...map[string]any) string {
	t.Helper()
	seedPath := filepath.Join(x.dir, name+"_tee_seed")
	writeSecret(t, seedPath, randomBytes(t, 32))
	sec := func(p ...string) string { return filepath.Join(append([]string{x.secrets}, p...)...) }
	cfg := map[string]any{
		"http": map[string]any{
			"listen_address":    loopback(t),
			"bearer_token_file": filepath.Join(x.dir, "api_token"),
			"tls": map[string]any{
				"enabled":     true,
				"server_cert": sec("sagvd", "tls", "server.crt"),
				"server_key":  sec("sagvd", "tls", "server.key"),
				"client_cas":  sec("shared", "tls", "ca.crt"),
			},
		},
		"tee": map[string]any{
			"provider":            "simulated",
			"insecure_simulation": true,
			"workload_descriptor": destinationDescriptor,
			"seed_path":           seedPath,
		},
		"source_authority": map[string]any{
			"kid":             "sagvd-authority-demo",
			"public_key_path": x.authorityPEM,
		},
		"health": map[string]any{"listen_address": loopback(t)},
		"log":    map[string]any{"level": "debug", "format": "json"},
	}
	for _, e := range extra {
		for k, v := range e {
			cfg[k] = v
		}
	}
	return writeJSON(t, name+".json", cfg)
}

// startDestination runs acp-bootstrap with cfg and waits for /readyz.
func (x *xcc) startDestination(t *testing.T, cfg string) {
	t.Helper()
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		HTTP struct {
			ListenAddress string `json:"listen_address"`
		} `json:"http"`
		Health struct {
			ListenAddress string `json:"listen_address"`
		} `json:"health"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	x.endpoint, x.health = "https://"+c.HTTP.ListenAddress, "http://"+c.Health.ListenAddress
	x.dest = startProc(t, "acp-bootstrap", bins.bootstrap, "-config", cfg)
	waitReady(t, x.dest, x.health+"/readyz")
}

// sourceConfig writes the sagvd config for crosscloud-restore: the usual
// vault material, a verifier registry trusting the destination identity
// dest (as printed by `acp-bootstrap identity`), and an allow-list of
// the given measurements.
func (x *xcc) sourceConfig(t *testing.T, dest map[string]string, allowedHex ...string) string {
	t.Helper()
	attPath := filepath.Join(t.TempDir(), "destination_attestor.pem")
	writeSecret(t, attPath, []byte(dest["attestor_public_key_pem"]))
	registry := writeJSON(t, "verifiers.json", map[string]any{
		"verifiers": []map[string]any{{
			"provider":                 dest["tee_provider"],
			"attestor_pubkey_path":     attPath,
			"expected_measurement_hex": dest["measurement_hex"],
		}},
	})
	allow := writeJSON(t, "allow.json", map[string]any{
		"version": "drill-policy-v1",
		"allowed": map[string]any{dest["tee_provider"]: allowedHex},
	})

	sec := func(p ...string) string { return filepath.Join(append([]string{x.secrets}, p...)...) }
	cfg := vaultConfig(x.secrets, loopback(t), loopback(t), loopback(t))
	cfg["crosscloud"] = map[string]any{
		"enabled":        true,
		"audit_log_path": x.auditLog,
		"operator_stop": map[string]any{
			"kid":             "operator-1",
			"public_key_path": x.operatorPEM,
			"list_path":       x.stopList,
		},
		"policy_version": "drill-policy-v1",
		// The destinations in these tests are simulated: say so.
		"insecure_simulated_destinations": true,
		"policy_allow_list_path":          allow,
		"verifier_registry_path":          registry,
		"transport_bearer_token":          x.token,
		"request_timeout_seconds":         10,
		"transport_tls": map[string]any{
			"enabled":     true,
			"client_cert": sec("acp-compute", "tls", "client.crt"),
			"client_key":  sec("acp-compute", "tls", "client.key"),
			"ca_bundle":   sec("shared", "tls", "ca.crt"),
		},
	}
	return writeJSON(t, "sagvd-xcc.json", cfg)
}

// restoreResult is what `sagvd crosscloud-restore` prints.
type restoreResult struct {
	Status string `json:"status"`
	Error  *struct {
		Category string `json:"category"`
		Message  string `json:"message"`
	} `json:"error"`
	DestinationMeasurementHex string `json:"destination_measurement_hex"`
	RecipientKeySHA256        string `json:"recipient_key_sha256"`
	TokenID                   string `json:"token_id"`
	AuditChainLength          int    `json:"audit_chain_length"`
	AuditTip                  string `json:"audit_tip"`
	StopSerial                uint64 `json:"operator_stop_serial"`
}

// restore releases a fresh DEK with `sagvd crosscloud-restore` and
// returns its report, its combined output, and its exit error. The DEK
// goes in a 0600 key file, as an operator keeps it, never in argv.
func (x *xcc) restore(t *testing.T, config, endpoint string, dek []byte) (restoreResult, string, error) {
	t.Helper()
	x.releases++
	kid := fmt.Sprintf("genome-dek-%d", x.releases)
	keyFile := filepath.Join(x.dir, kid+".key")
	writeSecret(t, keyFile, dek)
	return x.release(t, config, endpoint, fmt.Sprintf("drill-decision-%d", x.releases), kid+":"+keyFile)
}

// release runs `sagvd crosscloud-restore` for decision with the given
// -key-file KID:PATH entries.
func (x *xcc) release(t *testing.T, config, endpoint, decision string, keyFiles ...string) (restoreResult, string, error) {
	t.Helper()
	args := []string{"crosscloud-restore",
		"-config", config,
		"-decision-id", decision,
		"-destination-kind", "simulated",
		"-destination-endpoint", endpoint,
	}
	for _, k := range keyFiles {
		args = append(args, "-key-file", k)
	}
	var res restoreResult
	out, err := runJSON(t, &res, bins.sagvd, args...)
	return res, out, err
}

// runJSON runs bin to completion, decodes its stdout as JSON into v, and
// returns its combined output and exit error.
func runJSON(t *testing.T, v any, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(jobTimeout):
		_ = cmd.Process.Kill()
		t.Fatalf("%s %s did not finish\nstdout:\n%s\nstderr:\n%s", filepath.Base(bin), args[0], stdout.String(), stderr.String())
	}
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), v); err != nil {
			t.Fatalf("%s %s output is not JSON: %v\n%s", filepath.Base(bin), args[0], err, stdout.String())
		}
	}
	return stdout.String() + stderr.String(), runErr
}

// destLog returns the destination's structured log lines with msg.
func (x *xcc) destLog(msg string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(x.dest.log.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// A key release completes end to end, and both sides record the same
// attested recipient key: the source in its report, the destination in
// its log when it answered the handshake.
func TestLiveCrossCloud_KeyReleaseToAttestedDestination(t *testing.T) {
	x := newXCC(t)
	dest := x.destinationConfig(t, "destination")
	id := identityOf(t, bins.bootstrap, dest)
	x.startDestination(t, dest)
	if id["insecure_simulation"] != "true" {
		t.Fatalf("a simulated destination's identity must say it is insecure: %v", id)
	}
	cfg := x.sourceConfig(t, id, id["measurement_hex"])

	res, out, err := x.restore(t, cfg, x.endpoint, randomBytes(t, 32))
	if err != nil || res.Status != "ok" {
		t.Fatalf("crosscloud-restore: %v\n%s", err, out)
	}
	if res.DestinationMeasurementHex != id["measurement_hex"] {
		t.Errorf("released to measurement %s, destination identity says %s", res.DestinationMeasurementHex, id["measurement_hex"])
	}
	if res.AuditChainLength != 3 {
		t.Errorf("audit chain has %d events, want handshake → attestation → release (3)", res.AuditChainLength)
	}

	// The release is on record: the log on disk verifies under the key
	// `sagvd identity` published, and ends where the report says.
	ok, events, tip := x.auditVerify(t)
	if !ok || events != 3 || tip != res.AuditTip || tip == "" {
		t.Fatalf("audit log: ok=%v events=%d tip=%s, report tip %s", ok, events, tip, res.AuditTip)
	}
	// A second release extends the same chain.
	res2, out, err := x.restore(t, cfg, x.endpoint, randomBytes(t, 32))
	if err != nil || res2.Status != "ok" {
		t.Fatalf("second crosscloud-restore: %v\n%s", err, out)
	}
	if ok, events, tip := x.auditVerify(t); !ok || events != 6 || tip != res2.AuditTip {
		t.Fatalf("audit log after two releases: ok=%v events=%d tip=%s, report tip %s", ok, events, tip, res2.AuditTip)
	}

	waitFor(t, 5*time.Second, "destination to log the accepted tokens", func() bool {
		return len(x.destLog("crosscloud token accepted")) == 2
	})
	answered := x.destLog("crosscloud handshake answered")
	if len(answered) != 2 {
		t.Fatalf("destination answered %d handshakes, want 2", len(answered))
	}
	if got := answered[0]["recipient_key_sha256"]; got != res.RecipientKeySHA256 || res.RecipientKeySHA256 == "" {
		t.Fatalf("recipient key: source released to %q, destination attested %q", res.RecipientKeySHA256, got)
	}
	if got := x.destLog("crosscloud token accepted")[0]["registered_keys"]; got != float64(1) {
		t.Fatalf("destination registered %v keys, want 1", got)
	}
}

// Anti-worm gate: a genuine, attested destination whose measurement is
// not on the operator's allow-list receives nothing.
func TestLiveCrossCloud_UnlistedDestinationGetsNothing(t *testing.T) {
	x := newXCC(t)
	dest := x.destinationConfig(t, "destination")
	id := identityOf(t, bins.bootstrap, dest)
	x.startDestination(t, dest)
	cfg := x.sourceConfig(t, id, hex.EncodeToString(tee.MeasurementOf([]byte("some-other-workload"))))

	res, out, err := x.restore(t, cfg, x.endpoint, randomBytes(t, 32))
	if err == nil || res.Status != "failed" || res.Error == nil || res.Error.Category != "authority" {
		t.Fatalf("restore to an unlisted destination: err=%v result=%+v\n%s", err, res, out)
	}
	if res.TokenID != "" {
		t.Fatalf("a token was issued to an unlisted destination: %s", res.TokenID)
	}
	// On record: the handshake, the verified attestation and the refusal.
	if ok, events, _ := x.auditVerify(t); !ok || events != 3 {
		t.Fatalf("audit log after a refused release: ok=%v events=%d, want 3 verified events", ok, events)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(x.destLog("crosscloud token accepted")); n != 0 {
		t.Fatalf("unlisted destination accepted %d tokens", n)
	}
}

// A machine that is not the attested TEE (same workload descriptor, so
// the same claimed measurement, but a different attestation key) fails
// attestation and receives nothing.
func TestLiveCrossCloud_ImpostorDestinationFailsAttestation(t *testing.T) {
	x := newXCC(t)
	genuine := identityOf(t, bins.bootstrap, x.destinationConfig(t, "genuine"))
	x.startDestination(t, x.destinationConfig(t, "impostor"))
	cfg := x.sourceConfig(t, genuine, genuine["measurement_hex"])

	res, out, err := x.restore(t, cfg, x.endpoint, randomBytes(t, 32))
	if err == nil || res.Status != "failed" || res.Error == nil || res.Error.Category != "integrity" {
		t.Fatalf("restore to an impostor: err=%v result=%+v\n%s", err, res, out)
	}
	if res.TokenID != "" || len(x.destLog("crosscloud token accepted")) != 0 {
		t.Fatal("an impostor destination received a token")
	}
}

// The operator stop (ADR 0010): one signed list halts every release; the
// refusal is on record; lifting the stop needs a newer list, and the old
// stop cannot be put back once a newer list has been applied.
func TestLiveCrossCloud_OperatorStopHaltsReleases(t *testing.T) {
	x := newXCC(t)
	dest := x.destinationConfig(t, "destination")
	id := identityOf(t, bins.bootstrap, dest)
	x.startDestination(t, dest)
	cfg := x.sourceConfig(t, id, id["measurement_hex"])

	if res, out, err := x.restore(t, cfg, x.endpoint, randomBytes(t, 32)); err != nil || res.Status != "ok" {
		t.Fatalf("release before the stop: %v\n%s", err, out)
	}

	x.issueStop(t, "2", "-all", "-reason", "drill: suspected compromise")
	stopped := filepath.Join(x.dir, "stop-serial-2.json")
	raw, err := os.ReadFile(x.stopList)
	if err != nil {
		t.Fatal(err)
	}
	writeSecret(t, stopped, raw)

	res, out, err := x.restore(t, cfg, x.endpoint, randomBytes(t, 32))
	if err == nil || res.Error == nil || res.Error.Category != "authority" ||
		!strings.Contains(res.Error.Message, "operator stop in force (revocation serial 2): drill: suspected compromise") {
		t.Fatalf("release under a stop: err=%v result=%+v\n%s", err, res, out)
	}
	if res.TokenID != "" || res.StopSerial != 2 {
		t.Fatalf("under the stop: token %q, serial %d", res.TokenID, res.StopSerial)
	}
	if ok, events, _ := x.auditVerify(t); !ok || events != 6 {
		t.Fatalf("audit log: ok=%v events=%d, want 3 (release) + 3 (handshake, attestation, denied)", ok, events)
	}

	x.issueStop(t, "3", "-reason", "all clear")
	if res, out, err := x.restore(t, cfg, x.endpoint, randomBytes(t, 32)); err != nil || res.Status != "ok" || res.StopSerial != 3 {
		t.Fatalf("release after the stop was lifted: %v\n%s", err, out)
	}

	// Rolling back to the stop list — or to any list older than serial 3
	// — is refused before anything happens.
	writeSecret(t, x.stopList, raw)
	_, out, err = x.restore(t, cfg, x.endpoint, randomBytes(t, 32))
	if err == nil || !strings.Contains(out, "rollback refused") {
		t.Fatalf("an older stop list was accepted: %v\n%s", err, out)
	}
	waitFor(t, 5*time.Second, "destination to log the accepted tokens", func() bool {
		return len(x.destLog("crosscloud token accepted")) == 2
	})
	time.Sleep(200 * time.Millisecond)
	if n := len(x.destLog("crosscloud token accepted")); n != 2 {
		t.Fatalf("destination accepted %d tokens; only the two releases outside the stop may land", n)
	}
}

// The operator can revoke one destination without stopping the others.
func TestLiveCrossCloud_OperatorRevokesDestination(t *testing.T) {
	x := newXCC(t)
	dest := x.destinationConfig(t, "destination")
	id := identityOf(t, bins.bootstrap, dest)
	x.startDestination(t, dest)
	cfg := x.sourceConfig(t, id, id["measurement_hex"])
	x.issueStop(t, "2", "-revoke", "simulated:"+id["measurement_hex"], "-reason", "decommissioned")

	res, out, err := x.restore(t, cfg, x.endpoint, randomBytes(t, 32))
	if err == nil || res.Error == nil || res.Error.Category != "authority" ||
		!strings.Contains(res.Error.Message, "destination measurement revoked by the operator") {
		t.Fatalf("release to a revoked destination: err=%v result=%+v\n%s", err, res, out)
	}
	if n := len(x.destLog("crosscloud token accepted")); n != 0 {
		t.Fatalf("revoked destination accepted %d tokens", n)
	}
}

// Simulation is never mistaken for hardware: without the operator saying
// so in the config, the source refuses to trust a simulated destination
// at all, before any handshake.
func TestLiveCrossCloud_SimulatedDestinationNeedsAcknowledgement(t *testing.T) {
	x := newXCC(t)
	dest := x.destinationConfig(t, "destination")
	id := identityOf(t, bins.bootstrap, dest)
	x.startDestination(t, dest)
	cfg := x.sourceConfig(t, id, id["measurement_hex"])

	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	delete(c["crosscloud"].(map[string]any), "insecure_simulated_destinations")
	strict := writeJSON(t, "sagvd-strict.json", c)

	_, out, err := x.restore(t, strict, x.endpoint, randomBytes(t, 32))
	if err == nil || !strings.Contains(out, "insecure_simulated_destinations") {
		t.Fatalf("release to a simulated destination without the acknowledgement: err=%v\n%s", err, out)
	}
	if n := len(x.destLog("crosscloud handshake answered")); n != 0 {
		t.Fatalf("the refusal came after %d handshakes; it must come before any", n)
	}
}

// A key release is never sent in the clear across a network: plain http
// to a non-loopback destination is refused before any connection.
func TestLiveCrossCloud_PlaintextRemoteEndpointRefused(t *testing.T) {
	x := newXCC(t)
	id := identityOf(t, bins.bootstrap, x.destinationConfig(t, "destination"))
	cfg := x.sourceConfig(t, id, id["measurement_hex"])
	_, out, err := x.restore(t, cfg, "http://203.0.113.7:8443", randomBytes(t, 32))
	if err == nil || !strings.Contains(out, "plain http is accepted only for a loopback destination") {
		t.Fatalf("plaintext remote endpoint: err=%v\n%s", err, out)
	}
}

// acp-bootstrap refuses to expose its key-release endpoint to a network
// without TLS and caller authentication.
func TestAcpBootstrap_RefusesUnauthenticatedNetworkExposure(t *testing.T) {
	x := newXCC(t)
	seed := filepath.Join(x.dir, "tee_seed")
	writeSecret(t, seed, randomBytes(t, 32))
	cfg := writeJSON(t, "open.json", map[string]any{
		"http":             map[string]any{"listen_address": "0.0.0.0:0"},
		"tee":              map[string]any{"provider": "simulated", "insecure_simulation": true, "workload_descriptor": destinationDescriptor, "seed_path": seed},
		"source_authority": map[string]any{"kid": "sagvd-authority-demo", "public_key_path": x.authorityPEM},
	})
	out, err := exec.Command(bins.bootstrap, "-config", cfg).CombinedOutput()
	if err == nil {
		t.Fatalf("acp-bootstrap started on 0.0.0.0 without TLS\n%s", out)
	}
	for _, want := range []string{"http.tls.enabled required", "http.tls.client_cas or http.bearer_token(_file) required"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("refusal does not say %q:\n%s", want, out)
		}
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func writeSecret(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
