// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// help names every command, every endpoint and where the schema lives.
func TestPrintUsage_NamesEveryCommand(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	printUsage()
	os.Stdout = stdout
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"acp-bootstrap -config", "acp-bootstrap identity -config", "acp-bootstrap seal-keys -config", "acp-bootstrap version", "acp-bootstrap help",
		"/v1/crosscloud/handshake", "/v1/crosscloud/token", "/v1/genome/restores", "/v1/genome/receipt", "cmd/acp-bootstrap/config.go",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

// run stops before it listens when a secret it must resolve is not there
// or its TEE cannot be built.
func TestRun_StopsOnStartupFaults(t *testing.T) {
	dst := newDestination(t)
	noToken := dst.config()
	noToken.HTTP.BearerTokenFile = filepath.Join(dst.dir, "absent_token")
	noSeed := dst.config()
	noSeed.TEE.SeedPath = filepath.Join(dst.dir, "absent_seed")
	for name, tc := range map[string]struct {
		cfg  Config
		want string
	}{
		"token file that is not there": {noToken, "read http.bearer_token_file"},
		"material that does not load":  {noSeed, "read tee.seed_path"},
	} {
		if err := tc.cfg.Validate(); err != nil {
			t.Fatalf("%s: the config itself validates: %v", name, err)
		}
		err := run([]string{"-config", writeConfigFile(t, dst.dir, tc.cfg)})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: run returned %v, want an error mentioning %q", name, err, tc.want)
		}
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, timeout)
		}
		<-time.After(20 * time.Millisecond)
	}
}

// The daemon as the operator runs it: a config file, the health surface
// up, SIGTERM to stop, and a clean return with the listeners down.
func TestRun_ServesAndStopsOnSIGTERM(t *testing.T) {
	dst := newDestination(t)
	cfg := dst.config()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthAddr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Health.ListenAddress = healthAddr
	cfg.Log = LogConfig{Level: "error", Format: "text"}
	cfgPath := writeConfigFile(t, dst.dir, cfg)

	// The test process keeps SIGTERM non-fatal for the whole test: the
	// daemon arms its own handler after the listeners are up.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	defer signal.Stop(sigs)

	done := make(chan error, 1)
	go func() { done <- run([]string{"-config", cfgPath}) }()

	client := &http.Client{Timeout: time.Second}
	up := func() bool {
		resp, err := client.Get("http://" + healthAddr + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	waitFor(t, "the health surface coming up", 10*time.Second, func() bool {
		select {
		case err := <-done:
			t.Fatalf("run returned before the health surface came up: %v", err)
		default:
		}
		return up()
	})

	// Stop it as the service manager would; repeat until it is heard.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("a signalled stop is a clean stop, got %v", err)
			}
			if up() {
				t.Fatal("the health surface is still up after the stop")
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon did not stop on SIGTERM")
		}
	}
}

// A provider nobody knows is refused by name before anything is built.
func TestNewDaemon_RefusesAnUnknownProvider(t *testing.T) {
	dst := newDestination(t)
	cfg := dst.config()
	cfg.TEE.Provider = "nope"
	d, err := newDaemon(cfg, quietLog)
	if err == nil || !strings.Contains(err.Error(), "acp-bootstrap: tee.provider") {
		if d != nil {
			_ = d.apiLn.Close()
		}
		t.Fatalf("newDaemon: %v", err)
	}
}

// With genome restore configured the daemon brings the restorer up with
// its directories, mounts its routes beside the cross-cloud ones and runs
// it until shutdown; a receipt it cannot read stops the start.
func TestNewDaemon_GenomeRestore(t *testing.T) {
	dst := newDestination(t)
	cfg := dst.config()
	cfg.Genome = GenomeConfig{BundleDir: filepath.Join(dst.dir, "bundles"), RestoreDir: filepath.Join(dst.dir, "restored"), RescanSeconds: 1,
		Gate: &GateConfig{Command: []string{"/nonexistent/vg-door", "--genome", "{genome}"}, Atol: 1e-3}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	r := start(t, cfg)
	if r.d.restorer == nil {
		t.Fatal("no restorer")
	}
	for _, d := range []string{cfg.Genome.BundleDir, cfg.Genome.RestoreDir} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			t.Fatalf("%s was not created: %v", d, err)
		}
	}
	get := func(path string) (int, string) {
		resp, err := http.Get(r.url + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	if status, body := get("/v1/genome/restores"); status != http.StatusOK || !strings.Contains(body, `"restores"`) {
		t.Fatalf("restores: HTTP %d %s", status, body)
	}
	if status, body := get("/v1/genome/receipt"); status != http.StatusBadRequest || !strings.Contains(body, "key_id") {
		t.Fatalf("receipt without key_id: HTTP %d %s", status, body)
	}
	r.stop()
	if !r.waitStopped() || r.err != nil {
		t.Fatalf("stop: %v", r.err)
	}

	writeFile(t, filepath.Join(cfg.Genome.RestoreDir, "dek-9.receipt.json"), []byte("not a receipt"))
	d, err := newDaemon(cfg, quietLog)
	if err == nil || !strings.Contains(err.Error(), "acp-bootstrap: genome:") {
		if d != nil {
			_ = d.apiLn.Close()
		}
		t.Fatalf("a broken receipt was accepted: %v", err)
	}
}

// A server key that is not the certificate's is refused as the pair, and
// no listener is bound.
func TestBuildHTTPServer_RejectsAKeyThatIsNotTheCertificates(t *testing.T) {
	dst := newDestination(t)
	p := newPKI(t, dst.dir)
	_, otherKey := p.issue(t, "another", x509.ExtKeyUsageServerAuth)
	otherKeyPath := filepath.Join(dst.dir, "other.key")
	writeFile(t, otherKeyPath, otherKey)
	cfg := HTTPConfig{ListenAddress: "127.0.0.1:0", TLS: TLSServerConfig{Enabled: true, ServerCert: p.serverCert, ServerKey: otherKeyPath}}
	_, ln, err := buildHTTPServer(TEEConfig{}, cfg, http.NewServeMux(), quietLog)
	if err == nil || !strings.Contains(err.Error(), "load tls.server_cert/server_key") {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatalf("buildHTTPServer: %v", err)
	}
}

// serve reports an API listener that fails underneath it and takes the
// health listener down with it.
func TestServe_ReportsAFailedAPIListener(t *testing.T) {
	dst := newDestination(t)
	d, err := newDaemon(dst.config(), quietLog)
	if err != nil {
		t.Fatal(err)
	}
	healthAddr := d.healthLn.Addr().String()
	if err := d.apiLn.Close(); err != nil {
		t.Fatal(err)
	}
	err = d.serve(context.Background())
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve on a closed listener returned %v", err)
	}
	waitFor(t, "the health listener closing", 5*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", healthAddr, time.Second)
		if err != nil {
			return true
		}
		_ = c.Close()
		return false
	})
}
