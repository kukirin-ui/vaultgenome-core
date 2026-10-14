// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/vault-genome/vaultgenome-core/internal/shared/buildinfo"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/crosscloud"
	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/restorer"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// version / commit are populated at link time by the Makefile.
var (
	version = "0.0.0-dev"
	commit  = "none"
)

func main() {
	version, commit = buildinfo.Resolve(version, commit)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("acp-bootstrap %s (commit %s)\n", version, commit)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		case "identity":
			if err := runIdentity(os.Args[2:], os.Stdout); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("acp-bootstrap identity: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		case "seal-keys":
			if err := runSealKeys(os.Args[2:], os.Stdout, os.Stderr); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("acp-bootstrap seal-keys: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		}
	}
	if err := run(os.Args[1:]); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).
			Error("acp-bootstrap: terminated with error", "err", err.Error())
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`acp-bootstrap %s — destination daemon for Phase 4 cross-cloud restore

USAGE
    acp-bootstrap -config /path/to/config.json
    acp-bootstrap identity -config /path/to/config.json
    acp-bootstrap seal-keys -config /path/to/config.json
    acp-bootstrap version
    acp-bootstrap help

    identity prints, as JSON, what the source operator pins for this
    destination: TEE provider, measurement, and (simulated backend) the
    attestation public key. It opens no listener.

CONFIG FORMAT
    JSON file with sections: http, tee, source_authority, genome, health, log.
    See cmd/acp-bootstrap/config.go for the full schema.

ENDPOINTS
    POST /v1/crosscloud/handshake — answer a signed handshake with a fresh
                                    X25519 key and Evidence that binds it
    POST /v1/crosscloud/token     — accept a signed key-release token whose
                                    DEKs are encapsulated to that key
    GET  /v1/genome/restores      — (genome section) every released
                                    genome's restore and where it stands
    GET  /v1/genome/receipt?key_id=ID
                                  — a completed restore's receipt, signed
                                    with this TEE's Evidence

REFERENCES
    ADR 0006 — Cross-Cloud KMS-Mediated Restore
    ADR 0009 — X25519 KEM for cross-cloud DEK delivery
    docs/operator/06_cross_cloud_restore.md
`, version)
}

func run(args []string) error {
	fs := flag.NewFlagSet("acp-bootstrap", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("acp-bootstrap: -config is required (see acp-bootstrap help)")
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("acp-bootstrap: config validation: %w", err)
	}
	if err := cfg.ResolveSecrets(); err != nil {
		return err
	}

	d, err := newDaemon(cfg, buildLogger(cfg.Log))
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return d.serve(ctx)
}

// daemon is a fully wired acp-bootstrap: receiver, keystore and bound
// listeners. newDaemon does everything that can fail on bad
// configuration, so a misconfigured daemon exits before it accepts a
// single connection; serve only serves.
type daemon struct {
	log      *slog.Logger
	receiver *crosscloud.Receiver
	keystore *keys.InMemoryStore
	restorer *restorer.Restorer // nil unless genome restore is configured

	api      *http.Server
	apiLn    net.Listener
	health   *http.Server
	healthLn net.Listener
}

func newDaemon(cfg Config, logger *slog.Logger) (*daemon, error) {
	clock := shared_time.NewSystemClock()

	kind, err := tee.ParseProvider(cfg.TEE.Provider)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: tee.provider: %w", err)
	}
	producer, err := buildTEEProducer(cfg.TEE)
	if err != nil {
		return nil, err
	}
	sourceResolver, err := loadSourceAuthorityResolver(cfg.SourceAuthority, clock)
	if err != nil {
		return nil, err
	}

	// Unwrapped DEKs land here. Each is encapsulated with the X25519 KEM
	// to a key the Receiver generates per handshake and never writes out
	// (ADR 0009); there is no other way in.
	keystore := keys.NewInMemoryStore(clock)

	// With genome restore configured, a released genome key brings its
	// bundle up here, opened with the key where it lies (ADR 0011).
	var rest *restorer.Restorer
	if cfg.Genome.Enabled() {
		rest, err = restorer.New(restorer.Config{
			BundleDir:  cfg.Genome.BundleDir,
			RestoreDir: cfg.Genome.RestoreDir,
			Keys:       keystore,
			Erase:      keystore.EraseSealing,
			TEE:        producer,
			Kind:       kind,
			Logger:     logger,
			Clock:      clock,
			Rescan:     time.Duration(cfg.Genome.RescanSeconds) * time.Second,
			Gate:       gateConfig(cfg.Genome.Gate),
		})
		if err != nil {
			return nil, fmt.Errorf("acp-bootstrap: genome: %w", err)
		}
	}
	rcfg := crosscloud.Config{
		SourceAuthorityKeys: sourceResolver,
		LocalTEE:            producer,
		Kind:                kind,
		Registrar:           keystore,
		Clock:               clock,
	}
	if rest != nil {
		rcfg.OnDelivery = rest.Delivered
	}
	receiver, err := crosscloud.NewReceiver(rcfg)
	if err != nil {
		return nil, err
	}
	handler, err := crosscloud.NewHTTPHandler(crosscloud.HTTPHandlerConfig{
		Receiver:    receiver,
		BearerToken: cfg.HTTP.BearerToken,
		Logger:      logger,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	for path, h := range handler.Routes() {
		mux.HandleFunc(path, h)
	}
	if rest != nil {
		for path, h := range rest.Routes(cfg.HTTP.BearerToken) {
			mux.HandleFunc(path, h)
		}
	}

	api, apiLn, err := buildHTTPServer(cfg.TEE, cfg.HTTP, mux, logger)
	if err != nil {
		return nil, err
	}
	d := &daemon{log: logger, receiver: receiver, keystore: keystore, restorer: rest, api: api, apiLn: apiLn}

	if cfg.Health.ListenAddress != "" {
		ln, err := net.Listen("tcp", cfg.Health.ListenAddress)
		if err != nil {
			_ = apiLn.Close()
			return nil, fmt.Errorf("acp-bootstrap: bind health %s: %w", cfg.Health.ListenAddress, err)
		}
		d.health = &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: buildHealthMux()}
		d.healthLn = ln
	}

	if kind == tee.ProviderSimulated {
		logger.Warn("SIMULATED TEE: no hardware isolation — its Evidence is signed by a key read from a file; development and tests only")
	}
	logger.Info("acp-bootstrap ready",
		"version", version,
		"commit", commit,
		"http_listen", apiLn.Addr().String(),
		"tls", cfg.HTTP.TLS.Enabled,
		"mtls", cfg.HTTP.TLS.ClientCAs != "",
		"bearer_token", cfg.HTTP.BearerToken != "",
		"tee_provider", string(kind),
		"measurement_hex", fmt.Sprintf("%x", producer.Measurement()),
		"source_authority_kid", cfg.SourceAuthority.KeyID,
		"key_delivery", kms.DeliveryModeX25519KEM,
		"genome_restore", rest != nil,
		"genome_gate", cfg.Genome.Gate != nil,
		"genome_bundle_dir", cfg.Genome.BundleDir,
		"genome_restore_dir", cfg.Genome.RestoreDir,
	)
	return d, nil
}

// serve runs the listeners until ctx is cancelled or the API server
// fails, then shuts both down gracefully.
func (d *daemon) serve(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- d.api.Serve(d.apiLn) }()
	restoreCtx, stopRestorer := context.WithCancel(context.Background())
	restorerDone := make(chan struct{})
	if d.restorer != nil {
		go func() { d.restorer.Run(restoreCtx); close(restorerDone) }()
	} else {
		close(restorerDone)
	}
	defer func() { stopRestorer(); <-restorerDone }()
	if d.health != nil {
		go func() {
			if err := d.health.Serve(d.healthLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				d.log.Warn("health server stopped", "err", err.Error())
			}
		}()
	}

	var serveErr error
	select {
	case <-ctx.Done():
		d.log.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.api.Shutdown(shutdownCtx); err != nil {
		d.log.Warn("http server shutdown error", "err", err.Error())
	}
	if d.health != nil {
		_ = d.health.Shutdown(shutdownCtx)
	}
	d.log.Info("acp-bootstrap stopped")
	return serveErr
}

// gateConfig turns the genome.gate section into the restorer's gate.
func gateConfig(g *GateConfig) *restorer.GateConfig {
	if g == nil {
		return nil
	}
	timeout := 1800 * time.Second
	if g.TimeoutSeconds > 0 {
		timeout = time.Duration(g.TimeoutSeconds) * time.Second
	}
	return &restorer.GateConfig{
		Command:     g.Command,
		Env:         g.Env,
		Tolerance:   equivalence.Tolerance{Atol: g.Atol, Rtol: g.Rtol},
		MaxOutliers: g.MaxOutliers,
		Timeout:     timeout,
		Required:    g.Required,
	}
}

// buildTEEProducer constructs the local TEE producer per cfg.Provider.
func buildTEEProducer(cfg TEEConfig) (tee.Producer, error) {
	switch cfg.Provider {
	case string(tee.ProviderGCPSEVSNP):
		return tee.NewGCPSEVProducer(tee.GCPSEVProducerConfig{TSMReportDir: cfg.TSMReportDir})
	case string(tee.ProviderGCPTDX):
		return tee.NewGCPTDXProducer(tee.GCPTDXProducerConfig{TSMReportDir: cfg.TSMReportDir})
	case string(tee.ProviderAzureCGPU):
		return tee.NewAzureCGPUProducer(tee.AzureCGPUProducerConfig{GPUAttestCommand: cfg.GPUAttestCommand, TPM2ToolsDir: cfg.TPM2ToolsDir, AKHandle: cfg.AKHandle})
	case string(tee.ProviderSimulated):
		seed, err := readExactly(cfg.SeedPath, crypto.Ed25519SeedSize, "tee.seed_path")
		if err != nil {
			return nil, err
		}
		return tee.NewSimulated([]byte(cfg.WorkloadDescriptor), seed)
	default:
		return nil, fmt.Errorf("acp-bootstrap: tee.provider %q is not available in this build (supported: %v)", cfg.Provider, supportedProviders)
	}
}

// pubkeyResolver is a verify-only keys.Resolver wrapping a single
// (kid, purpose, pubkey) triple. The destination needs to verify
// signatures on incoming handshakes / tokens but never signs with
// the source authority key, so a pubkey-only resolver is the right
// shape.
type pubkeyResolver struct {
	kid     ids.KeyID
	purpose keys.Purpose
	pub     crypto.PublicKey
	created int64
}

func (r *pubkeyResolver) Resolve(kid ids.KeyID, want keys.Purpose) (keys.VerifyingKey, error) {
	if kid != r.kid {
		return keys.VerifyingKey{}, fmt.Errorf("acp-bootstrap: kid %q not registered (have %q)", kid, r.kid)
	}
	if want != r.purpose {
		return keys.VerifyingKey{}, fmt.Errorf("acp-bootstrap: kid %q registered for purpose %d, requested %d", kid, r.purpose, want)
	}
	return keys.VerifyingKey{
		KeyID:     r.kid,
		Purpose:   r.purpose,
		PublicKey: r.pub,
		CreatedAt: r.created,
	}, nil
}

// loadSourceAuthorityResolver loads the source-authority public key
// from disk (raw or PEM) and wraps it in a verify-only resolver
// keyed by cfg.KeyID under keys.PurposeSigningAuthority.
func loadSourceAuthorityResolver(cfg SourceAuthorityConfig, clock shared_time.Clock) (keys.Resolver, error) {
	pub, err := loadAttestorPubKey(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: load source authority pubkey: %w", err)
	}
	return &pubkeyResolver{
		kid:     ids.KeyID(cfg.KeyID),
		purpose: keys.PurposeSigningAuthority,
		pub:     pub,
		created: clock.Now().UTC().Unix(),
	}, nil
}

// loadAttestorPubKey reads either a raw 32-byte Ed25519 public key
// file or a PEM-encoded SubjectPublicKeyInfo and returns the
// crypto.PublicKey.
func loadAttestorPubKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(data), "-----BEGIN") {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("attestor pubkey: invalid PEM")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attestor pubkey: parse PKIX: %w", err)
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("attestor pubkey: PEM key is %T, want ed25519.PublicKey", key)
		}
		return crypto.PublicKey(ed), nil
	}
	if len(data) != crypto.Ed25519PublicKeySize {
		return nil, fmt.Errorf("attestor pubkey: file %d bytes, want %d (raw Ed25519) or PEM-encoded", len(data), crypto.Ed25519PublicKeySize)
	}
	return crypto.PublicKey(data), nil
}

// buildHTTPServer assembles the http.Server and binds its listener.
// With TLS enabled the listener speaks TLS 1.3 only; the server
// certificate and (for mTLS) the client CA bundle are loaded here, so a
// bad path fails startup instead of the first handshake.
func buildHTTPServer(teeCfg TEEConfig, cfg HTTPConfig, handler http.Handler, logger *slog.Logger) (*http.Server, net.Listener, error) {
	var tlsCfg *tls.Config
	if cfg.TLS.Enabled {
		certPEM, err := os.ReadFile(cfg.TLS.ServerCert)
		if err != nil {
			return nil, nil, fmt.Errorf("acp-bootstrap: load tls.server_cert/server_key: %w", err)
		}
		// The key file may be sealed to this host (`acp-bootstrap seal-keys`, ADR 0023).
		keyPEM, err := readSecret(teeCfg, cfg.TLS.ServerKey, 0, "http.tls.server_key")
		if err != nil {
			return nil, nil, fmt.Errorf("acp-bootstrap: load tls.server_cert/server_key: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("acp-bootstrap: load tls.server_cert/server_key: %w", err)
		}
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
		if cfg.TLS.ClientCAs != "" {
			caRaw, err := os.ReadFile(cfg.TLS.ClientCAs)
			if err != nil {
				return nil, nil, fmt.Errorf("acp-bootstrap: read tls.client_cas: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caRaw) {
				return nil, nil, errors.New("acp-bootstrap: tls.client_cas contained no PEM certs")
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	ln, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("acp-bootstrap: bind %s: %w", cfg.ListenAddress, err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout(),
		WriteTimeout:      cfg.WriteTimeout(),
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	return srv, ln, nil
}

func buildHealthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	return mux
}

func buildLogger(cfg LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.ToLower(cfg.Format) == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

// readExactly reads a file and verifies it is exactly want bytes.
// Used for raw-bytes key files (Ed25519 seeds, AES keys,
// measurements).
func readExactly(path string, want int, label string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("acp-bootstrap: %s required", label)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: read %s %q: %w", label, path, err)
	}
	if len(data) != want {
		return nil, fmt.Errorf("acp-bootstrap: %s %q: %d bytes, want %d", label, path, len(data), want)
	}
	return data, nil
}
