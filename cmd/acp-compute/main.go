// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/vault-genome/vaultgenome-core/internal/shared/buildinfo"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// Build-time variables. -ldflags "-X main.version=... -X main.commit=..."
// at release time; the defaults here are what a local `go run` sees.
var (
	version = "0.0.0-dev"
	commit  = "none"
)

func main() {
	version, commit = buildinfo.Resolve(version, commit)
	// Sub-command dispatch (version / help) — these short-circuit before
	// any daemon wiring so the binary remains cheap to probe in CI.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("acp-compute %s (commit %s)\n", version, commit)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		case "seal-keys":
			if err := runSealKeysCmd(os.Args[2:], os.Stdout, os.Stderr); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("acp-compute seal-keys: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		case "identity":
			if err := runIdentityCmd(os.Args[2:], os.Stdout); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("acp-compute identity: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		}
	}

	if err := runDaemon(os.Args[1:]); err != nil {
		// Error path: JSON-log the failure so operators see the
		// category/code in their log aggregator, then exit non-zero.
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).
			Error("acp-compute: terminated with error", "err", err.Error())
		os.Exit(1)
	}
}

// runDaemon is the full daemon entry point extracted out of main() so
// it is testable (no os.Exit, no global state).
func runDaemon(args []string) error {
	fs := flag.NewFlagSet("acp-compute", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("acp-compute: -config is required (see acp-compute help)")
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("acp-compute: config validation: %w", err)
	}

	logger := buildLogger(cfg.Log)
	clock := shared_time.NewSystemClock()

	logger.Info("acp-compute starting",
		"version", version,
		"commit", commit,
		"config_path", configPath,
		"vault_address", cfg.Vault.Address,
		"workload_descriptor", cfg.TEE.WorkloadDescriptor,
	)

	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return err
	}

	// Log the worker's signing pubkey once; the operator copies this
	// into sagvd's PublicKeyResolver config so the vault can verify
	// every CandidateOutputFrame this worker produces.
	logger.Info("worker signing identity",
		"kid", string(mat.SigningKeyID),
		"pubkey_hex", hex.EncodeToString(mat.SigningPublicKey),
	)
	logger.Info("worker TEE identity",
		"tee_provider", string(mat.Provider),
		"measurement_hex", hex.EncodeToString(mat.Producer.Measurement()),
		"peer_provider", string(mat.PeerProvider),
	)
	if mat.Provider == tee.ProviderSimulated {
		logger.Warn("SIMULATED TEE: no hardware isolation — this worker's Return Path Evidence is signed by a key read from a file; development and tests only")
	}

	// R-11 swap point. The Reconstructor interface was frozen in
	// iteration 5, so the backend is the only production line that
	// changes: the daemon loop, the Return Path client and the
	// validation surface consume the interface. The worker restores a
	// genome's model through the door its config names and returns the
	// model's outputs for the authority to gate.
	recon, err := worker.NewGenomeReconstructor(worker.GenomeConfig{
		Command: cfg.Genome.Door.Command,
		Env:     cfg.Genome.Door.Env,
		Timeout: cfg.Genome.Door.Timeout(),
	}, clock)
	if err != nil {
		return err
	}
	logger.Info("genome door",
		"command", cfg.Genome.Door.Command,
		"timeout_seconds", cfg.Genome.Door.TimeoutSeconds,
	)

	registry := NewRegistry()
	daemon, err := NewDaemon(cfg, mat, clock, logger, recon, registry)
	if err != nil {
		return err
	}

	// Wire the HTTP surface (optional: empty ListenAddress disables).
	hs := NewHealthServer(cfg.Health.ListenAddress, daemon.Health(), registry, logger)
	if err := hs.Start(); err != nil {
		return fmt.Errorf("acp-compute: health server: %w", err)
	}

	// Signal-driven shutdown: SIGINT / SIGTERM cancel the ctx handed
	// to daemon.Run; on return we run graceful cleanup.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runErr := daemon.Run(ctx)

	// Graceful shutdown: flip health flags first so any in-flight
	// probe sees 503 before we tear down state; then close the HTTP
	// server; finally zeroize keys.
	daemon.Shutdown()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := hs.Close(shutCtx); err != nil {
		logger.Warn("health server shutdown error", "err", err)
	}
	daemon.Zeroize()

	logger.Info("acp-compute stopped")
	return runErr
}

// buildLogger constructs a *slog.Logger per the LogConfig. Invalid
// combinations are filtered out in Validate(); buildLogger treats any
// survivor as one of the four accepted values.
func buildLogger(cfg LogConfig) *slog.Logger {
	var lvl slog.Level
	switch cfg.Level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func printUsage() {
	fmt.Println("acp-compute — external compute worker (delegated, non-authority)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  acp-compute -config PATH")
	fmt.Println("  acp-compute identity -config PATH")
	fmt.Println("  acp-compute seal-keys -config PATH")
	fmt.Println("  acp-compute version")
	fmt.Println("  acp-compute help")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Long-lived worker daemon. Dials sagvd over the Return Path,")
	fmt.Println("  serves one gate job per session, then reconnects.")
	fmt.Println()
	fmt.Println("  identity prints what sagvd pins for this worker — its signing key,")
	fmt.Println("  its TEE provider and launch measurement — as JSON.")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -config PATH   JSON config file; see cmd/acp-compute/doc.go for schema.")
}
