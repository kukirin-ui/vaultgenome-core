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

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/observability/health"
	"github.com/vault-genome/vaultgenome-core/internal/observability/metrics"
	"github.com/vault-genome/vaultgenome-core/internal/observability/teemetrics"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/incident"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
	"github.com/vault-genome/vaultgenome-core/internal/vault/trust"
)

// These variables are populated at link time by the Makefile /
// release pipeline. See Makefile target "build" and
// .github/workflows/release.yml.
var (
	version = "0.0.0-dev"
	commit  = "none"
)

func main() {
	version, commit = buildinfo.Resolve(version, commit)
	// Sub-command dispatch (version / help) — these short-circuit
	// before any daemon wiring so the binary remains cheap to probe
	// in CI.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("sagvd %s (commit %s)\n", version, commit)
			return
		case "help", "--help", "-h":
			printUsage()
			return
		case "identity":
			if err := runIdentityCmd(os.Args[2:], os.Stdout); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("sagvd identity: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		case "crosscloud-restore":
			// Phase 4 Cross-Cloud KMS-Mediated Restore CLI entry
			// point. Loads cross-cloud materials from the same
			// config file the daemon uses, instantiates a
			// kms.Coordinator, and runs CoordinateRestore once.
			// Output is JSON: CoordinationResult on success;
			// classified-error envelope on failure.
			if err := runCrossCloudRestoreCmd(os.Args[2:]); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("sagvd crosscloud-restore: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		case "failover":
			// Carries out the operator's failover policy (ADR 0012).
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			code, err := runFailoverCmd(ctx, os.Args[2:])
			stop()
			if err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("sagvd failover: terminated with error", "err", err.Error())
			}
			os.Exit(code)
		case "seal-keys":
			if err := runSealKeysCmd(os.Args[2:], os.Stdout, os.Stderr); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("sagvd seal-keys: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		case "escrow-provision":
			// The escrow key, made in this process and sealed to this
			// host's TEE before it is written (ADR 0016).
			if err := runEscrowProvisionCmd(os.Args[2:], os.Stdin, os.Stdout, os.Stderr); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("sagvd escrow-provision: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		case "crosscloud-confirm":
			// Confirms a released genome's restore from the
			// destination's TEE-signed receipt and records it
			// (ADR 0011).
			if err := runCrossCloudConfirmCmd(os.Args[2:]); err != nil {
				slog.New(slog.NewJSONHandler(os.Stderr, nil)).
					Error("sagvd crosscloud-confirm: terminated with error", "err", err.Error())
				os.Exit(1)
			}
			return
		}
	}

	if err := runDaemon(os.Args[1:]); err != nil {
		// Error path: JSON-log the failure so operators see the
		// category/code in their log aggregator, then exit
		// non-zero.
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).
			Error("sagvd: terminated with error", "err", err.Error())
		os.Exit(1)
	}
}

// runDaemon is the full daemon entry point extracted out of main()
// so it is testable (no os.Exit, no global state).
func runDaemon(args []string) error {
	fs := flag.NewFlagSet("sagvd", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("sagvd: -config is required (see sagvd help)")
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("sagvd: config validation: %w", err)
	}
	if err := cfg.ResolveSecrets(); err != nil {
		return err
	}

	logger := buildLogger(cfg.Log)
	clock := shared_time.NewSystemClock()

	logger.Info("sagvd starting",
		"version", version,
		"commit", commit,
		"config_path", configPath,
		"vault_listen_address", cfg.Vault.ListenAddress,
		"http_api_listen_address", cfg.HTTPAPI.ListenAddress,
		"health_listen_address", cfg.Health.ListenAddress,
		"workload_descriptor", cfg.TEE.WorkloadDescriptor,
	)

	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return err
	}
	defer func() { _ = mat.Close() }()

	// Log the vault's authority-signing pubkey + every accepted
	// worker kid/pubkey once. Operators cross-check against the
	// worker-side `worker signing identity` line emitted by
	// acp-compute at startup.
	logger.Info("sagvd authority signing identity",
		"kid", string(mat.AuthoritySigningKeyID),
		"pubkey_hex", hex.EncodeToString(mat.AuthoritySigningPublicKey),
	)
	logger.Info("sagvd session sealing identity",
		"kid", string(mat.SessionSealingKeyID),
	)
	logger.Info("sagvd TEE identity",
		"tee_provider", string(mat.Provider),
		"measurement_hex", hex.EncodeToString(mat.Producer.Measurement()),
		"peer_provider", string(mat.PeerProvider),
	)
	if mat.Provider == tee.ProviderSimulated {
		logger.Warn("SIMULATED TEE: no hardware isolation — this vault's Return Path Evidence is signed by a key read from a file; development and tests only")
	}
	if mat.Escrow != nil {
		logger.Info("sagvd escrow key identity",
			"escrow_key", escrow.KeyTag(mat.Escrow.PublicKey()),
			"storage", mat.EscrowSource,
		)
		if mat.EscrowSource == escrowSourcePlaintext {
			logger.Warn("PLAINTEXT ESCROW KEY: key_escrow_path holds the escrow private key in the clear; accepted under the simulated TEE only — on hardware, seal it with `sagvd escrow-provision` (ADR 0016)")
		}
	}
	for _, w := range mat.WorkerEntries {
		logger.Info("sagvd accepted worker signing identity",
			"kid", w.KeyID,
			"pubkey_hex", w.SigningPublicKeyHex,
			"note", w.Note,
		)
	}

	registry := metrics.NewRegistry()
	teeRec := teemetrics.New(registry)
	mat.InstrumentTEE(teeRec, string(mat.Provider))
	teeRec.RecordCapability(string(mat.Provider), true)

	queue := NewJobQueue(clock, cfg.Runtime.QueuePoll())

	// The Return Path audit log: opened and verified before anything is
	// decided. Without it (no gate jobs configured) trust decisions are
	// not on record, and the daemon says so.
	audit, err := openReturnPathAudit(cfg, clock, registry)
	if err != nil {
		return err
	}
	defer func() { _ = audit.Close() }()
	if audit != nil {
		logger.Info("sagvd audit log open",
			"path", cfg.Audit.LogPath,
			"events", audit.Len(),
			"tip", audit.Tip(),
			"audit_kid", cfg.Keys.AuditSigning.KeyID,
		)
	} else {
		logger.Warn("sagvd runs without a Return Path audit log: trust decisions are not on record (set audit.log_path)")
	}

	genomes := newGenomeJobs(cfg, clock, mat.Escrow)

	// The authority that drives the nine stages for every gate job
	// (ADR 0015): its decisions go to the Return Path audit log, its
	// artifacts are signed under the authority key, its disclosures are
	// sealed to the workers' session-sealing key.
	var authority *orchestration.Authority
	if genomes != nil {
		var stopList trust.StopListSource
		if cfg.OperatorStopEnabled() {
			src, serial, err := newOperatorStopSource(cfg.OperatorStop)
			if err != nil {
				return err
			}
			stopList = src
			logger.Info("sagvd operator stop list in force for gate jobs",
				"list_path", cfg.OperatorStop.ListPath, "kid", cfg.OperatorStop.KeyID, "serial", serial)
		}
		authority, err = orchestration.NewAuthority(orchestration.AuthorityOptions{
			Clock:          clock,
			Signer:         mat.Store,
			Sealer:         mat.Store,
			Resolver:       mat.Store,
			AuthorityKeyID: mat.AuthoritySigningKeyID,
			RecipientKeyID: mat.SessionSealingKeyID,
			Audit:          audit.Chain(),
			AuditSigner:    audit.Signer(),
			AuditKeyID:     audit.KeyID(),
			PolicyVersion:  ids.PolicyVersion(cfg.PolicyVersion()),
			Profiles:       []string{PolicyProfileGate},
			StopList:       stopList,
			Zeroizer:       incident.ZeroizerFunc(mat.Store.Zeroize),
		})
		if err != nil {
			return fmt.Errorf("sagvd: build the orchestration authority: %w", err)
		}
		logger.Info("sagvd gate jobs enabled: the nine-stage flow is driven for every job",
			"bundle_dir", cfg.Genome.BundleDir,
			"escrow_key_configured", mat.Escrow != nil,
			"policy_version", cfg.PolicyVersion(),
			"policy_profile", PolicyProfileGate,
			"operator_stop", cfg.OperatorStopEnabled(),
			"evidence_max_age", cfg.Runtime.EvidenceMaxAge().String(),
		)
	} else if cfg.HTTPAPI.ListenAddress != "" {
		logger.Warn("sagvd REST API accepts no jobs: genome.bundle_dir is not configured")
	}

	daemon, err := NewDaemon(cfg, mat, queue, genomes, audit, clock, logger, registry)
	if err != nil {
		return err
	}

	httpAPI, err := NewHTTPAPIServer(
		cfg.HTTPAPI, cfg.Runtime, queue,
		genomes, authority,
		clock, registry, logger,
	)
	if err != nil {
		return err
	}
	if err := httpAPI.Start(); err != nil {
		return err
	}

	// Health / metrics HTTP surface. Empty ListenAddress disables
	// the server (tests and loopback-only demos).
	hs := health.NewServer(cfg.Health.ListenAddress, daemon.Health(), registry, logger)
	if err := hs.Start(); err != nil {
		return fmt.Errorf("sagvd: health server: %w", err)
	}

	// Signal-driven shutdown: SIGINT / SIGTERM cancel the ctx
	// handed to daemon.Run; on return we run graceful cleanup.
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runErr := daemon.Run(ctx)

	// Graceful shutdown: flip health flags first so any in-flight
	// probe sees 503 before we tear down state; then close the
	// two HTTP servers; finally zeroize keys.
	daemon.Shutdown()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := httpAPI.Close(shutCtx); err != nil {
		logger.Warn("sagvd HTTP API server shutdown error", "err", err)
	}
	if err := hs.Close(shutCtx); err != nil {
		logger.Warn("sagvd health server shutdown error", "err", err)
	}
	daemon.Zeroize()

	logger.Info("sagvd stopped")
	return runErr
}

// buildLogger constructs a *slog.Logger per the LogConfig. Invalid
// combinations are filtered out in Validate(); buildLogger treats
// any survivor as one of the four accepted values.
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
	fmt.Println("sagvd — Secure AI Genome Vault Daemon (authority / vault)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sagvd -config PATH")
	fmt.Println("  sagvd identity -config PATH")
	fmt.Println("  sagvd crosscloud-restore -config PATH -decision-id ID -destination-kind KIND \\")
	fmt.Println("        -destination-endpoint URL {-key-file KID:PATH | -key-escrow ENVELOPE}... [-session-id ID] [-manifest-id ID]")
	fmt.Println("  sagvd crosscloud-confirm -config PATH -decision-id ID -destination-endpoint URL \\")
	fmt.Println("        {-bundle PATH | -key-id KID} [-require-gate EQUIVALENT|EXACT] [-wait DURATION]")
	fmt.Println("  sagvd failover -config PATH -policy POLICY.json -outbox DIR [-poll 2s] [-confirm-wait 15m] [-report PATH]")
	fmt.Println("  sagvd escrow-provision -config PATH -out SEALED -pub PUBLIC.pem [-recovery-to RECOVERY.pem -recovery-out ENVELOPE] [-stdin]")
	fmt.Println("  sagvd seal-keys -config PATH")
	fmt.Println("  sagvd version")
	fmt.Println("  sagvd help")
	fmt.Println()
	fmt.Println("Description:")
	fmt.Println("  Authority daemon. Binds the Return Path listener for")
	fmt.Println("  acp-compute workers and the operator REST API for job")
	fmt.Println("  submission (POST /v1/jobs) and lookup (GET /v1/jobs/{id}).")
	fmt.Println()
	fmt.Println("  identity prints the authority signing key and TEE identity other")
	fmt.Println("  hosts pin, as JSON. crosscloud-restore releases DEKs to an attested,")
	fmt.Println("  allow-listed acp-bootstrap destination (docs/operator/06_cross_cloud_restore.md);")
	fmt.Println("  crosscloud-confirm records its restore once the destination's TEE-signed")
	fmt.Println("  receipt checks out against that release (ADR 0011). failover carries out")
	fmt.Println("  the operator's signed failover policy: when the primary's sentinel reports")
	fmt.Println("  a compromise or its heartbeat stops, it releases the last trustworthy")
	fmt.Println("  genome's escrowed key to the standby the policy names and confirms the")
	fmt.Println("  restore (ADR 0012). escrow-provision makes the authority's escrow key")
	fmt.Println("  inside this process and writes it sealed to this host's TEE, never in")
	fmt.Println("  the clear; with -recovery-to it also wraps the key to the operator's")
	fmt.Println("  recovery key, and -stdin re-seals a recovered key on a new host (ADR 0016).")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -config PATH   JSON config file; see cmd/sagvd/doc.go for schema.")
}
