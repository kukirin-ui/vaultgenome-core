// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/genome/tree"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// confirmPoll is how often -wait asks again while a restore is running.
var confirmPoll = 2 * time.Second

// runCrossCloudConfirmCmd confirms, from the destination's own receipt,
// that a genome whose key was released to it has been restored, and
// records the confirmation in the audit log (ADR 0011).
//
// Flags:
//
//	-config <path>               sagvd JSON config (required)
//	-decision-id <id>            the release decision, as recorded (required)
//	-destination-endpoint <url>  the destination acp-bootstrap (required)
//	-bundle <path>               the operator's bundle: it names the key, and
//	                             the destination must have restored exactly it
//	-key-id <kid>                the released key, when no bundle is given
//	-wait <duration>             keep asking while the restore is in progress
//
// The release is read from the verified audit log, never from flags: the
// receipt must be signed by the TEE the key went to and name the same
// decision, request, token and key.
func runCrossCloudConfirmCmd(args []string) error {
	fs := flag.NewFlagSet("sagvd crosscloud-confirm", flag.ContinueOnError)
	var (
		configPath, decisionID, endpoint, bundlePath, keyID, requireGate string
		wait                                                             time.Duration
	)
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	fs.StringVar(&decisionID, "decision-id", "", "the release decision to confirm (required)")
	fs.StringVar(&endpoint, "destination-endpoint", "", "destination acp-bootstrap base URL (required)")
	fs.StringVar(&bundlePath, "bundle", "", "the operator's .genome bundle the key was released for")
	fs.StringVar(&keyID, "key-id", "", "the released genome key, when no -bundle is given")
	fs.DurationVar(&wait, "wait", 0, "keep asking this long while the restore is still in progress")
	fs.StringVar(&requireGate, "require-gate", "", "require the destination's gate verdict on the restored model: EQUIVALENT (or better) or EXACT")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case configPath == "":
		return errors.New("crosscloud-confirm: -config required")
	case decisionID == "":
		return errors.New("crosscloud-confirm: -decision-id required")
	case endpoint == "":
		return errors.New("crosscloud-confirm: -destination-endpoint required")
	case bundlePath == "" && keyID == "":
		return errors.New("crosscloud-confirm: -bundle or -key-id required")
	case wait < 0:
		return errors.New("crosscloud-confirm: -wait must not be negative")
	case requireGate != "" && requireGate != receipt.GateEquivalent && requireGate != receipt.GateExact:
		return fmt.Errorf("crosscloud-confirm: -require-gate %q (want %s or %s)", requireGate, receipt.GateEquivalent, receipt.GateExact)
	}
	if err := checkDestinationEndpoint(endpoint); err != nil {
		return err
	}

	var expect *kms.ExpectedGenome
	if bundlePath != "" {
		id, err := bundle.Identify(bundlePath)
		if err != nil {
			return fmt.Errorf("crosscloud-confirm: -bundle: %w", err)
		}
		if keyID != "" && keyID != id.Header.KeyID {
			return fmt.Errorf("crosscloud-confirm: -bundle is keyed %s, not -key-id %s", id.Header.KeyID, keyID)
		}
		keyID = id.Header.KeyID
		files, err := tree.Files(id.Header)
		if err != nil {
			return fmt.Errorf("crosscloud-confirm: -bundle: %w", err)
		}
		expect = &kms.ExpectedGenome{BundleSHA256: id.SHA256, PayloadSHA256: id.Header.PayloadSHA256, TreeSHA256: tree.Digest(files)}
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("crosscloud-confirm: config validation: %w", err)
	}
	if !cfg.CrossCloud.Enabled {
		return errors.New("crosscloud-confirm: crosscloud.enabled=false in config — refusing to run")
	}
	clock := shared_time.NewSystemClock()
	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return err
	}
	xcc, err := LoadCrossCloudMaterials(cfg, clock)
	if err != nil {
		return err
	}
	if xcc == nil {
		return errors.New("crosscloud-confirm: cross-cloud materials nil despite cfg.CrossCloud.Enabled=true")
	}
	defer func() { _ = xcc.Close() }()

	out := confirmOutput{Status: "ok", DecisionID: decisionID, KeyID: keyID}
	release, err := kms.FindAuthorizedRelease(xcc.AuditChain.Events(), ids.DecisionID(decisionID))
	if err != nil {
		return printConfirm(out, xcc, err)
	}
	coord, err := kms.NewCoordinator(kms.Config{
		AuditChain:   xcc.AuditEmitter,
		Signer:       mat.Store,
		Verifiers:    xcc.VerifierRegistry,
		Policy:       xcc.Policy,
		Transport:    xcc.Transport,
		IDGenerator:  xcc.IDGenerator,
		NonceSource:  xcc.NonceSource,
		Clock:        clock,
		SigningKeyID: mat.AuthoritySigningKeyID,
		Receipts:     xcc.Transport,
	})
	if err != nil {
		return err
	}

	req := kms.ConfirmRequest{Release: release, DestinationEndpoint: endpoint, KeyID: ids.KeyID(keyID), Expect: expect, RequireGate: requireGate}
	deadline := time.Now().Add(wait)
	res, confirmErr := coord.ConfirmRestore(context.Background(), req)
	for confirmErr != nil && shared_errors.Is(confirmErr, shared_errors.CategoryOperational) && time.Now().Add(confirmPoll).Before(deadline) {
		time.Sleep(confirmPoll)
		res, confirmErr = coord.ConfirmRestore(context.Background(), req)
	}

	if confirmErr == nil {
		rc := res.Receipt
		out.DestinationKind = rc.DestinationKind
		out.DestinationMeasurement = rc.DestinationMeasurement
		out.BundleSHA256 = rc.BundleSHA256
		out.Generation = rc.Generation
		out.PayloadSHA256 = rc.PayloadSHA256
		out.TreeSHA256 = rc.TreeSHA256
		out.Files = rc.Files
		out.Bytes = rc.Bytes
		out.RestoreSeconds = rc.RestoreSeconds
		out.KeyToRestoredSeconds = rc.RestoredAt.Sub(rc.KeyReceivedAt).Seconds()
		out.AuthorizedToConfirmedSeconds = res.ConfirmedAt.Sub(release.AuthorizedAt).Seconds()
		out.MatchedOperatorBundle = res.MatchedOperatorBundle
		out.ReceiptSHA256 = hex.EncodeToString(res.ReceiptSHA256)
		out.AuditID = string(res.AuditID)
		out.Gate = rc.Gate
	}
	return printConfirm(out, xcc, confirmErr)
}

// printConfirm completes out with the audit log's state and err, prints
// it as JSON, and returns err.
func printConfirm(out confirmOutput, xcc *crossCloudMaterials, err error) error {
	out.AuditChainLength = xcc.AuditChain.Len()
	out.AuditTip = hex.EncodeToString(xcc.AuditChain.Tip())
	if err != nil {
		out.Status = "failed"
		out.Error = &crossCloudErrorEnvelope{Category: classifyEnvelopeCategory(err), Code: errCodeOrUnknown(err), Message: err.Error()}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if encErr := enc.Encode(out); encErr != nil {
		return fmt.Errorf("crosscloud-confirm: encode output: %w", encErr)
	}
	return err
}

// confirmOutput is what crosscloud-confirm prints. Durations come from
// one clock each: key_to_restored from the destination's, authorized to
// confirmed from this host's.
type confirmOutput struct {
	Status                       string                   `json:"status"`
	Error                        *crossCloudErrorEnvelope `json:"error,omitempty"`
	DecisionID                   string                   `json:"decision_id"`
	KeyID                        string                   `json:"key_id"`
	DestinationKind              string                   `json:"destination_kind,omitempty"`
	DestinationMeasurement       string                   `json:"destination_measurement_hex,omitempty"`
	BundleSHA256                 string                   `json:"bundle_sha256,omitempty"`
	Generation                   uint64                   `json:"generation,omitempty"`
	PayloadSHA256                string                   `json:"payload_sha256,omitempty"`
	TreeSHA256                   string                   `json:"tree_sha256,omitempty"`
	Files                        int                      `json:"files,omitempty"`
	Bytes                        int64                    `json:"bytes,omitempty"`
	RestoreSeconds               float64                  `json:"restore_seconds,omitempty"`
	KeyToRestoredSeconds         float64                  `json:"key_to_restored_seconds,omitempty"`
	AuthorizedToConfirmedSeconds float64                  `json:"authorized_to_confirmed_seconds,omitempty"`
	MatchedOperatorBundle        bool                     `json:"matched_operator_bundle"`
	Gate                         *receipt.Gate            `json:"gate,omitempty"`
	ReceiptSHA256                string                   `json:"receipt_sha256,omitempty"`
	AuditID                      string                   `json:"audit_id,omitempty"`
	AuditChainLength             int                      `json:"audit_chain_length"`
	AuditTip                     string                   `json:"audit_tip,omitempty"`
}
