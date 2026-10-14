// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	cchr "github.com/vault-genome/vaultgenome-core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/exposure"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// runCrossCloudRestoreCmd parses the operator's flags, loads
// configuration + materials, instantiates a kms.Coordinator, runs
// CoordinateRestore, and prints JSON output.
//
// Flags:
//
//	-config <path>             path to sagvd JSON config (required)
//	-decision-id <id>          source-side ReleaseDecision id (required)
//	-destination-kind <kind>   tee.Provider name of destination (required)
//	-destination-endpoint <url> destination acp-bootstrap base URL (required)
//	-key-file <kid:path>       a key to release, repeatable: path holds the
//	                           raw 32-byte key (acpctl genome seal
//	                           --key-out writes one), mode 0600. Keys are
//	                           never taken on the command line, where
//	                           process listings and shell history keep them.
//	-session-id <id>           optional audit correlator
//	-manifest-id <id>          optional audit correlator
//
// Exit codes:
//
//	0 — coordinator returned a CoordinationResult; printed as JSON to stdout
//	1 — any failure; classified-error envelope printed to stdout, error logged to stderr
func runCrossCloudRestoreCmd(args []string) error {
	fs := flag.NewFlagSet("sagvd crosscloud-restore", flag.ContinueOnError)
	var (
		configPath          string
		decisionID          string
		destinationKindStr  string
		destinationEndpoint string
		sessionID           string
		manifestID          string
	)
	var keyFiles, escrows repeatableFlag
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	fs.StringVar(&decisionID, "decision-id", "", "source-side ReleaseDecision id (required)")
	fs.StringVar(&destinationKindStr, "destination-kind", "", "destination TEE kind (required; e.g. gcp-sev-snp)")
	fs.StringVar(&destinationEndpoint, "destination-endpoint", "", "destination acp-bootstrap base URL (required)")
	fs.Var(&keyFiles, "key-file", "KID:PATH of a key to release, repeatable (PATH: raw 32-byte key, mode 0600)")
	fs.Var(&escrows, "key-escrow", "escrow envelope of a genome key to release (acpctl genome seal --escrow-to), repeatable")
	fs.StringVar(&sessionID, "session-id", "", "optional audit correlator: SessionID")
	fs.StringVar(&manifestID, "manifest-id", "", "optional audit correlator: ManifestID")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if configPath == "" {
		return errors.New("crosscloud-restore: -config required")
	}
	if decisionID == "" {
		return errors.New("crosscloud-restore: -decision-id required")
	}
	if destinationKindStr == "" {
		return errors.New("crosscloud-restore: -destination-kind required")
	}
	if destinationEndpoint == "" {
		return errors.New("crosscloud-restore: -destination-endpoint required")
	}
	if err := checkDestinationEndpoint(destinationEndpoint); err != nil {
		return err
	}
	if len(keyFiles) == 0 && len(escrows) == 0 {
		return errors.New("crosscloud-restore: at least one -key-file KID:PATH or -key-escrow PATH required")
	}

	destinationKind, err := tee.ParseProvider(destinationKindStr)
	if err != nil {
		return fmt.Errorf("crosscloud-restore: -destination-kind: %w", err)
	}

	keyMaterials, err := readKeyFiles(keyFiles)
	if err != nil {
		return err
	}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("crosscloud-restore: config validation: %w", err)
	}
	if !cfg.CrossCloud.Enabled {
		return errors.New("crosscloud-restore: crosscloud.enabled=false in config — refusing to run")
	}
	clock := shared_time.NewSystemClock()
	mat, err := LoadMaterials(cfg, clock)
	if err != nil {
		return err
	}
	defer func() { _ = mat.Close() }()
	if len(escrows) > 0 {
		escrowed, err := openEscrows(mat.Escrow, escrows)
		if err != nil {
			return err
		}
		for _, k := range escrowed {
			for _, have := range keyMaterials {
				if have.KeyID == k.KeyID {
					return fmt.Errorf("crosscloud-restore: key id %s given twice", k.KeyID)
				}
			}
		}
		keyMaterials = append(keyMaterials, escrowed...)
	}
	xcc, err := LoadCrossCloudMaterials(cfg, clock)
	if err != nil {
		return err
	}
	if xcc == nil {
		return errors.New("crosscloud-restore: cross-cloud materials nil despite cfg.CrossCloud.Enabled=true")
	}
	defer func() { _ = xcc.Close() }()

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
	})
	if err != nil {
		return err
	}

	req := kms.CoordinationRequest{
		DecisionID:          ids.DecisionID(decisionID),
		DestinationKind:     destinationKind,
		DestinationEndpoint: destinationEndpoint,
		KeysToRelease:       keyMaterials,
		SessionID:           ids.SessionID(sessionID),
		ManifestID:          ids.ManifestID(manifestID),
	}

	res, coordErr := coord.CoordinateRestore(context.Background(), req)
	out := buildCoordinationOutput(res, coordErr, xcc.AuditChain.Len())
	out.AuditTip = hex.EncodeToString(xcc.AuditChain.Tip())
	out.StopSerial = xcc.StopSerial
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("crosscloud-restore: encode output: %w", err)
	}
	if coordErr != nil {
		// Non-zero exit so shell scripts can check.
		return coordErr
	}
	return nil
}

// checkDestinationEndpoint refuses an endpoint that would carry a key
// release in the clear across a network: https always, plain http only
// to a loopback destination.
func checkDestinationEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("crosscloud-restore: -destination-endpoint %q is not an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if exposure.IsLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("crosscloud-restore: -destination-endpoint %q: plain http is accepted only for a loopback destination; use https", raw)
	default:
		return fmt.Errorf("crosscloud-restore: -destination-endpoint %q: scheme must be https", raw)
	}
}

// repeatableFlag implements flag.Value for repeated -key-file occurrences.
type repeatableFlag []string

func (r *repeatableFlag) String() string { return strings.Join(*r, ",") }
func (r *repeatableFlag) Set(s string) error {
	*r = append(*r, s)
	return nil
}

// readKeyFiles reads each "KID:PATH" entry into a kms.KeyMaterial. KID is
// the key ID the destination registers the key under; PATH holds the raw
// AES-256 key. A key file others can read is refused, as a key the
// release host should not have trusted. A genome key ID (acpctl genome
// seal) carries a tag of its key, so a key file that does not belong to
// the ID is refused before anything is released.
func readKeyFiles(in []string) ([]kms.KeyMaterial, error) {
	out := make([]kms.KeyMaterial, 0, len(in))
	seen := make(map[string]bool, len(in))
	for i, e := range in {
		kid, path, ok := strings.Cut(e, ":")
		if !ok || kid == "" || path == "" {
			return nil, fmt.Errorf("crosscloud-restore: -key-file[%d] %q must be KID:PATH", i, e)
		}
		if seen[kid] {
			return nil, fmt.Errorf("crosscloud-restore: -key-file[%d]: key id %s given twice", i, kid)
		}
		seen[kid] = true
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("crosscloud-restore: -key-file[%d]: %w", i, err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("crosscloud-restore: -key-file[%d]: %s is open to other users (mode %04o); chmod 600 it", i, path, perm)
		}
		key, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("crosscloud-restore: -key-file[%d]: %w", i, err)
		}
		if len(key) != crypto.AES256KeySize {
			return nil, fmt.Errorf("crosscloud-restore: -key-file[%d]: %s holds %d bytes, not a %d-byte key", i, path, len(key), crypto.AES256KeySize)
		}
		if bundle.IsKeyID(kid) {
			if err := bundle.CheckKey(kid, key); err != nil {
				return nil, fmt.Errorf("crosscloud-restore: -key-file[%d]: %w", i, err)
			}
		}
		out = append(out, kms.KeyMaterial{
			KeyID:     ids.KeyID(kid),
			Purpose:   krt.PurposeSealing,
			Plaintext: key,
		})
	}
	return out, nil
}

// openEscrows opens each escrow envelope with the authority's escrow key,
// as the materials hold it in memory.
func openEscrows(priv *ecdh.PrivateKey, paths []string) ([]kms.KeyMaterial, error) {
	if priv == nil {
		return nil, errors.New("crosscloud-restore: -key-escrow needs crosscloud.key_escrow_path")
	}
	out := make([]kms.KeyMaterial, 0, len(paths))
	for i, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("crosscloud-restore: -key-escrow[%d]: %w", i, err)
		}
		env, err := escrow.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("crosscloud-restore: -key-escrow[%d]: %w", i, err)
		}
		dek, err := escrow.Open(env, priv)
		if err != nil {
			return nil, fmt.Errorf("crosscloud-restore: -key-escrow[%d]: %w", i, err)
		}
		for _, have := range out {
			if string(have.KeyID) == env.KeyID {
				return nil, fmt.Errorf("crosscloud-restore: -key-escrow[%d]: key id %s given twice", i, env.KeyID)
			}
		}
		out = append(out, kms.KeyMaterial{KeyID: ids.KeyID(env.KeyID), Purpose: krt.PurposeSealing, Plaintext: dek})
	}
	return out, nil
}

// coordinationOutput is the JSON shape printed to stdout. Includes
// the CoordinationResult fields (success path) plus a top-level
// status / error envelope (failure path) so shell scripts can grep
// reliably.
type coordinationOutput struct {
	Status                 string                   `json:"status"` // "ok" or "failed"
	Error                  *crossCloudErrorEnvelope `json:"error,omitempty"`
	HandshakeRequestID     ids.RequestID            `json:"handshake_request_id,omitempty"`
	HandshakeAuditID       ids.AuditEventID         `json:"handshake_audit_id,omitempty"`
	AttestationAuditID     ids.AuditEventID         `json:"attestation_audit_id,omitempty"`
	KeyReleaseAuditID      ids.AuditEventID         `json:"key_release_audit_id,omitempty"`
	DestinationMeasurement string                   `json:"destination_measurement_hex,omitempty"`
	RecipientKeySHA256     string                   `json:"recipient_key_sha256,omitempty"`
	PolicyVersion          string                   `json:"policy_version,omitempty"`
	TokenID                ids.DecisionID           `json:"token_id,omitempty"`
	DispatchedAt           string                   `json:"dispatched_at,omitempty"`
	AuditChainLength       int                      `json:"audit_chain_length"`
	// AuditTip is the hash of the audit log's last event. Record it:
	// a log whose tail was cut off still verifies, but not to this tip.
	AuditTip string `json:"audit_tip,omitempty"`
	// StopSerial is the operator stop list the decision was made under.
	StopSerial uint64 `json:"operator_stop_serial,omitempty"`
}

type crossCloudErrorEnvelope struct {
	Category string `json:"category"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

func buildCoordinationOutput(res kms.CoordinationResult, err error, chainLen int) coordinationOutput {
	out := coordinationOutput{
		AuditChainLength: chainLen,
	}
	if res.HandshakeRequestID != "" {
		out.HandshakeRequestID = res.HandshakeRequestID
	}
	if res.HandshakeAuditID != "" {
		out.HandshakeAuditID = res.HandshakeAuditID
	}
	if res.AttestationAuditID != "" {
		out.AttestationAuditID = res.AttestationAuditID
	}
	if res.KeyReleaseAuditID != "" {
		out.KeyReleaseAuditID = res.KeyReleaseAuditID
	}
	if len(res.DestinationMeasurement) > 0 {
		out.DestinationMeasurement = hex.EncodeToString(res.DestinationMeasurement)
	}
	if len(res.RecipientKeySHA256) > 0 {
		out.RecipientKeySHA256 = hex.EncodeToString(res.RecipientKeySHA256)
	}
	if res.PolicyVersion != "" {
		out.PolicyVersion = res.PolicyVersion
	}
	if res.TokenID != "" {
		out.TokenID = res.TokenID
	}
	if !res.DispatchedAt.IsZero() {
		out.DispatchedAt = res.DispatchedAt.Format("2006-01-02T15:04:05.000Z")
	}
	if err != nil {
		out.Status = "failed"
		out.Error = &crossCloudErrorEnvelope{
			Category: classifyEnvelopeCategory(err),
			Code:     errCodeOrUnknown(err),
			Message:  err.Error(),
		}
	} else {
		out.Status = "ok"
	}
	return out
}

// classifyEnvelopeCategory maps the project's classified-error
// category onto the wire envelope string.
func classifyEnvelopeCategory(err error) string {
	switch {
	case shared_errors.Is(err, shared_errors.CategoryStructural):
		return "structural"
	case shared_errors.Is(err, shared_errors.CategoryAuthority):
		return "authority"
	case shared_errors.Is(err, shared_errors.CategoryIntegrity):
		return "integrity"
	case shared_errors.Is(err, shared_errors.CategoryOperational):
		return "operational"
	case shared_errors.Is(err, shared_errors.CategoryIncident):
		return "incident"
	default:
		return "unknown"
	}
}

// errCodeOrUnknown returns the error's classified code or "unknown"
// when the error did not originate from shared_errors.
func errCodeOrUnknown(err error) string {
	if c := shared_errors.CodeOf(err); c != "" {
		return c
	}
	return "unknown"
}

// Reference cchr/krt to keep the dependency edges explicit even when
// the human-readable types are referenced only via kms.
var (
	_ = cchr.SchemaVersionCurrent
	_ = krt.SchemaVersionCurrent
)
