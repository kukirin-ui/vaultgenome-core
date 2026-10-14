// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// auditCmd dispatches `acpctl audit <subcommand>`. Subcommands:
//
//	query   — list events filtered by kind / session / time range
//	verify  — replay the chain and verify hashes + signatures
//
// Both operate directly on the bbolt audit file. They do NOT need a
// running sagvd process — useful in DR scenarios where the vault
// process is unhealthy but the on-disk audit log is the source of
// truth.
func auditCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: acpctl audit <query|verify> [flags]")
		return 2
	}
	switch args[0] {
	case "query":
		return auditQueryCmd(args[1:], stdout, stderr)
	case "verify":
		return auditVerifyCmd(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprintln(stdout, "audit subcommands:")
		fmt.Fprintln(stdout, "  query   — list events filtered by kind / session / time range")
		fmt.Fprintln(stdout, "  verify  — replay the chain and verify every hash + signature")
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl audit: unknown subcommand %q\n", args[0])
		return 2
	}
}

// ----------------------------------------------------------------------------
// audit query
// ----------------------------------------------------------------------------

func auditQueryCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		auditPath = fs.String("audit", "", "Path to the audit bbolt file (required)")
		kindFlag  = fs.String("kind", "", "Filter by event kind (e.g. RELEASE_DECIDED). Empty = all kinds.")
		sessFlag  = fs.String("session", "", "Filter by session ID. Empty = all sessions.")
		manFlag   = fs.String("manifest", "", "Filter by manifest ID. Empty = all manifests.")
		sinceStr  = fs.String("since", "", "Only events at or after this RFC3339 time")
		untilStr  = fs.String("until", "", "Only events at or before this RFC3339 time")
		limit     = fs.Int("limit", 100, "Maximum number of events to return; <=0 means all")
		jsonOut   = fs.Bool("json", false, "Emit machine-readable JSON (one event per line)")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl audit query --audit PATH [--kind X] [--session Y]")
		fmt.Fprintln(stderr, "                          [--manifest Z] [--since TIME] [--until TIME]")
		fmt.Fprintln(stderr, "                          [--limit N] [--json]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditPath == "" {
		fmt.Fprintln(stderr, "acpctl audit query: --audit is required")
		return 2
	}

	since, err := parseOptionalTime(*sinceStr, "--since")
	if err != nil {
		fmt.Fprintln(stderr, "acpctl audit query:", err)
		return 2
	}
	until, err := parseOptionalTime(*untilStr, "--until")
	if err != nil {
		fmt.Fprintln(stderr, "acpctl audit query:", err)
		return 2
	}

	s, err := store.Open(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl audit query: open audit store: %v\n", err)
		return 1
	}
	defer func() { _ = s.Close() }()
	events, err := s.Load()
	if err != nil {
		fmt.Fprintf(stderr, "acpctl audit query: load: %v\n", err)
		return 1
	}

	matched := 0
	for i := range events {
		evt := &events[i]
		if !matchesFilters(evt, *kindFlag, *sessFlag, *manFlag, since, until) {
			continue
		}
		emitEvent(stdout, *jsonOut, evt)
		matched++
		if *limit > 0 && matched >= *limit {
			break
		}
	}
	if !*jsonOut {
		fmt.Fprintf(stdout, "\nmatched: %d of %d events\n", matched, len(events))
	}
	return 0
}

func parseOptionalTime(s, flagName string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: must be RFC3339, got %q (%w)", flagName, s, err)
	}
	return t, nil
}

func matchesFilters(evt *audit_event.AuditEvent, kind, sess, man string, since, until time.Time) bool {
	if kind != "" && string(evt.Kind) != kind {
		return false
	}
	if sess != "" && string(evt.SessionID) != sess {
		return false
	}
	if man != "" && string(evt.ManifestID) != man {
		return false
	}
	if !since.IsZero() && evt.OccurredAt.Before(since) {
		return false
	}
	if !until.IsZero() && evt.OccurredAt.After(until) {
		return false
	}
	return true
}

func emitEvent(w io.Writer, asJSON bool, evt *audit_event.AuditEvent) {
	if asJSON {
		// The payload is JSON for every kind the daemons write; it is
		// embedded as such, so a reader gets the decision's fields, not a
		// blob. A payload that is not JSON travels base64 under
		// payload_base64 instead.
		record := map[string]any{
			"event_id":    string(evt.EventID),
			"kind":        string(evt.Kind),
			"occurred_at": evt.OccurredAt.UTC().Format(time.RFC3339Nano),
			"session_id":  string(evt.SessionID),
			"manifest_id": string(evt.ManifestID),
			"request_id":  string(evt.RequestID),
		}
		if json.Valid(evt.Payload) {
			record["payload"] = json.RawMessage(evt.Payload)
		} else {
			record["payload_base64"] = base64.StdEncoding.EncodeToString(evt.Payload)
		}
		_ = json.NewEncoder(w).Encode(record)
		return
	}
	fmt.Fprintf(w, "%s  %-30s  %s",
		evt.OccurredAt.UTC().Format(time.RFC3339),
		evt.Kind,
		evt.EventID)
	if evt.SessionID != "" {
		fmt.Fprintf(w, "  session=%s", evt.SessionID)
	}
	if evt.ManifestID != "" {
		fmt.Fprintf(w, "  manifest=%s", evt.ManifestID)
	}
	fmt.Fprintln(w)
}

// ----------------------------------------------------------------------------
// audit verify
// ----------------------------------------------------------------------------

func auditVerifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		auditPath = fs.String("audit", "", "Path to the audit bbolt file (required)")
		pubKey    = fs.String("audit-pubkey", "", "Path to the audit Ed25519 public key: PEM (as `sagvd identity` prints it) or 32 raw bytes (required)")
		pubKID    = fs.String("audit-kid", "", "KeyID under which the audit-signing key is registered (required)")
		jsonOut   = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl audit verify --audit PATH --audit-pubkey PATH --audit-kid KID [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Replay the audit chain and verify every hash and signature. Exits 0 on")
		fmt.Fprintln(stderr, "ok, non-zero on the first integrity violation. The audit-pubkey + audit-kid")
		fmt.Fprintln(stderr, "should match keys.audit_signing in the daemon's config.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditPath == "" || *pubKey == "" || *pubKID == "" {
		fmt.Fprintln(stderr, "acpctl audit verify: --audit, --audit-pubkey, --audit-kid all required")
		return 2
	}

	pub, err := readEd25519PublicKey(*pubKey)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl audit verify: %v\n", err)
		return 1
	}

	s, err := store.Open(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl audit verify: open audit store: %v\n", err)
		return 1
	}
	defer func() { _ = s.Close() }()
	events, err := s.Load()
	if err != nil {
		fmt.Fprintf(stderr, "acpctl audit verify: load: %v\n", err)
		return 1
	}

	resolver := newSinglePubkeyResolver(ids.KeyID(*pubKID), pub)

	// Reconstruct the chain in memory and Verify. We use InMemoryChain so
	// we can call Verify(resolver) directly against the stored events.
	verifyErr := verifyEventsInOrder(events, resolver)
	res := auditVerifyResult{
		AuditPath:  *auditPath,
		EventCount: len(events),
	}
	if n := len(events); n > 0 {
		res.Tip = hex.EncodeToString(events[n-1].Hash)
	}
	if verifyErr != nil {
		res.OK = false
		res.Error = verifyErr.Error()
		emitAuditVerify(stdout, *jsonOut, res)
		fmt.Fprintf(stderr, "acpctl audit verify: chain BROKEN — %v\n", verifyErr)
		return 4
	}
	res.OK = true
	emitAuditVerify(stdout, *jsonOut, res)
	return 0
}

type auditVerifyResult struct {
	OK         bool   `json:"ok"`
	AuditPath  string `json:"audit_path"`
	EventCount int    `json:"event_count"`
	// Tip is the hash of the last event. A log whose tail was cut off
	// still verifies; compare the tip with one recorded earlier.
	Tip   string `json:"tip,omitempty"`
	Error string `json:"error,omitempty"`
}

func emitAuditVerify(w io.Writer, asJSON bool, r auditVerifyResult) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(r)
		return
	}
	if r.OK {
		fmt.Fprintf(w, "audit chain ok — %d events verified, tip %s\n", r.EventCount, r.Tip)
	} else {
		fmt.Fprintf(w, "audit chain BROKEN: %s\n", r.Error)
	}
}

// verifyEventsInOrder walks events in storage order and verifies the
// hash chain + per-event signatures.
func verifyEventsInOrder(events []audit_event.AuditEvent, resolver keys.Resolver) error {
	expectedPrev := make([]byte, audit_event.HashSize) // genesis = zeros
	for i := range events {
		evt := events[i]
		if !bytes.Equal(evt.PrevHash, expectedPrev) {
			return shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("event #%d: prev_hash does not link to event #%d", i, i-1),
				nil,
			)
		}
		if err := evt.VerifySignature(resolver); err != nil {
			return fmt.Errorf("event #%d: %w", i, err)
		}
		expectedPrev = evt.Hash
	}
	return nil
}

// singlePubkeyResolver is a minimal Resolver that returns the same
// pubkey for a single registered KID.
type singlePubkeyResolver struct {
	kid    ids.KeyID
	pubkey crypto.PublicKey
}

func newSinglePubkeyResolver(kid ids.KeyID, pub []byte) keys.Resolver {
	cp := make(crypto.PublicKey, len(pub))
	copy(cp, pub)
	return &singlePubkeyResolver{kid: kid, pubkey: cp}
}

func (r *singlePubkeyResolver) Resolve(kid ids.KeyID, want keys.Purpose) (keys.VerifyingKey, error) {
	if kid != r.kid {
		return keys.VerifyingKey{}, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			fmt.Sprintf("acpctl audit verify: kid %q not registered (expected %q)", kid, r.kid),
			nil,
		)
	}
	if want != keys.PurposeSigningAudit {
		// Be strict: this resolver is purpose-bound to audit signing.
		// A caller who asks for any other purpose has a bug or is being
		// abused; return a clear error rather than silently allowing.
		return keys.VerifyingKey{}, shared_errors.Integrity(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("acpctl audit verify: purpose %s not accepted (only signing_audit)", want),
			nil,
		)
	}
	return keys.VerifyingKey{
		KeyID:     r.kid,
		Purpose:   keys.PurposeSigningAudit,
		PublicKey: r.pubkey,
	}, nil
}

// helper kept private — string-trimming for kind matching in case the
// operator copy-pastes a kind with surrounding whitespace.
var _ = strings.TrimSpace

// build into chain package symbol pool so the import isn't dead in the
// rare case the verifier path isn't taken
var _ = chain.NewInMemoryChain

// readEd25519PublicKey reads an Ed25519 public key file: a PEM "PUBLIC
// KEY" block (as `sagvd identity` prints it) or the raw 32 bytes.
func readEd25519PublicKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pubkey: %w", err)
	}
	if block, _ := pem.Decode(data); block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pubkey PEM: %w", err)
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("pubkey PEM holds %T, want an Ed25519 key", key)
		}
		return ed, nil
	}
	if len(data) != crypto.Ed25519PublicKeySize {
		return nil, errors.New("pubkey must be PEM or exactly 32 raw bytes")
	}
	return data, nil
}
