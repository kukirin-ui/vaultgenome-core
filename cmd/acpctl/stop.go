// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// stopCmd dispatches `acpctl stop <subcommand>` — the operator stop of
// ADR 0010. The operator key these commands use belongs on the
// operator's machine, never on the release host; the release host holds
// only its public half.
//
//	keygen  — create an operator key (seed file + PEM public key)
//	issue   — sign a list: stop everything, or revoke measurements
//	verify  — check a list against the operator public key and show it
func stopCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: acpctl stop <keygen|issue|verify> [flags]")
		return 2
	}
	switch args[0] {
	case "keygen":
		return stopKeygenCmd(args[1:], stdout, stderr)
	case "issue":
		return stopIssueCmd(args[1:], stdout, stderr)
	case "verify":
		return stopVerifyCmd(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprintln(stdout, "stop subcommands:")
		fmt.Fprintln(stdout, "  keygen  — create an operator key (seed file + PEM public key)")
		fmt.Fprintln(stdout, "  issue   — sign a list that stops every release or revokes measurements")
		fmt.Fprintln(stdout, "  verify  — check a list against the operator public key and print it")
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl stop: unknown subcommand %q\n", args[0])
		return 2
	}
}

func stopKeygenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stop keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	seedPath := fs.String("out", "", "Where to write the 32-byte operator seed (required; created 0600, never overwritten)")
	pubPath := fs.String("pub", "", "Where to write the PEM public key the release host pins (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *seedPath == "" || *pubPath == "" {
		fmt.Fprintln(stderr, "acpctl stop keygen: --out and --pub are required")
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl stop keygen: %v\n", err)
		return 1
	}
	f, err := os.OpenFile(*seedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl stop keygen: %v\n", err)
		return 1
	}
	if _, err := f.Write(priv.Seed()); err != nil {
		_ = f.Close()
		fmt.Fprintf(stderr, "acpctl stop keygen: write seed: %v\n", err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(stderr, "acpctl stop keygen: write seed: %v\n", err)
		return 1
	}
	pemBytes, err := crypto.PublicKeyPEM(crypto.PublicKey(pub))
	if err == nil {
		err = os.WriteFile(*pubPath, pemBytes, 0o644)
	}
	if err != nil {
		fmt.Fprintf(stderr, "acpctl stop keygen: write public key: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "operator key written: seed %s (keep it off the release host), public key %s\n", *seedPath, *pubPath)
	return 0
}

// repeatedFlag collects every occurrence of a repeatable flag.
type repeatedFlag []string

func (r *repeatedFlag) String() string     { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(v string) error { *r = append(*r, v); return nil }

func stopIssueCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stop issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var revoke repeatedFlag
	seedPath := fs.String("key", "", "Operator seed file (required)")
	kid := fs.String("kid", "", "Operator key ID the release host trusts (required)")
	serial := fs.Uint64("serial", 0, "List serial; must be higher than any list issued before (required)")
	all := fs.Bool("all", false, "Stop every cross-cloud key release")
	reason := fs.String("reason", "", "Why; recorded with every refusal the list causes")
	out := fs.String("out", "", "Where to write the signed list (required)")
	fs.Var(&revoke, "revoke", "Revoke a destination measurement, as provider:hex (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *seedPath == "" || *kid == "" || *serial == 0 || *out == "" {
		fmt.Fprintln(stderr, "acpctl stop issue: --key, --kid, --serial (>= 1) and --out are required")
		return 2
	}
	seed, err := os.ReadFile(*seedPath)
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintf(stderr, "acpctl stop issue: --key must be a %d-byte seed file (%v)\n", ed25519.SeedSize, err)
		return 1
	}
	l := revocation.List{
		Serial:       *serial,
		IssuedAt:     time.Now().UTC().Truncate(time.Second),
		StopAll:      *all,
		Reason:       *reason,
		SigningKeyID: *kid,
	}
	for _, r := range revoke {
		provider, measurement, ok := strings.Cut(r, ":")
		if !ok {
			fmt.Fprintf(stderr, "acpctl stop issue: --revoke %q must be provider:hex\n", r)
			return 2
		}
		if l.RevokedMeasurements == nil {
			l.RevokedMeasurements = map[string][]string{}
		}
		l.RevokedMeasurements[provider] = append(l.RevokedMeasurements[provider], strings.ToLower(measurement))
	}
	signed, err := revocation.Sign(l, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		fmt.Fprintf(stderr, "acpctl stop issue: %v\n", err)
		return 1
	}
	raw, err := json.MarshalIndent(signed, "", "  ")
	if err == nil {
		err = os.WriteFile(*out, append(raw, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintf(stderr, "acpctl stop issue: write: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "signed list serial %d written to %s\n", signed.Serial, *out)
	return 0
}

func stopVerifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stop verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "Signed list (required)")
	pubPath := fs.String("pubkey", "", "Operator public key: PEM or 32 raw bytes (required)")
	kid := fs.String("kid", "", "Operator key ID (required)")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" || *pubPath == "" || *kid == "" {
		fmt.Fprintln(stderr, "acpctl stop verify: --in, --pubkey and --kid are required")
		return 2
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl stop verify: %v\n", err)
		return 1
	}
	pub, err := readEd25519PublicKey(*pubPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl stop verify: %v\n", err)
		return 1
	}
	l, err := revocation.Parse(raw, ed25519.PublicKey(pub), *kid)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl stop verify: %v\n", err)
		return 4
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(l)
		return 0
	}
	state := "releases allowed (except revoked measurements)"
	if l.StopAll {
		state = "ALL RELEASES STOPPED"
	}
	fmt.Fprintf(stdout, "valid list, serial %d, issued %s: %s\n", l.Serial, l.IssuedAt.Format(time.RFC3339), state)
	for provider, list := range l.RevokedMeasurements {
		for _, m := range list {
			fmt.Fprintf(stdout, "  revoked %s %s\n", provider, m)
		}
	}
	if l.Reason != "" {
		fmt.Fprintf(stdout, "  reason: %s\n", l.Reason)
	}
	return 0
}
