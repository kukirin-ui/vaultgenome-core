// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
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

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// attestCmd dispatches "acpctl attest <subcommand>": offline audits of
// captured attestation evidence with the same code the daemons verify with.
func attestCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: acpctl attest <nitro> [flags]")
		return 2
	}
	switch args[0] {
	case "nitro":
		return attestNitroCmd(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, "usage: acpctl attest <nitro> [flags]")
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl attest: unknown subcommand %q\n", args[0])
		return 2
	}
}

// nitroAuditOutput is the JSON form of the audit: the report with its
// byte fields in hex, the time the chain was checked at, and the verdict.
type nitroAuditOutput struct {
	Verified             bool              `json:"verified"`
	VerifiedAt           time.Time         `json:"verified_at"`
	ModuleID             string            `json:"module_id,omitempty"`
	Timestamp            time.Time         `json:"timestamp,omitempty"`
	PCRs                 map[string]string `json:"pcrs,omitempty"`
	Nonce                string            `json:"nonce,omitempty"`
	UserData             string            `json:"user_data,omitempty"`
	PublicKey            string            `json:"public_key,omitempty"`
	Chain                []string          `json:"chain,omitempty"`
	SigningCertNotBefore time.Time         `json:"signing_cert_not_before,omitempty"`
	SigningCertNotAfter  time.Time         `json:"signing_cert_not_after,omitempty"`
	Debug                bool              `json:"debug"`
	ExpectedPCR0         string            `json:"expected_pcr0,omitempty"`
	ExpectedPCR0Matches  *bool             `json:"expected_pcr0_matches,omitempty"`
	Error                string            `json:"error,omitempty"`
}

// attestNitroCmd audits a captured AWS Nitro Enclaves attestation document
// offline: the COSE_Sign1 envelope, the certificate chain to AWS's root at
// the chosen time, the ES384 signature, and what the document says. It
// is the verifier the daemons run (internal/shared/tee, AuditAWSNitroDocument)
// without a challenge: a captured document is audited at its own timestamp
// by default, because the hypervisor's signing certificate expires three
// hours after it signed.
//
//	acpctl attest nitro --doc 04-attestation-document.bin [--at capture|now|RFC3339] [--expected-pcr0 HEX] [--root root.pem] [--json]
func attestNitroCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attest nitro", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		docPath      = fs.String("doc", "", "The captured attestation document, raw COSE_Sign1 bytes (required)")
		at           = fs.String("at", "capture", "When to check the chain's validity: capture (the document's timestamp), now, or an RFC 3339 time")
		expectedPCR0 = fs.String("expected-pcr0", "", "PCR0 the document must carry, hex (from `nitro-cli describe-eif`); a mismatch exits 5")
		rootPath     = fs.String("root", "", "PEM file with the root certificate(s) to pin instead of the built-in AWS Nitro Enclaves Root G1")
		jsonOut      = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl attest nitro --doc FILE [--at capture|now|RFC3339] [--expected-pcr0 HEX] [--root PEM] [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Audit a captured AWS Nitro Enclaves attestation document offline with the")
		fmt.Fprintln(stderr, "daemons' own verifier: envelope, chain to the pinned root at the chosen time,")
		fmt.Fprintln(stderr, "signature, and what the document says. Exit 0 when it verifies, 5 when not.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *docPath == "" {
		fmt.Fprintln(stderr, "acpctl attest nitro: --doc is required")
		fs.Usage()
		return 2
	}
	var when time.Time
	switch *at {
	case "capture", "":
	case "now":
		when = time.Now()
	default:
		t, err := time.Parse(time.RFC3339Nano, *at)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl attest nitro: --at must be capture, now or an RFC 3339 time: %v\n", err)
			return 2
		}
		when = t
	}
	var expected []byte
	if *expectedPCR0 != "" {
		b, err := hex.DecodeString(*expectedPCR0)
		if err != nil || (len(b) != 32 && len(b) != 48 && len(b) != 64) {
			fmt.Fprintln(stderr, "acpctl attest nitro: --expected-pcr0 must be 32, 48 or 64 bytes of hex")
			return 2
		}
		expected = b
	}
	var roots [][]byte
	if *rootPath != "" {
		r, err := readPEMCertificates(*rootPath)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl attest nitro: --root: %v\n", err)
			return 2
		}
		roots = r
	}
	raw, err := os.ReadFile(*docPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl attest nitro: %v\n", err)
		return 1
	}

	out := nitroAuditOutput{VerifiedAt: when, ExpectedPCR0: *expectedPCR0}
	report, err := tee.AuditAWSNitroDocument(raw, roots, when)
	if err != nil {
		out.Error = err.Error()
		return emitNitroAudit(out, *jsonOut, stdout, stderr)
	}
	if when.IsZero() {
		out.VerifiedAt = report.Timestamp
	}
	out.Verified = true
	out.ModuleID = report.ModuleID
	out.Timestamp = report.Timestamp
	out.PCRs = make(map[string]string, len(report.PCRs))
	for i, v := range report.PCRs {
		out.PCRs[fmt.Sprintf("%d", i)] = hex.EncodeToString(v)
	}
	out.Nonce = hex.EncodeToString(report.Nonce)
	out.UserData = hex.EncodeToString(report.UserData)
	out.PublicKey = hex.EncodeToString(report.PublicKey)
	out.Chain = report.Chain
	out.SigningCertNotBefore = report.SigningCertNotBefore
	out.SigningCertNotAfter = report.SigningCertNotAfter
	out.Debug = report.Debug
	if report.Debug {
		out.Verified = false
		out.Error = "debug-mode enclave: PCR0 is all zeroes"
	}
	if expected != nil {
		match := hex.EncodeToString(report.PCRs[0]) == hex.EncodeToString(expected)
		out.ExpectedPCR0Matches = &match
		if !match {
			out.Verified = false
			out.Error = "PCR0 is not the expected value"
		}
	}
	return emitNitroAudit(out, *jsonOut, stdout, stderr)
}

func emitNitroAudit(out nitroAuditOutput, asJSON bool, stdout, stderr io.Writer) int {
	code := 0
	if !out.Verified {
		code = 5
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "acpctl attest nitro: %v\n", err)
			return 1
		}
		return code
	}
	if out.ModuleID != "" {
		fmt.Fprintf(stdout, "module      %s\n", out.ModuleID)
		fmt.Fprintf(stdout, "signed      %s\n", out.Timestamp.Format(time.RFC3339Nano))
		fmt.Fprintf(stdout, "cert valid  %s to %s\n", out.SigningCertNotBefore.Format(time.RFC3339), out.SigningCertNotAfter.Format(time.RFC3339))
		for i, s := range out.Chain {
			label := "signer"
			if i == len(out.Chain)-1 {
				label = "root"
			} else if i > 0 {
				label = fmt.Sprintf("ca %d", i)
			}
			fmt.Fprintf(stdout, "%-11s %s\n", label, s)
		}
		for _, k := range []string{"0", "1", "2"} {
			if v, ok := out.PCRs[k]; ok {
				fmt.Fprintf(stdout, "pcr%-8s %s\n", k, v)
			}
		}
		fmt.Fprintf(stdout, "pcrs        %d carried\n", len(out.PCRs))
		fmt.Fprintf(stdout, "user_data   %s\n", orAbsent(out.UserData))
		fmt.Fprintf(stdout, "nonce       %s\n", orAbsent(out.Nonce))
		fmt.Fprintf(stdout, "public_key  %s\n", orAbsent(out.PublicKey))
		fmt.Fprintf(stdout, "debug       %v\n", out.Debug)
		if out.ExpectedPCR0Matches != nil {
			fmt.Fprintf(stdout, "pcr0 match  %v (expected %s)\n", *out.ExpectedPCR0Matches, out.ExpectedPCR0)
		}
	}
	if out.Verified {
		fmt.Fprintf(stdout, "VERIFIED at %s: chain to the pinned root, ES384 signature valid\n", out.VerifiedAt.Format(time.RFC3339Nano))
	} else {
		fmt.Fprintf(stdout, "NOT VERIFIED: %s\n", out.Error)
	}
	return code
}

func orAbsent(hexValue string) string {
	if hexValue == "" {
		return "(absent)"
	}
	return hexValue
}

// readPEMCertificates returns the DER of every CERTIFICATE block in a file.
func readPEMCertificates(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
		raw = rest
	}
	if len(out) == 0 {
		return nil, errors.New("no CERTIFICATE block in " + strings.TrimSpace(path))
	}
	return out, nil
}
