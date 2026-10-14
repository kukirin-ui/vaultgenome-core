// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdh"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
)

// escrowCmd dispatches `acpctl escrow <keygen|recovery-keygen|recover>`.
//
// The release authority's escrow key is made on the release host itself,
// sealed to its TEE (`sagvd escrow-provision`, ADR 0016). What the
// operator holds is a recovery key: `recovery-keygen` makes it, off the
// release host; `sagvd escrow-provision -recovery-to` wraps the escrow key
// to it; and `recover` opens that envelope, on the operator's machine, so
// the escrow key can be re-sealed on a new host through
// `sagvd escrow-provision -stdin` without touching the new host's disk in
// the clear.
//
// `keygen` writes a plaintext escrow key: for the simulated TEE,
// development and tests.
func escrowCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printEscrowUsage(stderr)
		return 2
	}
	switch args[0] {
	case "keygen":
		return escrowKeygenCmd(args[1:], stdout, stderr)
	case "recovery-keygen":
		return escrowRecoveryKeygenCmd(args[1:], stdout, stderr)
	case "recover":
		return escrowRecoverCmd(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printEscrowUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "acpctl escrow: unknown subcommand %q\n", args[0])
		printEscrowUsage(stderr)
		return 2
	}
}

func printEscrowUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: acpctl escrow <keygen|recovery-keygen|recover> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  keygen           a plaintext escrow key pair: simulated TEE, development and tests only")
	fmt.Fprintln(w, "                   (on a hardware TEE the release host makes its own: sagvd escrow-provision)")
	fmt.Fprintln(w, "  recovery-keygen  the operator's recovery key pair; keep the private half off the release host")
	fmt.Fprintln(w, "  recover          open a recovery envelope (sagvd escrow-provision -recovery-out) with the")
	fmt.Fprintln(w, "                   recovery private key; the escrow key goes to stdout, for")
	fmt.Fprintln(w, "                   `sagvd escrow-provision -stdin` on the new host")
}

func escrowKeygenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("escrow keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "Where to write the private key (32 raw bytes, mode 0600; never overwritten)")
	pub := fs.String("pub", "", "Where to write the public key (PEM) that sealers use")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || *pub == "" {
		fmt.Fprintln(stderr, "acpctl escrow keygen: --out and --pub are required")
		return 2
	}
	priv, err := escrow.GenerateKey()
	if err != nil {
		fmt.Fprintf(stderr, "acpctl escrow keygen: %v\n", err)
		return 1
	}
	if err := writeKeyPair(*out, *pub, priv.Bytes(), priv.PublicKey()); err != nil {
		fmt.Fprintf(stderr, "acpctl escrow keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "escrow key %s: private %s (plaintext: accepted under the simulated TEE only), public %s (give it to sealers)\n",
		escrow.KeyTag(priv.PublicKey()), *out, *pub)
	return 0
}

func escrowRecoveryKeygenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("escrow recovery-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "Where to write the recovery private key (32 raw bytes, mode 0600; never overwritten); keep it off the release host")
	pub := fs.String("pub", "", "Where to write the recovery public key (PEM) for sagvd escrow-provision -recovery-to")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || *pub == "" {
		fmt.Fprintln(stderr, "acpctl escrow recovery-keygen: --out and --pub are required")
		return 2
	}
	priv, err := escrow.GenerateKey()
	if err != nil {
		fmt.Fprintf(stderr, "acpctl escrow recovery-keygen: %v\n", err)
		return 1
	}
	if err := writeKeyPair(*out, *pub, priv.Bytes(), priv.PublicKey()); err != nil {
		fmt.Fprintf(stderr, "acpctl escrow recovery-keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "recovery key %s: private %s (keep it off the release host), public %s (for sagvd escrow-provision -recovery-to)\n",
		escrow.KeyTag(priv.PublicKey()), *out, *pub)
	return 0
}

// escrowRecoverCmd opens a recovery envelope and writes the 32-byte escrow
// private key to stdout — raw bytes, to be piped, never a file the
// operator forgets.
func escrowRecoverCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("escrow recover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "The recovery envelope (sagvd escrow-provision -recovery-out)")
	keyPath := fs.String("key", "", "The recovery private key file, mode 0600 (acpctl escrow recovery-keygen --out)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" || *keyPath == "" {
		fmt.Fprintln(stderr, "acpctl escrow recover: --in and --key are required")
		return 2
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl escrow recover: --in: %v\n", err)
		return 2
	}
	env, err := escrow.ParseRecovery(raw)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl escrow recover: --in: %v\n", err)
		return 2
	}
	recovery, err := escrow.ReadPrivate(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl escrow recover: --key: %v\n", err)
		return 2
	}
	priv, err := env.Open(recovery)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl escrow recover: %v\n", err)
		return 1
	}
	if _, err := stdout.Write(priv.Bytes()); err != nil {
		fmt.Fprintf(stderr, "acpctl escrow recover: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "escrow key %s recovered: pipe it into `sagvd escrow-provision -stdin` on the new host\n", env.EscrowKey)
	return 0
}

// writeKeyPair writes a private key (0600, never overwritten) and its
// public half as PEM.
func writeKeyPair(privPath, pubPath string, priv []byte, pub *ecdh.PublicKey) error {
	pemBytes, err := escrow.PublicPEM(pub)
	if err != nil {
		return err
	}
	if err := writeKeyFile(privPath, priv, false); err != nil {
		return err
	}
	return os.WriteFile(pubPath, pemBytes, 0o644)
}
