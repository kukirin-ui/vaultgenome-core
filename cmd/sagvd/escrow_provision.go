// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// escrowProvisionOutput is what `sagvd escrow-provision` prints.
type escrowProvisionOutput struct {
	EscrowKey      string `json:"escrow_key"`
	PublicKeyPEM   string `json:"public_key_pem"`
	TEE            string `json:"tee"`
	MeasurementHex string `json:"measurement_hex"`
	// Source is "generated" (a fresh key) or "stdin" (an existing key,
	// re-sealed on this host).
	Source      string `json:"source"`
	SealedPath  string `json:"sealed_path"`
	PublicPath  string `json:"public_path"`
	RecoveryKey string `json:"recovery_key,omitempty"`
	RecoveryOut string `json:"recovery_path,omitempty"`
}

// runEscrowProvisionCmd implements `sagvd escrow-provision`: the release
// authority's escrow key, made inside this process and sealed to this
// host's TEE before it is written (ADR 0016). The private key is never
// written in the clear. With -recovery-to it is also wrapped to the
// operator's recovery public key, so it survives the chip it was sealed
// to: `acpctl escrow recover` opens that envelope on the operator's
// machine, and its output is piped into `sagvd escrow-provision -stdin`
// on the new host, which seals it there.
//
// Flags:
//
//	-config <path>        sagvd JSON config (required): names the TEE
//	-out <path>           where to write the sealed key (mode 0600, never overwritten) (required)
//	-pub <path>           where to write the public key, PEM (required)
//	-recovery-to <path>   the operator's recovery public key (PEM, acpctl escrow recovery-keygen)
//	-recovery-out <path>  where to write the recovery envelope (required with -recovery-to)
//	-stdin                read the 32-byte escrow private key to seal from stdin instead of generating one
func runEscrowProvisionCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sagvd escrow-provision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath, out, pub, recoveryTo, recoveryOut string
		fromStdin                                     bool
	)
	fs.StringVar(&configPath, "config", "", "path to sagvd JSON config (required)")
	fs.StringVar(&out, "out", "", "where to write the sealed escrow key (0600, never overwritten) (required)")
	fs.StringVar(&pub, "pub", "", "where to write the escrow public key, PEM (required)")
	fs.StringVar(&recoveryTo, "recovery-to", "", "the operator's recovery public key (PEM): also wrap the key to it")
	fs.StringVar(&recoveryOut, "recovery-out", "", "where to write the recovery envelope (required with -recovery-to)")
	fs.BoolVar(&fromStdin, "stdin", false, "seal the 32-byte escrow private key read from stdin (re-provisioning) instead of a fresh one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case configPath == "" || out == "" || pub == "":
		return errors.New("escrow-provision: -config, -out and -pub required")
	case (recoveryTo == "") != (recoveryOut == ""):
		return errors.New("escrow-provision: -recovery-to and -recovery-out go together")
	}
	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("escrow-provision: config validation: %w", err)
	}
	var recoveryPub *ecdh.PublicKey
	if recoveryTo != "" {
		raw, err := os.ReadFile(recoveryTo)
		if err == nil {
			recoveryPub, err = escrow.ParsePublicPEM(raw)
		}
		if err != nil {
			return fmt.Errorf("escrow-provision: -recovery-to: %w", err)
		}
	}

	// The TEE first: a host that cannot seal writes nothing.
	mat, err := LoadMaterials(cfg, shared_time.NewSystemClock())
	if err != nil {
		return err
	}
	defer func() { mat.Store.Zeroize(); _ = mat.Close() }()
	sealer, err := mat.TEESealer()
	if err != nil {
		return err
	}
	if mat.Provider == tee.ProviderSimulated {
		fmt.Fprintln(stderr, "escrow-provision: SIMULATED TEE: the key is sealed under a key derived from the simulated measurement, with no hardware behind it; development and tests only")
	}

	var priv *ecdh.PrivateKey
	source := "generated"
	if fromStdin {
		raw, err := io.ReadAll(io.LimitReader(stdin, kms.RecipientKeySize+1))
		if err != nil {
			return fmt.Errorf("escrow-provision: -stdin: %w", err)
		}
		if len(raw) != kms.RecipientKeySize {
			return fmt.Errorf("escrow-provision: -stdin: read %d bytes, want the %d-byte escrow private key (acpctl escrow recover writes it)", len(raw), kms.RecipientKeySize)
		}
		priv, err = ecdh.X25519().NewPrivateKey(raw)
		clear(raw)
		if err != nil {
			return fmt.Errorf("escrow-provision: -stdin: %w", err)
		}
		source = "stdin"
	} else if priv, err = escrow.GenerateKey(); err != nil {
		return err
	}

	measurement := mat.Producer.Measurement()
	sealed, err := escrow.SealKey(priv, sealer, mat.Provider, measurement)
	if err != nil {
		return fmt.Errorf("escrow-provision: %w", err)
	}
	// Prove the seal opens here before anything is written: a sealer
	// that cannot round-trip must not leave a file an operator trusts.
	if _, err := sealed.Open(sealer, mat.Provider, measurement); err != nil {
		return fmt.Errorf("escrow-provision: the sealed key does not open on this host: %w", err)
	}
	var recovery *escrow.Recovery
	if recoveryPub != nil {
		env, err := escrow.WrapRecovery(priv, recoveryPub)
		if err != nil {
			return fmt.Errorf("escrow-provision: %w", err)
		}
		recovery = &env
	}

	sealedRaw, err := sealed.Marshal()
	if err != nil {
		return err
	}
	if err := writeExclusive(out, sealedRaw, 0o600); err != nil {
		return fmt.Errorf("escrow-provision: -out: %w", err)
	}
	if err := os.WriteFile(pub, []byte(sealed.PublicKeyPEM), 0o644); err != nil {
		return fmt.Errorf("escrow-provision: -pub: %w", err)
	}
	result := escrowProvisionOutput{
		EscrowKey: sealed.EscrowKey, PublicKeyPEM: sealed.PublicKeyPEM, TEE: sealed.TEE,
		MeasurementHex: hex.EncodeToString(measurement), Source: source, SealedPath: out, PublicPath: pub,
	}
	if recovery != nil {
		raw, err := recovery.Marshal()
		if err != nil {
			return err
		}
		if err := writeExclusive(recoveryOut, raw, 0o600); err != nil {
			return fmt.Errorf("escrow-provision: -recovery-out: %w", err)
		}
		result.RecoveryKey, result.RecoveryOut = recovery.RecoveryKey, recoveryOut
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// writeExclusive creates path with data and mode, and refuses to replace
// an existing file: a sealed key or a recovery envelope is never
// overwritten by accident.
func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
