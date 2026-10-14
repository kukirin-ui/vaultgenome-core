// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdh"
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// maxEscrowFileBytes bounds what is read as an escrow key file.
const maxEscrowFileBytes = 64 << 10

// Escrow key storage, as identity and the startup log name it.
const (
	escrowSourcePlaintext = "plaintext"
	escrowSourceSealed    = "sealed:" // followed by the TEE provider
)

// loadEscrowKey opens the escrow private key path names. The file is the
// one `sagvd escrow-provision` wrote — the key sealed to this host's TEE,
// opened here in memory and nowhere else — or, under the simulated TEE
// only, a raw 32-byte key as `acpctl escrow keygen` writes it. A raw key
// on a hardware TEE is refused: the whole point of the chip is that the
// key is not on the disk (ADR 0016, KNOWN_ISSUES #11).
func loadEscrowKey(path string, mat *materials) (*ecdh.PrivateKey, string, error) {
	raw, err := readEscrowFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("sagvd: key_escrow_path: %w", err)
	}
	if !escrow.IsSealed(raw) {
		if mat.Provider != tee.ProviderSimulated {
			return nil, "", fmt.Errorf("sagvd: key_escrow_path %q holds a plaintext escrow key; on tee.provider=%s the escrow key must be sealed to this host: run `sagvd escrow-provision` (ADR 0016)", path, mat.Provider)
		}
		priv, err := escrow.ReadPrivate(path)
		if err != nil {
			return nil, "", fmt.Errorf("sagvd: key_escrow_path: %w", err)
		}
		return priv, escrowSourcePlaintext, nil
	}
	sealed, err := escrow.ParseSealed(raw)
	if err != nil {
		return nil, "", fmt.Errorf("sagvd: key_escrow_path %q: %w", path, err)
	}
	sealer, err := mat.TEESealer()
	if err != nil {
		return nil, "", err
	}
	priv, err := sealed.Open(sealer, mat.Provider, mat.Producer.Measurement())
	if err != nil {
		return nil, "", fmt.Errorf("sagvd: key_escrow_path %q: %w", path, err)
	}
	return priv, escrowSourceSealed + sealed.TEE, nil
}

// escrowPublicFromFile reads the escrow public key from the file path
// names without unsealing anything: a sealed file carries it in the
// clear; a raw key file yields it by arithmetic.
func escrowPublicFromFile(path string) (*ecdh.PublicKey, string, error) {
	raw, err := readEscrowFile(path)
	if err != nil {
		return nil, "", err
	}
	if !escrow.IsSealed(raw) {
		priv, err := escrow.ReadPrivate(path)
		if err != nil {
			return nil, "", err
		}
		return priv.PublicKey(), escrowSourcePlaintext, nil
	}
	sealed, err := escrow.ParseSealed(raw)
	if err != nil {
		return nil, "", err
	}
	pub, err := sealed.PublicKey()
	if err != nil {
		return nil, "", err
	}
	return pub, escrowSourceSealed + sealed.TEE, nil
}

func readEscrowFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxEscrowFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxEscrowFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes: not an escrow key file", path, maxEscrowFileBytes)
	}
	return raw, nil
}
