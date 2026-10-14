// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/server"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// WorkerRegistryFile is the on-disk JSON schema that lists every
// worker signing public key this vault will accept a
// CandidateOutputFrame signature from.
//
// Phase 1: out-of-band operator-provisioned. The operator copies
// each worker's startup-log `worker signing identity` line (kid +
// pubkey_hex) into this file before bringing sagvd up.
//
// Phase 3: attestation-bound — the registry is produced by the
// vault's Verifier from fresh TEE evidence, not by operator config.
// The wire shape of the handshake does not change.
type WorkerRegistryFile struct {
	// Workers is the set of accepted worker signing keys.
	Workers []WorkerEntry `json:"workers"`
}

// WorkerEntry is one accepted worker's signing identity.
type WorkerEntry struct {
	// KeyID is the kid the worker sends on every
	// CandidateOutputFrame.WorkerSigningKeyID. Must be unique across
	// the registry.
	KeyID string `json:"kid"`

	// SigningPublicKeyHex is the 32-byte Ed25519 public key, in
	// lowercase hex (64 chars). Keyed in hex rather than base64 so
	// operators can eyeball-compare against the daemon's startup
	// log output, which emits hex.
	SigningPublicKeyHex string `json:"signing_pubkey_hex"`

	// Note is a free-form operator comment. Ignored by sagvd.
	Note string `json:"note,omitempty"`
}

// LoadWorkerRegistry reads path, decodes it as a WorkerRegistryFile,
// and returns a ready-to-wire server.PublicKeyResolver.
//
// Validation: every entry must have a non-empty kid, a 64-hex-char
// signing_pubkey_hex decoding to exactly 32 bytes, and no duplicate
// kids across the file. Any failure aborts the whole load — this is
// operator-config hygiene, not a runtime condition.
func LoadWorkerRegistry(path string) (*server.PublicKeyResolver, []WorkerEntry, error) {
	if path == "" {
		return nil, nil, errors.New("sagvd: workers.registry_path required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("sagvd: read worker registry %q: %w", path, err)
	}
	var file WorkerRegistryFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, nil, fmt.Errorf("sagvd: decode worker registry %q: %w", path, err)
	}
	if len(file.Workers) == 0 {
		return nil, nil, fmt.Errorf("sagvd: worker registry %q contains no entries", path)
	}

	entries := make(map[ids.KeyID]keys.VerifyingKey, len(file.Workers))
	outEntries := make([]WorkerEntry, 0, len(file.Workers))
	for i, w := range file.Workers {
		if strings.TrimSpace(w.KeyID) == "" {
			return nil, nil, fmt.Errorf("sagvd: worker registry entry %d: kid required", i)
		}
		pub, err := hex.DecodeString(w.SigningPublicKeyHex)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"sagvd: worker registry entry %d (kid=%q): signing_pubkey_hex invalid hex: %w",
				i, w.KeyID, err)
		}
		if len(pub) != crypto.Ed25519PublicKeySize {
			return nil, nil, fmt.Errorf(
				"sagvd: worker registry entry %d (kid=%q): signing_pubkey_hex must decode to %d bytes (got %d)",
				i, w.KeyID, crypto.Ed25519PublicKeySize, len(pub))
		}
		kid := ids.KeyID(w.KeyID)
		if _, dup := entries[kid]; dup {
			return nil, nil, fmt.Errorf(
				"sagvd: worker registry contains duplicate kid %q", w.KeyID)
		}
		entries[kid] = keys.VerifyingKey{
			KeyID:     kid,
			Purpose:   keys.PurposeSigningAuthority,
			PublicKey: crypto.PublicKey(pub),
		}
		outEntries = append(outEntries, w)
	}

	return server.NewPublicKeyResolver(entries), outEntries, nil
}
