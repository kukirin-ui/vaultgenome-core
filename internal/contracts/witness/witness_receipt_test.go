// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// buildReceipt assembles a valid WitnessReceipt for entries[leafIndex]
// at the given tree size, signed by the witness store under kid.
func buildReceipt(
	t *testing.T,
	store *keys.InMemoryStore,
	kid ids.KeyID,
	entries []witness.LogEntry,
	leafIndex int,
) *witness.WitnessReceipt {
	t.Helper()
	require.Less(t, leafIndex, len(entries))
	leaves := leafHashes(entries)
	path := buildInclusionPath(t, leaves, leafIndex)
	sth := newSignedSTH(t, store, kid, entries, coverTime(entries))

	receipt := &witness.WitnessReceipt{
		SchemaVersion: witness.SchemaVersionCurrent,
		Entry:         entries[leafIndex],
		InclusionProof: witness.InclusionProof{
			LeafIndex: uint64(leafIndex),
			TreeSize:  uint64(len(entries)),
			Path:      path,
		},
		STH: *sth,
	}
	return receipt
}

func TestWitnessReceipt_Verify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 5)

	for idx := range entries {
		receipt := buildReceipt(t, store, kid, entries, idx)
		require.NoError(t, receipt.Verify(store), "leaf %d", idx)
	}
}

func TestWitnessReceipt_Validate_CrossFieldBinding(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 4)
	receipt := buildReceipt(t, store, kid, entries, 1)

	// Force a cross-field mismatch: entry.index != inclusion_proof.leaf_index
	receipt.InclusionProof.LeafIndex = 3
	err := receipt.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestWitnessReceipt_Validate_ProofSizeMismatchesSTH(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 4)
	receipt := buildReceipt(t, store, kid, entries, 1)

	receipt.InclusionProof.TreeSize = 99
	err := receipt.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestWitnessReceipt_Validate_ChainHeadMismatchAtTail(t *testing.T) {
	t.Parallel()
	// When the entry IS the tail (index == TreeSize-1), receipt
	// enforces STH.TreeChainHead == Entry.LeafHash. Swap to mismatch.
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 3)
	receipt := buildReceipt(t, store, kid, entries, 2)

	receipt.STH.TreeChainHead = repeat(0xEE, crypto.HashSize)
	err := receipt.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestWitnessReceipt_Validate_TamperedEntry(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 4)
	receipt := buildReceipt(t, store, kid, entries, 1)

	// Corrupt the entry's payload — LeafHash derivation drifts.
	receipt.Entry.AttestationRoot[0] ^= 0xFF
	err := receipt.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestWitnessReceipt_Validate_TamperedInclusionPath(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 5)
	receipt := buildReceipt(t, store, kid, entries, 2)

	// Corrupt the first proof element.
	receipt.InclusionProof.Path[0] = append([]byte(nil), receipt.InclusionProof.Path[0]...)
	receipt.InclusionProof.Path[0][0] ^= 0xFF
	err := receipt.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestWitnessReceipt_Validate_STHTimestampBeforeEntry(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 3)
	receipt := buildReceipt(t, store, kid, entries, 1)

	// Force STH timestamp before entry timestamp — nonsensical.
	receipt.STH.Timestamp = entries[1].Timestamp.Add(-1)
	err := receipt.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestWitnessReceipt_VerifySignature_RejectsBrokenSTH(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 3)
	receipt := buildReceipt(t, store, kid, entries, 1)

	// Corrupt the STH tree hash — signature cover bytes drift.
	receipt.STH.TreeHash[0] ^= 0xFF
	err := receipt.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestWitnessReceipt_UnmarshalJSON_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 3)
	receipt := buildReceipt(t, store, kid, entries, 1)

	raw, err := json.Marshal(receipt)
	require.NoError(t, err)

	var decoded witness.WitnessReceipt
	require.NoError(t, decoded.UnmarshalJSON(raw))
	require.NoError(t, decoded.Verify(store))
}

func TestWitnessReceipt_UnmarshalJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 2)
	receipt := buildReceipt(t, store, kid, entries, 0)

	raw, err := json.Marshal(receipt)
	require.NoError(t, err)
	tampered := bytes.Replace(raw, []byte(`"entry":`), []byte(`"bogus":1,"entry":`), 1)

	var decoded witness.WitnessReceipt
	err = decoded.UnmarshalJSON(tampered)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// A verifier handed no key resolver is a malformed call, refused up front
// as Structural — never a nil dereference inside the signature check.
func TestWitnessReceipt_Verify_NilResolverRefused(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 2)
	receipt := buildReceipt(t, store, kid, entries, 1)

	for name, err := range map[string]error{
		"receipt.Verify":          receipt.Verify(nil),
		"receipt.VerifySignature": receipt.VerifySignature(nil),
		"sth.VerifySignature":     receipt.STH.VerifySignature(nil),
	} {
		require.Error(t, err, name)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), name)
		require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err), name)
	}
	require.NoError(t, receipt.Verify(store))
}
