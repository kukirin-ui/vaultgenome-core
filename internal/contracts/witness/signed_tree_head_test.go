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

func TestSTH_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 4)

	sth := newSignedSTH(t, store, kid, entries, defaultBaseTime())
	require.NoError(t, sth.Validate())
	require.NoError(t, sth.VerifySignature(store))
	require.NotEmpty(t, sth.Signature)
}

func TestSTH_Empty_Valid(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	sth := newSignedSTH(t, store, kid, nil, defaultBaseTime())
	require.NoError(t, sth.Validate())
	require.NoError(t, sth.VerifySignature(store))
	require.Equal(t, uint64(0), sth.TreeSize)
}

func TestSTH_Validate_EmptyTreeMustHaveZeroHash(t *testing.T) {
	t.Parallel()
	s := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      0,
		TreeHash:      repeat(0x11, crypto.HashSize), // non-zero
		TreeChainHead: make([]byte, crypto.HashSize),
		Timestamp:     defaultBaseTime(),
		SigningKeyID:  ids.KeyID("any"),
		Signature:     []byte{1, 2, 3},
	}
	err := s.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestSTH_Validate_NonEmptyTreeMustHaveNonZeroHash(t *testing.T) {
	t.Parallel()
	s := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      2,
		TreeHash:      make([]byte, crypto.HashSize),
		TreeChainHead: make([]byte, crypto.HashSize),
		Timestamp:     defaultBaseTime(),
		SigningKeyID:  ids.KeyID("any"),
		Signature:     []byte{1, 2, 3},
	}
	err := s.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestSTH_Validate_SingletonTreeEqualsChainHead(t *testing.T) {
	t.Parallel()
	// For TreeSize == 1, TreeHash MUST equal TreeChainHead.
	s := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      1,
		TreeHash:      repeat(0xAA, crypto.HashSize),
		TreeChainHead: repeat(0xBB, crypto.HashSize), // differ
		Timestamp:     defaultBaseTime(),
		SigningKeyID:  ids.KeyID("any"),
		Signature:     []byte{1, 2, 3},
	}
	err := s.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestSTH_VerifySignature_TamperedTreeHash(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 4)
	sth := newSignedSTH(t, store, kid, entries, defaultBaseTime())
	// Corrupt the tree hash post-sign.
	sth.TreeHash[0] ^= 0xFF
	err := sth.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestSTH_VerifySignature_PurposeMismatch(t *testing.T) {
	t.Parallel()
	// Try to use an authority-purpose key for witness signing — must
	// fail at Sign time.
	kid := ids.KeyID("authority-op")
	store := keys.NewInMemoryStore(nil)
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	s := &witness.SignedTreeHead{
		SchemaVersion: witness.SchemaVersionCurrent,
		TreeSize:      0,
		TreeHash:      make([]byte, crypto.HashSize),
		TreeChainHead: make([]byte, crypto.HashSize),
		Timestamp:     defaultBaseTime(),
		SigningKeyID:  kid,
	}
	err = s.SignWith(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestSTH_UnmarshalJSON_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 3)
	sth := newSignedSTH(t, store, kid, entries, defaultBaseTime())

	raw, err := json.Marshal(sth)
	require.NoError(t, err)

	var decoded witness.SignedTreeHead
	require.NoError(t, decoded.UnmarshalJSON(raw))
	require.NoError(t, decoded.Validate())
	require.NoError(t, decoded.VerifySignature(store))
	require.True(t, bytes.Equal(decoded.TreeHash, sth.TreeHash))
}

func TestSTH_UnmarshalJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-op-7")
	store := newWitnessStore(t, kid)
	entries := buildChain(t, 2)
	sth := newSignedSTH(t, store, kid, entries, defaultBaseTime())

	raw, err := json.Marshal(sth)
	require.NoError(t, err)
	tampered := bytes.Replace(raw, []byte(`"tree_size":`), []byte(`"bogus":1,"tree_size":`), 1)

	var decoded witness.SignedTreeHead
	err = decoded.UnmarshalJSON(tampered)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}
