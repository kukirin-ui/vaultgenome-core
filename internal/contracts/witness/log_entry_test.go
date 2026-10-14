// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func TestLogEntry_DeriveLeafHashAndID_Genesis(t *testing.T) {
	t.Parallel()
	base := defaultBaseTime()
	e := &witness.LogEntry{
		SchemaVersion:     witness.SchemaVersionCurrent,
		Index:             0,
		PrevLeafHash:      zeros32(),
		Timestamp:         base,
		GenomeID:          ids.GenomeID("gen:root"),
		AttestationRoot:   repeat(0x11, crypto.HashSize),
		BatteryMerkleRoot: repeat(0x22, crypto.HashSize),
		ScorecardRoot:     repeat(0x33, crypto.HashSize),
	}
	leaf, id, err := e.DeriveLeafHashAndID()
	require.NoError(t, err)
	require.Len(t, leaf, crypto.HashSize)
	require.Equal(t, "log:", string(id[:4]))
}

func TestLogEntry_DeriveLeafHashAndID_Deterministic(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 3)
	// Re-derive each entry's leaf hash from a fresh struct — must
	// match what buildChain computed.
	for i, e := range entries {
		cp := e
		leaf, id, err := cp.DeriveLeafHashAndID()
		require.NoError(t, err)
		require.True(t, bytes.Equal(leaf, entries[i].LeafHash), "leaf hash drift at index %d", i)
		require.Equal(t, entries[i].EntryID, id, "entry id drift at index %d", i)
	}
}

func TestLogEntry_DeriveLeafHashAndID_ContentSensitive(t *testing.T) {
	t.Parallel()
	// Two entries identical except for AttestationRoot produce
	// different LeafHash / EntryID.
	base := defaultBaseTime()
	build := func(seed byte) *witness.LogEntry {
		return &witness.LogEntry{
			SchemaVersion:     witness.SchemaVersionCurrent,
			Index:             0,
			PrevLeafHash:      zeros32(),
			Timestamp:         base,
			GenomeID:          ids.GenomeID("gen:x"),
			AttestationRoot:   repeat(seed, crypto.HashSize),
			BatteryMerkleRoot: repeat(0x22, crypto.HashSize),
			ScorecardRoot:     repeat(0x33, crypto.HashSize),
		}
	}
	a := build(0x11)
	b := build(0x12)
	la, ida, err := a.DeriveLeafHashAndID()
	require.NoError(t, err)
	lb, idb, err := b.DeriveLeafHashAndID()
	require.NoError(t, err)
	require.False(t, bytes.Equal(la, lb), "leaf hashes must differ")
	require.NotEqual(t, ida, idb)
}

func TestLogEntry_Validate_RoundTrip(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 4)
	for i := range entries {
		require.NoError(t, entries[i].Validate(), "entry %d", i)
	}
}

func TestLogEntry_Validate_TamperedPayload(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 3)
	// Corrupt attestation root AFTER derivation — stored LeafHash is
	// now stale. Validate must catch the mismatch as Integrity.
	entries[1].AttestationRoot[0] ^= 0xFF
	err := entries[1].Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestLogEntry_Validate_TamperedPrevLeafHash(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 3)
	entries[2].PrevLeafHash[0] ^= 0xFF
	err := entries[2].Validate()
	require.Error(t, err)
	// The tamper is to a field covered by LeafHash derivation, so it
	// surfaces as Integrity (derived leaf_hash disagrees with stored).
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestLogEntry_Validate_GenesisMustHaveZeroPrevLeafHash(t *testing.T) {
	t.Parallel()
	base := defaultBaseTime()
	e := &witness.LogEntry{
		SchemaVersion:     witness.SchemaVersionCurrent,
		Index:             0,
		PrevLeafHash:      repeat(0x01, crypto.HashSize), // non-zero at index 0
		Timestamp:         base,
		GenomeID:          ids.GenomeID("gen:root"),
		AttestationRoot:   repeat(0x11, crypto.HashSize),
		BatteryMerkleRoot: repeat(0x22, crypto.HashSize),
		ScorecardRoot:     repeat(0x33, crypto.HashSize),
	}
	_, _, err := e.DeriveLeafHashAndID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestLogEntry_Validate_NonGenesisMustHaveNonZeroPrevLeafHash(t *testing.T) {
	t.Parallel()
	base := defaultBaseTime()
	e := &witness.LogEntry{
		SchemaVersion:     witness.SchemaVersionCurrent,
		Index:             1,
		PrevLeafHash:      zeros32(), // all-zero at index != 0
		Timestamp:         base,
		GenomeID:          ids.GenomeID("gen:x"),
		AttestationRoot:   repeat(0x11, crypto.HashSize),
		BatteryMerkleRoot: repeat(0x22, crypto.HashSize),
		ScorecardRoot:     repeat(0x33, crypto.HashSize),
		ParentGenomeID:    ids.GenomeID("gen:parent"),
		DerivationMethod:  genome_descriptor.DerivationFineTune,
	}
	_, _, err := e.DeriveLeafHashAndID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestLogEntry_Validate_ParentAndMethodCoPresence(t *testing.T) {
	t.Parallel()
	base := defaultBaseTime()
	// Parent without method — reject.
	e := &witness.LogEntry{
		SchemaVersion:     witness.SchemaVersionCurrent,
		Index:             1,
		PrevLeafHash:      repeat(0xEE, crypto.HashSize),
		Timestamp:         base,
		GenomeID:          ids.GenomeID("gen:x"),
		AttestationRoot:   repeat(0x11, crypto.HashSize),
		BatteryMerkleRoot: repeat(0x22, crypto.HashSize),
		ScorecardRoot:     repeat(0x33, crypto.HashSize),
		ParentGenomeID:    ids.GenomeID("gen:parent"),
		// DerivationMethod intentionally unset.
	}
	_, _, err := e.DeriveLeafHashAndID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	// Method without parent — reject.
	e.ParentGenomeID = ""
	e.DerivationMethod = genome_descriptor.DerivationFineTune
	_, _, err = e.DeriveLeafHashAndID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestLogEntry_Validate_UnknownDerivationMethod(t *testing.T) {
	t.Parallel()
	base := defaultBaseTime()
	e := &witness.LogEntry{
		SchemaVersion:     witness.SchemaVersionCurrent,
		Index:             1,
		PrevLeafHash:      repeat(0xEE, crypto.HashSize),
		Timestamp:         base,
		GenomeID:          ids.GenomeID("gen:x"),
		AttestationRoot:   repeat(0x11, crypto.HashSize),
		BatteryMerkleRoot: repeat(0x22, crypto.HashSize),
		ScorecardRoot:     repeat(0x33, crypto.HashSize),
		ParentGenomeID:    ids.GenomeID("gen:parent"),
		DerivationMethod:  genome_descriptor.DerivationMethod("telepathy"),
	}
	_, _, err := e.DeriveLeafHashAndID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestLogEntry_UnmarshalJSON_RoundTrip(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 3)
	raw, err := json.Marshal(entries[1])
	require.NoError(t, err)

	var decoded witness.LogEntry
	require.NoError(t, decoded.UnmarshalJSON(raw))
	require.NoError(t, decoded.Validate())
	require.True(t, bytes.Equal(decoded.LeafHash, entries[1].LeafHash))
	require.Equal(t, entries[1].EntryID, decoded.EntryID)
}

func TestLogEntry_UnmarshalJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 2)
	raw, err := json.Marshal(entries[0])
	require.NoError(t, err)
	tampered := bytes.Replace(raw, []byte(`"genome_id":`), []byte(`"bogus":1,"genome_id":`), 1)

	var decoded witness.LogEntry
	err = decoded.UnmarshalJSON(tampered)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestLogEntry_UnmarshalJSON_RejectsUnsupportedSchemaVersion(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 1)
	raw, err := json.Marshal(entries[0])
	require.NoError(t, err)
	tampered := bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":999`), 1)

	var decoded witness.LogEntry
	err = decoded.UnmarshalJSON(tampered)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestComputeMerkleRoot_SingleLeafEqualsLeaf(t *testing.T) {
	t.Parallel()
	leaf := repeat(0xAB, crypto.HashSize)
	root, err := witness.ComputeMerkleRoot([][]byte{leaf})
	require.NoError(t, err)
	require.True(t, bytes.Equal(root, leaf))
}

func TestComputeMerkleRoot_EmptyIsAllZero(t *testing.T) {
	t.Parallel()
	root, err := witness.ComputeMerkleRoot(nil)
	require.NoError(t, err)
	require.Len(t, root, crypto.HashSize)
	for _, b := range root {
		require.Equal(t, byte(0), b)
	}
}

func TestComputeMerkleRoot_RejectsWrongSizeLeaf(t *testing.T) {
	t.Parallel()
	_, err := witness.ComputeMerkleRoot([][]byte{repeat(0xAB, 16)})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestCombineNodes_RejectsWrongSize(t *testing.T) {
	t.Parallel()
	_, err := witness.CombineNodes(repeat(0xAA, 16), repeat(0xBB, crypto.HashSize))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}
