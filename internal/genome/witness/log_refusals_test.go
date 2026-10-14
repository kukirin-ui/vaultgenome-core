// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	contract "github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/genome/witness"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// TestAppend_InvalidPayloadRefused proves that Append refuses a payload
// the contract cannot address: a zero timestamp trips the monotonic time
// gate (an Incident, since it reads as a rollback), every other defect is
// the contract's own structural refusal from leaf derivation. Nothing is
// committed either way: the log keeps its size and its tail.
func TestAppend_InvalidPayloadRefused(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mutate   func(e *contract.LogEntry)
		category shared_errors.Category
		code     string
	}{
		{
			name:     "zero timestamp reads as rollback",
			mutate:   func(e *contract.LogEntry) { e.Timestamp = time.Time{} },
			category: shared_errors.CategoryIncident,
			code:     shared_errors.CodeTamperSignal,
		},
		{
			name:     "missing genome id",
			mutate:   func(e *contract.LogEntry) { e.GenomeID = "" },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeRequiredFieldMissing,
		},
		{
			name:     "short attestation root",
			mutate:   func(e *contract.LogEntry) { e.AttestationRoot = e.AttestationRoot[:31] },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeFieldValueInvalid,
		},
		{
			name:     "missing battery root",
			mutate:   func(e *contract.LogEntry) { e.BatteryMerkleRoot = nil },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeFieldValueInvalid,
		},
		{
			name:     "long scorecard root",
			mutate:   func(e *contract.LogEntry) { e.ScorecardRoot = repeatByte(0x01, 33) },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeFieldValueInvalid,
		},
		{
			name:     "parent without derivation method",
			mutate:   func(e *contract.LogEntry) { e.ParentGenomeID = ids.GenomeID("gen:parent") },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeCrossFieldInconsistent,
		},
		{
			name:     "unknown derivation method",
			mutate:   func(e *contract.LogEntry) { e.ParentGenomeID = "gen:parent"; e.DerivationMethod = "teleport" },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeFieldValueInvalid,
		},
		{
			name:     "unsupported schema version",
			mutate:   func(e *contract.LogEntry) { e.SchemaVersion = contract.SchemaVersionMax + 1 },
			category: shared_errors.CategoryStructural,
			code:     shared_errors.CodeSchemaVersionUnsupported,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			log, _, _ := newLog(t)
			first := appendN(t, log, 1)[0]

			bad := samplePayload(1, defaultBaseTime().Add(time.Second))
			tc.mutate(&bad)
			committed, err := log.Append(bad)
			require.Error(t, err)
			require.Nil(t, committed)
			require.Equal(t, tc.category, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))

			require.Equal(t, uint64(1), log.Size(), "a refused append commits nothing")
			tail, err := log.Entry(0)
			require.NoError(t, err)
			require.Equal(t, first.LeafHash, tail.LeafHash)
		})
	}
}

// TestHeadAndReceipt_SignerRefusalSurfaces proves that a misconfigured
// signing key is caught at the first STH signing attempt, as the
// constructor promises: a key registered under another purpose is an
// Integrity refusal, an unknown key an Authority refusal, and both Head
// and Receipt surface it unchanged instead of issuing an unsigned head.
func TestHeadAndReceipt_SignerRefusalSurfaces(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		register func(t *testing.T, store *keys.InMemoryStore, kid ids.KeyID)
		category shared_errors.Category
		code     string
	}{
		{
			name: "key registered under audit purpose",
			register: func(t *testing.T, store *keys.InMemoryStore, kid ids.KeyID) {
				_, err := store.GenerateSigning(kid, keys.PurposeSigningAudit)
				require.NoError(t, err)
			},
			category: shared_errors.CategoryIntegrity,
			code:     shared_errors.CodeFieldValueInvalid,
		},
		{
			name:     "key never registered",
			register: func(*testing.T, *keys.InMemoryStore, ids.KeyID) {},
			category: shared_errors.CategoryAuthority,
			code:     shared_errors.CodeRequiredFieldMissing,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kid := ids.KeyID("witness-misconfigured")
			store := keys.NewInMemoryStore(nil)
			tc.register(t, store, kid)
			log, err := witness.NewInMemoryLog(store, kid, shared_time.NewFakeClock(defaultBaseTime()))
			require.NoError(t, err, "the constructor defers the key check to signing time")
			appendN(t, log, 2)

			sth, err := log.Head()
			require.Error(t, err)
			require.Nil(t, sth)
			require.Equal(t, tc.category, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))

			receipt, err := log.Receipt(1)
			require.Error(t, err)
			require.Nil(t, receipt)
			require.Equal(t, tc.category, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
		})
	}
}

// TestHead_TimestampNeverPredatesNewestEntry proves that an STH issued by
// a lagging clock carries the newest entry's timestamp rather than the
// clock's, so the head never claims to predate what it commits to and the
// receipt contract accepts it.
func TestHead_TimestampNeverPredatesNewestEntry(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-lagging-clock")
	store := keys.NewInMemoryStore(nil)
	_, err := store.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)
	lagging := shared_time.NewFakeClock(defaultBaseTime().Add(-time.Hour))
	log, err := witness.NewInMemoryLog(store, kid, lagging)
	require.NoError(t, err)

	ahead := defaultBaseTime().Add(30 * time.Minute)
	_, err = log.Append(samplePayload(0, ahead))
	require.NoError(t, err)

	sth, err := log.Head()
	require.NoError(t, err)
	require.Equal(t, ahead, sth.Timestamp)
	require.NoError(t, sth.VerifySignature(store))

	receipt, err := log.Receipt(0)
	require.NoError(t, err)
	require.NoError(t, receipt.Verify(store))
}
