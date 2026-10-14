// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe_battery_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/probe_battery"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// scoreEntriesForBattery builds a ScoreEntry for every probe in b.
// responseSeed lets the caller tag the response hashes so parent/
// child scorecards can differ in tests.
func scoreEntriesForBattery(b *probe_battery.ProbeBattery, responseSeed byte) []probe_battery.ScoreEntry {
	out := make([]probe_battery.ScoreEntry, len(b.Probes))
	for i := range b.Probes {
		// Deterministic per-probe response hash: mix InputHash with
		// the seed so different seeds produce different responses.
		h := make([]byte, crypto.HashSize)
		copy(h, b.Probes[i].InputHash)
		h[0] ^= responseSeed
		out[i] = probe_battery.ScoreEntry{
			ProbeID:      b.Probes[i].ID,
			ResponseHash: h,
		}
	}
	return out
}

func newSignedScorecard(
	t *testing.T,
	runnerStore *keys.InMemoryStore,
	runnerKID ids.KeyID,
	genome ids.GenomeID,
	battery *probe_battery.ProbeBattery,
	responseSeed byte,
) *probe_battery.Scorecard {
	t.Helper()
	s := &probe_battery.Scorecard{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          genome,
		BatteryName:       battery.Name,
		BatteryMerkleRoot: append([]byte(nil), battery.MerkleRoot...),
		Entries:           scoreEntriesForBattery(battery, responseSeed),
		MeasuredAt:        time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC),
		SigningKeyID:      runnerKID,
	}
	root, err := s.DeriveMerkleRoot()
	require.NoError(t, err)
	s.MerkleRoot = root
	require.NoError(t, s.SignWith(runnerStore))
	return s
}

func TestScorecard_MerkleRoot_DeterministicAndOrderInvariant(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := newSignedBattery(t, store, kid)

	entries := scoreEntriesForBattery(b, 0x00)
	shuffled := make([]probe_battery.ScoreEntry, len(entries))
	copy(shuffled, entries)
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	s1 := &probe_battery.Scorecard{Entries: entries}
	s2 := &probe_battery.Scorecard{Entries: shuffled}
	r1, err := s1.DeriveMerkleRoot()
	require.NoError(t, err)
	r2, err := s2.DeriveMerkleRoot()
	require.NoError(t, err)
	require.True(t, bytes.Equal(r1, r2), "scorecard root is order-invariant")
}

func TestScorecard_DeriveMerkleRoot_RejectsDuplicateProbeID(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := newSignedBattery(t, store, kid)
	entries := scoreEntriesForBattery(b, 0x00)
	entries = append(entries, entries[0])
	s := &probe_battery.Scorecard{Entries: entries}
	_, err := s.DeriveMerkleRoot()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestScorecard_DeriveMerkleRoot_RejectsWrongResponseHashSize(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := newSignedBattery(t, store, kid)
	entries := scoreEntriesForBattery(b, 0x00)
	entries[0].ResponseHash = entries[0].ResponseHash[:16]
	s := &probe_battery.Scorecard{Entries: entries}
	_, err := s.DeriveMerkleRoot()
	require.Error(t, err)
}

func TestScorecard_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	require.NotEmpty(t, s.Signature)
	require.NoError(t, s.VerifySignature(store))
}

func TestScorecard_VerifySignature_TamperedEntry(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	// Tamper with one response hash — Validate detects via content-
	// address gate on MerkleRoot.
	s.Entries[0].ResponseHash[0] ^= 0xFF
	err = s.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestScorecard_UnmarshalJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	tampered := bytes.Replace(raw, []byte(`"genome_id":`), []byte(`"bogus":1,"genome_id":`), 1)

	var decoded probe_battery.Scorecard
	err = decoded.UnmarshalJSON(tampered)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestScorecard_UnmarshalJSON_RoundTrip(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	original := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	raw, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded probe_battery.Scorecard
	require.NoError(t, decoded.UnmarshalJSON(raw))
	require.NoError(t, decoded.Validate())
	require.NoError(t, decoded.VerifySignature(store))
	require.True(t, bytes.Equal(original.MerkleRoot, decoded.MerkleRoot))
}
