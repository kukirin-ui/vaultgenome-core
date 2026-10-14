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

func newSignedAttestation(
	t *testing.T,
	store *keys.InMemoryStore,
	kid ids.KeyID,
	genome ids.GenomeID,
	battery *probe_battery.ProbeBattery,
	scorecard *probe_battery.Scorecard,
) *probe_battery.ProbeAttestation {
	t.Helper()
	runStart := time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC)
	runEnd := runStart.Add(90 * time.Second)
	a := &probe_battery.ProbeAttestation{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          genome,
		BatteryName:       battery.Name,
		BatteryMerkleRoot: append([]byte(nil), battery.MerkleRoot...),
		ScorecardRoot:     append([]byte(nil), scorecard.MerkleRoot...),
		RunnerIdentity:    "tee://runner-7",
		TEEMeasurement:    repeat(0x5A, crypto.HashSize),
		RunStartedAt:      runStart,
		RunCompletedAt:    runEnd,
		IssuedAt:          runEnd.Add(1 * time.Second),
		SigningKeyID:      kid,
	}
	require.NoError(t, a.SignWith(store))
	return a
}

func TestAttestation_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)
	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	a := newSignedAttestation(t, store, runnerKID, ids.GenomeID("gen:abc"), b, s)
	require.NotEmpty(t, a.Signature)
	require.NoError(t, a.VerifySignature(store))
}

func TestAttestation_VerifySignature_TamperedField(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)
	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	a := newSignedAttestation(t, store, runnerKID, ids.GenomeID("gen:abc"), b, s)

	// Swap the claimed runner identity after signing.
	a.RunnerIdentity = "tee://runner-rogue"
	err = a.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestAttestation_Validate_TemporalOrdering(t *testing.T) {
	t.Parallel()
	a := &probe_battery.ProbeAttestation{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          "gen:abc",
		BatteryName:       "x",
		BatteryMerkleRoot: repeat(0x11, crypto.HashSize),
		ScorecardRoot:     repeat(0x22, crypto.HashSize),
		RunnerIdentity:    "tee://r",
		TEEMeasurement:    repeat(0x33, crypto.HashSize),
		RunStartedAt:      time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		RunCompletedAt:    time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC), // BEFORE start
		IssuedAt:          time.Date(2026, 4, 20, 13, 0, 0, 0, time.UTC),
		SigningKeyID:      "kid",
		Signature:         []byte{1, 2, 3},
	}
	err := a.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	// Repair run_completed_at but force issued_at too early.
	a.RunCompletedAt = a.RunStartedAt.Add(time.Second)
	a.IssuedAt = a.RunStartedAt // before completion
	err = a.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestAttestation_UnmarshalJSON_RoundTrip(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)
	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	original := newSignedAttestation(t, store, runnerKID, ids.GenomeID("gen:abc"), b, s)

	raw, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded probe_battery.ProbeAttestation
	require.NoError(t, decoded.UnmarshalJSON(raw))
	require.NoError(t, decoded.Validate())
	require.NoError(t, decoded.VerifySignature(store))
	require.True(t, bytes.Equal(original.Signature, decoded.Signature))
}

func TestAttestation_UnmarshalJSON_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)
	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	original := newSignedAttestation(t, store, runnerKID, ids.GenomeID("gen:abc"), b, s)

	raw, err := json.Marshal(original)
	require.NoError(t, err)
	tampered := bytes.Replace(raw, []byte(`"runner_identity":`), []byte(`"bogus":true,"runner_identity":`), 1)
	var decoded probe_battery.ProbeAttestation
	err = decoded.UnmarshalJSON(tampered)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// A probe run inside real hardware reports a 48-byte (SEV-SNP, Nitro)
// or 64-byte measurement; it is carried whole. Other lengths are refused.
func TestAttestation_Validate_MeasurementLengths(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)
	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	a := newSignedAttestation(t, store, runnerKID, ids.GenomeID("gen:abc"), b, s)

	for n, ok := range map[int]bool{32: true, 48: true, 64: true, 0: false, 31: false, 33: false, 47: false} {
		c := *a
		c.TEEMeasurement = repeat(0x5A, n)
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("%d-byte measurement: Validate err = %v, want ok=%v", n, err, ok)
		}
	}
}
