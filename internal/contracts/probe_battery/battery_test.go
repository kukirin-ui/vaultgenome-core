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
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// newAuthStore mirrors the helper used in other contract packages:
// allocates an InMemoryStore with a single PurposeSigningAuthority key.
func newAuthStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

// buildProbes constructs a set of probes covering all three kinds.
// Returns probes with IDs already derived and assigned — ready to
// embed in a ProbeBattery.
func buildProbes(t *testing.T) []probe_battery.Probe {
	t.Helper()
	raw := []probe_battery.Probe{
		{
			Kind:              probe_battery.ProbeKindIdentity,
			InputHash:         repeat(0x01, crypto.HashSize),
			ExpectedShapeHash: repeat(0xA1, crypto.HashSize),
			Label:             "identity-alpha",
		},
		{
			Kind:              probe_battery.ProbeKindIdentity,
			InputHash:         repeat(0x02, crypto.HashSize),
			ExpectedShapeHash: repeat(0xA2, crypto.HashSize),
			Label:             "identity-beta",
		},
		{
			Kind:              probe_battery.ProbeKindCapability,
			InputHash:         repeat(0x03, crypto.HashSize),
			ExpectedShapeHash: nil,
			Label:             "capability-gamma",
		},
		{
			Kind:              probe_battery.ProbeKindCapability,
			InputHash:         repeat(0x04, crypto.HashSize),
			ExpectedShapeHash: nil,
			Label:             "capability-delta",
		},
		{
			Kind:              probe_battery.ProbeKindNegative,
			InputHash:         repeat(0x05, crypto.HashSize),
			ExpectedShapeHash: repeat(0xA5, crypto.HashSize),
			Label:             "negative-epsilon",
		},
	}
	out := make([]probe_battery.Probe, len(raw))
	for i := range raw {
		id, err := raw[i].DeriveID()
		require.NoError(t, err)
		raw[i].ID = id
		out[i] = raw[i]
	}
	return out
}

// newSignedBattery constructs a fully-valid, signed ProbeBattery
// ready for verification. kid must already exist in the keystore.
func newSignedBattery(t *testing.T, store *keys.InMemoryStore, kid ids.KeyID) *probe_battery.ProbeBattery {
	t.Helper()
	b := &probe_battery.ProbeBattery{
		SchemaVersion: probe_battery.SchemaVersionCurrent,
		Name:          "continuity-test-v1",
		Probes:        buildProbes(t),
		Policy:        probe_battery.DefaultTolerancePolicy(),
		IssuedAt:      time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID:  kid,
	}
	root, err := b.DeriveMerkleRoot()
	require.NoError(t, err)
	b.MerkleRoot = root
	require.NoError(t, b.SignWith(store))
	return b
}

func TestBattery_MerkleRoot_DeterministicAndOrderInvariant(t *testing.T) {
	t.Parallel()
	probes := buildProbes(t)
	shuffled := make([]probe_battery.Probe, len(probes))
	copy(shuffled, probes)
	// Simple swap-based shuffle; deterministic so the test is
	// reproducible but different from the input order.
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	b1 := &probe_battery.ProbeBattery{Probes: probes}
	b2 := &probe_battery.ProbeBattery{Probes: shuffled}
	r1, err := b1.DeriveMerkleRoot()
	require.NoError(t, err)
	r2, err := b2.DeriveMerkleRoot()
	require.NoError(t, err)
	require.True(t, bytes.Equal(r1, r2),
		"merkle root must be invariant to input order")
	require.Len(t, r1, crypto.HashSize)
}

func TestBattery_MerkleRoot_ChangesOnProbeMutation(t *testing.T) {
	t.Parallel()
	probes := buildProbes(t)
	b1 := &probe_battery.ProbeBattery{Probes: probes}
	r1, err := b1.DeriveMerkleRoot()
	require.NoError(t, err)

	// Replace the first probe with a freshly-derived, different probe.
	mutated := make([]probe_battery.Probe, len(probes))
	copy(mutated, probes)
	alt := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindIdentity,
		InputHash:         repeat(0xFF, crypto.HashSize),
		ExpectedShapeHash: repeat(0xEE, crypto.HashSize),
		Label:             "identity-alpha-reshaped",
	}
	altID, err := alt.DeriveID()
	require.NoError(t, err)
	alt.ID = altID
	mutated[0] = alt
	b2 := &probe_battery.ProbeBattery{Probes: mutated}
	r2, err := b2.DeriveMerkleRoot()
	require.NoError(t, err)
	require.False(t, bytes.Equal(r1, r2), "root must move on probe replacement")
}

func TestBattery_DeriveMerkleRoot_RejectsDuplicateIDs(t *testing.T) {
	t.Parallel()
	probes := buildProbes(t)
	probes = append(probes, probes[0]) // exact duplicate
	b := &probe_battery.ProbeBattery{Probes: probes}
	_, err := b.DeriveMerkleRoot()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestBattery_DeriveMerkleRoot_RejectsMissingID(t *testing.T) {
	t.Parallel()
	probes := buildProbes(t)
	probes[2].ID = "" // clobber one id
	b := &probe_battery.ProbeBattery{Probes: probes}
	_, err := b.DeriveMerkleRoot()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestBattery_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := newSignedBattery(t, store, kid)
	require.NotEmpty(t, b.Signature)
	require.NoError(t, b.VerifySignature(store))
}

func TestBattery_VerifySignature_TamperedProbe(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := newSignedBattery(t, store, kid)

	// Mutate an existing probe's label after signing. Validate must
	// catch it before the signature gate even runs — the per-probe
	// content-address is violated.
	b.Probes[0].Label = "tampered"
	err := b.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestBattery_VerifySignature_TamperedMerkleRoot(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := newSignedBattery(t, store, kid)

	// Flip one byte of the stored MerkleRoot — the content-address
	// gate in Validate must catch this.
	b.MerkleRoot[0] ^= 0xFF
	err := b.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestBattery_Validate_RejectsSchemaOutOfRange(t *testing.T) {
	t.Parallel()
	probes := buildProbes(t)
	b := &probe_battery.ProbeBattery{
		SchemaVersion: 99,
		Name:          "x",
		Probes:        probes,
		Policy:        probe_battery.DefaultTolerancePolicy(),
		IssuedAt:      time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID:  "kid",
		Signature:     []byte{1, 2, 3},
		MerkleRoot:    repeat(0, crypto.HashSize),
	}
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestBattery_UnmarshalJSON_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := newSignedBattery(t, store, kid)
	raw, err := json.Marshal(b)
	require.NoError(t, err)
	// Splice an unknown field in.
	tampered := bytes.Replace(raw, []byte(`"name":`), []byte(`"bogus_field":true,"name":`), 1)

	var decoded probe_battery.ProbeBattery
	err = decoded.UnmarshalJSON(tampered)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestBattery_UnmarshalJSON_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	original := newSignedBattery(t, store, kid)

	raw, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded probe_battery.ProbeBattery
	require.NoError(t, decoded.UnmarshalJSON(raw))
	require.NoError(t, decoded.Validate())
	require.NoError(t, decoded.VerifySignature(store))
	require.True(t, bytes.Equal(original.MerkleRoot, decoded.MerkleRoot))
	require.Equal(t, original.Name, decoded.Name)
}

func TestBattery_SignWith_RefusesMissingMerkleRoot(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := &probe_battery.ProbeBattery{
		SchemaVersion: probe_battery.SchemaVersionCurrent,
		Name:          "x",
		Probes:        buildProbes(t),
		Policy:        probe_battery.DefaultTolerancePolicy(),
		IssuedAt:      time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID:  kid,
		// Deliberately no MerkleRoot set.
	}
	err := b.SignWith(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestBattery_SignWith_RefusesMissingKeyID(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	b := &probe_battery.ProbeBattery{
		SchemaVersion: probe_battery.SchemaVersionCurrent,
		Name:          "x",
		Probes:        buildProbes(t),
		Policy:        probe_battery.DefaultTolerancePolicy(),
		IssuedAt:      time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		MerkleRoot:    repeat(0x11, crypto.HashSize),
		// SigningKeyID intentionally zero.
	}
	err := b.SignWith(store)
	require.Error(t, err)
}

func TestBattery_SignatureIsOrderInvariant(t *testing.T) {
	t.Parallel()
	// Two batteries with the same probe set but constructed from
	// differently-ordered slices must produce THE SAME canonical
	// bytes, hence the same signature under a deterministic signer
	// (Ed25519).
	kid := ids.KeyID("battery-signer")
	store := newAuthStore(t, kid)
	probes := buildProbes(t)

	b1 := &probe_battery.ProbeBattery{
		SchemaVersion: probe_battery.SchemaVersionCurrent,
		Name:          "order-test",
		Probes:        append([]probe_battery.Probe{}, probes...),
		Policy:        probe_battery.DefaultTolerancePolicy(),
		IssuedAt:      time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID:  kid,
	}
	shuffled := append([]probe_battery.Probe{}, probes...)
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	b2 := &probe_battery.ProbeBattery{
		SchemaVersion: probe_battery.SchemaVersionCurrent,
		Name:          "order-test",
		Probes:        shuffled,
		Policy:        probe_battery.DefaultTolerancePolicy(),
		IssuedAt:      time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID:  kid,
	}
	r1, err := b1.DeriveMerkleRoot()
	require.NoError(t, err)
	b1.MerkleRoot = r1
	r2, err := b2.DeriveMerkleRoot()
	require.NoError(t, err)
	b2.MerkleRoot = r2
	require.NoError(t, b1.SignWith(store))
	require.NoError(t, b2.SignWith(store))
	require.True(t, bytes.Equal(b1.Signature, b2.Signature),
		"deterministic signer + canonical ordering must yield equal signatures")
}
