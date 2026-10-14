// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe_battery_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/probe_battery"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// flipEntry returns a copy of entries with the ResponseHash for
// probeID perturbed so the child scorecard drifts on that probe.
func flipEntry(entries []probe_battery.ScoreEntry, probeID probe_battery.ProbeID) []probe_battery.ScoreEntry {
	out := make([]probe_battery.ScoreEntry, len(entries))
	for i := range entries {
		out[i] = probe_battery.ScoreEntry{
			ProbeID:      entries[i].ProbeID,
			ResponseHash: append([]byte(nil), entries[i].ResponseHash...),
		}
		if out[i].ProbeID == probeID {
			out[i].ResponseHash[0] ^= 0xFF
		}
	}
	return out
}

func TestCompare_HappyPath_IdenticalScorecards(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	parent := newSignedScorecard(t, store, runnerKID, "gen:parent", b, 0x00)
	child := newSignedScorecard(t, store, runnerKID, "gen:child", b, 0x00)
	out, err := probe_battery.Compare(parent, child, b,
		genome_descriptor.DerivationFineTune, b.Policy)
	require.NoError(t, err)
	require.True(t, out.Pass)
	require.Equal(t, 0.0, out.CapabilityDriftFraction)
	require.Empty(t, out.IdentityViolations)
	require.Empty(t, out.NegativeFlips)
	require.Empty(t, out.CapabilityDrifts)
}

func TestCompare_IdentityViolation_Fails(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	// Find an identity probe.
	var identityID probe_battery.ProbeID
	for i := range b.Probes {
		if b.Probes[i].Kind == probe_battery.ProbeKindIdentity {
			identityID = b.Probes[i].ID
			break
		}
	}
	require.NotEmpty(t, identityID)

	parent := newSignedScorecard(t, store, runnerKID, "gen:parent", b, 0x00)
	child := &probe_battery.Scorecard{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          "gen:child",
		BatteryName:       b.Name,
		BatteryMerkleRoot: append([]byte(nil), b.MerkleRoot...),
		Entries:           flipEntry(parent.Entries, identityID),
		MeasuredAt:        parent.MeasuredAt,
		SigningKeyID:      runnerKID,
	}
	root, err := child.DeriveMerkleRoot()
	require.NoError(t, err)
	child.MerkleRoot = root
	require.NoError(t, child.SignWith(store))

	out, err := probe_battery.Compare(parent, child, b,
		genome_descriptor.DerivationFineTune, b.Policy)
	require.NoError(t, err)
	require.False(t, out.Pass, "identity drift must fail continuity")
	require.Contains(t, out.IdentityViolations, identityID)
}

func TestCompare_NegativeFlip_Fails(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	var negativeID probe_battery.ProbeID
	for i := range b.Probes {
		if b.Probes[i].Kind == probe_battery.ProbeKindNegative {
			negativeID = b.Probes[i].ID
			break
		}
	}
	require.NotEmpty(t, negativeID)

	parent := newSignedScorecard(t, store, runnerKID, "gen:parent", b, 0x00)
	child := &probe_battery.Scorecard{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          "gen:child",
		BatteryName:       b.Name,
		BatteryMerkleRoot: append([]byte(nil), b.MerkleRoot...),
		Entries:           flipEntry(parent.Entries, negativeID),
		MeasuredAt:        parent.MeasuredAt,
		SigningKeyID:      runnerKID,
	}
	root, err := child.DeriveMerkleRoot()
	require.NoError(t, err)
	child.MerkleRoot = root
	require.NoError(t, child.SignWith(store))

	out, err := probe_battery.Compare(parent, child, b,
		genome_descriptor.DerivationReconstruct, b.Policy)
	require.NoError(t, err)
	require.False(t, out.Pass,
		"a descendant passing a negative probe its ancestor failed is a swap signal")
	require.Contains(t, out.NegativeFlips, negativeID)
}

func TestCompare_CapabilityDrift_WithinBudgetPasses(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	// Battery has 2 capability probes. Drift one ⇒ 50%. Under
	// DerivationQuantize (budget 25%) this FAILS; under a hypothetical
	// 60% cap it would pass. Quantize is tight enough that this is
	// the cleanest test.
	var capabilityID probe_battery.ProbeID
	for i := range b.Probes {
		if b.Probes[i].Kind == probe_battery.ProbeKindCapability {
			capabilityID = b.Probes[i].ID
			break
		}
	}
	require.NotEmpty(t, capabilityID)

	parent := newSignedScorecard(t, store, runnerKID, "gen:parent", b, 0x00)
	child := &probe_battery.Scorecard{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          "gen:child",
		BatteryName:       b.Name,
		BatteryMerkleRoot: append([]byte(nil), b.MerkleRoot...),
		Entries:           flipEntry(parent.Entries, capabilityID),
		MeasuredAt:        parent.MeasuredAt,
		SigningKeyID:      runnerKID,
	}
	root, err := child.DeriveMerkleRoot()
	require.NoError(t, err)
	child.MerkleRoot = root
	require.NoError(t, child.SignWith(store))

	// Under Quantize (25% budget), drifting 50% of capability probes
	// is over-budget ⇒ fail.
	out, err := probe_battery.Compare(parent, child, b,
		genome_descriptor.DerivationQuantize, b.Policy)
	require.NoError(t, err)
	require.False(t, out.Pass)
	require.InDelta(t, 0.5, out.CapabilityDriftFraction, 0.0001)
	require.Contains(t, out.CapabilityDrifts, capabilityID)
}

func TestCompare_CapabilityDrift_UnderMethodCeilingPasses(t *testing.T) {
	t.Parallel()
	// With zero capability drift, every method must pass under the
	// default policy. This guards against accidental off-by-one
	// semantics like `<` vs `<=`.
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	parent := newSignedScorecard(t, store, runnerKID, "gen:parent", b, 0x00)
	child := newSignedScorecard(t, store, runnerKID, "gen:child", b, 0x00)

	for _, m := range []genome_descriptor.DerivationMethod{
		genome_descriptor.DerivationFineTune,
		genome_descriptor.DerivationDistill,
		genome_descriptor.DerivationMerge,
		genome_descriptor.DerivationQuantize,
		genome_descriptor.DerivationReconstruct,
	} {
		out, err := probe_battery.Compare(parent, child, b, m, b.Policy)
		require.NoError(t, err, m)
		require.True(t, out.Pass, "no drift, method=%s, must pass", m)
	}
}

func TestCompare_BatteryRootMismatch_IsIntegrity(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	parent := newSignedScorecard(t, store, runnerKID, "gen:parent", b, 0x00)
	child := newSignedScorecard(t, store, runnerKID, "gen:child", b, 0x00)

	// Doctor the child's stored BatteryMerkleRoot AFTER signing to
	// point at a different battery. (Validate would normally catch
	// this, but Compare is supposed to be the gate, not a spurious
	// trust; we verify Compare classifies the mismatch as Integrity.)
	child.BatteryMerkleRoot = repeat(0xAA, crypto.HashSize)

	_, err = probe_battery.Compare(parent, child, b,
		genome_descriptor.DerivationFineTune, b.Policy)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestCompare_ScorecardDoesNotMatchBattery_IsIntegrity(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)

	parent := newSignedScorecard(t, store, runnerKID, "gen:parent", b, 0x00)
	child := newSignedScorecard(t, store, runnerKID, "gen:child", b, 0x00)

	// Flip the PROVIDED battery's root to simulate the caller passing
	// a different battery than the scorecards reference.
	divergent := *b
	divergent.MerkleRoot = repeat(0xBB, crypto.HashSize)

	_, err = probe_battery.Compare(parent, child, &divergent,
		genome_descriptor.DerivationFineTune, b.Policy)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestTolerancePolicy_Validate_AllMethodsRequired(t *testing.T) {
	t.Parallel()
	p := probe_battery.DefaultTolerancePolicy()
	delete(p.MaxCapabilityDrift, genome_descriptor.DerivationQuantize)
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestTolerancePolicy_Validate_RejectsOverDoctrinal(t *testing.T) {
	t.Parallel()
	p := probe_battery.DefaultTolerancePolicy()
	p.MaxCapabilityDrift[genome_descriptor.DerivationFineTune] =
		probe_battery.MaxDriftFineTune + 0.01
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestTolerancePolicy_Validate_RejectsNegativeBound(t *testing.T) {
	t.Parallel()
	p := probe_battery.DefaultTolerancePolicy()
	p.MaxCapabilityDrift[genome_descriptor.DerivationMerge] = -0.01
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestTolerancePolicy_Validate_RejectsUnknownMethodKey(t *testing.T) {
	t.Parallel()
	p := probe_battery.DefaultTolerancePolicy()
	p.MaxCapabilityDrift[genome_descriptor.DerivationMethod("bogus")] = 0.01
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestMethodBudget_KnownAndUnknown(t *testing.T) {
	t.Parallel()
	cases := map[genome_descriptor.DerivationMethod]float64{
		genome_descriptor.DerivationFineTune:    probe_battery.MaxDriftFineTune,
		genome_descriptor.DerivationDistill:     probe_battery.MaxDriftDistill,
		genome_descriptor.DerivationMerge:       probe_battery.MaxDriftMerge,
		genome_descriptor.DerivationQuantize:    probe_battery.MaxDriftQuantize,
		genome_descriptor.DerivationReconstruct: probe_battery.MaxDriftReconstruct,
	}
	for m, expected := range cases {
		got, err := probe_battery.MethodBudget(m)
		require.NoError(t, err, m)
		require.Equal(t, expected, got, m)
	}
	_, err := probe_battery.MethodBudget(genome_descriptor.DerivationMethod("bogus"))
	require.Error(t, err)
}

func TestCompare_RejectsNilScorecard(t *testing.T) {
	t.Parallel()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)
	parent := newSignedScorecard(t, store, runnerKID, "gen:parent", b, 0x00)

	_, err = probe_battery.Compare(parent, nil, b,
		genome_descriptor.DerivationFineTune, b.Policy)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = probe_battery.Compare(nil, parent, b,
		genome_descriptor.DerivationFineTune, b.Policy)
	require.Error(t, err)
}
