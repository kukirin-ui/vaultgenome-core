// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe_battery_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/probe_battery"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// repeat is a test helper producing an N-byte slice with a fixed pattern.
// Bound to test-only so we can construct stable 32-byte hashes without
// actually running SHA-256 in each assertion.
func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestProbe_DeriveID_DeterministicAndContentAddressed(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindIdentity,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: repeat(0x22, crypto.HashSize),
		Label:             "identity-core-001",
	}
	id1, err := p.DeriveID()
	require.NoError(t, err)
	id2, err := p.DeriveID()
	require.NoError(t, err)
	require.Equal(t, id1, id2, "DeriveID must be deterministic")
	require.True(t, strings.HasPrefix(id1.String(), probe_battery.ProbeIDPrefix),
		"ID must carry the prb: prefix")
	require.Greater(t, len(id1.String()), len(probe_battery.ProbeIDPrefix),
		"ID must have a hex body after the prefix")
}

func TestProbe_DeriveID_ChangesOnContent(t *testing.T) {
	t.Parallel()
	base := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindIdentity,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: repeat(0x22, crypto.HashSize),
		Label:             "base",
	}
	baseID, err := base.DeriveID()
	require.NoError(t, err)

	cases := []struct {
		name string
		mut  func(p *probe_battery.Probe)
	}{
		{"kind changes ID", func(p *probe_battery.Probe) {
			p.Kind = probe_battery.ProbeKindCapability
		}},
		{"input_hash changes ID", func(p *probe_battery.Probe) {
			p.InputHash = repeat(0x99, crypto.HashSize)
		}},
		{"expected_shape_hash changes ID", func(p *probe_battery.Probe) {
			p.ExpectedShapeHash = repeat(0x77, crypto.HashSize)
		}},
		{"label changes ID", func(p *probe_battery.Probe) {
			p.Label = "different"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := base
			// Preserve slice independence.
			mutated.InputHash = append([]byte(nil), base.InputHash...)
			mutated.ExpectedShapeHash = append([]byte(nil), base.ExpectedShapeHash...)
			tc.mut(&mutated)
			mutID, err := mutated.DeriveID()
			require.NoError(t, err)
			require.NotEqual(t, baseID, mutID, tc.name)
		})
	}
}

func TestProbe_Validate_RejectsUnknownKind(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKind("bogus"),
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: repeat(0x22, crypto.HashSize),
	}
	_, err := p.DeriveID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestProbe_Validate_RejectsWrongHashSize(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindCapability,
		InputHash:         repeat(0x11, 16), // wrong size
		ExpectedShapeHash: nil,
	}
	_, err := p.DeriveID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestProbe_Validate_IdentityRequiresShape(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindIdentity,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: nil,
	}
	_, err := p.DeriveID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestProbe_Validate_NegativeRequiresShape(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindNegative,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: nil,
	}
	_, err := p.DeriveID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestProbe_Validate_CapabilityAllowsNoShape(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindCapability,
		InputHash:         repeat(0x33, crypto.HashSize),
		ExpectedShapeHash: nil,
	}
	id, err := p.DeriveID()
	require.NoError(t, err)
	p.ID = id
	require.NoError(t, p.Validate())
}

func TestProbe_Validate_RejectsForgedID(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindIdentity,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: repeat(0x22, crypto.HashSize),
		Label:             "legit",
	}
	id, err := p.DeriveID()
	require.NoError(t, err)
	p.ID = id
	require.NoError(t, p.Validate())

	// Mutate the label — the stored ID now disagrees with the derivation.
	p.Label = "forged"
	err = p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestProbe_Validate_RequiresStoredID(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindCapability,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: nil,
	}
	// Did not call DeriveID, so ID is empty.
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestProbe_DeriveID_NilReceiver(t *testing.T) {
	t.Parallel()
	var p *probe_battery.Probe
	_, err := p.DeriveID()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestProbe_CanonicalPreImage_ExcludesID(t *testing.T) {
	t.Parallel()
	// The presence of the stored ID in a probe must not shift the
	// re-derived ID. This is the core property that lets DeriveID be
	// idempotent on already-assigned probes.
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindIdentity,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: repeat(0x22, crypto.HashSize),
		Label:             "stable",
	}
	id1, err := p.DeriveID()
	require.NoError(t, err)
	p.ID = id1
	id2, err := p.DeriveID()
	require.NoError(t, err)
	require.Equal(t, id1, id2,
		"DeriveID must be stable regardless of whether ID is already populated")
}

func TestProbe_IDIsHexBody(t *testing.T) {
	t.Parallel()
	p := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindCapability,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: nil,
	}
	id, err := p.DeriveID()
	require.NoError(t, err)
	body := strings.TrimPrefix(id.String(), probe_battery.ProbeIDPrefix)
	require.Len(t, body, 2*crypto.HashSize)
	// Hex-only.
	for _, c := range body {
		require.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"body must be lowercase hex, got %q", c)
	}
}

func TestProbe_DifferentInputs_DifferentIDs(t *testing.T) {
	t.Parallel()
	// Probes that differ only in a single byte of InputHash must yield
	// distinct IDs under SHA-256's avalanche property.
	pA := probe_battery.Probe{
		Kind:              probe_battery.ProbeKindCapability,
		InputHash:         repeat(0x11, crypto.HashSize),
		ExpectedShapeHash: nil,
	}
	pB := pA
	pB.InputHash = append([]byte(nil), pA.InputHash...)
	pB.InputHash[0] ^= 0x01
	idA, err := pA.DeriveID()
	require.NoError(t, err)
	idB, err := pB.DeriveID()
	require.NoError(t, err)
	require.NotEqual(t, idA, idB)
	require.False(t, bytes.Equal([]byte(idA), []byte(idB)))
}
