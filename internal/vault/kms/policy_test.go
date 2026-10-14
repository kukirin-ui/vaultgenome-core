// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func makeMeasurement(b byte) []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = b
	}
	return m
}

func TestAllowListPolicy_ConstructorRequiresVersion(t *testing.T) {
	t.Parallel()
	_, err := NewAllowListPolicy("", map[tee.Provider][][]byte{})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestAllowListPolicy_ConstructorRejectsBadMeasurementSize(t *testing.T) {
	t.Parallel()
	_, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{
		tee.ProviderAWSNitro: {[]byte{1, 2, 3}},
	})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestAllowListPolicy_AuthorizedMatch(t *testing.T) {
	t.Parallel()
	measurement := makeMeasurement(0x42)
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{
		tee.ProviderAWSNitro: {measurement},
	})
	require.NoError(t, err)
	v, err := p.AuthorizeKeyRelease(tee.ProviderAWSNitro, measurement, ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
	require.NoError(t, err)
	require.True(t, v.Authorized)
	require.Contains(t, v.Reason, "allow-list match")
}

func TestAllowListPolicy_DeniesUnknownKind(t *testing.T) {
	t.Parallel()
	measurement := makeMeasurement(0x42)
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{
		tee.ProviderAWSNitro: {measurement},
	})
	require.NoError(t, err)
	v, err := p.AuthorizeKeyRelease(tee.ProviderGCPSEVSNP, measurement, ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
	require.NoError(t, err)
	require.False(t, v.Authorized)
	require.Contains(t, v.Reason, "no allow-list entries")
}

func TestAllowListPolicy_DeniesMeasurementMismatch(t *testing.T) {
	t.Parallel()
	allowed := makeMeasurement(0x42)
	other := makeMeasurement(0x99)
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{
		tee.ProviderAWSNitro: {allowed},
	})
	require.NoError(t, err)
	v, err := p.AuthorizeKeyRelease(tee.ProviderAWSNitro, other, ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
	require.NoError(t, err)
	require.False(t, v.Authorized)
	require.Contains(t, v.Reason, "not in allow-list")
}

func TestAllowListPolicy_RequiresKind(t *testing.T) {
	t.Parallel()
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{tee.ProviderAWSNitro: {makeMeasurement(0x42)}})
	require.NoError(t, err)
	_, err = p.AuthorizeKeyRelease("", makeMeasurement(0x42), ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestAllowListPolicy_RequiresMeasurementSize(t *testing.T) {
	t.Parallel()
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{tee.ProviderAWSNitro: {makeMeasurement(0x42)}})
	require.NoError(t, err)
	_, err = p.AuthorizeKeyRelease(tee.ProviderAWSNitro, []byte{1, 2, 3}, ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestAllowListPolicy_RequiresDecisionID(t *testing.T) {
	t.Parallel()
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{tee.ProviderAWSNitro: {makeMeasurement(0x42)}})
	require.NoError(t, err)
	_, err = p.AuthorizeKeyRelease(tee.ProviderAWSNitro, makeMeasurement(0x42), "", []ids.KeyID{"k1"})
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestAllowListPolicy_RequiresKeyIDs(t *testing.T) {
	t.Parallel()
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{tee.ProviderAWSNitro: {makeMeasurement(0x42)}})
	require.NoError(t, err)
	_, err = p.AuthorizeKeyRelease(tee.ProviderAWSNitro, makeMeasurement(0x42), ids.DecisionID("dec-1"), nil)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestAllowListPolicy_PolicyVersion(t *testing.T) {
	t.Parallel()
	p, err := NewAllowListPolicy("xcc-policy-2026-05-09", map[tee.Provider][][]byte{tee.ProviderAWSNitro: {makeMeasurement(0x42)}})
	require.NoError(t, err)
	require.Equal(t, "xcc-policy-2026-05-09", p.PolicyVersion())
	var nilP *AllowListPolicy
	require.Equal(t, "", nilP.PolicyVersion())
}

func TestAllowListPolicy_MultipleEntriesForSameKind(t *testing.T) {
	t.Parallel()
	m1 := makeMeasurement(0x01)
	m2 := makeMeasurement(0x02)
	m3 := makeMeasurement(0x03)
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{
		tee.ProviderAWSNitro: {m1, m2, m3},
	})
	require.NoError(t, err)
	for _, m := range [][]byte{m1, m2, m3} {
		v, err := p.AuthorizeKeyRelease(tee.ProviderAWSNitro, m, ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
		require.NoError(t, err)
		require.True(t, v.Authorized)
	}
	other := makeMeasurement(0x04)
	v, err := p.AuthorizeKeyRelease(tee.ProviderAWSNitro, other, ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
	require.NoError(t, err)
	require.False(t, v.Authorized)
}

// Hardware measurements (SEV-SNP MEASUREMENT, Nitro PCR0: 48 bytes) are
// allow-listed and matched whole; a 32-byte prefix of one is not it.
func TestAllowListPolicy_HardwareMeasurementsMatchWhole(t *testing.T) {
	t.Parallel()
	m48 := make([]byte, 48)
	for i := range m48 {
		m48[i] = byte(i)
	}
	p, err := NewAllowListPolicy("v1", map[tee.Provider][][]byte{tee.ProviderGCPSEVSNP: {m48}})
	require.NoError(t, err)

	v, err := p.AuthorizeKeyRelease(tee.ProviderGCPSEVSNP, m48, ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
	require.NoError(t, err)
	require.True(t, v.Authorized)

	v, err = p.AuthorizeKeyRelease(tee.ProviderGCPSEVSNP, m48[:32], ids.DecisionID("dec-1"), []ids.KeyID{"k1"})
	require.NoError(t, err)
	require.False(t, v.Authorized, "a truncated measurement must not match")

	_, err = NewAllowListPolicy("v1", map[tee.Provider][][]byte{tee.ProviderGCPSEVSNP: {make([]byte, 33)}})
	require.Error(t, err)
}
