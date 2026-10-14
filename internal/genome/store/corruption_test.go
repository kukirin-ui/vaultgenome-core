// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// These tests damage the store's backing bytes from inside the package to
// prove the load-time tripwires: a record that no longer decodes, or
// whose content no longer derives the ID it is filed under, is refused as
// an Integrity failure by Get and surfaced unchanged by Each.

func hash32(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

func signedDescriptor(t *testing.T, ks *keys.InMemoryStore, kid ids.KeyID, family string) *genome_descriptor.GenomeDescriptor {
	t.Helper()
	g := &genome_descriptor.GenomeDescriptor{
		SchemaVersion: genome_descriptor.SchemaVersionCurrent,
		FamilyName:    family,
		Kind:          genome_descriptor.KindTransformer,
		Architecture: genome_descriptor.ArchitectureDescriptor{
			Framework:      "pytorch-2.1",
			ModelClass:     "transformer-decoder",
			ParameterCount: 7_000_000_000,
			PrecisionBits:  16,
			ConfigHash:     hash32(0xA1),
		},
		ComponentTreeRoot: hash32(0xB2),
		ComponentCount:    512,
		TotalBytes:        14_000_000_000,
		Provenance: genome_descriptor.ProvenanceRecord{
			ProducerIdentity:   "producer:alpha-lab",
			ProducedAt:         time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC),
			TrainingDataRoot:   hash32(0xC3),
			TrainingRecipeHash: hash32(0xD4),
		},
		BehavioralFingerprint: genome_descriptor.ProbeBatteryRoot{
			BatteryID:            "llm-reasoning-v3",
			BatterySchemaVersion: 1,
			BatteryMerkleRoot:    hash32(0xE5),
			CanonicalScoresRoot:  hash32(0xF6),
			ProbeCount:           256,
			MinPassingScore:      0.85,
		},
		IssuedAt:     time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID: kid,
	}
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	require.NoError(t, g.SignWith(ks))
	return g
}

func populatedStore(t *testing.T) (*InMemoryStore, ids.GenomeID, ids.GenomeID) {
	t.Helper()
	kid := ids.KeyID("vault-auth-1")
	ks := keys.NewInMemoryStore(nil)
	_, err := ks.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	s, err := NewInMemoryStore(ks)
	require.NoError(t, err)
	a, err := s.Put(signedDescriptor(t, ks, kid, "family-a"))
	require.NoError(t, err)
	b, err := s.Put(signedDescriptor(t, ks, kid, "family-b"))
	require.NoError(t, err)
	return s, a, b
}

// TestGet_CorruptedBackingBytesAreIntegrityRefusals proves that Get does
// not return a descriptor whose stored bytes no longer decode, or whose
// content derives an ID other than the one it is filed under.
func TestGet_CorruptedBackingBytesAreIntegrityRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		corrupt func(s *InMemoryStore, a, b ids.GenomeID)
		code    string
		want    string
	}{
		"bytes no longer decode": {
			corrupt: func(s *InMemoryStore, a, _ ids.GenomeID) { s.entries[a] = []byte(`{"schema_version":`) },
			code:    shared_errors.CodeFieldValueInvalid,
			want:    "decode failed",
		},
		"bytes filed under another id": {
			corrupt: func(s *InMemoryStore, a, b ids.GenomeID) { s.entries[a] = s.entries[b] },
			code:    shared_errors.CodeSignatureInvalid,
			want:    "derived ID disagrees",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, a, b := populatedStore(t)
			s.mu.Lock()
			tc.corrupt(s, a, b)
			s.mu.Unlock()

			got, err := s.Get(a)
			require.Error(t, err)
			require.Nil(t, got)
			require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.Contains(t, err.Error(), tc.want)

			untouched, err := s.Get(b)
			require.NoError(t, err)
			require.Equal(t, b, untouched.GenomeID, "the undamaged record still loads")

			err = s.Each(func(ids.GenomeID, *genome_descriptor.GenomeDescriptor) error { return nil })
			require.Error(t, err, "Each surfaces the corruption instead of skipping it")
			require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
		})
	}
}

// TestEach_KeyRemovedDuringIterationIsSkipped proves the documented
// benign case: a key that was in the iteration snapshot but is gone by the
// time it is loaded is skipped, not reported, and the walk completes.
func TestEach_KeyRemovedDuringIterationIsSkipped(t *testing.T) {
	t.Parallel()
	s, a, b := populatedStore(t)
	var visited []ids.GenomeID
	err := s.Each(func(id ids.GenomeID, g *genome_descriptor.GenomeDescriptor) error {
		visited = append(visited, id)
		other := b
		if id == b {
			other = a
		}
		s.mu.Lock()
		delete(s.entries, other)
		s.mu.Unlock()
		require.Equal(t, id, g.GenomeID)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, visited, 1, "the key removed mid-walk is skipped, the walk still completes")
	require.Equal(t, 1, s.Size())
	require.True(t, s.Exists(visited[0]))
}
