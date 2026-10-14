// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reassembly_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
	"github.com/vault-genome/vaultgenome-core/internal/reassembly"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// errSealerDown is what the unclassified sealer returns.
var errSealerDown = errors.New("sealing backend unavailable")

// plainErrorSealer is a sealer whose failures carry no classification,
// as a third-party backend's might.
type plainErrorSealer struct{}

func (plainErrorSealer) Seal(ids.KeyID, []byte, []byte) ([]byte, []byte, error) {
	return nil, nil, errSealerDown
}

func (plainErrorSealer) Open(ids.KeyID, []byte, []byte, []byte) ([]byte, error) {
	return nil, errSealerDown
}

// TestNewAGDReassembler_RefusesAnInvalidAGD proves the AGD's own
// validator runs before anything else and its refusal is passed
// through unchanged rather than relabelled as a reassembly fault.
func TestNewAGDReassembler_RefusesAnInvalidAGD(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	h.agd.ComponentTreeRoot = nil
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.Nil(t, r)
	require.Error(t, err)
	require.NotContains(t, shared_errors.CodeOf(err), "reassembly_")
	require.NotEqual(t, shared_errors.CategoryUnknown, shared_errors.CategoryOf(err))
}

// TestNewAGDReassembler_RefusesAMalformedComponentMap proves a map of
// the right size is still refused when an entry has no ComponentID,
// two entries share a path, or an entry cannot be a tree leaf.
func TestNewAGDReassembler_RefusesAMalformedComponentMap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(m reassembly.ComponentMap)
		want   string
	}{
		{
			name: "zero component id",
			mutate: func(m reassembly.ComponentMap) {
				m[""] = m["c-cfg"]
				delete(m, "c-cfg")
			},
			want: "zero ComponentID",
		},
		{
			name:   "duplicate path",
			mutate: func(m reassembly.ComponentMap) { m["c-tok"] = m["c-cfg"] },
			want:   "duplicate path: config/architecture",
		},
		{
			name: "entry that is not a valid leaf",
			mutate: func(m reassembly.ComponentMap) {
				c := m["c-cfg"]
				c.Kind = componenttree.Kind("not-a-kind")
				m["c-cfg"] = c
			},
			want: "does not form a valid tree",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := buildHarness(t, defaultSpecs())
			tc.mutate(h.compMap)
			r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
			require.Nil(t, r)
			require.Error(t, err)
			require.Equal(t, reassembly.CodeComponentMapMismatch, shared_errors.CodeOf(err))
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestAGDReassembler_Admit_RefusesAMalformedEnvelope proves an envelope
// that fails its own validator is refused with the validator's error
// before the sealer is consulted.
func TestAGDReassembler_Admit_RefusesAMalformedEnvelope(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	bad := *h.messages[0]
	bad.Signature = nil
	err = r.Admit(&bad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Contains(t, err.Error(), "disclosure_message: signature required")
	require.NoError(t, r.Admit(h.messages[0]), "the honest envelope is still admissible afterwards")
}

// TestAGDReassembler_Admit_SealerErrorsKeepTheirClass proves a
// classified sealer refusal (here: a recipient key the receive side does
// not hold) is passed through with its own class, while an unclassified
// sealer failure is reported as a sealed-open failure with the cause
// attached.
func TestAGDReassembler_Admit_SealerErrorsKeepTheirClass(t *testing.T) {
	t.Parallel()

	t.Run("unknown recipient key is an authority refusal", func(t *testing.T) {
		t.Parallel()
		h := buildHarness(t, defaultSpecs())
		r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
		require.NoError(t, err)
		bad := *h.messages[0]
		bad.RecipientKeyID = ids.KeyID("recv-seal-unknown")
		err = r.Admit(&bad)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
		require.NotEqual(t, reassembly.CodeSealedOpenFailed, shared_errors.CodeOf(err))
	})

	t.Run("unclassified sealer failure", func(t *testing.T) {
		t.Parallel()
		h := buildHarness(t, defaultSpecs())
		r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, plainErrorSealer{})
		require.NoError(t, err)
		err = r.Admit(h.messages[0])
		require.Error(t, err)
		require.Equal(t, reassembly.CodeSealedOpenFailed, shared_errors.CodeOf(err))
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
		require.ErrorIs(t, err, errSealerDown)
	})
}

// TestAGDReassembler_Finalize_RefusesAnAGDChangedUnderneath proves that
// an AGD whose commitments no longer match what was built at
// construction is refused at Finalize — the rebuilt root and the genome
// ID are both checked again — and that the refusal is final.
func TestAGDReassembler_Finalize_RefusesAnAGDChangedUnderneath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(h *harness)
		code   string
		want   string
	}{
		{
			name:   "tree root",
			mutate: func(h *harness) { h.agd.ComponentTreeRoot = fixedHash(0x33) },
			code:   reassembly.CodeMerkleRootMismatch,
			want:   "diverged",
		},
		{
			name:   "genome id",
			mutate: func(h *harness) { h.agd.GenomeID = ids.GenomeID("agd-substituted") },
			code:   reassembly.CodeGenomeIDRoundTripMismatch,
			want:   "DeriveID() disagrees",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := buildHarness(t, defaultSpecs())
			r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
			require.NoError(t, err)
			for _, m := range h.messages {
				require.NoError(t, r.Admit(m))
			}
			tc.mutate(h)
			res, err := r.Finalize()
			require.Nil(t, res)
			require.Error(t, err)
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
			require.Contains(t, err.Error(), tc.want)
			require.True(t, r.IsFinalized())

			again, err2 := r.Finalize()
			require.Nil(t, again)
			require.Equal(t, err, err2, "the refusal is final")
			err = r.Admit(h.messages[0])
			require.Equal(t, reassembly.CodeReassemblerFinalized, shared_errors.CodeOf(err))
		})
	}
}
