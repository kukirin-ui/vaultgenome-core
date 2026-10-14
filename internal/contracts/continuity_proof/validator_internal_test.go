// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
)

// isKnownDerivation is the chain gate's own copy of the doctrinal set of
// derivation methods, kept so a relaxation of the embedded AGD gate cannot
// let an unknown method into a descent record unnoticed. The set is closed
// and exact: the five doctrinal methods pass and nothing else does — not
// the empty string, not another case, not a method with whitespace.
func TestIsKnownDerivation_ClosedSet(t *testing.T) {
	t.Parallel()
	for _, m := range []genome_descriptor.DerivationMethod{
		genome_descriptor.DerivationFineTune,
		genome_descriptor.DerivationDistill,
		genome_descriptor.DerivationMerge,
		genome_descriptor.DerivationQuantize,
		genome_descriptor.DerivationReconstruct,
	} {
		require.True(t, isKnownDerivation(m), "%q", string(m))
	}
	for _, m := range []genome_descriptor.DerivationMethod{
		"", "alchemy", "Fine-Tune", "fine-tune ", "fine_tune",
	} {
		require.False(t, isKnownDerivation(m), "%q", string(m))
	}
}

// decStr renders chain indexes for error messages without pulling strconv
// into the contract; it must agree with strconv on every value it could be
// handed, including the sign an index never carries in practice.
func TestDecStr_AgreesWithStrconv(t *testing.T) {
	t.Parallel()
	for _, i := range []int{0, 1, 7, 9, 10, 11, 42, 99, 100, 1234567890, -1, -9, -10, -305} {
		require.Equal(t, strconv.Itoa(i), decStr(i), "decStr(%d)", i)
	}
}
