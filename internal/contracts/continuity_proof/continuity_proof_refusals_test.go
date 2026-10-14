// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// unencodableTime lies outside the year range RFC 3339 can express, so
// the canonical encoder refuses it. Validate accepts it as issued_at
// (it is not the zero time and it does not predate the witness tree
// head), which is what reaches the encoder's refusal.
var unencodableTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// A receipt for another genome — a real entry of the same witness log,
// included under a signed tree head, committing to exactly the battery
// root and scorecard root the scorecard carries — does not bind: the
// witnessed entry must name the Subject. The receipt passes its own
// gates, so only the cross-binding check can refuse it.
func TestContinuityProof_Validate_WitnessEntryNamesAnotherGenome(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	other := appendAndReceipt(t, f.Log, ids.GenomeID("gen:someone-else"),
		f.AttestationRoot, f.Scorecard.BatteryMerkleRoot, f.Scorecard.MerkleRoot, f.STHTime)
	require.NoError(t, other.Validate(), "the receipt is well formed on its own")

	p := buildProof(t, f)
	p.WitnessReceipt = *other
	err := p.Validate()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent)
	require.ErrorContains(t, err, "witness_receipt.entry.genome_id != subject")
}

// A bundle whose issued_at the canonical encoder cannot express has no
// cover-bytes and cannot be signed: Validate accepts the time, and the
// refusal comes from the encoder in both CanonicalBytes and SignWith, as
// Structural with the field code. The bundle stays unsigned.
func TestContinuityProof_UnencodableIssuedAt_RefusedByEncoder(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	p := buildProof(t, f)
	p.IssuedAt = unencodableTime
	require.NoError(t, p.Validate())
	b, err := p.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "continuity_proof: canonical encode failed")

	p = buildProof(t, f)
	p.IssuedAt = unencodableTime
	p.Signature = nil
	err = p.SignWith(f.Store)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.ErrorContains(t, err, "continuity_proof: canonical encode failed")
	require.Empty(t, p.Signature)
}
