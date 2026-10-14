// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstitution_decision

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// unencodableTime lies outside the year range RFC 3339 can express, so
// the canonical encoder refuses it. Validate accepts it (it is not the
// zero time), which is what reaches the encoder's refusal.
var unencodableTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// A decision whose timestamp the canonical encoder cannot express has no
// cover-bytes and cannot be signed: Validate accepts the time, and the
// refusal comes from the encoder in both CanonicalBytes and SignWith, as
// Structural with the field code. The decision stays unsigned.
func TestReconstitutionDecision_UnencodableDecidedAt_RefusedByEncoder(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvAuthStore(t, kid)

	r := validAcceptFixture()
	r.DecidedAt = unencodableTime
	require.NoError(t, r.Validate())
	b, err := r.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, b)
	require.ErrorContains(t, err, "reconstitution_decision: canonical encode failed")

	r = validAcceptFixture()
	r.DecidedAt = unencodableTime
	r.SigningKeyID = kid
	r.Signature = nil
	err = r.SignWith(store)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.ErrorContains(t, err, "reconstitution_decision: canonical encode failed")
	require.Empty(t, r.Signature)

	// The same decision with an expressible time signs under the key it names.
	r.DecidedAt = validAcceptFixture().DecidedAt
	require.NoError(t, r.SignWith(store))
	require.NoError(t, r.VerifySignature(store))
}
