// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_manifest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// unencodableTime lies outside the year range RFC 3339 can express, so
// the canonical encoder refuses it. Validate accepts it as a deadline
// (it is not the zero time and it is after issued_at), which is what
// reaches the encoder's refusal.
var unencodableTime = time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

// A manifest whose deadline the canonical encoder cannot express has no
// cover-bytes and cannot be signed: Validate accepts the time, and the
// refusal comes from the encoder in both CanonicalBytes and SignWith, as
// Structural with the field code. The manifest stays unsigned.
func TestBootstrapManifest_UnencodableDeadline_RefusedByEncoder(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvStore(t, kid)

	b := validFixture()
	b.Deadline = unencodableTime
	require.NoError(t, b.Validate())
	out, err := b.CanonicalBytes()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.Nil(t, out)
	require.ErrorContains(t, err, "bootstrap_manifest: canonical encode failed")

	b = validFixture()
	b.Deadline = unencodableTime
	b.SigningKeyID = kid
	b.Signature = nil
	err = b.SignWith(store)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	require.ErrorContains(t, err, "bootstrap_manifest: canonical encode failed")
	require.Empty(t, b.Signature)

	// The same manifest with an expressible deadline signs under the key it names.
	b.Deadline = validFixture().Deadline
	require.NoError(t, b.SignWith(store))
	require.NoError(t, b.VerifySignature(store))
}
