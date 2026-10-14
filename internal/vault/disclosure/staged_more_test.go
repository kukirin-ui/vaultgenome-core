// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/disclosure"
)

// The constructor checks that key ids are named, not that the keystore
// holds them. A sealing or signing key the store does not have is found
// at the first emission: nothing is emitted, the counter does not move,
// and the plaintext is wiped all the same.
func TestStagedIssuer_Emit_RefusesKeysTheStoreDoesNotHold(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		signingKID ids.KeyID
		sealingKID ids.KeyID
		want       string
	}{
		{"sealing key missing", kidAuthority, "no-such-sealing-key", "unknown sealing kid"},
		{"signing key missing", "no-such-signing-key", kidSealing, "unknown kid on sign"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newStagedFixture(t)
			iss, err := disclosure.NewStagedIssuer(fx.clock, fx.store, fx.store, fx.store, tc.signingKID, tc.sealingKID,
				fx.session, fx.activePolicy, disclosure.StagedOptions{})
			require.NoError(t, err)

			plaintext := []byte("component bytes")
			msg, err := iss.Emit(disclosure.EmitParams{ComponentID: testCompA, Plaintext: plaintext, RecipientKeyID: testRecipKey})
			require.Nil(t, msg)
			require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
			require.ErrorContains(t, err, tc.want)
			require.True(t, allZero(plaintext), "the plaintext is wiped on a refused emission")
			require.Zero(t, iss.SequenceIndex(), "a refused emission does not advance the sequence")
			require.False(t, iss.IsFinalized())
		})
	}
}
