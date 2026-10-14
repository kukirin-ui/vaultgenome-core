// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/transport"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// TestKeyStoreOpener proves the adapter refuses to run without a sealer
// and otherwise opens exactly what the same keystore sealed.
func TestKeyStoreOpener(t *testing.T) {
	t.Parallel()
	_, err := KeyStoreOpener{}.Open("kid", []byte("n"), []byte("c"), nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "Sealer not set")

	store := keys.NewInMemoryStore(shared_time.NewFakeClock(time.Unix(0, 0)))
	require.NoError(t, store.GenerateSealing("recipient-1"))
	nonce, ct, err := store.Seal("recipient-1", []byte("plaintext"), []byte("aad"))
	require.NoError(t, err)
	pt, err := KeyStoreOpener{Sealer: store}.Open("recipient-1", nonce, ct, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("plaintext"), pt)
	_, err = KeyStoreOpener{Sealer: store}.Open("recipient-1", nonce, ct, []byte("other-aad"))
	require.Error(t, err, "material bound to other context does not open")
}

// TestSafeCode proves the reject reason is the error's own code when it
// has one and the reconstruct-failure code otherwise, nil included.
func TestSafeCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, CodeReconstructFailure},
		{"unclassified", errors.New("plain"), CodeReconstructFailure},
		{"classified", shared_errors.Authority("policy_denied", "no", nil), "policy_denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, safeCode(tc.err))
		})
	}
}

// TestShortMessage proves the human message is the error text capped at
// 256 bytes, and empty for no error.
func TestShortMessage(t *testing.T) {
	t.Parallel()
	require.Equal(t, "", shortMessage(nil))
	require.Equal(t, "short", shortMessage(errors.New("short")))
	long := strings.Repeat("x", 300)
	got := shortMessage(errors.New(long))
	require.Len(t, got, 256)
	require.Equal(t, long[:256], got)
}

// TestManifestFromJobRequest proves the projection carries exactly the
// wire-visible fields and leaves the rest zero.
func TestManifestFromJobRequest(t *testing.T) {
	t.Parallel()
	issued := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	req := transport.JobRequest{
		ManifestID: "m-1", SessionID: "s-1", ExpectedOutputKind: string(rjm.OutputKindBytesFixedLength),
		ExpectedOutputMaxBytes: 99, Deadline: issued.Add(time.Minute), IssuedAt: issued,
	}
	got := manifestFromJobRequest(req)
	require.Equal(t, rjm.ReconstructionJobManifest{
		SchemaVersion: rjm.SchemaVersionCurrent, ManifestID: "m-1", SessionID: "s-1",
		ExpectedOutputKind: rjm.OutputKindBytesFixedLength, ExpectedOutputMaxBytes: 99,
		Deadline: issued.Add(time.Minute), IssuedAt: issued,
	}, got)
	require.Empty(t, got.GenomeID)
	require.Empty(t, got.DisclosureIDs)
	require.Empty(t, got.Signature)
}

// TestMaterialComponentID proves the synthesized IDs are 64 lowercase
// hex characters, stable for the same job and slot, and distinct across
// slots and jobs, including jobs whose IDs share a prefix.
func TestMaterialComponentID(t *testing.T) {
	t.Parallel()
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	a0 := materialComponentID("manifest-a", 0)
	require.Regexp(t, hex64, string(a0))
	require.Equal(t, a0, materialComponentID("manifest-a", 0))
	require.NotEqual(t, a0, materialComponentID("manifest-a", 1))
	require.NotEqual(t, a0, materialComponentID("manifest-b", 0))
	require.NotEqual(t, materialComponentID("ab", 0), materialComponentID("a", 0), "the length prefix keeps prefixes apart")
}
