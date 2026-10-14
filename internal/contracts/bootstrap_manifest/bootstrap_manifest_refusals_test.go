// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_manifest

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- required-field matrix -------------------------------------------------

// Each required handle and timestamp is refused on its own, as Structural
// with CodeRequiredFieldMissing — one case per field, so a regression that
// drops a check is pinned to the field it dropped.
func TestBootstrapManifest_Validate_RequiredFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*BootstrapManifest)
	}{
		{"session_id", func(b *BootstrapManifest) { b.SessionID = "" }},
		{"manifest_id", func(b *BootstrapManifest) { b.ManifestID = "" }},
		{"genome_id", func(b *BootstrapManifest) { b.GenomeID = "" }},
		{"policy_version", func(b *BootstrapManifest) { b.PolicyVersion = "" }},
		{"issued_at", func(b *BootstrapManifest) { b.IssuedAt = time.Time{} }},
		{"deadline", func(b *BootstrapManifest) { b.Deadline = time.Time{} }},
		{"signing_key_id", func(b *BootstrapManifest) { b.SigningKeyID = "" }},
		{"signature", func(b *BootstrapManifest) { b.Signature = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			b := validFixture()
			c.mutate(&b)
			err := b.Validate()
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
		})
	}
}

// ---- wire-format gates -----------------------------------------------------

// A second JSON value after the manifest is refused: the decoder consumes
// exactly one value, so nothing rides in behind a well-formed manifest.
func TestBootstrapManifest_UnmarshalJSON_RejectsTrailingContent(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	raw, err := json.Marshal(&orig)
	require.NoError(t, err)
	payload := append(append([]byte{}, raw...), []byte(` null`)...)

	var b BootstrapManifest
	err = b.UnmarshalJSON(payload)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

// The schema gate runs at decode time, not only in Validate: a manifest
// written by a build this one does not understand is refused before any
// other field is interpreted — below the supported range as well as above.
func TestBootstrapManifest_UnmarshalJSON_SchemaVersionOutOfRange(t *testing.T) {
	t.Parallel()
	for _, v := range []int{int(SchemaVersionMin) - 1, int(SchemaVersionMax) + 1} {
		payload := `{"schema_version":` + strconv.Itoa(v) + `}`
		var b BootstrapManifest
		err := b.UnmarshalJSON([]byte(payload))
		require.Error(t, err, payload)
		require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err), payload)
	}
}

// An invalid manifest has no canonical cover-bytes: CanonicalBytes runs
// Validate first and returns its refusal unchanged, with no bytes.
func TestBootstrapManifest_CanonicalBytes_InvalidManifestRefused(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.ManifestID = ""
	out, err := b.CanonicalBytes()
	require.Error(t, err)
	require.Nil(t, out)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// ---- signer and resolver refusals -----------------------------------------

// SignWith asks the signer for b.SigningKeyID under PurposeSigningAuthority
// and passes its refusal through unchanged: a store without that key
// refuses as Authority, a store holding the kid under another purpose as
// Integrity. Either way the manifest stays unsigned.
func TestBootstrapManifest_SignWith_SignerRefusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	at := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)

	t.Run("unknown_key", func(t *testing.T) {
		t.Parallel()
		empty := keys.NewInMemoryStore(shared_time.NewFakeClock(at))
		b := validFixture()
		b.SigningKeyID = kid
		b.Signature = nil
		err := b.SignWith(empty)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
		require.Empty(t, b.Signature)
	})
	t.Run("wrong_purpose", func(t *testing.T) {
		t.Parallel()
		witnessOnly := keys.NewInMemoryStore(shared_time.NewFakeClock(at))
		_, err := witnessOnly.GenerateSigning(kid, keys.PurposeSigningWitness)
		require.NoError(t, err)
		b := validFixture()
		b.SigningKeyID = kid
		b.Signature = nil
		err = b.SignWith(witnessOnly)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
		require.Empty(t, b.Signature)
	})
}

// VerifySignature refuses an unsigned manifest as Structural before it
// touches the resolver: there are no cover-bytes to check, so the refusal
// is a missing field, never a signature mismatch dressed up as Integrity.
func TestBootstrapManifest_VerifySignature_UnsignedManifestRefused(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvStore(t, kid)
	b := validFixture()
	b.SigningKeyID = kid
	b.Signature = nil
	err := b.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// A well-formed, signed manifest verified against the wrong key material
// is refused by the resolver, and the refusal keeps the resolver's class:
// Authority when it does not hold the kid, Integrity when it holds the kid
// under another purpose. The same manifest still verifies under the key
// that signed it.
func TestBootstrapManifest_VerifySignature_ResolverRefusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvStore(t, kid)
	b := validFixture()
	b.SigningKeyID = kid
	b.Signature = nil
	require.NoError(t, b.SignWith(store))

	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	empty := keys.NewInMemoryStore(fc)
	err := b.VerifySignature(empty)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))

	witnessOnly := keys.NewInMemoryStore(fc)
	_, err = witnessOnly.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)
	err = b.VerifySignature(witnessOnly)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	require.NoError(t, b.VerifySignature(store))
}
