// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_message

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

func newAuthStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

func TestDisclosureMessage_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)

	d := validFixture()
	d.SigningKeyID = kid
	d.Signature = nil

	require.NoError(t, d.SignWith(store))
	require.NotEmpty(t, d.Signature)

	require.NoError(t, d.VerifySignature(store))
}

func TestDisclosureMessage_VerifySignature_TamperedSealedPayloadRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)

	d := validFixture()
	d.SigningKeyID = kid
	d.Signature = nil
	require.NoError(t, d.SignWith(store))

	// Flip the ciphertext after signing — the authority signature must
	// no longer verify.
	d.SealedPayload[0] ^= 0xFF
	err := d.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// TestDisclosureMessage_VerifySignature_FlippedSignatureRejected covers
// the adversary vector where the envelope (cover-bytes) is UNTOUCHED but
// the signature field itself has been tampered with: a single bit is
// flipped. Ed25519 is deterministic and fully bound to the cover-bytes,
// so any perturbation of the signature must be detected and classified
// as Integrity. This is the complementary case to the tampered-ciphertext
// test above; together they cover both sides of the authority contract.
//
// Also exercised: empty Signature and truncated Signature — both must
// be rejected. A resolver that accepted either would defeat the whole
// point of signing. The test is deliberately exhaustive because a
// silent no-op here would convert the doctrine "no unsigned
// disclosure leaves the vault" into an empty assertion.
func TestDisclosureMessage_VerifySignature_FlippedSignatureRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-key-1")
	store := newAuthStore(t, kid)

	// Flipped-bit case.
	d := validFixture()
	d.SigningKeyID = kid
	d.Signature = nil
	require.NoError(t, d.SignWith(store))
	require.NotEmpty(t, d.Signature)

	// Preserve the original and flip exactly one bit of the first byte.
	// Ed25519 signatures are 64 bytes; a single-bit flip is guaranteed
	// to invalidate the signature under the same public key and
	// cover-bytes.
	d.Signature[0] ^= 0x01
	err := d.VerifySignature(store)
	require.Error(t, err,
		"bit-flipped signature must fail VerifySignature")
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
		"bit-flipped signature must classify as Integrity, got %s",
		shared_errors.CategoryOf(err))

	// Empty-signature case.
	d2 := validFixture()
	d2.SigningKeyID = kid
	d2.Signature = nil
	require.NoError(t, d2.SignWith(store))
	d2.Signature = nil
	err = d2.VerifySignature(store)
	require.Error(t, err, "empty signature must fail VerifySignature")

	// Truncated-signature case — slice off the tail.
	d3 := validFixture()
	d3.SigningKeyID = kid
	d3.Signature = nil
	require.NoError(t, d3.SignWith(store))
	d3.Signature = d3.Signature[:len(d3.Signature)-1]
	err = d3.VerifySignature(store)
	require.Error(t, err, "truncated signature must fail VerifySignature")
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
		"truncated signature must classify as Integrity")
}

// A verifier handed no key resolver is a malformed call, refused up front
// as Structural — never a nil dereference inside the signature check.
func TestDisclosureMessage_VerifySignature_NilResolverRefused(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("nil-resolver-key")
	store := newAuthStore(t, kid)
	d := validFixture()
	d.SigningKeyID = kid
	d.Signature = nil
	require.NoError(t, d.SignWith(store))

	err := d.VerifySignature(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.NoError(t, d.VerifySignature(store))
}
