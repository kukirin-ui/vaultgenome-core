// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package genome_descriptor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// newAuthorityStore boots an InMemoryStore with a single authority signing
// key registered under kid. The fake clock keeps CreatedAt deterministic.
func newAuthorityStore(t *testing.T, kid ids.KeyID) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kid, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	return s
}

// producerSequence runs the canonical producer sequence:
//
//	populate → Derive → Sign → Validate
//
// — and returns the fully-populated descriptor bound to kid.
func producerSequence(t *testing.T, store *keys.InMemoryStore, kid ids.KeyID) GenomeDescriptor {
	t.Helper()
	g := genesisFixture()
	g.SigningKeyID = kid

	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id

	require.NoError(t, g.SignWith(store))
	require.NotEmpty(t, g.Signature, "SignWith must populate Signature")

	require.NoError(t, g.Validate())
	return g
}

func TestGenomeDescriptor_SignAndVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newAuthorityStore(t, kid)

	g := producerSequence(t, store, kid)
	require.NoError(t, g.VerifySignature(store))
}

func TestGenomeDescriptor_VerifySignature_TamperedBodyRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newAuthorityStore(t, kid)

	g := producerSequence(t, store, kid)

	// Mutate a covered field post-sign. Two things now go wrong:
	//   (1) the stored GenomeID no longer matches the content-addressed
	//       derivation, so Validate inside VerifySignature trips first,
	//   (2) the signature no longer verifies.
	// Either way the error must classify Integrity.
	g.FamilyName = "adversary-renamed"
	err := g.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestGenomeDescriptor_VerifySignature_TamperedSignatureRejected(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newAuthorityStore(t, kid)

	g := producerSequence(t, store, kid)

	// Flip a single bit of the signature. Body is still self-consistent,
	// so Validate passes; crypto.Verify rejects with Integrity.
	g.Signature[0] ^= 0x01
	err := g.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestGenomeDescriptor_VerifySignature_WrongPurposeRejected(t *testing.T) {
	t.Parallel()
	// A key registered under the AUDIT purpose cannot sign genome
	// descriptors. Resolve must reject the cross-purpose lookup as an
	// Integrity error.
	kid := ids.KeyID("vault-audit-1")
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(fc)
	_, err := store.GenerateSigning(kid, keys.PurposeSigningAudit)
	require.NoError(t, err)

	// Try to sign under the audit key — Signer.Sign rejects the purpose.
	g := genesisFixture()
	g.SigningKeyID = kid
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	err = g.SignWith(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestGenomeDescriptor_VerifySignature_UnknownKeyRejected(t *testing.T) {
	t.Parallel()
	// Sign with a real key, then hand verification a resolver that does
	// not know that key. Resolver returns an Authority-classified error.
	kid := ids.KeyID("vault-auth-1")
	signStore := newAuthorityStore(t, kid)

	g := producerSequence(t, signStore, kid)

	// Empty store — kid not registered.
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	emptyStore := keys.NewInMemoryStore(fc)
	err := g.VerifySignature(emptyStore)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
}

func TestGenomeDescriptor_SignWith_RefusesMissingID(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newAuthorityStore(t, kid)

	g := genesisFixture()
	g.SigningKeyID = kid
	// Deliberately skip DeriveID — the SignWith contract says the ID
	// must be populated first so the signature binds the identity.
	err := g.SignWith(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestGenomeDescriptor_SignWith_RefusesMissingKeyID(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("vault-auth-1")
	store := newAuthorityStore(t, kid)

	g := genesisFixture()
	g.SigningKeyID = ""
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	err = g.SignWith(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestGenomeDescriptor_Signature_IndependentOfPolicyLabelOrder(t *testing.T) {
	t.Parallel()
	// PolicyLabels is a Go map: iteration order is unspecified. The JCS
	// canonical encoder sorts keys, so two descriptors whose maps were
	// populated in different orders must produce the same signature.
	kid := ids.KeyID("vault-auth-1")
	store := newAuthorityStore(t, kid)

	g1 := genesisFixture()
	g1.SigningKeyID = kid
	g1.PolicyLabels = map[string]string{"a": "1", "b": "2", "c": "3"}
	id1, err := g1.DeriveID()
	require.NoError(t, err)
	g1.GenomeID = id1
	require.NoError(t, g1.SignWith(store))

	g2 := genesisFixture()
	g2.SigningKeyID = kid
	// Same content, different insertion order — must yield same bytes.
	g2.PolicyLabels = map[string]string{}
	for _, k := range []string{"c", "a", "b"} {
		g2.PolicyLabels[k] = map[string]string{"a": "1", "b": "2", "c": "3"}[k]
	}
	id2, err := g2.DeriveID()
	require.NoError(t, err)
	g2.GenomeID = id2
	require.NoError(t, g2.SignWith(store))

	require.Equal(t, id1, id2, "GenomeID must be order-independent")
	// Ed25519 signatures are deterministic: same key, same message ⇒
	// same signature bytes. Both messages are the same canonical form.
	require.Equal(t, g1.Signature, g2.Signature, "signature must be deterministic across label-insertion orders")
}
