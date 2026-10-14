// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func TestTenantID_Validation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in    TenantID
		valid bool
	}{
		{"acme-bank", true},
		{"customer_001", true},
		{"X", true},
		{"a-b-c-d-e-f", true},
		{"a1B2c3D4", true},
		{"", false},
		{"contains spaces", false},
		{"contains/slash", false},
		{"contains.dot", false},
		{"contains:colon", false},
		// 64 valid chars — boundary
		{TenantID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), true},
		// 65 chars — over limit
		{TenantID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), false},
	}
	for _, c := range cases {
		require.Equal(t, c.valid, c.in.IsValid(), "TenantID %q", c.in)
	}
}

func TestTenantKeyID_RoundTrip(t *testing.T) {
	t.Parallel()
	master := ids.KeyID("session-sealing-2026-q1")
	tenant := TenantID("acme-bank")

	derivedKID, err := TenantKeyID(master, tenant, PurposeSealing)
	require.NoError(t, err)
	require.Equal(t, ids.KeyID("session-sealing-2026-q1/tenant/acme-bank/sealing"), derivedKID)

	gotMaster, gotTenant, gotPurpose, ok := ParseTenantKeyID(derivedKID)
	require.True(t, ok)
	require.Equal(t, master, gotMaster)
	require.Equal(t, tenant, gotTenant)
	require.Equal(t, PurposeSealing, gotPurpose)
}

func TestTenantKeyID_RejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	_, err := TenantKeyID("", "acme", PurposeSealing)
	require.Error(t, err, "empty master kid")

	_, err = TenantKeyID("master", "bad/tenant", PurposeSealing)
	require.Error(t, err, "tenant with slash")

	_, err = TenantKeyID("master", "acme", PurposeUnknown)
	require.Error(t, err, "unknown purpose")
}

func TestParseTenantKeyID_NonTenantKid(t *testing.T) {
	t.Parallel()
	_, _, _, ok := ParseTenantKeyID("plain-master-kid")
	require.False(t, ok)

	_, _, _, ok = ParseTenantKeyID("master/something/tenant/foo")
	require.False(t, ok, "wrong section structure")
}

// ----------------------------------------------------------------------------
// DeriveTenantSealing
// ----------------------------------------------------------------------------

func TestDeriveTenantSealing_Determinism(t *testing.T) {
	t.Parallel()
	store1 := newStore(t)
	store2 := newStore(t)

	masterKID := ids.KeyID("master-sealing")
	masterMat := bytes.Repeat([]byte{0x42}, crypto.AES256KeySize)
	require.NoError(t, store1.RegisterSealing(masterKID, masterMat))
	require.NoError(t, store2.RegisterSealing(masterKID, masterMat))

	tenant := TenantID("acme")
	kid1, err := store1.DeriveTenantSealing(masterKID, tenant)
	require.NoError(t, err)
	kid2, err := store2.DeriveTenantSealing(masterKID, tenant)
	require.NoError(t, err)
	require.Equal(t, kid1, kid2, "derivation MUST be deterministic across stores")

	// Verify the derived material itself is identical: seal under both
	// stores with the same nonce-equivalent (we can't pin the nonce so
	// we test by sealing under store1 and unsealing under store2 — if
	// the keys match, this round-trips).
	pt := []byte("payload")
	aad := []byte("aad")
	nonce, ct, err := store1.Seal(kid1, pt, aad)
	require.NoError(t, err)
	got, err := store2.Open(kid2, nonce, ct, aad)
	require.NoError(t, err)
	require.Equal(t, pt, got)
}

func TestDeriveTenantSealing_Isolation(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	masterKID := ids.KeyID("master-sealing")
	require.NoError(t, store.RegisterSealing(masterKID, bytes.Repeat([]byte{0x77}, 32)))

	kidA, err := store.DeriveTenantSealing(masterKID, TenantID("tenant-A"))
	require.NoError(t, err)
	kidB, err := store.DeriveTenantSealing(masterKID, TenantID("tenant-B"))
	require.NoError(t, err)

	// Tenant A seals; tenant B MUST NOT be able to open.
	pt := []byte("tenant-A-secret")
	nonce, ct, err := store.Seal(kidA, pt, []byte("aad"))
	require.NoError(t, err)
	_, err = store.Open(kidB, nonce, ct, []byte("aad"))
	require.Error(t, err, "tenant B's key MUST NOT decrypt tenant A's ciphertext")
}

func TestDeriveTenantSealing_DistinctFromMaster(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	masterKID := ids.KeyID("master")
	require.NoError(t, store.RegisterSealing(masterKID, bytes.Repeat([]byte{0xAA}, 32)))
	tenantKID, err := store.DeriveTenantSealing(masterKID, TenantID("tenant"))
	require.NoError(t, err)

	// Master encrypts; tenant key MUST NOT decrypt (no key reuse).
	pt := []byte("master-only")
	nonce, ct, err := store.Seal(masterKID, pt, []byte("aad"))
	require.NoError(t, err)
	_, err = store.Open(tenantKID, nonce, ct, []byte("aad"))
	require.Error(t, err)
}

func TestDeriveTenantSealing_RejectsUnknownMaster(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	_, err := store.DeriveTenantSealing("nonexistent", TenantID("tenant"))
	require.Error(t, err)
}

func TestDeriveTenantSealing_RejectsDuplicate(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	masterKID := ids.KeyID("master")
	require.NoError(t, store.RegisterSealing(masterKID, bytes.Repeat([]byte{0x33}, 32)))
	_, err := store.DeriveTenantSealing(masterKID, TenantID("tenant"))
	require.NoError(t, err)
	_, err = store.DeriveTenantSealing(masterKID, TenantID("tenant"))
	require.Error(t, err, "second derivation MUST fail (re-use EnsureTenantSealing for idempotency)")
}

func TestEnsureTenantSealing_Idempotent(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	masterKID := ids.KeyID("master")
	require.NoError(t, store.RegisterSealing(masterKID, bytes.Repeat([]byte{0x88}, 32)))
	tenant := TenantID("acme")

	kid1, err := store.EnsureTenantSealing(masterKID, tenant)
	require.NoError(t, err)
	kid2, err := store.EnsureTenantSealing(masterKID, tenant)
	require.NoError(t, err, "second Ensure MUST succeed (idempotent)")
	require.Equal(t, kid1, kid2)
}

// ----------------------------------------------------------------------------
// DeriveTenantSigning
// ----------------------------------------------------------------------------

func TestDeriveTenantSigning_Determinism(t *testing.T) {
	t.Parallel()
	store1 := newStore(t)
	store2 := newStore(t)

	masterKID := ids.KeyID("master-signing")
	seed := bytes.Repeat([]byte{0x91}, crypto.Ed25519SeedSize)
	_, err := store1.RegisterSigningFromSeed(masterKID, PurposeSigningAuthority, seed)
	require.NoError(t, err)
	_, err = store2.RegisterSigningFromSeed(masterKID, PurposeSigningAuthority, seed)
	require.NoError(t, err)

	vk1, err := store1.DeriveTenantSigning(masterKID, TenantID("acme"), PurposeSigningAuthority)
	require.NoError(t, err)
	vk2, err := store2.DeriveTenantSigning(masterKID, TenantID("acme"), PurposeSigningAuthority)
	require.NoError(t, err)
	require.Equal(t, vk1.PublicKey, vk2.PublicKey, "derivation MUST be deterministic")
	require.Equal(t, vk1.KeyID, vk2.KeyID)
}

func TestDeriveTenantSigning_Isolation(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	masterKID := ids.KeyID("master-signing")
	seed := bytes.Repeat([]byte{0x44}, crypto.Ed25519SeedSize)
	_, err := store.RegisterSigningFromSeed(masterKID, PurposeSigningAuthority, seed)
	require.NoError(t, err)

	vkA, err := store.DeriveTenantSigning(masterKID, TenantID("tenant-A"), PurposeSigningAuthority)
	require.NoError(t, err)
	vkB, err := store.DeriveTenantSigning(masterKID, TenantID("tenant-B"), PurposeSigningAuthority)
	require.NoError(t, err)
	require.NotEqual(t, vkA.PublicKey, vkB.PublicKey, "tenants MUST get distinct signing keys")

	// Tenant A signs; tenant B's verifying key MUST NOT verify.
	msg := []byte("attestation-bytes")
	sig, err := store.Sign(vkA.KeyID, PurposeSigningAuthority, msg)
	require.NoError(t, err)
	require.NoError(t, crypto.Verify(vkA.PublicKey, msg, sig))
	require.Error(t, crypto.Verify(vkB.PublicKey, msg, sig))
}

func TestDeriveTenantSigning_DistinctPurposes(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	masterKID := ids.KeyID("master-signing")
	seed := bytes.Repeat([]byte{0x66}, crypto.Ed25519SeedSize)
	_, err := store.RegisterSigningFromSeed(masterKID, PurposeSigningAuthority, seed)
	require.NoError(t, err)

	vkAuth, err := store.DeriveTenantSigning(masterKID, TenantID("acme"), PurposeSigningAuthority)
	require.NoError(t, err)
	vkAudit, err := store.DeriveTenantSigning(masterKID, TenantID("acme"), PurposeSigningAudit)
	require.NoError(t, err)
	require.NotEqual(t, vkAuth.PublicKey, vkAudit.PublicKey,
		"different purposes within the same tenant MUST produce distinct keys")
}

func TestDeriveTenantSigning_RejectsNonSigningPurpose(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	_, err := store.DeriveTenantSigning("master", TenantID("acme"), PurposeSealing)
	require.Error(t, err)
}

func TestEnsureTenantSigning_Idempotent(t *testing.T) {
	t.Parallel()
	store := newStore(t)
	masterKID := ids.KeyID("master-signing")
	seed := bytes.Repeat([]byte{0x77}, crypto.Ed25519SeedSize)
	_, err := store.RegisterSigningFromSeed(masterKID, PurposeSigningAuthority, seed)
	require.NoError(t, err)

	tenant := TenantID("acme")
	vk1, err := store.EnsureTenantSigning(masterKID, tenant, PurposeSigningAuthority)
	require.NoError(t, err)
	vk2, err := store.EnsureTenantSigning(masterKID, tenant, PurposeSigningAuthority)
	require.NoError(t, err, "second Ensure MUST succeed")
	require.Equal(t, vk1.PublicKey, vk2.PublicKey)
}

// Integration: full multi-tenant sealing scenario.
func TestMultiTenant_FullScenario(t *testing.T) {
	t.Parallel()
	store := newStore(t)

	// One master sealing key, three tenants sharing the vault.
	master := ids.KeyID("vault-master-sealing-2026")
	require.NoError(t, store.RegisterSealing(master, bytes.Repeat([]byte{0x12}, 32)))

	tenants := []TenantID{"bank-of-elbonia", "memorial-hospital", "research-lab-zeta"}
	tenantKIDs := make(map[TenantID]ids.KeyID)
	for _, tn := range tenants {
		kid, err := store.DeriveTenantSealing(master, tn)
		require.NoError(t, err)
		tenantKIDs[tn] = kid
	}

	// Each tenant seals a payload; round-trips against its own key only.
	for _, tn := range tenants {
		kid := tenantKIDs[tn]
		pt := append([]byte("payload-for-"), []byte(tn)...)
		aad := []byte("session=demo")
		nonce, ct, err := store.Seal(kid, pt, aad)
		require.NoError(t, err)
		got, err := store.Open(kid, nonce, ct, aad)
		require.NoError(t, err)
		require.Equal(t, pt, got)

		// Cross-tenant attempt MUST fail.
		for _, otherTn := range tenants {
			if otherTn == tn {
				continue
			}
			otherKID := tenantKIDs[otherTn]
			_, err := store.Open(otherKID, nonce, ct, aad)
			require.Error(t, err, "tenant %s MUST NOT open tenant %s ciphertext", otherTn, tn)
		}
	}
}
