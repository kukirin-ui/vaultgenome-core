// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

// Property-based tests for the multi-tenant key derivation surface.
//
// Where the example-based tests in tenant_test.go exercise specific
// (master, tenant, purpose) triples, the property tests below
// universally quantify over the input space — testing/quick generates
// hundreds of random inputs per property and asserts the invariant
// holds for every one of them.
//
// Why this matters: example tests prove the code works on the cases
// the author thought to write. Property tests prove the code's
// *invariants* — the things that must be true regardless of input.
// Mutation testing complements both: it asks "do the tests fail when
// the code is wrong?".
//
// Library choice: stdlib testing/quick rather than pgregory.net/rapid.
// quick lacks shrinking but is dependency-free; the dependency policy
// in go.mod requires a docs/dependencies/<name>.md file for new deps,
// and the marginal value of shrinking did not warrant the process for
// this use case. If we hit a property bug whose minimal counterexample
// is hard to find, we'll reconsider rapid as a follow-up.

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// quickConfig sets a higher-than-default sample size; default is 100,
// we use 200 so every property exercises ~5x more terrain than the
// example tests.
var quickConfig = &quick.Config{MaxCount: 200}

// generableTenant wraps TenantID with a quick.Generator that produces
// only well-formed IDs. Without this, quick generates random byte
// strings (most invalid) and the property never gets a chance to
// observe the well-formed-input invariants we want to check.
type generableTenant struct {
	ID TenantID
}

func (generableTenant) Generate(r *rand.Rand, _ int) reflect.Value {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	// Length 1..32 — exercises the boundary range without hitting the
	// 64-byte upper limit on every test (which would slow generation
	// without adding coverage).
	n := 1 + r.Intn(32)
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = alphabet[r.Intn(len(alphabet))]
	}
	return reflect.ValueOf(generableTenant{ID: TenantID(buf)})
}

// generableMasterKID generates a sealing-master KeyID. The format is
// arbitrary (any non-empty alphanumeric string up to 32 chars).
type generableMasterKID struct {
	KID ids.KeyID
}

func (generableMasterKID) Generate(r *rand.Rand, _ int) reflect.Value {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
	n := 1 + r.Intn(32)
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = alphabet[r.Intn(len(alphabet))]
	}
	return reflect.ValueOf(generableMasterKID{KID: ids.KeyID(buf)})
}

// generableMaterial generates a 32-byte (AES-256-sized) random
// pseudorandom byte slice for use as master sealing material.
type generableMaterial struct {
	Bytes []byte
}

func (generableMaterial) Generate(r *rand.Rand, _ int) reflect.Value {
	out := make([]byte, crypto.AES256KeySize)
	r.Read(out)
	return reflect.ValueOf(generableMaterial{Bytes: out})
}

// ----------------------------------------------------------------------------
// Properties of TenantKeyID / ParseTenantKeyID round-trip
// ----------------------------------------------------------------------------

// Property: format → parse round-trips for every well-formed
// (master, tenant, purpose).
func TestProperty_TenantKeyID_RoundTrip(t *testing.T) {
	t.Parallel()
	purposes := []Purpose{
		PurposeSigningAuthority, PurposeSigningAudit,
		PurposeSigningWitness, PurposeSealing,
	}
	prop := func(m generableMasterKID, tn generableTenant, pIdx uint8) bool {
		purpose := purposes[int(pIdx)%len(purposes)]
		kid, err := TenantKeyID(m.KID, tn.ID, purpose)
		if err != nil {
			return false
		}
		gotMaster, gotTenant, gotPurpose, ok := ParseTenantKeyID(kid)
		if !ok {
			t.Logf("Parse failed for kid=%q", kid)
			return false
		}
		return gotMaster == m.KID && gotTenant == tn.ID && gotPurpose == purpose
	}
	if err := quick.Check(prop, quickConfig); err != nil {
		t.Error(err)
	}
}

// Property: distinct (tenant, purpose) pairs ALWAYS produce distinct
// derived KIDs. This is the canonical-form invariant the encoding
// must preserve.
func TestProperty_TenantKeyID_NoCollisions(t *testing.T) {
	t.Parallel()
	master := ids.KeyID("collision-test-master")
	prop := func(tnA, tnB generableTenant) bool {
		// Skip cases where tenant IDs are equal — they SHOULD collide.
		if tnA.ID == tnB.ID {
			return true
		}
		kidA, errA := TenantKeyID(master, tnA.ID, PurposeSealing)
		kidB, errB := TenantKeyID(master, tnB.ID, PurposeSealing)
		if errA != nil || errB != nil {
			return false
		}
		return kidA != kidB
	}
	if err := quick.Check(prop, quickConfig); err != nil {
		t.Error(err)
	}
}

// ----------------------------------------------------------------------------
// Properties of DeriveTenantSealing
// ----------------------------------------------------------------------------

// Property: deriving the same (master, material, tenant) on two fresh
// stores produces byte-identical material — i.e., derivation is a
// pure function of inputs, no hidden state.
func TestProperty_DeriveTenantSealing_Deterministic(t *testing.T) {
	t.Parallel()
	prop := func(masterKID generableMasterKID, mat generableMaterial, tn generableTenant) bool {
		s1 := newPropStore(t)
		s2 := newPropStore(t)
		if err := s1.RegisterSealing(masterKID.KID, mat.Bytes); err != nil {
			return true // unrelated registration error; skip
		}
		if err := s2.RegisterSealing(masterKID.KID, mat.Bytes); err != nil {
			return true
		}
		_, err1 := s1.DeriveTenantSealing(masterKID.KID, tn.ID)
		_, err2 := s2.DeriveTenantSealing(masterKID.KID, tn.ID)
		if err1 != nil || err2 != nil {
			return false
		}
		// Compare the actual derived material via cross-store decrypt:
		// if encryption under one and decryption under the other
		// round-trips, the keys are bit-identical.
		derivedKID1, _ := TenantKeyID(masterKID.KID, tn.ID, PurposeSealing)
		derivedKID2, _ := TenantKeyID(masterKID.KID, tn.ID, PurposeSealing)
		pt := []byte("property-payload")
		aad := []byte("property-aad")
		nonce, ct, err := s1.Seal(derivedKID1, pt, aad)
		if err != nil {
			return false
		}
		got, err := s2.Open(derivedKID2, nonce, ct, aad)
		if err != nil {
			return false
		}
		return bytes.Equal(got, pt)
	}
	if err := quick.Check(prop, quickConfig); err != nil {
		t.Error(err)
	}
}

// Property: different tenants ALWAYS get distinct sealing keys (tenant
// isolation). A round-tripped ciphertext under tenant A's key MUST NOT
// open under tenant B's key.
func TestProperty_DeriveTenantSealing_Isolation(t *testing.T) {
	t.Parallel()
	masterKID := ids.KeyID("isolation-property-master")
	masterMat := bytes.Repeat([]byte{0x77}, crypto.AES256KeySize)

	prop := func(tnA, tnB generableTenant) bool {
		if tnA.ID == tnB.ID {
			return true // not the property's domain
		}
		s := newPropStore(t)
		if err := s.RegisterSealing(masterKID, masterMat); err != nil {
			return false
		}
		kidA, errA := s.DeriveTenantSealing(masterKID, tnA.ID)
		kidB, errB := s.DeriveTenantSealing(masterKID, tnB.ID)
		if errA != nil || errB != nil {
			return false
		}
		// Tenant A seals; tenant B's key MUST fail to open.
		pt := []byte("isolation-payload")
		aad := []byte("isolation-aad")
		nonce, ct, err := s.Seal(kidA, pt, aad)
		if err != nil {
			return false
		}
		_, err = s.Open(kidB, nonce, ct, aad)
		return err != nil // we WANT the open to fail
	}
	if err := quick.Check(prop, quickConfig); err != nil {
		t.Error(err)
	}
}

// ----------------------------------------------------------------------------
// Properties of HKDF-derived material
// ----------------------------------------------------------------------------

// Property: HKDFExpand-prefix property — the first L bytes of a
// length-N derivation equal the result of a length-L derivation with
// the same (PRK, info). RFC 5869 §2.3 makes this an explicit guarantee
// of the spec; encoding it as a property catches regressions that
// would silently break key-extension scenarios.
func TestProperty_HKDFSHA256_PrefixStable(t *testing.T) {
	t.Parallel()
	prop := func(prkBytes [32]byte, info []byte, lenShort uint8, lenLong uint8) bool {
		ls := int(lenShort) + 1    // 1..256
		ll := int(lenLong)*2 + 256 // 256..768
		if ll <= ls {
			return true // skip; need ll > ls
		}
		short, err := crypto.HKDFSHA256(nil, prkBytes[:], info, ls)
		if err != nil {
			return false
		}
		long, err := crypto.HKDFSHA256(nil, prkBytes[:], info, ll)
		if err != nil {
			return false
		}
		return bytes.Equal(short, long[:ls])
	}
	if err := quick.Check(prop, quickConfig); err != nil {
		t.Error(err)
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func newPropStore(t *testing.T) *InMemoryStore {
	t.Helper()
	return NewInMemoryStore(shared_time.NewSystemClock())
}

// Compile-time check that our generables produce the right type
// (catches a refactor that breaks the Generate signature).
var _ = func() {
	var _ = generableTenant{}.Generate
	var _ = generableMasterKID{}.Generate
	var _ = generableMaterial{}.Generate
	_ = fmt.Sprintf // import sentinel
}
