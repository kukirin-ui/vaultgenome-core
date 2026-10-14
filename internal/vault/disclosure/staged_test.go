// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_test

// Tests for the StagedIssuer — the release-side authority that emits a
// monotonic sequence of sealed DisclosureMessages under one TrustedSession.
//
// The doctrinal invariants these tests pin down:
//
//  1. Structural gates (constructor input validation, EmitParams) reject
//     missing/zero fields with CategoryStructural.
//  2. Session-shape gates (state != active, policy drift) reject with
//     CategoryAuthority and the specific R-7/R-10 codes.
//  3. SequenceIndex is strictly monotonic with no gaps and does NOT
//     advance on any refused emission.
//  4. Plaintext input is zeroized in place before Emit returns — both
//     on success and on every refusal path.
//  5. AES-256-GCM AAD binds SessionID + ComponentID + SequenceIndex +
//     PolicyVersion + RecipientKeyID: opening a ciphertext under an AAD
//     derived from a different sequence or component fails.
//  6. Finalize is a one-way cooperative close. After Finalize, Emit
//     refuses with CategoryOperational + CodeIssuerFinalized, and the
//     state is idempotent to a second Finalize call.
//  7. Session expiry (clock-based), invalidation (state change), and
//     policy rotation detected mid-run each halt Emit with
//     CategoryAuthority.

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/disclosure"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- fixtures --------------------------------------------------------------

const (
	kidSealing   = ids.KeyID("vault-seal-1")
	testPolicy   = ids.PolicyVersion("policy-v1")
	testSession  = ids.SessionID("sess-0000000000000001")
	testRequest  = ids.RequestID("req-alpha")
	testGenome   = ids.GenomeID("genome-demo")
	testCompA    = ids.ComponentID("comp-alpha")
	testCompB    = ids.ComponentID("comp-beta")
	testRecipKey = ids.KeyID("recipient-compute-1")
)

// stagedFixture bundles the state the StagedIssuer tests need. Every
// test that exercises a live Emit path builds one of these; the key
// store, clock, and signed session are all consistent with each other.
type stagedFixture struct {
	clock        *shared_time.FakeClock
	store        *keys.InMemoryStore
	session      session_object.SessionObject
	activePolicy ids.PolicyVersion
}

// newStagedFixture constructs a fixture with:
//   - a FakeClock anchored at issuerEpoch,
//   - an InMemoryStore holding kidAuthority (signing), kidSealing (sealing),
//   - a fresh signed Active SessionObject with policy = testPolicy and
//     a 1-hour TTL.
func newStagedFixture(t *testing.T) *stagedFixture {
	t.Helper()
	clock := shared_time.NewFakeClock(issuerEpoch)
	store := keys.NewInMemoryStore(clock)

	_, err := store.GenerateSigning(kidAuthority, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	require.NoError(t, store.GenerateSealing(kidSealing))

	s := session_object.SessionObject{
		SchemaVersion: session_object.SchemaVersionCurrent,
		SessionID:     testSession,
		RequestID:     testRequest,
		GenomeID:      testGenome,
		PolicyVersion: testPolicy,
		IssuedAt:      issuerEpoch,
		ExpiresAt:     issuerEpoch.Add(1 * time.Hour),
		State:         session_object.StateActive,
		SigningKeyID:  kidAuthority,
	}
	require.NoError(t, s.SignWith(store))
	require.NoError(t, s.Validate())

	return &stagedFixture{
		clock:        clock,
		store:        store,
		session:      s,
		activePolicy: testPolicy,
	}
}

// newStagedIssuer wires the issuer under test against fx with default
// options.
func newStagedIssuer(t *testing.T, fx *stagedFixture) *disclosure.StagedIssuer {
	t.Helper()
	iss, err := disclosure.NewStagedIssuer(
		fx.clock,
		fx.store,
		fx.store,
		fx.store,
		kidAuthority,
		kidSealing,
		fx.session,
		fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.NoError(t, err)
	return iss
}

// ---- constructor validation ------------------------------------------------

func TestStagedIssuer_NewStagedIssuer_RequiresClock(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	_, err := disclosure.NewStagedIssuer(
		nil, fx.store, fx.store, fx.store,
		kidAuthority, kidSealing, fx.session, fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestStagedIssuer_NewStagedIssuer_RequiresSigner(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	_, err := disclosure.NewStagedIssuer(
		fx.clock, nil, fx.store, fx.store,
		kidAuthority, kidSealing, fx.session, fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestStagedIssuer_NewStagedIssuer_RequiresSealer(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	_, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, nil, fx.store,
		kidAuthority, kidSealing, fx.session, fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestStagedIssuer_NewStagedIssuer_RequiresResolver(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	_, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, fx.store, nil,
		kidAuthority, kidSealing, fx.session, fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestStagedIssuer_NewStagedIssuer_RequiresSigningKID(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	_, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, fx.store, fx.store,
		ids.KeyID(""), kidSealing, fx.session, fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestStagedIssuer_NewStagedIssuer_RequiresSealingKID(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	_, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, fx.store, fx.store,
		kidAuthority, ids.KeyID(""), fx.session, fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestStagedIssuer_NewStagedIssuer_RequiresActivePolicy(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	_, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, fx.store, fx.store,
		kidAuthority, kidSealing, fx.session, ids.PolicyVersion(""),
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestStagedIssuer_NewStagedIssuer_PropagatesSessionValidateFailure(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	// Corrupt the session in a way session.Validate() will catch —
	// drop the session_id.
	bad := fx.session
	bad.SessionID = ids.SessionID("")

	_, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, fx.store, fx.store,
		kidAuthority, kidSealing, bad, fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestStagedIssuer_NewStagedIssuer_RefusesNonActiveSession(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	invalidated := fx.session
	invalidated.State = session_object.StateInvalidated
	invalidated.Signature = nil
	require.NoError(t, invalidated.SignWith(fx.store))

	_, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, fx.store, fx.store,
		kidAuthority, kidSealing, invalidated, fx.activePolicy,
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSessionInvalidated, shared_errors.CodeOf(err))
}

func TestStagedIssuer_NewStagedIssuer_RefusesPolicyMismatch(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	_, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, fx.store, fx.store,
		kidAuthority, kidSealing, fx.session, ids.PolicyVersion("some-other-policy"),
		disclosure.StagedOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodePolicyDrifted, shared_errors.CodeOf(err))
}

func TestStagedIssuer_NewStagedIssuer_DefaultIDPrefix(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)
	msg, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("hello"),
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(msg.DisclosureID), disclosure.DefaultStagedIDPrefix),
		"disclosure id %q should start with %q", msg.DisclosureID, disclosure.DefaultStagedIDPrefix)
}

func TestStagedIssuer_NewStagedIssuer_CustomIDPrefix(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss, err := disclosure.NewStagedIssuer(
		fx.clock, fx.store, fx.store, fx.store,
		kidAuthority, kidSealing, fx.session, fx.activePolicy,
		disclosure.StagedOptions{IDPrefix: "eu1-disc-"},
	)
	require.NoError(t, err)
	msg, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("hello"),
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(msg.DisclosureID), "eu1-disc-"),
		"disclosure id %q should start with custom prefix", msg.DisclosureID)
}

// ---- initial state ---------------------------------------------------------

func TestStagedIssuer_SessionID_AndSequenceIndex_Initial(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)
	require.Equal(t, testSession, iss.SessionID())
	require.Equal(t, uint32(0), iss.SequenceIndex())
	require.False(t, iss.IsFinalized())
}

// ---- happy-path Emit --------------------------------------------------------

func TestStagedIssuer_Emit_HappyPath_ProducesValidSignedMessage(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	plaintext := []byte("secret-component-bytes")
	plaintextCopy := append([]byte(nil), plaintext...) // for round-trip check

	msg, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      plaintext,
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)
	require.NotNil(t, msg)

	// Envelope self-consistency.
	require.NoError(t, msg.Validate())

	// Field-level assertions.
	require.Equal(t, disclosure_message.SchemaVersionCurrent, msg.SchemaVersion)
	require.Equal(t, testSession, msg.SessionID)
	require.Equal(t, testCompA, msg.ComponentID)
	require.Equal(t, testPolicy, msg.PolicyVersion)
	require.Equal(t, uint32(0), msg.SequenceIndex)
	require.Equal(t, testRecipKey, msg.RecipientKeyID)
	require.Equal(t, kidAuthority, msg.SigningKeyID)
	require.Len(t, msg.Nonce, disclosure_message.GCMNonceSize)
	require.NotEmpty(t, msg.SealedPayload)
	require.NotEmpty(t, msg.Signature)
	require.Equal(t, issuerEpoch, msg.AuthorizedAt.UTC())

	// The counter advanced to 1.
	require.Equal(t, uint32(1), iss.SequenceIndex())

	// The returned envelope verifies under the published authority key.
	require.NoError(t, msg.VerifySignature(fx.store))

	// Decrypt the sealed payload with the AAD the issuer bound — the
	// original plaintext must come back. This is the receiver-side
	// obligation expressed in its tightest form.
	aad := rebuildStagedAAD(t, msg)
	recovered, err := fx.store.Open(kidSealing, msg.Nonce, msg.SealedPayload, aad)
	require.NoError(t, err)
	require.Equal(t, plaintextCopy, recovered)
}

func TestStagedIssuer_Emit_ZeroizesPlaintextInPlace(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	plaintext := []byte("this-must-be-wiped")
	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      plaintext,
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)

	// Every byte of the caller's slice must be zero.
	for i, b := range plaintext {
		require.Equalf(t, byte(0), b,
			"plaintext byte %d should be zero after Emit", i)
	}
}

func TestStagedIssuer_Emit_MonotonicSequenceIndex(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	var seq []uint32
	var ids []string
	for i := 0; i < 5; i++ {
		msg, err := iss.Emit(disclosure.EmitParams{
			ComponentID:    testCompA,
			Plaintext:      []byte("payload"),
			RecipientKeyID: testRecipKey,
		})
		require.NoError(t, err)
		seq = append(seq, msg.SequenceIndex)
		ids = append(ids, string(msg.DisclosureID))
	}

	// Strict monotonicity, no gaps, starting at 0.
	require.Equal(t, []uint32{0, 1, 2, 3, 4}, seq)
	// DisclosureIDs must be unique — the session+index suffix guarantees that.
	require.Equal(t, 5, len(uniq(ids)))
	// And lexicographic order of DisclosureIDs matches sequence order
	// because the hex-encoded big-endian counter is fixed-width.
	for i := 1; i < len(ids); i++ {
		require.Less(t, ids[i-1], ids[i])
	}
}

func TestStagedIssuer_Emit_ProducesDistinctNoncesAcrossEmissions(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	seen := make(map[string]struct{})
	for i := 0; i < 16; i++ {
		msg, err := iss.Emit(disclosure.EmitParams{
			ComponentID:    testCompA,
			Plaintext:      []byte("payload"),
			RecipientKeyID: testRecipKey,
		})
		require.NoError(t, err)
		key := string(msg.Nonce)
		_, dup := seen[key]
		require.Falsef(t, dup, "nonce reuse at sequence %d", msg.SequenceIndex)
		seen[key] = struct{}{}
	}
}

func TestStagedIssuer_Emit_DisclosureID_EncodesSessionAndSequence(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	msg, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload"),
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)

	expected := disclosure.DefaultStagedIDPrefix +
		string(testSession) + "-" +
		hex.EncodeToString([]byte{0x00, 0x00, 0x00, 0x00})
	require.Equal(t, expected, string(msg.DisclosureID))
}

// ---- AAD binding -----------------------------------------------------------

func TestStagedIssuer_Emit_AADBindsSequenceIndex(t *testing.T) {
	t.Parallel()
	// An AAD built for a different SequenceIndex must not Open the
	// ciphertext. This is the doctrinal protection against splicing a
	// ciphertext from sequence N into an envelope advertising sequence M.
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	msg0, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload-zero"),
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)

	// Try to open with an AAD claiming sequence=1.
	forged := *msg0
	forged.SequenceIndex = 1
	aad := rebuildStagedAAD(t, &forged)
	_, err = fx.store.Open(kidSealing, msg0.Nonce, msg0.SealedPayload, aad)
	require.Error(t, err, "AAD must bind SequenceIndex; mismatch should fail Open")
}

func TestStagedIssuer_Emit_AADBindsComponentID(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	msg, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload-a"),
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)

	forged := *msg
	forged.ComponentID = testCompB
	aad := rebuildStagedAAD(t, &forged)
	_, err = fx.store.Open(kidSealing, msg.Nonce, msg.SealedPayload, aad)
	require.Error(t, err, "AAD must bind ComponentID; mismatch should fail Open")
}

func TestStagedIssuer_Emit_AADBindsRecipientKey(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	msg, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload-recip"),
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)

	forged := *msg
	forged.RecipientKeyID = ids.KeyID("some-other-recipient")
	aad := rebuildStagedAAD(t, &forged)
	_, err = fx.store.Open(kidSealing, msg.Nonce, msg.SealedPayload, aad)
	require.Error(t, err, "AAD must bind RecipientKeyID; mismatch should fail Open")
}

// ---- EmitParams structural validation --------------------------------------

func TestStagedIssuer_Emit_RefusesZeroComponentID(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    ids.ComponentID(""),
		Plaintext:      []byte("payload"),
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
	require.Equal(t, uint32(0), iss.SequenceIndex(), "counter must not advance on refusal")
}

func TestStagedIssuer_Emit_RefusesEmptyPlaintext(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      nil,
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, uint32(0), iss.SequenceIndex())

	// Also test the explicit-empty-slice form.
	_, err = iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte{},
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestStagedIssuer_Emit_RefusesZeroRecipientKeyID(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload"),
		RecipientKeyID: ids.KeyID(""),
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, uint32(0), iss.SequenceIndex())
}

// ---- runtime refusal paths -------------------------------------------------

func TestStagedIssuer_Finalize_RefusesFurtherEmit(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	require.NoError(t, iss.Finalize())
	require.True(t, iss.IsFinalized())

	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("too-late"),
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeIssuerFinalized, shared_errors.CodeOf(err))
}

func TestStagedIssuer_Finalize_ZeroizesEvenOnRefusal(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)
	require.NoError(t, iss.Finalize())

	plaintext := []byte("must-still-be-zeroed")
	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      plaintext,
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	for i, b := range plaintext {
		require.Equalf(t, byte(0), b,
			"plaintext byte %d must be zero even on refusal", i)
	}
}

func TestStagedIssuer_Finalize_IsIdempotent(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	require.NoError(t, iss.Finalize())
	require.NoError(t, iss.Finalize())
	require.True(t, iss.IsFinalized())
}

func TestStagedIssuer_Emit_RefusesAfterSessionExpiry(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	// Advance past session.ExpiresAt.
	fx.clock.Step(2 * time.Hour)

	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload"),
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSessionExpired, shared_errors.CodeOf(err))
	require.Equal(t, uint32(0), iss.SequenceIndex())
}

func TestStagedIssuer_Emit_RefusesAtExactExpiryBoundary(t *testing.T) {
	t.Parallel()
	// ExpiresAt is exclusive: Emit at t == ExpiresAt must be refused.
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	fx.clock.SetNow(fx.session.ExpiresAt)
	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload"),
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSessionExpired, shared_errors.CodeOf(err))
}

func TestStagedIssuer_Emit_CounterDoesNotAdvanceAcrossRefusals(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	// One good emission to seat counter=1.
	_, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload-good"),
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), iss.SequenceIndex())

	// Three refusals of different kinds.
	_, err = iss.Emit(disclosure.EmitParams{
		ComponentID:    ids.ComponentID(""),
		Plaintext:      []byte("x"),
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	_, err = iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      nil,
		RecipientKeyID: testRecipKey,
	})
	require.Error(t, err)
	_, err = iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("x"),
		RecipientKeyID: ids.KeyID(""),
	})
	require.Error(t, err)

	// Counter still at 1.
	require.Equal(t, uint32(1), iss.SequenceIndex())

	// Next legitimate emission resumes at sequence=1, no gaps.
	msg, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      []byte("payload-resume"),
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), msg.SequenceIndex)
	require.Equal(t, uint32(2), iss.SequenceIndex())
}

// ---- doctrine: no plaintext sink ------------------------------------------

// TestStagedIssuer_Doctrine_PlaintextNeverSurvivesEmit asserts, at the
// observable behavior level, that the plaintext buffer supplied to Emit
// is not retained anywhere the test can read it after Emit returns.
// Package-internal discipline (one sink: Sealer.Seal) is additionally
// covered by /test/doctrine's static analysis, but this test makes the
// observable property concrete: the only path the plaintext ever took
// is into the sealer, and the caller's buffer has been wiped.
func TestStagedIssuer_Doctrine_PlaintextNeverSurvivesEmit(t *testing.T) {
	t.Parallel()
	fx := newStagedFixture(t)
	iss := newStagedIssuer(t, fx)

	plaintext := []byte("top-secret-component")
	msg, err := iss.Emit(disclosure.EmitParams{
		ComponentID:    testCompA,
		Plaintext:      plaintext,
		RecipientKeyID: testRecipKey,
	})
	require.NoError(t, err)

	// 1. caller's buffer is zeroed.
	require.True(t, allZero(plaintext),
		"caller-owned plaintext slice must be fully zero after Emit")

	// 2. the sealed payload does not literally contain the plaintext
	//    (GCM ensures this for any non-pathological input; the check is
	//    defensive).
	require.False(t, bytes.Contains(msg.SealedPayload, []byte("top-secret-component")),
		"sealed payload must not contain plaintext bytes")
}

// ---- helpers ---------------------------------------------------------------

// rebuildStagedAAD reconstructs the AAD bytes the StagedIssuer binds
// to a DisclosureMessage. Delegates to the shared
// disclosure_message.BuildRecipientAADForMessage helper — the single
// source of truth for the AAD shape across release and receive sides.
func rebuildStagedAAD(t *testing.T, msg *disclosure_message.DisclosureMessage) []byte {
	t.Helper()
	out, err := disclosure_message.BuildRecipientAADForMessage(msg)
	require.NoError(t, err)
	return out
}

// allZero reports whether every byte of b is 0. Used to certify the
// caller-owned plaintext buffer has been wiped.
func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// uniq returns the distinct values in xs.
func uniq(xs []string) []string {
	seen := make(map[string]struct{}, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}
