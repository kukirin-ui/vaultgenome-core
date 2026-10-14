// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	cchr "github.com/vault-genome/vaultgenome-core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// --- Helpers --------------------------------------------------------

func mustRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// receiverFixture wires a Receiver against a real simulated TEE,
// a real keystore, and a real source-authority signer.
type receiverFixture struct {
	receiver     *Receiver
	keystore     *keys.InMemoryStore
	clock        *shared_time.FakeClock
	sourceKID    ids.KeyID
	source       *keys.InMemoryStore // signs as the source authority
	destProducer *tee.Simulated
	destMeasure  tee.Measurement
}

func makeReceiverFixture(t *testing.T, tune ...func(*Config)) *receiverFixture {
	t.Helper()
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))

	// Source-authority keystore + signing key (stand-in for the
	// pre-loaded source authority's pubkey on the destination side).
	sourceKeystore := keys.NewInMemoryStore(clock)
	sourceKID := ids.KeyID("source-auth-1")
	_, err := sourceKeystore.GenerateSigning(sourceKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	destProducer, err := tee.NewSimulated([]byte("vault-genome-receiver-test"), mustRandomBytes(t, 32))
	require.NoError(t, err)
	destKeystore := keys.NewInMemoryStore(clock)

	cfg := Config{
		SourceAuthorityKeys: sourceKeystore,
		LocalTEE:            destProducer,
		Kind:                tee.ProviderSimulated,
		Registrar:           destKeystore,
		Clock:               clock,
	}
	for _, f := range tune {
		f(&cfg)
	}
	receiver, err := NewReceiver(cfg)
	require.NoError(t, err)

	return &receiverFixture{
		receiver:     receiver,
		keystore:     destKeystore,
		clock:        clock,
		sourceKID:    sourceKID,
		source:       sourceKeystore,
		destProducer: destProducer,
		destMeasure:  destProducer.Measurement(),
	}
}

// signedHandshake produces a CrossCloudHandshakeRequest signed by the
// source authority.
func signedHandshake(
	t *testing.T,
	signer keys.Signer,
	sourceKID ids.KeyID,
	requestID ids.RequestID,
	destinationKind tee.Provider,
	nonce []byte,
) cchr.CrossCloudHandshakeRequest {
	t.Helper()
	req := cchr.CrossCloudHandshakeRequest{
		SchemaVersion:       cchr.SchemaVersionCurrent,
		RequestID:           requestID,
		DecisionID:          ids.DecisionID("dec-test-1"),
		DestinationTEEKind:  destinationKind,
		DestinationEndpoint: "https://acp-bootstrap.test:8443",
		HandshakeNonce:      nonce,
		InitiatedAt:         stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC),
		SigningKeyID:        sourceKID,
		Signature:           []byte{0x00},
		AuditEventID:        ids.AuditEventID("evt-handshake-1"),
	}
	require.NoError(t, req.SignWith(signer))
	return req
}

// handshake runs an honest signed handshake for requestID and returns the
// key the destination presented.
func (f *receiverFixture) handshake(t *testing.T, requestID ids.RequestID) []byte {
	t.Helper()
	req := signedHandshake(t, f.source, f.sourceKID, requestID, tee.ProviderSimulated, mustRandomBytes(t, tee.NonceMinBytes))
	resp, err := f.receiver.HandleHandshakeRequest(req)
	require.NoError(t, err)
	return resp.RecipientPublicKey
}

// tokenSpec describes a source-signed token; zero fields take the values
// an honest source would use for handshake "xcc-req-test-1".
type tokenSpec struct {
	requestID    ids.RequestID
	decisionID   ids.DecisionID
	measurement  []byte
	recipientPub []byte
	keys         map[ids.KeyID][]byte
}

func (f *receiverFixture) signedToken(t *testing.T, s tokenSpec) krt.KeyReleaseToken {
	t.Helper()
	if s.requestID == "" {
		s.requestID = "xcc-req-test-1"
	}
	if s.decisionID == "" {
		s.decisionID = "dec-test-1"
	}
	if s.measurement == nil {
		s.measurement = f.destMeasure[:]
	}
	tokenID := ids.DecisionID("xcc-tok-test-1")
	wrapped := make([]krt.WrappedKey, 0, len(s.keys))
	for kid, plaintext := range s.keys {
		aad := canonicalWrapAAD(tokenID, s.measurement, kid)
		ct, err := kms.X25519KeyWrapper{}.Wrap(plaintext, s.recipientPub, aad)
		require.NoError(t, err)
		wrapped = append(wrapped, krt.WrappedKey{KeyID: kid, Purpose: krt.PurposeSealing, Ciphertext: ct, AAD: aad})
	}
	tok := krt.KeyReleaseToken{
		SchemaVersion:          krt.SchemaVersionCurrent,
		TokenID:                tokenID,
		DecisionID:             s.decisionID,
		RequestID:              s.requestID,
		DestinationMeasurement: s.measurement,
		Wrapped:                wrapped,
		PolicyVersion:          "policy-test-v1",
		AuthorizedAt:           stdtime.Date(2026, 5, 9, 12, 5, 0, 0, stdtime.UTC),
		SigningKeyID:           f.sourceKID,
		Signature:              []byte{0x00},
		AuditEventID:           ids.AuditEventID("evt-release-1"),
	}
	require.NoError(t, tok.SignWith(f.source))
	return tok
}

func (f *receiverFixture) resign(t *testing.T, tok *krt.KeyReleaseToken) {
	t.Helper()
	tok.Signature = []byte{0x00}
	require.NoError(t, tok.SignWith(f.source))
}

func oneKey(t *testing.T) map[ids.KeyID][]byte {
	return map[ids.KeyID][]byte{ids.KeyID("dek-1"): mustRandomBytes(t, 32)}
}

func requireIntegrity(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "got %v", err)
}

// --- Constructor tests ----------------------------------------------

func TestNewReceiver_RequiresAllFields(t *testing.T) {
	t.Parallel()
	clock := shared_time.NewFakeClock(stdtime.Now())
	prod, err := tee.NewSimulated([]byte("test"), bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)

	full := Config{
		SourceAuthorityKeys: keys.NewInMemoryStore(clock),
		LocalTEE:            prod,
		Kind:                tee.ProviderSimulated,
		Registrar:           keys.NewInMemoryStore(clock),
	}
	cases := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"SourceAuthorityKeys", func(c *Config) { c.SourceAuthorityKeys = nil }},
		{"LocalTEE", func(c *Config) { c.LocalTEE = nil }},
		{"Registrar", func(c *Config) { c.Registrar = nil }},
		{"Kind", func(c *Config) { c.Kind = "" }},
		{"unknown Kind", func(c *Config) { c.Kind = "enclave-of-my-own" }},
		{"negative TTL", func(c *Config) { c.PendingTTL = -stdtime.Second }},
		{"negative MaxPending", func(c *Config) { c.MaxPending = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := full
			tc.mutate(&cp)
			_, err := NewReceiver(cp)
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
		})
	}
	_, err = NewReceiver(full)
	require.NoError(t, err)
}

// --- HandleHandshakeRequest tests ---------------------------------

func TestHandleHandshakeRequest_HappyPath(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	nonce := mustRandomBytes(t, tee.NonceMinBytes)
	req := signedHandshake(t, f.source, f.sourceKID, "xcc-req-test-1", tee.ProviderSimulated, nonce)

	resp, err := f.receiver.HandleHandshakeRequest(req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Evidence)
	require.Equal(t, []byte(f.destMeasure[:]), []byte(resp.MeasurementHint))
	require.NoError(t, kms.ValidateRecipientPublicKey(resp.RecipientPublicKey))
	require.Equal(t, 1, f.receiver.Outstanding())
}

// The Evidence is what makes the presented key trustworthy: it verifies
// under RecipientChallenge(key, nonce) and under nothing else.
func TestHandleHandshakeRequest_EvidenceBindsThePresentedKey(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	nonce := mustRandomBytes(t, tee.NonceMinBytes)
	req := signedHandshake(t, f.source, f.sourceKID, "xcc-req-test-1", tee.ProviderSimulated, nonce)
	resp, err := f.receiver.HandleHandshakeRequest(req)
	require.NoError(t, err)

	verifier := tee.NewSimulatedVerifier(f.destProducer.PublicKey(), f.destMeasure)
	measured, err := verifier.Verify(resp.Evidence, kms.RecipientChallenge(resp.RecipientPublicKey, nonce))
	require.NoError(t, err)
	require.Equal(t, f.destMeasure, measured)

	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = verifier.Verify(resp.Evidence, kms.RecipientChallenge(other.PublicKey().Bytes(), nonce))
	require.Error(t, err, "Evidence must not vouch for a substituted key")
	_, err = verifier.Verify(resp.Evidence, nonce)
	require.Error(t, err, "Evidence must not be over the bare nonce")
}

func TestHandleHandshakeRequest_FreshKeyPerHandshake(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	a := f.handshake(t, "xcc-req-a")
	b := f.handshake(t, "xcc-req-b")
	require.NotEqual(t, a, b)
	require.Equal(t, 2, f.receiver.Outstanding())
}

func TestHandleHandshakeRequest_RejectsBadSignature(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	req := signedHandshake(t, f.source, f.sourceKID, "xcc-req-test-1", tee.ProviderSimulated, mustRandomBytes(t, tee.NonceMinBytes))
	req.Signature[0] ^= 0xFF
	_, err := f.receiver.HandleHandshakeRequest(req)
	requireIntegrity(t, err)
	require.Zero(t, f.receiver.Outstanding(), "a forged handshake must not create a key")
}

func TestHandleHandshakeRequest_RejectsStructuralInvalid(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	// Empty handshake nonce (below minimum).
	req := cchr.CrossCloudHandshakeRequest{
		SchemaVersion:       cchr.SchemaVersionCurrent,
		RequestID:           ids.RequestID("x"),
		DecisionID:          ids.DecisionID("d"),
		DestinationTEEKind:  tee.ProviderSimulated,
		DestinationEndpoint: "https://x",
		HandshakeNonce:      []byte{1, 2, 3}, // too short
		InitiatedAt:         stdtime.Now(),
		SigningKeyID:        f.sourceKID,
		Signature:           []byte{0xFF},
		AuditEventID:        ids.AuditEventID("e"),
	}
	_, err := f.receiver.HandleHandshakeRequest(req)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

// A source that thinks it is talking to a Nitro enclave would verify our
// Evidence with a Nitro verifier; refuse instead of answering.
func TestHandleHandshakeRequest_RejectsWrongKind(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	req := signedHandshake(t, f.source, f.sourceKID, "xcc-req-test-1", tee.ProviderAWSNitro, mustRandomBytes(t, tee.NonceMinBytes))
	_, err := f.receiver.HandleHandshakeRequest(req)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.Zero(t, f.receiver.Outstanding())
}

// Replaying a captured handshake must not replace the key the source is
// about to wrap to.
func TestHandleHandshakeRequest_ReplayCannotReplaceTheKey(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	req := signedHandshake(t, f.source, f.sourceKID, "xcc-req-test-1", tee.ProviderSimulated, mustRandomBytes(t, tee.NonceMinBytes))
	first, err := f.receiver.HandleHandshakeRequest(req)
	require.NoError(t, err)

	_, err = f.receiver.HandleHandshakeRequest(req)
	requireIntegrity(t, err)

	tok := f.signedToken(t, tokenSpec{recipientPub: first.RecipientPublicKey, keys: oneKey(t)})
	n, err := f.receiver.HandleKeyReleaseToken(tok)
	require.NoError(t, err, "the original key must still open the token")
	require.Equal(t, 1, n)
}

func TestHandleHandshakeRequest_BoundsOutstandingHandshakes(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t, func(c *Config) { c.MaxPending = 2 })
	f.handshake(t, "xcc-req-1")
	f.handshake(t, "xcc-req-2")
	req := signedHandshake(t, f.source, f.sourceKID, "xcc-req-3", tee.ProviderSimulated, mustRandomBytes(t, tee.NonceMinBytes))
	_, err := f.receiver.HandleHandshakeRequest(req)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))

	// Expired entries free their slots.
	f.clock.Step(DefaultPendingTTL)
	_, err = f.receiver.HandleHandshakeRequest(req)
	require.NoError(t, err)
}

// --- HandleKeyReleaseToken tests ----------------------------------

func TestHandleKeyReleaseToken_HappyPath_RegistersAllKeys(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	pub := f.handshake(t, "xcc-req-test-1")
	tok := f.signedToken(t, tokenSpec{recipientPub: pub, keys: map[ids.KeyID][]byte{
		ids.KeyID("dek-1"): mustRandomBytes(t, 32),
		ids.KeyID("dek-2"): mustRandomBytes(t, 32),
	}})

	registered, err := f.receiver.HandleKeyReleaseToken(tok)
	require.NoError(t, err)
	require.Equal(t, 2, registered)
	require.Zero(t, f.receiver.Outstanding(), "the handshake key is consumed")

	// Both keys must be usable in the destination's keystore now.
	// keys.InMemoryStore.Seal opens against an existing sealing key
	// — round-tripping a tiny payload proves the key is registered.
	_, _, err = f.keystore.Seal(ids.KeyID("dek-1"), []byte("ping"), nil)
	require.NoError(t, err)
	_, _, err = f.keystore.Seal(ids.KeyID("dek-2"), []byte("ping"), nil)
	require.NoError(t, err)
}

func TestHandleKeyReleaseToken_HandshakeKeyIsSingleUse(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	pub := f.handshake(t, "xcc-req-test-1")
	tok := f.signedToken(t, tokenSpec{recipientPub: pub, keys: oneKey(t)})
	_, err := f.receiver.HandleKeyReleaseToken(tok)
	require.NoError(t, err)
	require.Zero(t, f.receiver.Outstanding())

	_, err = f.receiver.HandleKeyReleaseToken(tok)
	requireIntegrity(t, err)
	require.ErrorContains(t, err, "no outstanding handshake")
}

func TestHandleKeyReleaseToken_ExpiredHandshakeKeyIsGone(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	pub := f.handshake(t, "xcc-req-test-1")
	f.clock.Step(DefaultPendingTTL)

	n, err := f.receiver.HandleKeyReleaseToken(f.signedToken(t, tokenSpec{recipientPub: pub, keys: oneKey(t)}))
	requireIntegrity(t, err)
	require.ErrorContains(t, err, "no outstanding handshake")
	require.Zero(t, n)
	require.Zero(t, f.receiver.Outstanding())
}

func TestHandleKeyReleaseToken_RejectsTokenWithoutHandshake(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	n, err := f.receiver.HandleKeyReleaseToken(f.signedToken(t, tokenSpec{recipientPub: other.PublicKey().Bytes(), keys: oneKey(t)}))
	requireIntegrity(t, err)
	require.Zero(t, n)
}

func TestHandleKeyReleaseToken_RejectsDecisionMismatch(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	pub := f.handshake(t, "xcc-req-test-1")
	n, err := f.receiver.HandleKeyReleaseToken(f.signedToken(t, tokenSpec{decisionID: "dec-other", recipientPub: pub, keys: oneKey(t)}))
	requireIntegrity(t, err)
	require.Zero(t, n)
}

// DEKs encapsulated to any key other than the one this handshake minted
// do not open, even in a correctly signed token.
func TestHandleKeyReleaseToken_RejectsKeysWrappedToAnotherRecipient(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	f.handshake(t, "xcc-req-test-1")
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	n, err := f.receiver.HandleKeyReleaseToken(f.signedToken(t, tokenSpec{recipientPub: other.PublicKey().Bytes(), keys: oneKey(t)}))
	requireIntegrity(t, err)
	require.Zero(t, n)
}

// A forged token is rejected before it can touch, let alone burn, the
// handshake key: the genuine token still opens afterwards.
func TestHandleKeyReleaseToken_ForgedTokenDoesNotConsumeTheKey(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	pub := f.handshake(t, "xcc-req-test-1")
	tok := f.signedToken(t, tokenSpec{recipientPub: pub, keys: oneKey(t)})

	forged := tok
	forged.Signature = append([]byte(nil), tok.Signature...)
	forged.Signature[0] ^= 0xFF
	n, err := f.receiver.HandleKeyReleaseToken(forged)
	requireIntegrity(t, err)
	require.Zero(t, n)

	n, err = f.receiver.HandleKeyReleaseToken(tok)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}

// Re-releasing the same DEK under the same kid (a retry whose first
// answer was lost) succeeds; a different DEK under a registered kid is
// refused as the sender's error, not reported as an outage.
func TestHandleKeyReleaseToken_ReReleaseSameKeyOnlyOnce(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	dek := mustRandomBytes(t, 32)

	pub := f.handshake(t, "xcc-req-1")
	_, err := f.receiver.HandleKeyReleaseToken(f.signedToken(t, tokenSpec{requestID: "xcc-req-1", recipientPub: pub, keys: map[ids.KeyID][]byte{"dek-1": dek}}))
	require.NoError(t, err)

	pub = f.handshake(t, "xcc-req-2")
	n, err := f.receiver.HandleKeyReleaseToken(f.signedToken(t, tokenSpec{requestID: "xcc-req-2", recipientPub: pub, keys: map[ids.KeyID][]byte{"dek-1": dek}}))
	require.NoError(t, err, "the same key again is idempotent")
	require.Equal(t, 1, n)

	pub = f.handshake(t, "xcc-req-3")
	_, err = f.receiver.HandleKeyReleaseToken(f.signedToken(t, tokenSpec{requestID: "xcc-req-3", recipientPub: pub, keys: map[ids.KeyID][]byte{"dek-1": mustRandomBytes(t, 32)}}))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural), "got %v", err)
}

func TestHandleKeyReleaseToken_RejectsWrongMeasurement(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	pub := f.handshake(t, "xcc-req-test-1")
	tok := f.signedToken(t, tokenSpec{measurement: bytes.Repeat([]byte{0xCC}, 32), recipientPub: pub, keys: oneKey(t)})
	n, err := f.receiver.HandleKeyReleaseToken(tok)
	requireIntegrity(t, err)
	require.Zero(t, n)
}

func TestHandleKeyReleaseToken_RejectsTamperedAAD(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	pub := f.handshake(t, "xcc-req-test-1")
	tok := f.signedToken(t, tokenSpec{recipientPub: pub, keys: oneKey(t)})
	tok.Wrapped[0].AAD = append(tok.Wrapped[0].AAD, 0xAA)
	f.resign(t, &tok)
	n, err := f.receiver.HandleKeyReleaseToken(tok)
	requireIntegrity(t, err)
	require.Zero(t, n)
}

func TestHandleKeyReleaseToken_RejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	pub := f.handshake(t, "xcc-req-test-1")
	tok := f.signedToken(t, tokenSpec{recipientPub: pub, keys: oneKey(t)})
	tok.Wrapped[0].Ciphertext[len(tok.Wrapped[0].Ciphertext)-1] ^= 0x01
	f.resign(t, &tok)
	n, err := f.receiver.HandleKeyReleaseToken(tok)
	requireIntegrity(t, err)
	require.Zero(t, n)
}

func TestHandleKeyReleaseToken_RejectsStructuralInvalid(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	n, err := f.receiver.HandleKeyReleaseToken(krt.KeyReleaseToken{}) // all zero — Validate fails
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
	require.Zero(t, n)
}

func TestLocalMeasurement_DefensiveCopy(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	got := f.receiver.LocalMeasurement()
	require.Equal(t, []byte(f.destMeasure[:]), []byte(got))
	// Mutating returned slice must not affect Receiver internals.
	got[0] = 0xFF
	again := f.receiver.LocalMeasurement()
	require.Equal(t, []byte(f.destMeasure[:]), []byte(again))
}

// --- End-to-end round-trip with source-side Coordinator -----------

// coordinatorFor wires a real source-side Coordinator to f's receiver,
// in process.
func coordinatorFor(t *testing.T, f *receiverFixture, idGen kms.IDGenerator) *kms.Coordinator {
	t.Helper()
	destMeasureBytes := append([]byte(nil), f.destMeasure...)
	registry, err := tee.NewRegistry([]tee.RegistrySpec{{
		Provider: tee.ProviderSimulated,
		Spec: tee.VerifierSpec{
			Provider:            tee.ProviderSimulated,
			AttestorPubKey:      f.destProducer.PublicKey(),
			ExpectedMeasurement: f.destMeasure,
		},
	}})
	require.NoError(t, err)
	policy, err := kms.NewAllowListPolicy("e2e-policy-v1", map[tee.Provider][][]byte{
		tee.ProviderSimulated: {destMeasureBytes},
	})
	require.NoError(t, err)
	coord, err := kms.NewCoordinator(kms.Config{
		AuditChain:   &silentAudit{},
		Signer:       f.source,
		Verifiers:    registry,
		Policy:       policy,
		Transport:    &receiverBackedTransport{receiver: f.receiver},
		IDGenerator:  idGen,
		NonceSource:  func(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err },
		Clock:        f.clock,
		SigningKeyID: f.sourceKID,
	})
	require.NoError(t, err)
	return coord
}

func TestEndToEnd_SourceCoordinatorToDestinationReceiver(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	coord := coordinatorFor(t, f, &counterIDGen{})

	res, err := coord.CoordinateRestore(context.Background(), kms.CoordinationRequest{
		DecisionID:          ids.DecisionID("e2e-dec-1"),
		DestinationKind:     tee.ProviderSimulated,
		DestinationEndpoint: "https://destination.test",
		KeysToRelease: []kms.KeyMaterial{
			{KeyID: ids.KeyID("e2e-dek-1"), Purpose: krt.PurposeSealing, Plaintext: mustRandomBytes(t, 32)},
			{KeyID: ids.KeyID("e2e-dek-2"), Purpose: krt.PurposeSealing, Plaintext: mustRandomBytes(t, 32)},
		},
		SessionID:  ids.SessionID("e2e-sess-1"),
		ManifestID: ids.ManifestID("e2e-man-1"),
	})
	require.NoError(t, err)
	require.Equal(t, []byte(f.destMeasure), res.DestinationMeasurement)
	require.Len(t, res.RecipientKeySHA256, 32)
	require.NotEmpty(t, res.TokenID)
	require.Zero(t, f.receiver.Outstanding())

	// Destination keystore must now hold both DEKs registered under
	// their original KeyIDs.
	for _, kid := range []ids.KeyID{"e2e-dek-1", "e2e-dek-2"} {
		_, _, err := f.keystore.Seal(kid, []byte("ping"), nil)
		require.NoError(t, err, "DEK %s must be registered after cross-cloud restore", kid)
	}
}

// Many restores against one destination at once: every one gets its own
// key and every DEK lands. Run under -race.
func TestEndToEnd_ConcurrentRestores(t *testing.T) {
	t.Parallel()
	f := makeReceiverFixture(t)
	coord := coordinatorFor(t, f, &uniqueIDGen{})

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := coord.CoordinateRestore(context.Background(), kms.CoordinationRequest{
				DecisionID:          ids.DecisionID(fmt.Sprintf("dec-%d", i)),
				DestinationKind:     tee.ProviderSimulated,
				DestinationEndpoint: "https://destination.test",
				KeysToRelease:       []kms.KeyMaterial{{KeyID: ids.KeyID(fmt.Sprintf("dek-%d", i)), Purpose: krt.PurposeSealing, Plaintext: bytes.Repeat([]byte{byte(i + 1)}, 32)}},
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	for i := 0; i < n; i++ {
		_, _, err := f.keystore.Seal(ids.KeyID(fmt.Sprintf("dek-%d", i)), []byte("ping"), nil)
		require.NoError(t, err)
	}
	require.Zero(t, f.receiver.Outstanding())
}

// receiverBackedTransport is a kms.Transport that routes calls
// directly into a destination Receiver. Used in the end-to-end test
// to wire source coordinator and destination receiver into a single
// in-process flow.
type receiverBackedTransport struct {
	receiver *Receiver
}

func (t *receiverBackedTransport) SendHandshakeRequest(
	_ context.Context,
	_ string,
	req cchr.CrossCloudHandshakeRequest,
) (kms.HandshakeResponse, error) {
	resp, err := t.receiver.HandleHandshakeRequest(req)
	if err != nil {
		return kms.HandshakeResponse{}, err
	}
	return kms.HandshakeResponse{Evidence: resp.Evidence, MeasurementHint: resp.MeasurementHint, RecipientPublicKey: resp.RecipientPublicKey}, nil
}

func (t *receiverBackedTransport) SendKeyReleaseToken(
	_ context.Context,
	_ string,
	tok krt.KeyReleaseToken,
) error {
	_, err := t.receiver.HandleKeyReleaseToken(tok)
	return err
}

// silentAudit accepts and discards all events — sufficient for the
// e2e test which asserts on key-registration, not audit-chain shape.
type silentAudit struct{}

func (silentAudit) Emit(_ audit_event.Kind, _ []byte, _ ids.SessionID, _ ids.ManifestID, _ ids.RequestID) (ids.AuditEventID, error) {
	return ids.AuditEventID("audit-noop"), nil
}

type counterIDGen struct{ n int }

func (g *counterIDGen) NewRequestID() (ids.RequestID, error) {
	g.n++
	return ids.RequestID("e2e-req-1"), nil
}

func (g *counterIDGen) NewDecisionID() (ids.DecisionID, error) {
	g.n++
	return ids.DecisionID("e2e-dec-tok-1"), nil
}

// uniqueIDGen hands out distinct IDs and is safe for concurrent use.
type uniqueIDGen struct {
	mu sync.Mutex
	n  int
}

func (g *uniqueIDGen) next() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return g.n
}

func (g *uniqueIDGen) NewRequestID() (ids.RequestID, error) {
	return ids.RequestID(fmt.Sprintf("req-%d", g.next())), nil
}

func (g *uniqueIDGen) NewDecisionID() (ids.DecisionID, error) {
	return ids.DecisionID(fmt.Sprintf("tok-%d", g.next())), nil
}
