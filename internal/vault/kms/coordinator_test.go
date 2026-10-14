// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
)

// --- Test mocks ----------------------------------------------------

type emittedEvent struct {
	Kind       audit_event.Kind
	Payload    []byte
	SessionID  ids.SessionID
	ManifestID ids.ManifestID
	RequestID  ids.RequestID
}

type fakeAuditChain struct {
	events   []emittedEvent
	failKind audit_event.Kind // if non-empty, Emit fails for this kind
	counter  int
}

func newFakeAuditChain() *fakeAuditChain {
	return &fakeAuditChain{events: []emittedEvent{}}
}

func (f *fakeAuditChain) Emit(
	kind audit_event.Kind,
	payload []byte,
	sessionID ids.SessionID,
	manifestID ids.ManifestID,
	requestID ids.RequestID,
) (ids.AuditEventID, error) {
	if f.failKind == kind {
		return "", errors.New("audit chain emit failed (test injection)")
	}
	f.counter++
	f.events = append(f.events, emittedEvent{Kind: kind, Payload: payload, SessionID: sessionID, ManifestID: manifestID, RequestID: requestID})
	return ids.AuditEventID(fmt.Sprintf("audit-%d", f.counter)), nil
}

type fakeIDGen struct {
	reqCounter      int
	decisionCounter int
}

func (g *fakeIDGen) NewRequestID() (ids.RequestID, error) {
	g.reqCounter++
	return ids.RequestID(fmt.Sprintf("xcc-req-%04d", g.reqCounter)), nil
}

func (g *fakeIDGen) NewDecisionID() (ids.DecisionID, error) {
	g.decisionCounter++
	return ids.DecisionID(fmt.Sprintf("xcc-dec-%04d", g.decisionCounter)), nil
}

// producerBackedTransport simulates a destination by holding a real
// tee.Producer. By default it behaves like an honest ADR-0009
// destination: it generates an X25519 key per handshake and quotes over
// RecipientChallenge(key, nonce). The remaining knobs model destinations
// and networks that must be refused.
type producerBackedTransport struct {
	producer      tee.Producer
	handshakeErr  error
	tokenErr      error
	emptyEvidence bool // destination returns no Evidence

	withholdKey    bool   // destination presents no recipient key (pre-ADR-0009)
	quoteBareNonce bool   // destination quotes over the bare nonce, not the challenge
	substituteKey  []byte // a man in the middle replaces the presented key
	chosenKey      []byte // the destination itself presents (and quotes over) this key

	recipientPriv  []byte // private half of the key the destination generated
	recipientPub   []byte // the key the destination presented
	sentTokens     []krt.KeyReleaseToken
	sentHandshakes []cchr.CrossCloudHandshakeRequest
}

func (t *producerBackedTransport) SendHandshakeRequest(
	ctx context.Context,
	endpoint string,
	req cchr.CrossCloudHandshakeRequest,
) (HandshakeResponse, error) {
	t.sentHandshakes = append(t.sentHandshakes, req)
	if t.handshakeErr != nil {
		return HandshakeResponse{}, t.handshakeErr
	}
	if t.emptyEvidence {
		return HandshakeResponse{}, nil
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return HandshakeResponse{}, err
	}
	t.recipientPriv, t.recipientPub = k.Bytes(), k.PublicKey().Bytes()
	if t.chosenKey != nil {
		t.recipientPriv, t.recipientPub = nil, t.chosenKey
	}
	challenge := RecipientChallenge(t.recipientPub, req.HandshakeNonce)
	if t.quoteBareNonce {
		challenge = req.HandshakeNonce
	}
	evidence, err := t.producer.Quote(challenge)
	if err != nil {
		return HandshakeResponse{}, err
	}
	m := t.producer.Measurement()
	resp := HandshakeResponse{Evidence: evidence, MeasurementHint: m[:], RecipientPublicKey: t.recipientPub}
	switch {
	case t.withholdKey:
		resp.RecipientPublicKey = nil
	case t.substituteKey != nil:
		resp.RecipientPublicKey = t.substituteKey
	}
	return resp, nil
}

func (t *producerBackedTransport) SendKeyReleaseToken(
	ctx context.Context,
	endpoint string,
	token krt.KeyReleaseToken,
) error {
	if t.tokenErr != nil {
		return t.tokenErr
	}
	t.sentTokens = append(t.sentTokens, token)
	return nil
}

// deterministicNonceSource returns a fixed-content nonce padded to n
// bytes; lets us assert nonce-related fields without RNG variability.
func deterministicNonceSource(seed byte) NonceSource {
	return func(n int) ([]byte, error) {
		out := make([]byte, n)
		for i := range out {
			out[i] = seed + byte(i)
		}
		return out, nil
	}
}

func failingNonceSource(_ int) ([]byte, error) {
	return nil, errors.New("rng failure (test injection)")
}

func tooShortNonceSource(_ int) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}

// --- Test fixtures -------------------------------------------------

// fixture builds a fully-wired Coordinator with a destination-side
// simulated TEE producer / verifier and an allow-listed measurement.
type fixture struct {
	coord        *Coordinator
	auditChain   *fakeAuditChain
	idGen        *fakeIDGen
	transport    *producerBackedTransport
	keyStore     *keys.InMemoryStore
	sourceKID    ids.KeyID
	destKind     tee.Provider
	destMeasure  tee.Measurement
	destProducer *tee.Simulated
	registry     *tee.Registry
}

func makeFixture(t *testing.T) *fixture {
	t.Helper()
	return makeFixtureWith(t, nil)
}

// makeFixtureWith builds the fixture with the destination's verifier
// wrapped — a verifier that says more than the measurement, for the
// audit record tests — or as it is when wrap is nil.
func makeFixtureWith(t *testing.T, wrap func(tee.Verifier) tee.Verifier) *fixture {
	t.Helper()
	clock := shared_time.NewFakeClock(stdtime.Date(2026, 5, 9, 12, 0, 0, 0, stdtime.UTC))

	// Source-authority signing key.
	keyStore := keys.NewInMemoryStore(clock)
	sourceKID := ids.KeyID("source-auth-1")
	_, err := keyStore.GenerateSigning(sourceKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	// Destination simulated TEE producer + matching verifier in registry.
	destDescriptor := []byte("vault-genome-destination-test")
	destSeed := make([]byte, 32)
	for i := range destSeed {
		destSeed[i] = byte(0x80 + i)
	}
	destProducer, err := tee.NewSimulated(destDescriptor, destSeed)
	require.NoError(t, err)

	destMeasurement := destProducer.Measurement()
	destMeasurementBytes := make([]byte, 32)
	copy(destMeasurementBytes, destMeasurement[:])

	var verifier tee.Verifier = tee.NewSimulatedVerifier(destProducer.PublicKey(), destMeasurement)
	if wrap != nil {
		verifier = wrap(verifier)
	}
	registry := tee.NewRegistryOf(map[tee.Provider]tee.Verifier{tee.ProviderSimulated: verifier})

	policy, err := NewAllowListPolicy("policy-test-v1", map[tee.Provider][][]byte{
		tee.ProviderSimulated: {destMeasurementBytes},
	})
	require.NoError(t, err)

	auditChain := newFakeAuditChain()
	idGen := &fakeIDGen{}
	transport := &producerBackedTransport{producer: destProducer}

	coord, err := NewCoordinator(Config{
		AuditChain:   auditChain,
		Signer:       keyStore,
		Verifiers:    registry,
		Policy:       policy,
		Transport:    transport,
		IDGenerator:  idGen,
		NonceSource:  deterministicNonceSource(0xA0),
		Clock:        clock,
		SigningKeyID: sourceKID,
	})
	require.NoError(t, err)

	return &fixture{
		coord:        coord,
		auditChain:   auditChain,
		idGen:        idGen,
		transport:    transport,
		keyStore:     keyStore,
		sourceKID:    sourceKID,
		destKind:     tee.ProviderSimulated,
		destMeasure:  destMeasurement,
		destProducer: destProducer,
		registry:     registry,
	}
}

func validKeyMaterial() []KeyMaterial {
	return []KeyMaterial{
		{KeyID: ids.KeyID("dek-1"), Purpose: krt.PurposeSealing, Plaintext: []byte("super-secret-DEK-bytes-vault-001")},
		{KeyID: ids.KeyID("dek-2"), Purpose: krt.PurposeSealing, Plaintext: []byte("super-secret-DEK-bytes-vault-002")},
	}
}

func validRequest(f *fixture) CoordinationRequest {
	return CoordinationRequest{
		DecisionID:          ids.DecisionID("dec-vault-0001"),
		DestinationKind:     f.destKind,
		DestinationEndpoint: "https://acp-bootstrap.example.com:8443",
		KeysToRelease:       validKeyMaterial(),
		SessionID:           ids.SessionID("sess-0001"),
		ManifestID:          ids.ManifestID("man-0001"),
	}
}

// --- NewCoordinator constructor tests ------------------------------

func TestNewCoordinator_RequiresAllFields(t *testing.T) {
	t.Parallel()
	clock := shared_time.NewFakeClock(stdtime.Now())
	store := keys.NewInMemoryStore(clock)
	registry, err := tee.NewRegistry(nil)
	require.NoError(t, err)
	policy, err := NewAllowListPolicy("v1", nil)
	require.NoError(t, err)

	full := Config{
		AuditChain:   newFakeAuditChain(),
		Signer:       store,
		Verifiers:    registry,
		Policy:       policy,
		Transport:    &producerBackedTransport{},
		IDGenerator:  &fakeIDGen{},
		NonceSource:  deterministicNonceSource(0),
		Clock:        clock,
		SigningKeyID: ids.KeyID("k1"),
	}

	// Each pruned field must trigger error.
	cases := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"AuditChain", func(c *Config) { c.AuditChain = nil }},
		{"Signer", func(c *Config) { c.Signer = nil }},
		{"Verifiers", func(c *Config) { c.Verifiers = nil }},
		{"Policy", func(c *Config) { c.Policy = nil }},
		{"Transport", func(c *Config) { c.Transport = nil }},
		{"IDGenerator", func(c *Config) { c.IDGenerator = nil }},
		{"NonceSource", func(c *Config) { c.NonceSource = nil }},
		{"Clock", func(c *Config) { c.Clock = nil }},
		{"SigningKeyID", func(c *Config) { c.SigningKeyID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := full
			tc.mutate(&cp)
			_, err := NewCoordinator(cp)
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
		})
	}

	// Full config succeeds.
	_, err = NewCoordinator(full)
	require.NoError(t, err)
}

// --- CoordinateRestore happy path ----------------------------------

func TestCoordinateRestore_HappyPath(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	res, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.NoError(t, err)

	// Result fields populated.
	require.NotEmpty(t, res.HandshakeRequestID)
	require.NotEmpty(t, res.HandshakeAuditID)
	require.NotEmpty(t, res.AttestationAuditID)
	require.NotEmpty(t, res.KeyReleaseAuditID)
	require.Equal(t, []byte(f.destMeasure[:]), []byte(res.DestinationMeasurement))
	require.Equal(t, "policy-test-v1", res.PolicyVersion)
	require.NotEmpty(t, res.TokenID)

	// Three audit events emitted in strict order.
	require.Len(t, f.auditChain.events, 3)
	require.Equal(t, audit_event.KindCrossCloudHandshakeInitiated, f.auditChain.events[0].Kind)
	require.Equal(t, audit_event.KindCrossCloudAttestationVerified, f.auditChain.events[1].Kind)
	require.Equal(t, audit_event.KindKeyReleaseAuthorized, f.auditChain.events[2].Kind)

	// Each event tagged with the same RequestID correlator.
	require.Equal(t, res.HandshakeRequestID, f.auditChain.events[0].RequestID)
	require.Equal(t, res.HandshakeRequestID, f.auditChain.events[1].RequestID)
	require.Equal(t, res.HandshakeRequestID, f.auditChain.events[2].RequestID)

	// One handshake dispatched.
	require.Len(t, f.transport.sentHandshakes, 1)
	hs := f.transport.sentHandshakes[0]
	require.Equal(t, res.HandshakeRequestID, hs.RequestID)
	require.Equal(t, ids.DecisionID("dec-vault-0001"), hs.DecisionID)
	require.Equal(t, f.destKind, hs.DestinationTEEKind)
	require.GreaterOrEqual(t, len(hs.HandshakeNonce), tee.NonceMinBytes)
	require.NotEmpty(t, hs.Signature)
	require.Equal(t, res.HandshakeAuditID, hs.AuditEventID)

	// One token dispatched, with two wrapped keys.
	require.Len(t, f.transport.sentTokens, 1)
	tok := f.transport.sentTokens[0]
	require.Equal(t, res.TokenID, tok.TokenID)
	require.Equal(t, ids.DecisionID("dec-vault-0001"), tok.DecisionID)
	require.Equal(t, res.HandshakeRequestID, tok.RequestID)
	require.Equal(t, []byte(f.destMeasure[:]), []byte(tok.DestinationMeasurement))
	require.Len(t, tok.Wrapped, 2)
	for _, w := range tok.Wrapped {
		require.Equal(t, krt.PurposeSealing, w.Purpose)
		require.NotEmpty(t, w.Ciphertext)
		require.NotEmpty(t, w.AAD)
	}
	require.Equal(t, "policy-test-v1", tok.PolicyVersion)
	require.Equal(t, res.KeyReleaseAuditID, tok.AuditEventID)
	require.NotEmpty(t, tok.Signature)
}

// TestCoordinateRestore_TokenUnwrapsAtDestination exercises the full
// crypto loop: each DEK is encapsulated to the key the destination
// attested, and only that key's private half opens it.
func TestCoordinateRestore_TokenUnwrapsAtDestination(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	req := validRequest(f)
	res, err := f.coord.CoordinateRestore(context.Background(), req)
	require.NoError(t, err)
	pubHash := sha256.Sum256(f.transport.recipientPub)
	require.Equal(t, pubHash[:], res.RecipientKeySHA256)

	require.Len(t, f.transport.sentTokens, 1)
	tok := f.transport.sentTokens[0]
	otherPriv, _ := newX25519(t)
	for i, w := range tok.Wrapped {
		plain, err := X25519KeyUnwrapper{}.Unwrap(w.Ciphertext, f.transport.recipientPriv, w.AAD)
		require.NoError(t, err, "wrapped key #%d must open with the attested key", i)
		require.Equal(t, req.KeysToRelease[i].Plaintext, plain, "round-trip plaintext must match")

		_, err = X25519KeyUnwrapper{}.Unwrap(w.Ciphertext, otherPriv, w.AAD)
		require.Error(t, err, "wrapped key #%d opened with a key the destination never attested", i)
	}
}

// TestCoordinateRestore_DefectB_TokenPlusMeasurementRevealsNothing is the
// regression test for defect (b). The old wrap key was
// SHA-256("vault-genome-xcc-wrap-v1" ‖ measurement), and the measurement is
// public, so anyone holding a token could open its DEKs. An eavesdropper
// with the token and the measurement must now learn nothing, whichever way
// they try to use the measurement.
func TestCoordinateRestore_DefectB_TokenPlusMeasurementRevealsNothing(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	req := validRequest(f)
	_, err := f.coord.CoordinateRestore(context.Background(), req)
	require.NoError(t, err)
	tok := f.transport.sentTokens[0]
	measurement := tok.DestinationMeasurement // public: it is in the token itself

	oldKey := sha256.Sum256(append([]byte("vault-genome-xcc-wrap-v1"), measurement...))
	for i, w := range tok.Wrapped {
		_, err := aeadOpen(oldKey[:], w.Ciphertext, w.AAD)
		require.Error(t, err, "wrapped key #%d opened under the old measurement-derived key", i)
		_, err = aeadOpen(oldKey[:], w.Ciphertext[RecipientKeySize:], w.AAD)
		require.Error(t, err, "wrapped key #%d opened under the old key past the ephemeral share", i)
		_, err = X25519KeyUnwrapper{}.Unwrap(w.Ciphertext, measurement, w.AAD)
		require.Error(t, err, "wrapped key #%d opened with the measurement as an X25519 key", i)
		require.NotContains(t, string(w.Ciphertext), string(req.KeysToRelease[i].Plaintext))
	}
}

// --- A destination that cannot prove its key gets nothing ------------

func requireRefusedBeforeRelease(t *testing.T, f *fixture, err error) {
	t.Helper()
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "got %v", err)
	require.Empty(t, f.transport.sentTokens, "no token may leave for an unproven key")
	requireDenied(t, f, 1, denialAttestation)
}

// requireDenied checks the flow ended on the record with a refusal at
// stage, after the given number of earlier events and with nothing
// verified-then-authorised in between.
func requireDenied(t *testing.T, f *fixture, before int, stage string) {
	t.Helper()
	require.Len(t, f.auditChain.events, before+1, "the refusal closes the flow on the record")
	require.Equal(t, audit_event.KindCrossCloudHandshakeInitiated, f.auditChain.events[0].Kind)
	last := f.auditChain.events[before]
	require.Equal(t, audit_event.KindKeyReleaseDenied, last.Kind)
	var p keyReleaseDeniedPayload
	require.NoError(t, json.Unmarshal(last.Payload, &p))
	require.Equal(t, stage, p.Stage)
	require.NotEmpty(t, p.Reason)
	require.Equal(t, f.auditChain.events[0].RequestID, last.RequestID)
}

func TestCoordinateRestore_RefusesDestinationWithoutRecipientKey(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.withholdKey = true
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	requireRefusedBeforeRelease(t, f, err)
}

// A man in the middle swaps the destination's key for their own. The
// genuine Evidence was quoted over the real key, so it no longer verifies.
func TestCoordinateRestore_RefusesSubstitutedRecipientKey(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	_, attackerPub := newX25519(t)
	f.transport.substituteKey = attackerPub
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	requireRefusedBeforeRelease(t, f, err)
}

// Evidence over the bare nonce proves the TEE is genuine and fresh but
// says nothing about the key; it is not enough.
func TestCoordinateRestore_RefusesEvidenceNotBoundToKey(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.quoteBareNonce = true
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	requireRefusedBeforeRelease(t, f, err)
}

// A genuine TEE that attests a degenerate key (all-zero, a low-order
// point) passes attestation; the key itself must still be refused before
// anything is verified-on-record or wrapped to it.
func TestCoordinateRestore_RefusesLowOrderRecipientKey(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.chosenKey = make([]byte, RecipientKeySize)
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	requireRefusedBeforeRelease(t, f, err)
}

// The audit chain records which attested key the DEKs went to and how.
func TestCoordinateRestore_AuditRecordsRecipientKey(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.NoError(t, err)
	want := sha256.Sum256(f.transport.recipientPub)

	var verified attestationVerifiedPayload
	require.NoError(t, json.Unmarshal(f.auditChain.events[1].Payload, &verified))
	require.Equal(t, want[:], verified.RecipientKeySHA256)

	var released keyReleaseAuthorizedPayload
	require.NoError(t, json.Unmarshal(f.auditChain.events[2].Payload, &released))
	require.Equal(t, want[:], released.RecipientKeySHA256)
	require.Equal(t, DeliveryModeX25519KEM, released.DeliveryMode)
}

// --- CoordinateRestore error paths ---------------------------------

func TestCoordinateRestore_ValidationErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mut  func(r *CoordinationRequest)
	}{
		{"DecisionID empty", func(r *CoordinationRequest) { r.DecisionID = "" }},
		{"DestinationKind empty", func(r *CoordinationRequest) { r.DestinationKind = "" }},
		{"DestinationKind unregistered", func(r *CoordinationRequest) { r.DestinationKind = tee.ProviderGCPSEVSNP }},
		{"Endpoint empty", func(r *CoordinationRequest) { r.DestinationEndpoint = "" }},
		{"KeysToRelease empty", func(r *CoordinationRequest) { r.KeysToRelease = nil }},
		{"KeyMaterial KeyID empty", func(r *CoordinationRequest) { r.KeysToRelease[0].KeyID = "" }},
		{"KeyMaterial Plaintext empty", func(r *CoordinationRequest) { r.KeysToRelease[0].Plaintext = nil }},
		{"SourceMeasurement wrong size", func(r *CoordinationRequest) { r.SourceMeasurement = []byte{1, 2, 3} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t)
			req := validRequest(f)
			tc.mut(&req)
			_, err := f.coord.CoordinateRestore(context.Background(), req)
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
			require.Empty(t, f.auditChain.events, "no audit emission on input validation failure")
		})
	}
}

func TestCoordinateRestore_NonceSourceFailureIsOperational(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	// Replace the coordinator with a failing nonce source.
	bad := *f.coord
	bad.nonceSource = failingNonceSource
	_, err := bad.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
	require.Empty(t, f.auditChain.events)
}

func TestCoordinateRestore_NonceTooShortIsStructural(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	bad := *f.coord
	bad.nonceSource = tooShortNonceSource
	_, err := bad.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryStructural))
}

func TestCoordinateRestore_HandshakeAuditEmitFailureStopsFlow(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.auditChain.failKind = audit_event.KindCrossCloudHandshakeInitiated
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.Empty(t, f.transport.sentHandshakes, "no handshake dispatched if audit emission fails")
}

func TestCoordinateRestore_HandshakeTransportFailure(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.handshakeErr = errors.New("network unreachable")
	res, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
	// Handshake audit event was emitted before dispatch (audit-first-class).
	require.Len(t, f.auditChain.events, 1)
	require.Equal(t, audit_event.KindCrossCloudHandshakeInitiated, f.auditChain.events[0].Kind)
	// Handshake audit ID present in result for diagnostics.
	require.NotEmpty(t, res.HandshakeAuditID)
	// No token dispatched.
	require.Empty(t, f.transport.sentTokens)
}

func TestCoordinateRestore_DestinationReturnsEmptyEvidence(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.emptyEvidence = true
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	require.Len(t, f.auditChain.events, 1, "only handshake audit emitted before failure")
}

func TestCoordinateRestore_VerifierMismatchFailsAttestation(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	// Re-build registry with a verifier expecting a DIFFERENT measurement.
	wrongMeasure := makeMeasurement(0xDD)
	wrongMeasureFixed, err := tee.MeasurementFromBytes(wrongMeasure)
	require.NoError(t, err)
	registry2, err := tee.NewRegistry([]tee.RegistrySpec{{
		Provider: tee.ProviderSimulated,
		Spec: tee.VerifierSpec{
			Provider:            tee.ProviderSimulated,
			AttestorPubKey:      f.destProducer.PublicKey(),
			ExpectedMeasurement: wrongMeasureFixed,
		},
	}})
	require.NoError(t, err)
	bad := *f.coord
	bad.verifiers = registry2

	_, err = bad.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
	requireDenied(t, f, 1, denialAttestation)
}

func TestCoordinateRestore_PolicyDeniesRelease(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	// Replace policy with one that denies any measurement.
	denyAll, err := NewAllowListPolicy("deny-all-v1", map[tee.Provider][][]byte{})
	require.NoError(t, err)
	bad := *f.coord
	bad.policy = denyAll

	_, err = bad.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryAuthority))
	// Handshake and Attestation on record, then the refusal — never an
	// authorisation.
	require.Equal(t, audit_event.KindCrossCloudAttestationVerified, f.auditChain.events[1].Kind)
	requireDenied(t, f, 2, denialPolicy)
	var p keyReleaseDeniedPayload
	require.NoError(t, json.Unmarshal(f.auditChain.events[2].Payload, &p))
	require.Equal(t, "deny-all-v1", p.PolicyVersion)
	require.Equal(t, []byte(f.destMeasure), p.DestinationMeasurement)
	// No token dispatched on policy denial.
	require.Empty(t, f.transport.sentTokens)
}

// A refusal that cannot be recorded is still a refusal.
func TestCoordinateRestore_RefusalStandsWhenItCannotBeRecorded(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.withholdKey = true
	f.auditChain.failKind = audit_event.KindKeyReleaseDenied
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "the refusal's own class is kept: %v", err)
	require.ErrorContains(t, err, "recording the refusal failed")
	require.Empty(t, f.transport.sentTokens)
}

func TestCoordinateRestore_TokenTransportFailure(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	f.transport.tokenErr = errors.New("destination unreachable mid-flight")
	res, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
	// All three audits emitted before transport failure (audit-first-class).
	require.Len(t, f.auditChain.events, 3)
	// KeyReleaseAuditID present in result for diagnostics.
	require.NotEmpty(t, res.KeyReleaseAuditID)
}

func TestCoordinateRestore_AuditOrderingStrict(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.NoError(t, err)
	// Verify strict ordering: Handshake → Attestation → KeyRelease.
	require.Equal(t, []audit_event.Kind{
		audit_event.KindCrossCloudHandshakeInitiated,
		audit_event.KindCrossCloudAttestationVerified,
		audit_event.KindKeyReleaseAuthorized,
	}, []audit_event.Kind{
		f.auditChain.events[0].Kind,
		f.auditChain.events[1].Kind,
		f.auditChain.events[2].Kind,
	})
}

// --- Production NonceSource sanity ---------------------------------

// Sanity check that crypto/rand-backed NonceSource yields ≥ NonceMinBytes
// of distinct entropy on consecutive calls.
func TestProductionNonceSource_FreshPerCall(t *testing.T) {
	t.Parallel()
	src := func(n int) ([]byte, error) {
		b := make([]byte, n)
		_, err := rand.Read(b)
		return b, err
	}
	a, err := src(tee.NonceMinBytes)
	require.NoError(t, err)
	b, err := src(tee.NonceMinBytes)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	require.GreaterOrEqual(t, len(a), tee.NonceMinBytes)
}
