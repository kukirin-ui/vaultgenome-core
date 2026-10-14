// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	cchr "github.com/vault-genome/vaultgenome-core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// HandshakeResponse is the destination's reply to a
// CrossCloudHandshakeRequest. It mirrors the source-side
// kms.HandshakeResponse type but is defined here as a distinct type
// so the receiver package does not appear in source-side import
// graphs (Doctrinal Invariant #1: import-graph enforcement).
type HandshakeResponse struct {
	Evidence        []byte
	MeasurementHint []byte
	// RecipientPublicKey is the X25519 key generated for this handshake.
	// Evidence was quoted over kms.RecipientChallenge(RecipientPublicKey,
	// nonce), which is what lets the source trust it.
	RecipientPublicKey []byte
}

// KeyRegistrar is the destination-side keystore abstraction used to
// register unwrapped DEKs. The MVP implementation is
// keys.InMemoryStore (its RegisterSealing(kid, material) method
// matches this interface). Production deployments wrap a
// hardware-backed keystore (HSM, TEE-bound storage).
type KeyRegistrar interface {
	RegisterSealing(kid ids.KeyID, material []byte) error
}

// Defaults for the outstanding-handshake table.
const (
	// DefaultPendingTTL is how long a handshake's recipient key waits for
	// its token before it is destroyed. A restore dispatches the token
	// right after verifying the handshake, so minutes are generous.
	DefaultPendingTTL = 5 * time.Minute
	// DefaultMaxPending caps outstanding handshakes. Handshakes are signed
	// by the source authority, so the cap bounds memory against a replay
	// flood of captured requests rather than against strangers.
	DefaultMaxPending = 64
)

// Config bundles the Receiver's dependencies.
type Config struct {
	// SourceAuthorityKeys resolves the source authority's signing
	// public key. The Receiver looks up the SigningKeyID embedded
	// in each incoming handshake / token to verify the Ed25519
	// signature. Required.
	SourceAuthorityKeys keys.Resolver

	// LocalTEE is the destination's TEE producer, used to quote over
	// each handshake's key-binding challenge. Required.
	LocalTEE tee.Producer

	// Kind is the TEE family LocalTEE belongs to. A handshake that
	// declares any other destination_tee_kind is refused: the source
	// would verify our Evidence with the wrong verifier. Required.
	Kind tee.Provider

	// Registrar receives unwrapped DEKs and adds them to the local
	// keystore for subsequent disclosure-message processing. Required.
	Registrar KeyRegistrar

	// PendingTTL and MaxPending bound the outstanding-handshake table;
	// zero selects DefaultPendingTTL / DefaultMaxPending.
	PendingTTL time.Duration
	MaxPending int

	// Clock drives key expiry; nil selects the system clock.
	Clock shared_time.Clock

	// OnDelivery, if set, is told about every token whose keys were all
	// registered, before HandleKeyReleaseToken returns. It must not
	// block: it runs on the request's goroutine. acp-bootstrap hands it
	// to the genome restorer.
	OnDelivery func(Delivery)
}

// Delivery describes a key-release token the Receiver accepted.
type Delivery struct {
	DecisionID ids.DecisionID
	RequestID  ids.RequestID
	TokenID    ids.DecisionID
	KeyIDs     []ids.KeyID
	At         time.Time
}

// Receiver handles cross-cloud handshake requests and key-release
// tokens on the destination side. Construct via NewReceiver; the
// returned Receiver is safe for concurrent use.
//
// Every handshake gets its own X25519 key pair, generated here and kept
// only in memory until the matching token consumes it, or until it
// expires. The DEKs of one restore therefore stay confidential even if
// a later handshake's key, or the host after the restore, is
// compromised.
type Receiver struct {
	sourceKeys keys.Resolver
	localTEE   tee.Producer
	kind       tee.Provider
	registrar  KeyRegistrar
	clock      shared_time.Clock
	ttl        time.Duration
	maxPending int
	onDelivery func(Delivery)

	// localMeasurement is cached at construction; the local TEE's
	// measurement does not change for the life of the daemon
	// process (a measurement change implies a code-update event,
	// which restarts the daemon).
	localMeasurement tee.Measurement

	mu      sync.Mutex
	pending map[ids.RequestID]*pendingKey

	// delivered remembers, per kid, the SHA-256 of the key this
	// receiver registered, so a retried delivery of the same key (its
	// first answer lost) succeeds instead of tripping the keystore's
	// duplicate check. A different key under that kid still fails.
	delivered map[ids.KeyID][32]byte
}

// pendingKey is one handshake's recipient key, waiting for its token.
type pendingKey struct {
	priv       []byte
	decisionID ids.DecisionID
	expires    time.Time
}

// NewReceiver validates the Config and returns a ready-to-use
// Receiver.
func NewReceiver(cfg Config) (*Receiver, error) {
	if cfg.SourceAuthorityKeys == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud.NewReceiver: SourceAuthorityKeys required", nil)
	}
	if cfg.LocalTEE == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud.NewReceiver: LocalTEE required", nil)
	}
	if cfg.Registrar == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud.NewReceiver: Registrar required", nil)
	}
	if cfg.Kind == "" {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "crosscloud.NewReceiver: Kind required", nil)
	}
	if _, err := tee.ParseProvider(string(cfg.Kind)); err != nil {
		return nil, err
	}
	if cfg.PendingTTL < 0 || cfg.MaxPending < 0 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "crosscloud.NewReceiver: PendingTTL and MaxPending must not be negative", nil)
	}
	r := &Receiver{
		sourceKeys:       cfg.SourceAuthorityKeys,
		localTEE:         cfg.LocalTEE,
		kind:             cfg.Kind,
		registrar:        cfg.Registrar,
		clock:            cfg.Clock,
		ttl:              cfg.PendingTTL,
		maxPending:       cfg.MaxPending,
		onDelivery:       cfg.OnDelivery,
		localMeasurement: cfg.LocalTEE.Measurement(),
		pending:          make(map[ids.RequestID]*pendingKey),
		delivered:        make(map[ids.KeyID][32]byte),
	}
	if r.clock == nil {
		r.clock = shared_time.NewSystemClock()
	}
	if r.ttl == 0 {
		r.ttl = DefaultPendingTTL
	}
	if r.maxPending == 0 {
		r.maxPending = DefaultMaxPending
	}
	return r, nil
}

// HandleHandshakeRequest validates a CrossCloudHandshakeRequest from
// a source authority and answers with a fresh recipient key and
// Evidence that binds it.
//
// Steps, in order:
//
//  1. Structural validation via cchr.Validate.
//  2. The declared DestinationTEEKind must be the Kind this Receiver
//     was provisioned with.
//  3. Source signature verified against the source authority's
//     pre-loaded public key. Nothing below runs for an unsigned or
//     forged request.
//  4. A new X25519 key pair is generated and recorded against the
//     request ID; a request ID already outstanding is a replay and is
//     refused rather than allowed to replace the key.
//  5. Local Evidence is quoted over kms.RecipientChallenge(pub, nonce).
//
// The returned HandshakeResponse carries the Evidence, the public key
// and a MeasurementHint (informational; the source re-derives the
// measurement from the Evidence).
func (r *Receiver) HandleHandshakeRequest(
	req cchr.CrossCloudHandshakeRequest,
) (HandshakeResponse, error) {
	if err := req.Validate(); err != nil {
		return HandshakeResponse{}, err
	}
	if req.DestinationTEEKind != r.kind {
		return HandshakeResponse{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("crosscloud.HandleHandshakeRequest: request is for a %q destination; this destination runs %q", req.DestinationTEEKind, r.kind),
			nil,
		)
	}
	if err := req.VerifySignature(r.sourceKeys); err != nil {
		return HandshakeResponse{}, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crosscloud.HandleHandshakeRequest: source authority signature invalid",
			err,
		)
	}

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return HandshakeResponse{}, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"crosscloud.HandleHandshakeRequest: recipient key generation failed",
			err,
		)
	}
	pub := key.PublicKey().Bytes()
	if err := r.remember(req.RequestID, req.DecisionID, key.Bytes()); err != nil {
		return HandshakeResponse{}, err
	}

	evidence, err := r.localTEE.Quote(kms.RecipientChallenge(pub, req.HandshakeNonce))
	if err != nil {
		r.forget(req.RequestID)
		return HandshakeResponse{}, shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			"crosscloud.HandleHandshakeRequest: local Quote failed",
			err,
		)
	}
	measurementCopy := make([]byte, len(r.localMeasurement))
	copy(measurementCopy, r.localMeasurement[:])
	return HandshakeResponse{
		Evidence:           evidence,
		MeasurementHint:    measurementCopy,
		RecipientPublicKey: pub,
	}, nil
}

// HandleKeyReleaseToken validates a KeyReleaseToken and, on success,
// unwraps each WrappedKey and registers the result in the local
// keystore. The number of newly-registered keys is returned for
// caller diagnostics.
//
// Validation steps (in order):
//
//  1. Structural validation via krt.Validate.
//  2. Source signature verified against pre-loaded source authority key.
//  3. token.DestinationMeasurement byte-equality with local Measurement
//     (the policy gate: the source released to this workload).
//  4. The recipient key of the handshake named by token.RequestID is
//     taken out of the table (single use, whatever happens next); the
//     token's DecisionID must match that handshake's.
//  5. For each WrappedKey:
//     a. Purpose must equal krt.PurposeSealing.
//     b. AAD must equal the canonical SHA-256(TokenID ||
//     DestinationMeasurement || KeyID) derived locally.
//     c. The X25519 KEM opens the ciphertext with the handshake key.
//     d. Plaintext registered via Registrar.RegisterSealing(KeyID).
//
// Keys registered before a later WrappedKey fails are NOT rolled back
// (the keystore allows overwriting, so a partial registration is
// benign — the source-side coordinator will re-issue or surface to
// the operator). The handshake key is destroyed either way, so a
// retry needs a new handshake.
func (r *Receiver) HandleKeyReleaseToken(token krt.KeyReleaseToken) (int, error) {
	if err := token.Validate(); err != nil {
		return 0, err
	}
	if err := token.VerifySignature(r.sourceKeys); err != nil {
		return 0, shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"crosscloud.HandleKeyReleaseToken: source authority signature invalid",
			err,
		)
	}
	if !bytes.Equal(token.DestinationMeasurement, r.localMeasurement[:]) {
		return 0, shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			"crosscloud.HandleKeyReleaseToken: token DestinationMeasurement does not match local TEE Measurement",
			nil,
		)
	}

	pk, err := r.take(token.RequestID)
	if err != nil {
		return 0, err
	}
	defer zeroize(pk.priv)
	if token.DecisionID != pk.decisionID {
		return 0, shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			fmt.Sprintf("crosscloud.HandleKeyReleaseToken: token decision %q does not match the handshake's decision %q", token.DecisionID, pk.decisionID),
			nil,
		)
	}

	registered := 0
	for i, w := range token.Wrapped {
		if w.Purpose != krt.PurposeSealing {
			return registered, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("crosscloud.HandleKeyReleaseToken: wrapped[%d].Purpose must be PurposeSealing", i),
				nil,
			)
		}
		expectedAAD := canonicalWrapAAD(token.TokenID, token.DestinationMeasurement, w.KeyID)
		if !bytes.Equal(w.AAD, expectedAAD) {
			return registered, shared_errors.Integrity(
				shared_errors.CodeSignatureInvalid,
				fmt.Sprintf("crosscloud.HandleKeyReleaseToken: wrapped[%d].AAD does not match canonical derivation", i),
				nil,
			)
		}
		plaintext, err := kms.X25519KeyUnwrapper{}.Unwrap(w.Ciphertext, pk.priv, w.AAD)
		if err != nil {
			return registered, err
		}
		if err := r.register(w.KeyID, plaintext); err != nil {
			zeroize(plaintext)
			// Keep the keystore's classification: a conflicting key under
			// an existing kid is the sender's problem, not an outage.
			return registered, fmt.Errorf("crosscloud.HandleKeyReleaseToken: registering wrapped[%d] (kid %q): %w", i, w.KeyID, err)
		}
		registered++
		// Best-effort zeroize of the local plaintext copy. The
		// caller's keystore now owns the material; the local stack
		// frame should not leave plaintext behind.
		zeroize(plaintext)
	}
	if r.onDelivery != nil {
		d := Delivery{DecisionID: token.DecisionID, RequestID: token.RequestID, TokenID: token.TokenID, At: r.clock.Now().UTC()}
		for _, w := range token.Wrapped {
			d.KeyIDs = append(d.KeyIDs, w.KeyID)
		}
		r.onDelivery(d)
	}
	return registered, nil
}

// register hands key to the registrar once per kid; the same key under
// the same kid again is accepted without registering it twice.
func (r *Receiver) register(kid ids.KeyID, key []byte) error {
	digest := sha256OfBytes(key)
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.delivered[kid]; ok && subtle.ConstantTimeCompare(prev[:], digest[:]) == 1 {
		return nil
	}
	if err := r.registrar.RegisterSealing(kid, key); err != nil {
		return err
	}
	r.delivered[kid] = digest
	return nil
}

// LocalMeasurement returns a defensive copy of the destination's
// local TEE Measurement. Useful for diagnostic logs and for
// external tools that need to compare the measurement against
// operator-supplied allow-lists.
func (r *Receiver) LocalMeasurement() []byte {
	out := make([]byte, len(r.localMeasurement))
	copy(out, r.localMeasurement[:])
	return out
}

// Outstanding reports how many handshakes are waiting for their token.
func (r *Receiver) Outstanding() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.purgeExpiredLocked()
	return len(r.pending)
}

// remember records a handshake's key. A request ID that is already
// outstanding is refused, not replaced: replacing it would let a
// replayed handshake invalidate the key the source is about to wrap to.
func (r *Receiver) remember(id ids.RequestID, decision ids.DecisionID, priv []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.purgeExpiredLocked()
	if _, dup := r.pending[id]; dup {
		zeroize(priv)
		return shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			fmt.Sprintf("crosscloud.HandleHandshakeRequest: request %q already has an outstanding handshake (replay?)", id),
			nil,
		)
	}
	if len(r.pending) >= r.maxPending {
		zeroize(priv)
		return shared_errors.Operational(
			shared_errors.CodeResourceExhausted,
			fmt.Sprintf("crosscloud.HandleHandshakeRequest: %d handshakes already outstanding", len(r.pending)),
			nil,
		)
	}
	r.pending[id] = &pendingKey{
		priv:       priv,
		decisionID: decision,
		expires:    r.clock.Now().Add(r.ttl),
	}
	return nil
}

// take removes and returns the key for id. It is gone afterwards even if
// the caller then fails: a handshake key opens at most one token.
func (r *Receiver) take(id ids.RequestID) (*pendingKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pk, ok := r.pending[id]
	delete(r.pending, id)
	if ok && !r.clock.Now().Before(pk.expires) {
		zeroize(pk.priv)
		ok = false
	}
	if !ok {
		return nil, shared_errors.Integrity(
			shared_errors.CodeAttestationDenied,
			fmt.Sprintf("crosscloud.HandleKeyReleaseToken: no outstanding handshake for request %q (expired, already used, or never issued)", id),
			nil,
		)
	}
	return pk, nil
}

func (r *Receiver) forget(id ids.RequestID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pk, ok := r.pending[id]; ok {
		zeroize(pk.priv)
		delete(r.pending, id)
	}
}

func (r *Receiver) purgeExpiredLocked() {
	now := r.clock.Now()
	for id, pk := range r.pending {
		if !now.Before(pk.expires) {
			zeroize(pk.priv)
			delete(r.pending, id)
		}
	}
}

// canonicalWrapAAD MUST mirror exactly the AAD derivation used on the
// source-side coordinator (kms.canonicalWrapAAD). They are
// independent implementations of the same canonical formula:
//
//	AAD = SHA-256(TokenID || DestinationMeasurement || KeyID)
//
// The duplication is intentional: source and destination derive the
// AAD from independent codepaths and compare byte-for-byte, so a
// drift in either implementation surfaces immediately as an
// Integrity-class rejection at the destination.
func canonicalWrapAAD(tokenID ids.DecisionID, destinationMeasurement []byte, keyID ids.KeyID) []byte {
	buf := make([]byte, 0, len(tokenID)+len(destinationMeasurement)+len(keyID))
	buf = append(buf, []byte(tokenID)...)
	buf = append(buf, destinationMeasurement...)
	buf = append(buf, []byte(keyID)...)
	h := sha256OfBytes(buf)
	return h[:]
}

// zeroize overwrites the slice with zero bytes. Best-effort defense
// against key material lingering in memory after use.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
