// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"context"

	cchr "github.com/vault-genome/vaultgenome-core/internal/contracts/cross_cloud_handshake_request"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
)

// HandshakeResponse is the destination's reply to a
// CrossCloudHandshakeRequest. The destination signs nothing here at
// the wire level (the response is authenticated by the embedded
// Evidence — only a TEE matching the declared kind can produce
// verifiable Evidence under the source-supplied nonce).
//
// Carrying the destination's claimed Measurement here is purely
// informational — the source authority's Verifier re-derives the
// Measurement from Evidence and uses that derived value as ground
// truth.
type HandshakeResponse struct {
	// Evidence is the destination's TEE-signed attestation blob,
	// produced under the source-supplied handshake nonce. Opaque
	// at this layer; the source's Verifier (resolved from
	// tee.Registry by DestinationTEEKind) parses it.
	Evidence []byte

	// MeasurementHint is the destination's claimed measurement
	// (32 bytes when present). Never trusted; used only for
	// diagnostic mismatch detection.
	MeasurementHint []byte

	// RecipientPublicKey is the X25519 key the destination TEE generated
	// for this handshake. It is trusted only because the Evidence was
	// quoted over RecipientChallenge(RecipientPublicKey, nonce); the
	// Coordinator verifies exactly that before wrapping anything to it.
	RecipientPublicKey []byte
}

// Transport is the wire-delivery abstraction the Coordinator uses to
// reach a destination's CrossCloudReceiver. Production deployments
// implement this with TLS-mutual-authenticated HTTP/2; tests use
// in-memory mock implementations.
//
// Transport is intentionally minimal — the Coordinator handles all
// signing, audit-chain interaction, and policy enforcement; the
// transport only moves bytes.
type Transport interface {
	// SendHandshakeRequest dispatches a signed handshake request to
	// the destination at the given endpoint, blocking until the
	// destination's HandshakeResponse arrives or the context is
	// cancelled. Network and protocol errors surface as returned
	// errors.
	SendHandshakeRequest(
		ctx context.Context,
		endpoint string,
		req cchr.CrossCloudHandshakeRequest,
	) (HandshakeResponse, error)

	// SendKeyReleaseToken dispatches a signed token to the
	// destination at the given endpoint. The destination's response
	// is fire-and-forget at this layer — completion signalling is a
	// separate out-of-band channel. Production transports MAY return
	// an HTTP-style ack to the caller but the Coordinator does not
	// require it.
	SendKeyReleaseToken(
		ctx context.Context,
		endpoint string,
		token krt.KeyReleaseToken,
	) error
}
