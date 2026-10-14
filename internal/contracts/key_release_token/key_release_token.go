// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package key_release_token defines the KeyReleaseToken canonical
// contract — the signed authority artifact dispatched by a release-
// side authority to a destination environment AFTER successful
// cross-cloud attestation handshake, authorising delivery of wrapped
// data-encryption keys (DEKs) to the destination.
//
// # Doctrinal role
//
// A KeyReleaseToken is the second of the two cross-cloud wire artifacts
// (the first being CrossCloudHandshakeRequest). It is dispatched only
// after:
//
//  1. The destination has produced Evidence under the source-supplied
//     handshake nonce.
//  2. The source authority's KMS Coordinator has resolved the
//     appropriate Verifier from its tee.Registry and validated the
//     Evidence (KindCrossCloudAttestationVerified audit event
//     emitted).
//  3. The source authority's KeyReleasePolicy has authorised key
//     release for the verified destination measurement
//     (KindKeyReleaseAuthorized audit event emitted).
//
// The token carries a list of WrappedKey entries — each one is a DEK
// encapsulated to the destination's attested X25519 public key via the
// production KEM (ADR 0009). Only the destination TEE — which holds the
// corresponding private key, bound to its attestation Evidence
// (REPORT_DATA = hash(pubkey ‖ nonce)) — can decapsulate it. This is the
// cryptographic gate that prevents an attacker who intercepts the token in
// transit from extracting the DEKs: even with the bytes and the (public)
// measurement in hand, the attacker lacks the TEE-held private key. (The
// legacy symmetric measurement-derived wrap it replaced was defect b — the
// measurement is a public reference value, not a secret — and remains only in
// the simulation wrapper.)
//
// AuditEventID points at the KindKeyReleaseAuthorized audit record,
// asserted before the token is dispatched. An un-evidenced token is
// structurally invalid (audit-first-class invariant).
//
// Canonical term: "Key Release Token" — Phase 4. See ADR 0006
// §"New Wire Contracts".
package key_release_token

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	// SchemaVersionMin / Max / Current are all 1 — this contract is
	// introduced fresh in Phase 4. Future extensions follow the
	// docs/doctrine/bootstrap-contracts.md §5 freezing discipline.
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1

	// PurposeSealing is the keys.Purpose value (3) reserved for
	// AES-256-GCM sealing keys. A WrappedKey delivered via Phase 4
	// MUST carry this purpose — sealing is the only Phase 4 use case
	// for cross-cloud key delivery. Mirrors keys.PurposeSealing
	// without importing /internal/vault/keys, keeping the contract
	// layer self-contained.
	PurposeSealing uint8 = 3
)

// KeyReleaseToken is the source-authority artifact that authorises
// delivery of wrapped DEKs to a verified destination.
type KeyReleaseToken struct {
	SchemaVersion uint16 `json:"schema_version"`

	// TokenID is unique per release event. The destination MUST
	// reject a token whose TokenID has already been consumed in this
	// session, defending against replay of the same authorised
	// release.
	TokenID ids.DecisionID `json:"token_id"`

	// DecisionID binds this token to a specific source-side
	// ReleaseDecision. The destination MUST refuse to apply a token
	// whose DecisionID does not match the in-flight handshake's
	// DecisionID.
	DecisionID ids.DecisionID `json:"decision_id"`

	// RequestID binds this token to a specific
	// CrossCloudHandshakeRequest exchange. The destination MUST
	// refuse to apply a token whose RequestID does not match the
	// handshake it just completed.
	RequestID ids.RequestID `json:"request_id"`

	// DestinationMeasurement is the destination's verified
	// measurement. The destination MUST reject a token whose
	// DestinationMeasurement does not equal its local TEE Producer's
	// Measurement byte-for-byte. Length: 32, 48 or 64 bytes (see
	// ValidMeasurementLen).
	DestinationMeasurement []byte `json:"destination_measurement"`

	// Wrapped is the slice of sealed DEKs being released. Order is
	// significant only for canonicalization stability; the
	// destination indexes by KeyID, not position.
	Wrapped []WrappedKey `json:"wrapped"`

	// PolicyVersion is the version string of the KeyReleasePolicy
	// that authorised this release. Recorded in the audit payload so
	// that auditors can replay the policy against historical
	// decisions.
	PolicyVersion string `json:"policy_version"`

	// AuthorizedAt is the source-authority wall-clock moment the
	// KeyReleasePolicy approved the release. Used for freshness
	// checks at the destination — a token consumed long after its
	// AuthorizedAt is suspicious and SHOULD be rejected per operator
	// policy.
	AuthorizedAt time.Time `json:"authorized_at"`

	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`

	// AuditEventID points at the KindKeyReleaseAuthorized audit
	// event that records this dispatch. An un-evidenced token is
	// structurally invalid (audit-first-class invariant).
	AuditEventID ids.AuditEventID `json:"audit_event_id"`
}

// WrappedKey holds one sealed DEK plus its routing metadata.
type WrappedKey struct {
	// KeyID identifies the key inside the destination's local
	// keystore once unwrapped. The destination registers the
	// unwrapped material under this KeyID for the existing bootstrap
	// orchestrator to consume.
	KeyID ids.KeyID `json:"key_id"`

	// Purpose declares the keys.Purpose value the unwrapped material
	// will assume in the destination's keystore. Phase 4 admits only
	// PurposeSealing (= keys.PurposeSealing). Future versions may
	// extend.
	Purpose uint8 `json:"purpose"`

	// Ciphertext is the wrapped DEK material. Under the production KEM
	// (ADR 0009) it is ephPub(32) ‖ nonce(12) ‖ AES-256-GCM ciphertext,
	// decapsulable only with the destination TEE's X25519 private key.
	Ciphertext []byte `json:"ciphertext"`

	// AAD is the additional-authenticated-data binding the wrap to
	// the token. Canonical form: SHA-256(TokenID || DestinationMeasurement || KeyID).
	// The destination's Sealer.Unseal MUST be invoked with the
	// identical AAD; mismatch causes Integrity failure.
	AAD []byte `json:"aad"`
}
