// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package cross_cloud_handshake_request defines the
// CrossCloudHandshakeRequest canonical contract — the signed authority
// message dispatched by a release-side authority to a destination
// environment to initiate cross-cloud KMS-mediated restore.
//
// # Doctrinal role
//
// A CrossCloudHandshakeRequest is the entry artifact of the Phase 4
// optional cross-cloud orchestration mode. It is dispatched between
// StateRelease and StateAuditChainClosed when the operator-supplied
// recovery request opts into cross-cloud delivery. The request carries:
//
//   - The DecisionID of the source-side ReleaseDecision being shipped.
//   - The destination's expected TEE family and endpoint hint.
//   - A fresh handshake nonce (≥ 16 bytes) that the destination MUST
//     include in its attestation Evidence response.
//   - Optionally, the source authority's own attestation Evidence so
//     the destination can perform mutual attestation.
//
// The contract is signed under keys.PurposeSigningAuthority by the
// source authority's signing key. The destination verifies the
// signature against the source authority's pre-loaded public key
// (exchanged out-of-band per ADR 0006 §"Migration Path").
//
// AuditEventID points at the KindCrossCloudHandshakeInitiated audit
// record, asserted before the request is dispatched. An un-evidenced
// handshake request is structurally invalid (audit-first-class
// invariant — Doctrinal Invariant #8).
//
// Canonical term: "Cross-Cloud Handshake Request" — Phase 4. See
// ADR 0006 §"New Wire Contracts".
package cross_cloud_handshake_request

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

const (
	// SchemaVersionMin / Max / Current are all 1 — this contract is
	// introduced fresh in Phase 4. Future extensions follow the
	// docs/doctrine/bootstrap-contracts.md §5 freezing discipline:
	// safe additions bump Max (not Min); reordering or reinterpretation
	// bumps Min and Current together.
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1

	// HandshakeNonceMinBytes is the minimum acceptable length for the
	// handshake nonce. Aligned with tee.NonceMinBytes (RFC 9334 §10.1).
	HandshakeNonceMinBytes = tee.NonceMinBytes
)

// CrossCloudHandshakeRequest is the source-authority artifact that
// initiates a cross-cloud restore handshake.
type CrossCloudHandshakeRequest struct {
	SchemaVersion uint16 `json:"schema_version"`

	// RequestID correlates the handshake exchange across all four
	// cross-cloud audit kinds. Independent of any release-side
	// RecoveryRequest.RequestID.
	RequestID ids.RequestID `json:"request_id"`

	// DecisionID binds this handshake to a specific source-side
	// ReleaseDecision. The destination MUST refuse to consume a
	// later KeyReleaseToken whose DecisionID does not match.
	DecisionID ids.DecisionID `json:"decision_id"`

	// DestinationTEEKind is the TEE family the destination is
	// expected to be running. The source authority resolves the
	// matching Verifier from its tee.Registry under this key when the
	// destination's Evidence arrives. A mismatch between this field
	// and the destination's actual measurement vendor is an Integrity
	// failure.
	DestinationTEEKind tee.Provider `json:"destination_tee_kind"`

	// DestinationEndpoint is the operator-supplied transport hint
	// (e.g., "https://acp-bootstrap.example.com:8443"). Not
	// authenticated by this contract — transport-layer authentication
	// (mTLS) is the operator's responsibility.
	DestinationEndpoint string `json:"destination_endpoint"`

	// HandshakeNonce is fresh randomness (≥ HandshakeNonceMinBytes)
	// the destination MUST echo into its attestation Evidence. Replay
	// of a prior handshake response is rejected because the embedded
	// nonce will not match.
	HandshakeNonce []byte `json:"handshake_nonce"`

	// SourceEvidence is the optional attestation Evidence from the
	// source authority's own TEE. When non-empty the destination
	// SHOULD verify it before responding (mutual attestation).
	// Encoded as raw bytes; the destination treats it as an opaque
	// blob to be passed to the appropriate Verifier.
	SourceEvidence []byte `json:"source_evidence,omitempty"`

	// SourceMeasurement is the source authority's claimed
	// measurement, included for canonicalization stability. The
	// destination's verification of SourceEvidence yields a
	// measurement that MUST equal this field byte-for-byte. Length:
	// 32, 48 or 64 bytes, as tee.MeasurementFromBytes accepts.
	SourceMeasurement []byte `json:"source_measurement,omitempty"`

	// InitiatedAt is the source-authority wall-clock moment of
	// dispatch.
	InitiatedAt time.Time `json:"initiated_at"`

	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`

	// AuditEventID points at the KindCrossCloudHandshakeInitiated
	// audit event that records this dispatch. An un-evidenced
	// request is structurally invalid.
	AuditEventID ids.AuditEventID `json:"audit_event_id"`
}
