// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cross_cloud_handshake_request

import (
	"fmt"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Validate runs static consistency checks on the request. Invariants
// enforced here:
//
//   - SchemaVersion is in the supported range.
//   - All required IDs (RequestID, DecisionID, SigningKeyID,
//     AuditEventID) are non-zero — un-evidenced handshakes are
//     structurally invalid (audit-first-class).
//   - DestinationTEEKind is one of the registered Provider constants
//     (factory.go AllProviders set).
//   - DestinationEndpoint is non-empty.
//   - HandshakeNonce is at least HandshakeNonceMinBytes.
//   - SourceMeasurement, when present, is 32, 48 or 64 bytes.
//     SourceEvidence may be empty (mutual attestation is optional).
//   - InitiatedAt is non-zero.
//   - Signature is non-empty (sign before send is required).
//
// The Validate function does NOT verify the signature itself — that
// is the job of VerifySignature, which requires a Resolver. Validate
// is the cheap structural check; VerifySignature is the cryptographic
// check.
func (r CrossCloudHandshakeRequest) Validate() error {
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(
			shared_errors.CodeSchemaVersionUnsupported,
			"cross_cloud_handshake_request: schema_version out of supported range",
			nil,
		)
	}
	if r.RequestID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: request_id required",
			nil,
		)
	}
	if r.DecisionID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: decision_id required",
			nil,
		)
	}
	if r.DestinationTEEKind == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: destination_tee_kind required",
			nil,
		)
	}
	// destination_tee_kind must be a known Provider — enforce against
	// the factory.go Provider set so a typo doesn't slip past structural
	// validation only to fail at Registry resolution time.
	if !isKnownProvider(r.DestinationTEEKind) {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("cross_cloud_handshake_request: unknown destination_tee_kind %q", r.DestinationTEEKind),
			nil,
		)
	}
	if r.DestinationEndpoint == "" {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: destination_endpoint required",
			nil,
		)
	}
	if len(r.HandshakeNonce) < HandshakeNonceMinBytes {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("cross_cloud_handshake_request: handshake_nonce must be at least %d bytes", HandshakeNonceMinBytes),
			nil,
		)
	}
	// SourceEvidence is optional (mutual attestation may be off). When
	// SourceMeasurement is provided it must be a whole measurement of a
	// supported length; partial measurements are rejected to prevent
	// type confusion at the destination.
	if len(r.SourceMeasurement) != 0 {
		if _, err := tee.MeasurementFromBytes(r.SourceMeasurement); err != nil {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("cross_cloud_handshake_request: source_measurement must be 32, 48 or 64 bytes when present; got %d", len(r.SourceMeasurement)),
				err,
			)
		}
	}
	if r.InitiatedAt.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: initiated_at required",
			nil,
		)
	}
	if r.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: signing_key_id required",
			nil,
		)
	}
	if len(r.Signature) == 0 {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: signature required",
			nil,
		)
	}
	if r.AuditEventID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: audit_event_id required (un-evidenced handshakes are invalid)",
			nil,
		)
	}
	return nil
}

func isKnownProvider(p tee.Provider) bool {
	for _, known := range tee.AllProviders() {
		if p == known {
			return true
		}
	}
	return false
}
