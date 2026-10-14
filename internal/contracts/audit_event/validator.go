// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_event

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

var validKinds = map[Kind]struct{}{
	// Release-side (SchemaVersion 1).
	KindRequestReceived:      {},
	KindTrustEvaluated:       {},
	KindSessionIssued:        {},
	KindSessionInvalidated:   {},
	KindDisclosureAuthorized: {},
	KindManifestIssued:       {},
	KindCandidateReceived:    {},
	KindValidationStarted:    {},
	KindValidationDimension:  {},
	KindValidationFinding:    {},
	KindValidationCompleted:  {},
	KindReleaseDecided:       {},
	KindIncidentDetected:     {},
	KindIncidentTerminated:   {},
	// Receive-side envelope/decision (SchemaVersion 2). See audit_event.go doctrine comment.
	KindDisclosureReceived:    {},
	KindReconstitutionDecided: {},
	// Receive-side validator (SchemaVersion 3). Stage G.
	KindRecvValidationStarted:   {},
	KindRecvValidationCompleted: {},
	// Cross-cloud KMS-mediated restore (SchemaVersion 4). Phase 4.
	// See ADR 0006.
	KindCrossCloudHandshakeInitiated:  {},
	KindCrossCloudAttestationVerified: {},
	KindKeyReleaseAuthorized:          {},
	KindCrossCloudRestoreCompleted:    {},
	// Recorded refusals (SchemaVersion 5). See ADR 0010.
	KindKeyReleaseDenied: {},
	// Policy-driven failover (SchemaVersion 6). See ADR 0012.
	KindFailoverDecided: {},
}

// Validate runs static consistency checks. Chain continuity (PrevHash
// matches the previous event's Hash) is NOT checked here — that is a
// responsibility of /internal/audit/chain and the op.audit_chain_integrity
// operational sub-check.
func (e AuditEvent) Validate() error {
	if e.SchemaVersion < SchemaVersionMin || e.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "audit_event: schema_version out of supported range", nil)
	}
	if e.EventID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit_event: event_id required", nil)
	}
	if _, ok := validKinds[e.Kind]; !ok {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "audit_event: unknown kind", nil)
	}
	if e.OccurredAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit_event: occurred_at required", nil)
	}
	if len(e.Payload) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit_event: payload required", nil)
	}
	if len(e.PrevHash) != HashSize {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "audit_event: prev_hash must be exactly 32 bytes (SHA-256)", nil)
	}
	if len(e.Hash) != HashSize {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "audit_event: hash must be exactly 32 bytes (SHA-256)", nil)
	}
	if e.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit_event: signing_key_id required", nil)
	}
	if len(e.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "audit_event: signature required", nil)
	}
	return nil
}
