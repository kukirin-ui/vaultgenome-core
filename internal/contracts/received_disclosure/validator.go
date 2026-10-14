// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package received_disclosure

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Validate runs static consistency checks. Monotonicity of SequenceIndex
// across successive ReceivedDisclosures of the same BootstrapID is NOT
// asserted here; it is asserted in /internal/bootstrap, which holds the
// full ledger.
func (r ReceivedDisclosure) Validate() error {
	if r.SchemaVersion < SchemaVersionMin || r.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "received_disclosure: schema_version out of supported range", nil)
	}
	if r.ReceivedID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: received_id required", nil)
	}
	if r.BootstrapID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: bootstrap_id required", nil)
	}
	if r.SessionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: session_id required", nil)
	}
	if r.DisclosureID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: disclosure_id required", nil)
	}
	if r.ComponentID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: component_id required", nil)
	}
	if len(r.WireHash) != WireHashSize {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "received_disclosure: wire_hash must be exactly 32 bytes (SHA-256)", nil)
	}
	if r.ReceivedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: received_at required", nil)
	}
	// Un-evidenced acceptance is structurally invalid: receive-side
	// audit is first-class, mirroring release-side invariant #8.
	if r.AuditEventID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: audit_event_id required (un-evidenced acceptance is invalid)", nil)
	}
	if r.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: signing_key_id required", nil)
	}
	if len(r.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "received_disclosure: signature required", nil)
	}
	return nil
}
