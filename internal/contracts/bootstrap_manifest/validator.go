// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_manifest

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Validate runs static consistency checks. Cross-manifest agreement with
// the release-side ReconstructionJobManifest (same SessionID,
// PolicyVersion, same ordered DisclosureID set) is NOT asserted here; it
// is asserted in /internal/bootstrap, which is the only place that holds
// both artifacts at once.
func (b BootstrapManifest) Validate() error {
	if b.SchemaVersion < SchemaVersionMin || b.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "bootstrap_manifest: schema_version out of supported range", nil)
	}
	if b.BootstrapID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: bootstrap_id required", nil)
	}
	if b.SessionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: session_id required", nil)
	}
	if b.ManifestID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: manifest_id required", nil)
	}
	if b.GenomeID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: genome_id required", nil)
	}
	if b.PolicyVersion.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: policy_version required", nil)
	}
	if len(b.ExpectedDisclosureIDs) == 0 {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "bootstrap_manifest: expected_disclosure_ids must be non-empty", nil)
	}
	if len(b.ExpectedComponentIDs) != len(b.ExpectedDisclosureIDs) {
		return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "bootstrap_manifest: expected_component_ids length must equal expected_disclosure_ids length", nil)
	}
	// Disclosure and component slots must be populated, and the
	// disclosure list must contain no duplicates — a duplicate would
	// either indicate a drafting error in the manifest, or an
	// adversarial attempt to double-seat a disclosure under two
	// components, which the doctrine forbids.
	seenDisclosures := make(map[string]struct{}, len(b.ExpectedDisclosureIDs))
	for i, did := range b.ExpectedDisclosureIDs {
		if did.IsZero() {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "bootstrap_manifest: expected_disclosure_ids contains empty slot", nil)
		}
		if _, dup := seenDisclosures[did.String()]; dup {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "bootstrap_manifest: expected_disclosure_ids contains duplicate", nil)
		}
		seenDisclosures[did.String()] = struct{}{}
		if b.ExpectedComponentIDs[i].IsZero() {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "bootstrap_manifest: expected_component_ids contains empty slot", nil)
		}
	}
	if b.IssuedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: issued_at required", nil)
	}
	if b.Deadline.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: deadline required", nil)
	}
	if !b.Deadline.After(b.IssuedAt) {
		return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "bootstrap_manifest: deadline must be strictly after issued_at", nil)
	}
	if b.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: signing_key_id required", nil)
	}
	if len(b.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "bootstrap_manifest: signature required", nil)
	}
	return nil
}
