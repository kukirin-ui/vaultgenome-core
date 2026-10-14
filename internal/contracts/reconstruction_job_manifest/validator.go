// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction_job_manifest

import (
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

var validOutputKinds = map[OutputKind]struct{}{
	OutputKindBytesFixedLength: {},
	OutputKindTokensStream:     {},
}

// Validate runs static checks. Manifest integrity (SHA-256 match against
// the disclosure bundle and signature verification) is performed by
// /internal/vault/disclosure and the op.manifest_integrity sub-check.
func (m ReconstructionJobManifest) Validate() error {
	if m.SchemaVersion < SchemaVersionMin || m.SchemaVersion > SchemaVersionMax {
		return shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, "reconstruction_job_manifest: schema_version out of supported range", nil)
	}
	if m.ManifestID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: manifest_id required", nil)
	}
	if m.SessionID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: session_id required", nil)
	}
	if m.GenomeID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: genome_id required", nil)
	}
	if m.PolicyVersion.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: policy_version required", nil)
	}
	if len(m.DisclosureIDs) == 0 {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstruction_job_manifest: disclosure_ids must be non-empty", nil)
	}
	seen := make(map[ids.DisclosureID]struct{}, len(m.DisclosureIDs))
	for _, did := range m.DisclosureIDs {
		if did.IsZero() {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstruction_job_manifest: disclosure_ids contains zero value", nil)
		}
		if _, dup := seen[did]; dup {
			return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstruction_job_manifest: disclosure_ids contains duplicate", nil)
		}
		seen[did] = struct{}{}
	}
	if _, ok := validOutputKinds[m.ExpectedOutputKind]; !ok {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstruction_job_manifest: unknown expected_output_kind", nil)
	}
	if m.ExpectedOutputMaxBytes == 0 {
		return shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "reconstruction_job_manifest: expected_output_max_bytes must be > 0", nil)
	}
	if m.RecipientKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: recipient_key_id required", nil)
	}
	if m.IssuedAt.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: issued_at required", nil)
	}
	if m.Deadline.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: deadline required", nil)
	}
	if !m.Deadline.After(m.IssuedAt) {
		return shared_errors.Structural(shared_errors.CodeCrossFieldInconsistent, "reconstruction_job_manifest: deadline must be strictly after issued_at", nil)
	}
	if m.SigningKeyID.IsZero() {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: signing_key_id required", nil)
	}
	if len(m.Signature) == 0 {
		return shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "reconstruction_job_manifest: signature required", nil)
	}
	return nil
}
