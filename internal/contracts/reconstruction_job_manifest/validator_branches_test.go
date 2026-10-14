// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction_job_manifest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Every shape rule of Validate, one field at a time.
func TestManifest_Validate_EveryRule(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		mutate func(*ReconstructionJobManifest)
		code   string
	}{
		"schema_version below range": {func(m *ReconstructionJobManifest) { m.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		"manifest_id":                {func(m *ReconstructionJobManifest) { m.ManifestID = "" }, shared_errors.CodeRequiredFieldMissing},
		"session_id":                 {func(m *ReconstructionJobManifest) { m.SessionID = "" }, shared_errors.CodeRequiredFieldMissing},
		"genome_id":                  {func(m *ReconstructionJobManifest) { m.GenomeID = "" }, shared_errors.CodeRequiredFieldMissing},
		"policy_version":             {func(m *ReconstructionJobManifest) { m.PolicyVersion = "" }, shared_errors.CodeRequiredFieldMissing},
		"disclosure_ids zero value":  {func(m *ReconstructionJobManifest) { m.DisclosureIDs = []ids.DisclosureID{""} }, shared_errors.CodeFieldValueInvalid},
		"recipient_key_id":           {func(m *ReconstructionJobManifest) { m.RecipientKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		"issued_at":                  {func(m *ReconstructionJobManifest) { m.IssuedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		"deadline":                   {func(m *ReconstructionJobManifest) { m.Deadline = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		"signing_key_id":             {func(m *ReconstructionJobManifest) { m.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		"signature":                  {func(m *ReconstructionJobManifest) { m.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := validFixture()
			tc.mutate(&m)
			err := m.Validate()
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err), "%v", err)
			require.ErrorContains(t, err, "reconstruction_job_manifest:")
		})
	}
}
