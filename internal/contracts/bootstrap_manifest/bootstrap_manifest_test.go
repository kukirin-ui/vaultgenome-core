// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_manifest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validFixture() BootstrapManifest {
	return BootstrapManifest{
		SchemaVersion: SchemaVersionCurrent,
		BootstrapID:   ids.BootstrapManifestID("boot-0001"),
		SessionID:     ids.SessionID("sess-0001"),
		ManifestID:    ids.ManifestID("man-0001"),
		GenomeID:      ids.GenomeID("agd-0001"),
		PolicyVersion: ids.PolicyVersion("pol-1"),
		ExpectedDisclosureIDs: []ids.DisclosureID{
			ids.DisclosureID("disc-0001"),
			ids.DisclosureID("disc-0002"),
		},
		ExpectedComponentIDs: []ids.ComponentID{
			ids.ComponentID("weights-0"),
			ids.ComponentID("weights-1"),
		},
		Deadline:     time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		IssuedAt:     time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID: ids.KeyID("recv-key-1"),
		Signature:    []byte{0xFF},
	}
}

func TestBootstrapManifest_Validate_OK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validFixture().Validate())
}

func TestBootstrapManifest_Validate_SchemaVersionOutOfRange(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.SchemaVersion = SchemaVersionMax + 1
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_Validate_BootstrapIDRequired(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.BootstrapID = ""
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_Validate_ExpectedDisclosureIDsNonEmpty(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.ExpectedDisclosureIDs = nil
	b.ExpectedComponentIDs = nil
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_Validate_ParallelLengths(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.ExpectedComponentIDs = b.ExpectedComponentIDs[:1]
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_Validate_DuplicateDisclosureIDs(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.ExpectedDisclosureIDs[1] = b.ExpectedDisclosureIDs[0]
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_Validate_EmptyDisclosureSlot(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.ExpectedDisclosureIDs[1] = ""
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_Validate_EmptyComponentSlot(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.ExpectedComponentIDs[1] = ""
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_Validate_DeadlineAfterIssuedAt(t *testing.T) {
	t.Parallel()
	b := validFixture()
	b.Deadline = b.IssuedAt
	err := b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	b.Deadline = b.IssuedAt.Add(-time.Minute)
	err = b.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestBootstrapManifest_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got BootstrapManifest
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.BootstrapID, got.BootstrapID)
	require.Equal(t, orig.SessionID, got.SessionID)
	require.Equal(t, orig.ManifestID, got.ManifestID)
	require.Equal(t, orig.ExpectedDisclosureIDs, got.ExpectedDisclosureIDs)
	require.Equal(t, orig.ExpectedComponentIDs, got.ExpectedComponentIDs)
}

func TestBootstrapManifest_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"extra":"x"}`
	var b BootstrapManifest
	err := b.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
}

func TestBootstrapManifest_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	b := validFixture()
	out, err := b.CanonicalBytes()
	require.NoError(t, err)
	require.NotContains(t, string(out), `"signature":"`)
}
