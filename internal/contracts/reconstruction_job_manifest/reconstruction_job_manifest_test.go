// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction_job_manifest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validFixture() ReconstructionJobManifest {
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	return ReconstructionJobManifest{
		SchemaVersion:          SchemaVersionCurrent,
		ManifestID:             ids.ManifestID("man-0001"),
		SessionID:              ids.SessionID("sess-0001"),
		GenomeID:               ids.GenomeID("genome-alpha"),
		PolicyVersion:          ids.PolicyVersion("v1"),
		DisclosureIDs:          []ids.DisclosureID{"disc-0001", "disc-0002", "disc-0003"},
		ExpectedOutputKind:     OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 4096,
		RecipientKeyID:         ids.KeyID("recipient-1"),
		Deadline:               now.Add(10 * time.Minute),
		IssuedAt:               now,
		SigningKeyID:           ids.KeyID("vault-key-1"),
		Signature:              []byte{0x7F},
	}
}

func TestManifest_Validate_OK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validFixture().Validate())
}

func TestManifest_DuplicateDisclosureIDsRejected(t *testing.T) {
	t.Parallel()
	m := validFixture()
	m.DisclosureIDs = []ids.DisclosureID{"d1", "d2", "d1"}
	err := m.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestManifest_EmptyDisclosureIDsRejected(t *testing.T) {
	t.Parallel()
	m := validFixture()
	m.DisclosureIDs = nil
	err := m.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestManifest_DeadlineNotAfterIssuedAt(t *testing.T) {
	t.Parallel()
	m := validFixture()
	m.Deadline = m.IssuedAt
	err := m.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	m.Deadline = m.IssuedAt.Add(-time.Second)
	err = m.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestManifest_UnknownOutputKindRejected(t *testing.T) {
	t.Parallel()
	m := validFixture()
	m.ExpectedOutputKind = OutputKind("unknown-kind")
	err := m.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestManifest_ExpectedOutputMaxBytesZeroRejected(t *testing.T) {
	t.Parallel()
	m := validFixture()
	m.ExpectedOutputMaxBytes = 0
	err := m.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestManifest_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got ReconstructionJobManifest
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.ManifestID, got.ManifestID)
	require.Equal(t, orig.DisclosureIDs, got.DisclosureIDs)
	require.Equal(t, orig.ExpectedOutputKind, got.ExpectedOutputKind)
	require.Equal(t, orig.ExpectedOutputMaxBytes, got.ExpectedOutputMaxBytes)
}

func TestManifest_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"extra":true}`
	var m ReconstructionJobManifest
	err := m.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
}
