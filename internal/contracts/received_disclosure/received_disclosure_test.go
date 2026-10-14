// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package received_disclosure

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validFixture() ReceivedDisclosure {
	return ReceivedDisclosure{
		SchemaVersion: SchemaVersionCurrent,
		ReceivedID:    ids.ReceivedDisclosureID("rcv-0001"),
		BootstrapID:   ids.BootstrapManifestID("boot-0001"),
		SessionID:     ids.SessionID("sess-0001"),
		DisclosureID:  ids.DisclosureID("disc-0001"),
		ComponentID:   ids.ComponentID("weights-0"),
		SequenceIndex: 0,
		WireHash:      bytes.Repeat([]byte{0xAB}, WireHashSize),
		ReceivedAt:    time.Date(2026, 4, 20, 10, 5, 0, 0, time.UTC),
		AuditEventID:  ids.AuditEventID("evt-0001"),
		SigningKeyID:  ids.KeyID("recv-key-1"),
		Signature:     []byte{0xFF},
	}
}

func TestReceivedDisclosure_Validate_OK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validFixture().Validate())
}

func TestReceivedDisclosure_Validate_SchemaVersionOutOfRange(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.SchemaVersion = SchemaVersionMax + 1
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestReceivedDisclosure_Validate_WireHashWrongLength(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.WireHash = bytes.Repeat([]byte{0xAB}, WireHashSize-1)
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestReceivedDisclosure_Validate_WireHashEmpty(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.WireHash = nil
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestReceivedDisclosure_Validate_AuditEventIDRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.AuditEventID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestReceivedDisclosure_Validate_BootstrapIDRequired(t *testing.T) {
	t.Parallel()
	r := validFixture()
	r.BootstrapID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestReceivedDisclosure_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got ReceivedDisclosure
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.ReceivedID, got.ReceivedID)
	require.Equal(t, orig.BootstrapID, got.BootstrapID)
	require.Equal(t, orig.DisclosureID, got.DisclosureID)
	require.Equal(t, orig.ComponentID, got.ComponentID)
	require.Equal(t, orig.SequenceIndex, got.SequenceIndex)
	require.Equal(t, orig.WireHash, got.WireHash)
	require.Equal(t, orig.AuditEventID, got.AuditEventID)
}

func TestReceivedDisclosure_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"extra":"x"}`
	var r ReceivedDisclosure
	err := r.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
}

func TestReceivedDisclosure_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	r := validFixture()
	out, err := r.CanonicalBytes()
	require.NoError(t, err)
	require.NotContains(t, string(out), `"signature":"`)
}
