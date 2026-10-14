// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_message

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validFixture() DisclosureMessage {
	nonce := make([]byte, GCMNonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	return DisclosureMessage{
		SchemaVersion:  SchemaVersionCurrent,
		DisclosureID:   ids.DisclosureID("disc-0001"),
		SessionID:      ids.SessionID("sess-0001"),
		ComponentID:    ids.ComponentID("comp-core"),
		PolicyVersion:  ids.PolicyVersion("v1"),
		SequenceIndex:  0,
		SealedPayload:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Nonce:          nonce,
		RecipientKeyID: ids.KeyID("recipient-1"),
		AuthorizedAt:   time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID:   ids.KeyID("vault-key-1"),
		Signature:      []byte{0x01},
	}
}

func TestDisclosureMessage_Validate_OK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validFixture().Validate())
}

func TestDisclosureMessage_NonceSizeMustBe12(t *testing.T) {
	t.Parallel()
	d := validFixture()
	d.Nonce = make([]byte, GCMNonceSize-1)
	err := d.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))

	d.Nonce = make([]byte, GCMNonceSize+4)
	err = d.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestDisclosureMessage_EmptyPayloadRejected(t *testing.T) {
	t.Parallel()
	d := validFixture()
	d.SealedPayload = nil
	err := d.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestDisclosureMessage_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got DisclosureMessage
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.DisclosureID, got.DisclosureID)
	require.Equal(t, orig.SequenceIndex, got.SequenceIndex)
	require.Equal(t, orig.SealedPayload, got.SealedPayload)
	require.Equal(t, orig.Nonce, got.Nonce)
}

func TestDisclosureMessage_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"extra":"x"}`
	var d DisclosureMessage
	err := d.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
}

func TestDisclosureMessage_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	d := validFixture()
	b, err := d.CanonicalBytes()
	require.NoError(t, err)
	// Signature was [0x01] -> base64 "AQ==". Must not appear.
	require.NotContains(t, string(b), `"signature":"AQ==`)
}
