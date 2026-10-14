// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_event

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validFixture() AuditEvent {
	prev := bytes.Repeat([]byte{0x00}, HashSize)
	hash := bytes.Repeat([]byte{0xAA}, HashSize)
	return AuditEvent{
		SchemaVersion: SchemaVersionCurrent,
		EventID:       ids.AuditEventID("evt-0001"),
		Kind:          KindRequestReceived,
		OccurredAt:    time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SessionID:     ids.SessionID("sess-0001"),
		RequestID:     ids.RequestID("req-0001"),
		Payload:       []byte(`{"note":"entry point"}`),
		PrevHash:      prev,
		Hash:          hash,
		SigningKeyID:  ids.KeyID("audit-key-1"),
		Signature:     []byte{0xDE, 0xAD},
	}
}

func TestAuditEvent_Validate_OK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validFixture().Validate())
}

func TestAuditEvent_HashSizeEnforced(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.Hash = bytes.Repeat([]byte{0x00}, HashSize-1)
	err := e.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestAuditEvent_PrevHashSizeEnforced(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.PrevHash = []byte{0x00}
	err := e.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestAuditEvent_UnknownKindRejected(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.Kind = Kind("GOSSIP")
	err := e.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestAuditEvent_PayloadRequired(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.Payload = nil
	err := e.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestAuditEvent_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got AuditEvent
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.Kind, got.Kind)
	require.Equal(t, orig.EventID, got.EventID)
	require.Equal(t, orig.PrevHash, got.PrevHash)
	require.Equal(t, orig.Hash, got.Hash)
}

func TestAuditEvent_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"rumor":"x"}`
	var e AuditEvent
	err := e.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
}

func TestAuditEvent_CanonicalBytes_ExcludesHashAndSignature(t *testing.T) {
	t.Parallel()
	e := validFixture()
	b, err := e.CanonicalBytes()
	require.NoError(t, err)
	// Signature base64 "3q0=" and Hash base64-encoded bytes must be absent.
	require.NotContains(t, string(b), `"signature":"3q0=`)
	// The Hash was all 0xAA (32 bytes) → base64 "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=".
	// Easier: check that the string "qqqqqqqqqq" does not appear.
	require.NotContains(t, string(b), "qqqqqqqqqq")
}

func TestAuditEvent_AllKindsAreValidated(t *testing.T) {
	t.Parallel()
	all := []Kind{
		// Release-side (SchemaVersion 1).
		KindRequestReceived, KindTrustEvaluated, KindSessionIssued,
		KindSessionInvalidated, KindDisclosureAuthorized, KindManifestIssued,
		KindCandidateReceived, KindValidationStarted, KindValidationDimension,
		KindValidationFinding, KindValidationCompleted, KindReleaseDecided,
		KindIncidentDetected, KindIncidentTerminated,
		// Receive-side envelope/decision (SchemaVersion 2).
		KindDisclosureReceived, KindReconstitutionDecided,
		// Receive-side validator (SchemaVersion 3). Stage G.
		KindRecvValidationStarted, KindRecvValidationCompleted,
		// Cross-cloud KMS-mediated restore (SchemaVersion 4). Phase 4.
		// See ADR 0006.
		KindCrossCloudHandshakeInitiated, KindCrossCloudAttestationVerified,
		KindKeyReleaseAuthorized, KindCrossCloudRestoreCompleted,
		// Recorded refusals (SchemaVersion 5). See ADR 0010.
		KindKeyReleaseDenied,
		// Policy-driven failover (SchemaVersion 6). See ADR 0012.
		KindFailoverDecided,
	}
	for _, k := range all {
		t.Run(string(k), func(t *testing.T) {
			e := validFixture()
			e.Kind = k
			require.NoError(t, e.Validate())
		})
	}
}

// TestAuditEvent_SchemaVersion_MinBackwardCompatible asserts that a v1
// writer is still readable by a v4 reader — the whole point of holding
// SchemaVersionMin at 1 when bumping SchemaVersionMax over time.
func TestAuditEvent_SchemaVersion_MinBackwardCompatible(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.SchemaVersion = 1
	require.NoError(t, e.Validate())
}

// TestAuditEvent_SchemaVersion_V2BackwardCompatible asserts that a v2
// writer is still readable by a v4 reader. v2 is the schema that Stage
// F.2 froze for receive-side envelope/decision kinds; subsequent Kind
// additions do not break v2 records.
func TestAuditEvent_SchemaVersion_V2BackwardCompatible(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.SchemaVersion = 2
	require.NoError(t, e.Validate())
}

// TestAuditEvent_SchemaVersion_V3BackwardCompatible asserts that a v3
// writer is still readable by a v4 reader. v3 is the schema that Stage G
// froze for receive-side validator kinds; Phase 4's cross-cloud Kind
// additions do not break v3 records.
func TestAuditEvent_SchemaVersion_V3BackwardCompatible(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.SchemaVersion = 3
	require.NoError(t, e.Validate())
}

// TestAuditEvent_SchemaVersion_V4BackwardCompatible asserts that a v4
// record (the four cross-cloud kinds of ADR 0006) is still readable by a
// v6 reader.
func TestAuditEvent_SchemaVersion_V4BackwardCompatible(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.SchemaVersion = 4
	require.NoError(t, e.Validate())
}

// TestAuditEvent_SchemaVersion_V5BackwardCompatible asserts that a v5
// record (KindKeyReleaseDenied, ADR 0010) is still readable by a v6 reader.
func TestAuditEvent_SchemaVersion_V5BackwardCompatible(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.SchemaVersion = 5
	require.NoError(t, e.Validate())
}

// TestAuditEvent_SchemaVersion_V6CurrentAccepted asserts the current
// write-side schema version is accepted. ADR 0012 bumps
// SchemaVersionCurrent from 5 → 6 with KindFailoverDecided.
func TestAuditEvent_SchemaVersion_V6CurrentAccepted(t *testing.T) {
	t.Parallel()
	e := validFixture()
	e.SchemaVersion = SchemaVersionCurrent
	require.Equal(t, uint16(6), SchemaVersionCurrent,
		"ADR 0012 sets SchemaVersionCurrent to 6; a change here MUST be reflected in an ADR")
	require.NoError(t, e.Validate())
}
