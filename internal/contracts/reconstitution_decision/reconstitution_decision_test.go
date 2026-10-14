// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstitution_decision

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func validAcceptFixture() ReconstitutionDecision {
	return ReconstitutionDecision{
		SchemaVersion:      SchemaVersionCurrent,
		DecisionID:         ids.ReconstitutionDecisionID("rdec-0001"),
		BootstrapID:        ids.BootstrapManifestID("boot-0001"),
		SessionID:          ids.SessionID("sess-0001"),
		GenomeID:           ids.GenomeID("agd-0001"),
		ValidationResultID: ids.ValidationResultID("vr-recv-0001"),
		Accepted:           true,
		Reason:             ReasonReconstructedOK,
		DecidedAt:          time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC),
		SigningKeyID:       ids.KeyID("recv-key-1"),
		Signature:          []byte{0xFF},
		AuditEventID:       ids.AuditEventID("evt-recv-0001"),
	}
}

func TestReconstitutionDecision_Validate_AcceptOK(t *testing.T) {
	t.Parallel()
	require.NoError(t, validAcceptFixture().Validate())
}

func TestReconstitutionDecision_Validate_SchemaVersionOutOfRange(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	r.SchemaVersion = SchemaVersionMax + 1
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}

func TestReconstitutionDecision_AcceptRequiresAcceptedTrue(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	r.Accepted = false
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
}

func TestReconstitutionDecision_ReassemblyFailedRequiresAcceptedFalse(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	r.Reason = ReasonReassemblyFailed
	r.Accepted = true
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	r.Accepted = false
	require.NoError(t, r.Validate())
}

func TestReconstitutionDecision_ValidationFailedRequiresAcceptedFalse(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	r.Reason = ReasonValidationFailed
	r.Accepted = true
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))

	r.Accepted = false
	require.NoError(t, r.Validate())
}

func TestReconstitutionDecision_UnknownReasonRejected(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	r.Reason = Reason("vibes")
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

func TestReconstitutionDecision_ValidationResultIDRequired(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	r.ValidationResultID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestReconstitutionDecision_AuditEventIDRequired(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	r.AuditEventID = ""
	err := r.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestReconstitutionDecision_RoundTrip(t *testing.T) {
	t.Parallel()
	orig := validAcceptFixture()
	data, err := json.Marshal(&orig)
	require.NoError(t, err)
	var got ReconstitutionDecision
	require.NoError(t, json.Unmarshal(data, &got))
	require.Equal(t, orig.Reason, got.Reason)
	require.Equal(t, orig.Accepted, got.Accepted)
	require.Equal(t, orig.AuditEventID, got.AuditEventID)
	require.Equal(t, orig.ValidationResultID, got.ValidationResultID)
}

func TestReconstitutionDecision_UnmarshalJSON_UnknownFieldsRejected(t *testing.T) {
	t.Parallel()
	payload := `{"schema_version":1,"extra":"x"}`
	var r ReconstitutionDecision
	err := r.UnmarshalJSON([]byte(payload))
	require.Error(t, err)
}

func TestReconstitutionDecision_CanonicalBytes_ExcludesSignature(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	out, err := r.CanonicalBytes()
	require.NoError(t, err)
	require.NotContains(t, string(out), `"signature":"`)
}
