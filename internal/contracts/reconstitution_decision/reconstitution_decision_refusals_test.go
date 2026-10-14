// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstitution_decision

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- required-field matrix -------------------------------------------------

// Each required handle and timestamp is refused on its own, as Structural
// with CodeRequiredFieldMissing — one case per field, so a regression that
// drops a check is pinned to the field it dropped.
func TestReconstitutionDecision_Validate_RequiredFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*ReconstitutionDecision)
	}{
		{"decision_id", func(r *ReconstitutionDecision) { r.DecisionID = "" }},
		{"bootstrap_id", func(r *ReconstitutionDecision) { r.BootstrapID = "" }},
		{"session_id", func(r *ReconstitutionDecision) { r.SessionID = "" }},
		{"genome_id", func(r *ReconstitutionDecision) { r.GenomeID = "" }},
		{"decided_at", func(r *ReconstitutionDecision) { r.DecidedAt = time.Time{} }},
		{"signing_key_id", func(r *ReconstitutionDecision) { r.SigningKeyID = "" }},
		{"signature", func(r *ReconstitutionDecision) { r.Signature = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := validAcceptFixture()
			c.mutate(&r)
			err := r.Validate()
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
		})
	}
}

// ---- wire-format gates -----------------------------------------------------

// A second JSON value after the decision is refused: the decoder consumes
// exactly one value, so nothing rides in behind a well-formed decision.
func TestReconstitutionDecision_UnmarshalJSON_RejectsTrailingContent(t *testing.T) {
	t.Parallel()
	orig := validAcceptFixture()
	raw, err := json.Marshal(&orig)
	require.NoError(t, err)
	payload := append(append([]byte{}, raw...), []byte(` null`)...)

	var r ReconstitutionDecision
	err = r.UnmarshalJSON(payload)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeFieldValueInvalid, shared_errors.CodeOf(err))
}

// The schema gate runs at decode time, not only in Validate: a decision
// written by a build this one does not understand is refused before any
// other field is interpreted — below the supported range as well as above.
func TestReconstitutionDecision_UnmarshalJSON_SchemaVersionOutOfRange(t *testing.T) {
	t.Parallel()
	for _, v := range []int{int(SchemaVersionMin) - 1, int(SchemaVersionMax) + 1} {
		payload := `{"schema_version":` + strconv.Itoa(v) + `}`
		var r ReconstitutionDecision
		err := r.UnmarshalJSON([]byte(payload))
		require.Error(t, err, payload)
		require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err), payload)
	}
}

// An invalid decision has no canonical cover-bytes: CanonicalBytes runs
// Validate first and returns its refusal unchanged, with no bytes.
func TestReconstitutionDecision_CanonicalBytes_InvalidDecisionRefused(t *testing.T) {
	t.Parallel()
	r := validAcceptFixture()
	r.DecisionID = ""
	out, err := r.CanonicalBytes()
	require.Error(t, err)
	require.Nil(t, out)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// ---- signer and resolver refusals -----------------------------------------

// SignWith asks the signer for r.SigningKeyID under PurposeSigningAuthority
// and passes its refusal through unchanged: a store without that key
// refuses as Authority, a store holding the kid under another purpose as
// Integrity. Either way the decision stays unsigned.
func TestReconstitutionDecision_SignWith_SignerRefusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	at := time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC)

	t.Run("unknown_key", func(t *testing.T) {
		t.Parallel()
		empty := keys.NewInMemoryStore(shared_time.NewFakeClock(at))
		r := validAcceptFixture()
		r.SigningKeyID = kid
		r.Signature = nil
		err := r.SignWith(empty)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
		require.Empty(t, r.Signature)
	})
	t.Run("wrong_purpose", func(t *testing.T) {
		t.Parallel()
		witnessOnly := keys.NewInMemoryStore(shared_time.NewFakeClock(at))
		_, err := witnessOnly.GenerateSigning(kid, keys.PurposeSigningWitness)
		require.NoError(t, err)
		r := validAcceptFixture()
		r.SigningKeyID = kid
		r.Signature = nil
		err = r.SignWith(witnessOnly)
		require.Error(t, err)
		require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
		require.Empty(t, r.Signature)
	})
}

// VerifySignature refuses an unsigned decision as Structural before it
// touches the resolver: there are no cover-bytes to check, so the refusal
// is a missing field, never a signature mismatch dressed up as Integrity.
func TestReconstitutionDecision_VerifySignature_UnsignedDecisionRefused(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvAuthStore(t, kid)
	r := validAcceptFixture()
	r.SigningKeyID = kid
	r.Signature = nil
	err := r.VerifySignature(store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

// A well-formed, signed decision verified against the wrong key material
// is refused by the resolver, and the refusal keeps the resolver's class:
// Authority when it does not hold the kid, Integrity when it holds the kid
// under another purpose. The same decision still verifies under the key
// that signed it.
func TestReconstitutionDecision_VerifySignature_ResolverRefusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("recv-key-1")
	store := newRecvAuthStore(t, kid)
	r := validAcceptFixture()
	r.SigningKeyID = kid
	r.Signature = nil
	require.NoError(t, r.SignWith(store))

	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC))
	empty := keys.NewInMemoryStore(fc)
	err := r.VerifySignature(empty)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))

	witnessOnly := keys.NewInMemoryStore(fc)
	_, err = witnessOnly.GenerateSigning(kid, keys.PurposeSigningWitness)
	require.NoError(t, err)
	err = r.VerifySignature(witnessOnly)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	require.NoError(t, r.VerifySignature(store))
}
