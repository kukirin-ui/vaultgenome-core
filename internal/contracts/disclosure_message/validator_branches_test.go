// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_message

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Every shape rule of Validate, one field at a time: the refusal names the
// field and carries the code the caller classifies on.
func TestDisclosureMessage_Validate_EveryRule(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		mutate func(*DisclosureMessage)
		code   string
	}{
		"schema_version below range": {func(d *DisclosureMessage) { d.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		"schema_version above range": {func(d *DisclosureMessage) { d.SchemaVersion = SchemaVersionMax + 1 }, shared_errors.CodeSchemaVersionUnsupported},
		"disclosure_id":              {func(d *DisclosureMessage) { d.DisclosureID = "" }, shared_errors.CodeRequiredFieldMissing},
		"session_id":                 {func(d *DisclosureMessage) { d.SessionID = "" }, shared_errors.CodeRequiredFieldMissing},
		"component_id":               {func(d *DisclosureMessage) { d.ComponentID = "" }, shared_errors.CodeRequiredFieldMissing},
		"policy_version":             {func(d *DisclosureMessage) { d.PolicyVersion = "" }, shared_errors.CodeRequiredFieldMissing},
		"sealed_payload":             {func(d *DisclosureMessage) { d.SealedPayload = nil }, shared_errors.CodeFieldValueInvalid},
		"nonce":                      {func(d *DisclosureMessage) { d.Nonce = d.Nonce[:GCMNonceSize-1] }, shared_errors.CodeFieldValueInvalid},
		"recipient_key_id":           {func(d *DisclosureMessage) { d.RecipientKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		"authorized_at":              {func(d *DisclosureMessage) { d.AuthorizedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		"signing_key_id":             {func(d *DisclosureMessage) { d.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		"signature":                  {func(d *DisclosureMessage) { d.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := validFixture()
			tc.mutate(&d)
			err := d.Validate()
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, tc.code, shared_errors.CodeOf(err), "%v", err)
			require.ErrorContains(t, err, "disclosure_message:")
		})
	}
}
