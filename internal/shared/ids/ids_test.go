// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package ids_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Every identifier type prints as its string and is zero only when empty.
func TestIdentifiersPrintAndKnowWhenTheyAreEmpty(t *testing.T) {
	t.Parallel()
	rows := []struct {
		name      string
		printed   string
		emptyZero bool
		setZero   bool
	}{
		{"RequestID", ids.RequestID("x-1").String(), ids.RequestID("").IsZero(), ids.RequestID("x-1").IsZero()},
		{"AttestationID", ids.AttestationID("x-1").String(), ids.AttestationID("").IsZero(), ids.AttestationID("x-1").IsZero()},
		{"SessionID", ids.SessionID("x-1").String(), ids.SessionID("").IsZero(), ids.SessionID("x-1").IsZero()},
		{"GenomeID", ids.GenomeID("x-1").String(), ids.GenomeID("").IsZero(), ids.GenomeID("x-1").IsZero()},
		{"ComponentID", ids.ComponentID("x-1").String(), ids.ComponentID("").IsZero(), ids.ComponentID("x-1").IsZero()},
		{"DisclosureID", ids.DisclosureID("x-1").String(), ids.DisclosureID("").IsZero(), ids.DisclosureID("x-1").IsZero()},
		{"ManifestID", ids.ManifestID("x-1").String(), ids.ManifestID("").IsZero(), ids.ManifestID("x-1").IsZero()},
		{"ContinuityProofID", ids.ContinuityProofID("x-1").String(), ids.ContinuityProofID("").IsZero(), ids.ContinuityProofID("x-1").IsZero()},
		{"ValidationResultID", ids.ValidationResultID("x-1").String(), ids.ValidationResultID("").IsZero(), ids.ValidationResultID("x-1").IsZero()},
		{"DecisionID", ids.DecisionID("x-1").String(), ids.DecisionID("").IsZero(), ids.DecisionID("x-1").IsZero()},
		{"AuditEventID", ids.AuditEventID("x-1").String(), ids.AuditEventID("").IsZero(), ids.AuditEventID("x-1").IsZero()},
		{"BootstrapManifestID", ids.BootstrapManifestID("x-1").String(), ids.BootstrapManifestID("").IsZero(), ids.BootstrapManifestID("x-1").IsZero()},
		{"ReceivedDisclosureID", ids.ReceivedDisclosureID("x-1").String(), ids.ReceivedDisclosureID("").IsZero(), ids.ReceivedDisclosureID("x-1").IsZero()},
		{"ReconstitutionDecisionID", ids.ReconstitutionDecisionID("x-1").String(), ids.ReconstitutionDecisionID("").IsZero(), ids.ReconstitutionDecisionID("x-1").IsZero()},
		{"KeyID", ids.KeyID("x-1").String(), ids.KeyID("").IsZero(), ids.KeyID("x-1").IsZero()},
		{"PolicyVersion", ids.PolicyVersion("x-1").String(), ids.PolicyVersion("").IsZero(), ids.PolicyVersion("x-1").IsZero()},
	}
	for _, row := range rows {
		require.Equal(t, "x-1", row.printed, row.name)
		require.True(t, row.emptyZero, row.name)
		require.False(t, row.setZero, row.name)
	}
}
