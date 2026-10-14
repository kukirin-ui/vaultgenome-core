// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// agreedFixture returns a matched pair of BootstrapManifest and
// ReconstructionJobManifest whose every doctrine-required field agrees.
// Tests mutate individual fields on a copy to exercise mismatch codes.
func agreedFixture() (bootstrap_manifest.BootstrapManifest, reconstruction_job_manifest.ReconstructionJobManifest) {
	issued := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	deadline := issued.Add(1 * time.Hour)

	disc := []ids.DisclosureID{
		ids.DisclosureID("disc-0001"),
		ids.DisclosureID("disc-0002"),
		ids.DisclosureID("disc-0003"),
	}
	comp := []ids.ComponentID{
		ids.ComponentID("comp-weights"),
		ids.ComponentID("comp-config"),
		ids.ComponentID("comp-metadata"),
	}

	b := bootstrap_manifest.BootstrapManifest{
		SchemaVersion:         bootstrap_manifest.SchemaVersionCurrent,
		BootstrapID:           ids.BootstrapManifestID("boot-0001"),
		SessionID:             ids.SessionID("sess-0001"),
		ManifestID:            ids.ManifestID("mani-0001"),
		GenomeID:              ids.GenomeID("agd-0001"),
		PolicyVersion:         ids.PolicyVersion("policy-v3"),
		ExpectedDisclosureIDs: append([]ids.DisclosureID(nil), disc...),
		ExpectedComponentIDs:  append([]ids.ComponentID(nil), comp...),
		Deadline:              deadline,
		IssuedAt:              issued,
		SigningKeyID:          ids.KeyID("recv-auth-1"),
		Signature:             []byte{0x01},
	}

	r := reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             ids.ManifestID("mani-0001"),
		SessionID:              ids.SessionID("sess-0001"),
		GenomeID:               ids.GenomeID("agd-0001"),
		PolicyVersion:          ids.PolicyVersion("policy-v3"),
		DisclosureIDs:          append([]ids.DisclosureID(nil), disc...),
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 1 << 20,
		RecipientKeyID:         ids.KeyID("recipient-1"),
		Deadline:               deadline,
		IssuedAt:               issued,
		SigningKeyID:           ids.KeyID("vault-auth-1"),
		Signature:              []byte{0x02},
	}
	return b, r
}

func TestCheckAgreement_OK(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	require.NoError(t, CheckAgreement(&b, &r))
}

func TestCheckAgreement_NilBootstrapRefused(t *testing.T) {
	t.Parallel()
	_, r := agreedFixture()
	err := CheckAgreement(nil, &r)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCheckAgreement_NilReconstructionRefused(t *testing.T) {
	t.Parallel()
	b, _ := agreedFixture()
	err := CheckAgreement(&b, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestCheckAgreement_SessionMismatch(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	b.SessionID = ids.SessionID("sess-xxxx")
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementSessionMismatch, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestCheckAgreement_ManifestMismatch(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	b.ManifestID = ids.ManifestID("mani-xxxx")
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementManifestMismatch, shared_errors.CodeOf(err))
}

func TestCheckAgreement_PolicyMismatch(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	b.PolicyVersion = ids.PolicyVersion("policy-vX")
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementPolicyMismatch, shared_errors.CodeOf(err))
}

func TestCheckAgreement_GenomeMismatch(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	b.GenomeID = ids.GenomeID("agd-xxxx")
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementGenomeMismatch, shared_errors.CodeOf(err))
}

func TestCheckAgreement_DisclosureLenMismatch_BootstrapShorter(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	b.ExpectedDisclosureIDs = b.ExpectedDisclosureIDs[:2]
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementDisclosureLenMismatch, shared_errors.CodeOf(err))
}

func TestCheckAgreement_DisclosureLenMismatch_BootstrapLonger(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	b.ExpectedDisclosureIDs = append(b.ExpectedDisclosureIDs, ids.DisclosureID("disc-extra"))
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementDisclosureLenMismatch, shared_errors.CodeOf(err))
}

// TestCheckAgreement_DisclosureOrderMismatch_PermutationRefused is the
// doctrine-critical assertion: even when the SETS of DisclosureIDs are
// equal, a reordering is refused. Order is semantically significant
// because it is the acceptance order the receive-side committed to.
func TestCheckAgreement_DisclosureOrderMismatch_PermutationRefused(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	// Swap positions 0 and 2 — same set, different order.
	b.ExpectedDisclosureIDs[0], b.ExpectedDisclosureIDs[2] = b.ExpectedDisclosureIDs[2], b.ExpectedDisclosureIDs[0]
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementDisclosureOrderMismatch, shared_errors.CodeOf(err))
}

// TestCheckAgreement_DisclosureOrderMismatch_SingleSwap asserts a
// minimal single-element divergence is caught.
func TestCheckAgreement_DisclosureOrderMismatch_SingleSwap(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	b.ExpectedDisclosureIDs[1] = ids.DisclosureID("disc-other")
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementDisclosureOrderMismatch, shared_errors.CodeOf(err))
}

// TestCheckAgreement_ErrorOrdering_SessionFirst asserts that when
// multiple fields disagree at once, the check reports the first
// disagreement in the canonical order (session → manifest → policy →
// genome → disclosures). Stable ordering makes agreement failures
// diagnosable without having to fix fields one at a time in
// unpredictable order.
func TestCheckAgreement_ErrorOrdering_SessionFirst(t *testing.T) {
	t.Parallel()
	b, r := agreedFixture()
	b.SessionID = ids.SessionID("sess-xxxx")
	b.ManifestID = ids.ManifestID("mani-xxxx")
	b.PolicyVersion = ids.PolicyVersion("policy-vX")
	err := CheckAgreement(&b, &r)
	require.Error(t, err)
	require.Equal(t, CodeAgreementSessionMismatch, shared_errors.CodeOf(err),
		"session is first in the canonical check order; the error must name it")
}

func TestPositionLabel(t *testing.T) {
	t.Parallel()
	cases := map[int]string{
		0:  "0",
		1:  "1",
		9:  "9",
		10: "10",
		42: "42",
		99: "99",
	}
	for in, want := range cases {
		require.Equalf(t, want, positionLabel(in), "positionLabel(%d)", in)
	}
}
