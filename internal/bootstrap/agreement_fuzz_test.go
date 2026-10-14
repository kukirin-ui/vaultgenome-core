// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_test

import (
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/bootstrap"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// FuzzCheckAgreement asserts the cross-manifest agreement rule from
// docs/doctrine/bootstrap-contracts.md §3 is total: every (sessionA,
// manifestA, policyA, genomeA, sessionB, manifestB, policyB, genomeB)
// tuple either succeeds (when all four pairs match) or fails with a
// stable Structural code — never panics, never returns an unclassified
// error, never returns a non-Structural category.
//
// The fuzzer treats each input pair as bytes that drive the typed-id
// constructors. The seed corpus covers the canonical happy path and the
// four single-axis disagreement cases (the same shape the tests in
// agreement_test.go cover by construction).
func FuzzCheckAgreement(f *testing.F) {
	// Seed 1: full agreement (happy path).
	f.Add("session-A", "manifest-1", "policy-2026.04", "genome-Z",
		"session-A", "manifest-1", "policy-2026.04", "genome-Z")
	// Seed 2: session mismatch only.
	f.Add("session-A", "manifest-1", "policy-2026.04", "genome-Z",
		"session-B", "manifest-1", "policy-2026.04", "genome-Z")
	// Seed 3: manifest mismatch only.
	f.Add("session-A", "manifest-1", "policy-2026.04", "genome-Z",
		"session-A", "manifest-2", "policy-2026.04", "genome-Z")
	// Seed 4: policy mismatch only.
	f.Add("session-A", "manifest-1", "policy-2026.04", "genome-Z",
		"session-A", "manifest-1", "policy-2026.05", "genome-Z")
	// Seed 5: genome mismatch only.
	f.Add("session-A", "manifest-1", "policy-2026.04", "genome-Z",
		"session-A", "manifest-1", "policy-2026.04", "genome-Y")
	// Seed 6: empty pair (constructors produce zero-IDs which Validate
	// rejects upstream — but CheckAgreement itself must still be total).
	f.Add("", "", "", "", "", "", "", "")

	f.Fuzz(func(t *testing.T,
		sA, mA, pA, gA, sB, mB, pB, gB string,
	) {
		// Bound input lengths — typed-IDs in this codebase have no hard
		// upper limit but the fuzz engine may otherwise wander into
		// 100k-byte strings that have no diagnostic value.
		for _, s := range []string{sA, mA, pA, gA, sB, mB, pB, gB} {
			if len(s) > 256 {
				t.Skip()
			}
		}

		bm := mkBootstrapForFuzz(sA, mA, pA, gA)
		rj := mkReconstructionForFuzz(sB, mB, pB, gB)

		err := bootstrap.CheckAgreement(bm, rj)

		// 1. Never panic — pre-checked by the fuzzer infra.
		// 2. err is either nil or a classified Structural error.
		if err == nil {
			// Happy path: every field must match.
			if sA != sB || mA != mB || pA != pB || gA != gB {
				t.Fatalf("CheckAgreement returned nil but inputs disagree: A=(%q,%q,%q,%q) B=(%q,%q,%q,%q)",
					sA, mA, pA, gA, sB, mB, pB, gB)
			}
			return
		}

		cat := shared_errors.CategoryOf(err)
		if cat != shared_errors.CategoryStructural {
			t.Fatalf("CheckAgreement returned non-Structural error %v on inputs A=(%q,%q,%q,%q) B=(%q,%q,%q,%q)",
				cat, sA, mA, pA, gA, sB, mB, pB, gB)
		}

		// Stable error code: must be a known one. We check non-empty;
		// the per-axis codes are exported from /internal/bootstrap.
		if shared_errors.CodeOf(err) == "" {
			t.Fatalf("CheckAgreement returned classified error with empty code: %v", err)
		}
	})
}

// mkBootstrapForFuzz materializes a BootstrapManifest with the four
// caller-controlled identifiers and stable defaults for everything
// else. Side note: we deliberately skip the Validate() pre-flight
// because the fuzzer is allowed to feed arbitrary (including invalid)
// IDs — the agreement check itself must remain total over them.
func mkBootstrapForFuzz(session, manifest, policy, genome string) *bootstrap_manifest.BootstrapManifest {
	return &bootstrap_manifest.BootstrapManifest{
		SchemaVersion:         1,
		BootstrapID:           ids.BootstrapManifestID("bm-fuzz"),
		SessionID:             ids.SessionID(session),
		ManifestID:            ids.ManifestID(manifest),
		PolicyVersion:         ids.PolicyVersion(policy),
		GenomeID:              ids.GenomeID(genome),
		ExpectedDisclosureIDs: []ids.DisclosureID{},
		ExpectedComponentIDs:  []ids.ComponentID{},
		IssuedAt:              time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		SigningKeyID:          ids.KeyID("recv-authority"),
		Signature:             []byte{0xAA},
	}
}

func mkReconstructionForFuzz(session, manifest, policy, genome string) *reconstruction_job_manifest.ReconstructionJobManifest {
	return &reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion: 1,
		ManifestID:    ids.ManifestID(manifest),
		SessionID:     ids.SessionID(session),
		PolicyVersion: ids.PolicyVersion(policy),
		GenomeID:      ids.GenomeID(genome),
		DisclosureIDs: []ids.DisclosureID{},
		IssuedAt:      time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		SigningKeyID:  ids.KeyID("vault-authority"),
		Signature:     []byte{0xBB},
	}
}
