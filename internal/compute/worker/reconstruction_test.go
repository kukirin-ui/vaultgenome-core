// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	rjm "github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// These tests pin the iteration-5 R-11 contract for the DeterministicReconstructor
// MVP placeholder and, by transitivity, for any V2 backend that lands
// against the same Reconstructor interface. See
// docs/doctrine/bootstrap-contracts.md §15 for the freeze policy.
//
// The MVP is a content-addressed digest expansion; the tests verify the
// public properties that any reconstruction mechanism must preserve:
// determinism, purity, boundedness, input sensitivity, and the error
// taxonomy for malformed jobs.

// fixtureClock is the test clock used by every test in this file. All
// timestamps are deterministic so that comparisons against
// manifest.Deadline are exact.
func fixtureClock(t *testing.T) shared_time.Clock {
	t.Helper()
	return shared_time.NewFakeClock(time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC))
}

// sampleManifest builds a minimal valid manifest for reconstruction
// tests. Tests override individual fields as needed.
func sampleManifest() rjm.ReconstructionJobManifest {
	return rjm.ReconstructionJobManifest{
		SchemaVersion:          rjm.SchemaVersionCurrent,
		ManifestID:             ids.ManifestID("mf-001"),
		SessionID:              ids.SessionID("ses-001"),
		GenomeID:               ids.GenomeID("gen-001"),
		PolicyVersion:          ids.PolicyVersion("pol-1"),
		DisclosureIDs:          []ids.DisclosureID{"d-0", "d-1"},
		ExpectedOutputKind:     rjm.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 64,
		RecipientKeyID:         ids.KeyID("k-recip"),
		Deadline:               time.Date(2026, 4, 20, 13, 0, 0, 0, time.UTC),
		IssuedAt:               time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC),
		SigningKeyID:           ids.KeyID("k-sign"),
	}
}

// sampleComponents returns two component materials with distinct IDs
// and plaintexts. The SequenceIndex values mirror the manifest's
// DisclosureIDs order (0, 1).
func sampleComponents() []worker.ComponentMaterial {
	return []worker.ComponentMaterial{
		{
			ComponentID:   ids.ComponentID("c-0"),
			SequenceIndex: 0,
			Plaintext:     []byte("alpha-plaintext-bytes"),
		},
		{
			ComponentID:   ids.ComponentID("c-1"),
			SequenceIndex: 1,
			Plaintext:     []byte("beta-plaintext-bytes-9"),
		},
	}
}

func newReconstructor(t *testing.T) *worker.DeterministicReconstructor {
	t.Helper()
	r, err := worker.NewDeterministicReconstructor(fixtureClock(t))
	require.NoError(t, err)
	return r
}

func TestNewDeterministicReconstructor_NilClockRejected(t *testing.T) {
	t.Parallel()
	_, err := worker.NewDeterministicReconstructor(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// TestReconstruct_ProducesCandidateOutputShape pins the most basic
// property: the Reconstructor returns a CandidateOutput whose identity
// fields all come from the manifest, not from anywhere else.
func TestReconstruct_ProducesCandidateOutputShape(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()

	out, err := r.Reconstruct(context.Background(), m, sampleComponents())
	require.NoError(t, err)
	require.Equal(t, m.ManifestID, out.ManifestID)
	require.Equal(t, m.SessionID, out.SessionID)
	require.Equal(t, m.ExpectedOutputKind, out.OutputKind)
	require.Equal(t, int(m.ExpectedOutputMaxBytes), len(out.Bytes),
		"MVP reconstruction fills the full byte budget")
	require.False(t, out.ProducedAt.IsZero(),
		"ProducedAt must be populated by the injected clock")
}

// TestReconstruct_Deterministic pins the single most important
// property of any reconstruction mechanism: pure function of inputs.
// Run the same inputs twice, get byte-identical Bytes. The MVP backend
// gets this by construction; the V2 generative backend MUST preserve it.
func TestReconstruct_Deterministic(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()
	comps := sampleComponents()

	a, err := r.Reconstruct(context.Background(), m, comps)
	require.NoError(t, err)
	b, err := r.Reconstruct(context.Background(), m, comps)
	require.NoError(t, err)

	require.True(t, bytes.Equal(a.Bytes, b.Bytes),
		"Reconstructor output must be deterministic given the same inputs")
}

// TestReconstruct_OrderInsensitive pins that the canonical digest
// depends on (SequenceIndex, ComponentID) — not on slice order.
// A caller that happens to hand us the components in reverse should
// still get the same bytes.
func TestReconstruct_OrderInsensitive(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()
	comps := sampleComponents()
	reversed := []worker.ComponentMaterial{comps[1], comps[0]}

	a, err := r.Reconstruct(context.Background(), m, comps)
	require.NoError(t, err)
	b, err := r.Reconstruct(context.Background(), m, reversed)
	require.NoError(t, err)

	require.True(t, bytes.Equal(a.Bytes, b.Bytes),
		"reconstruction must be invariant under caller slice order; "+
			"identity is (SequenceIndex, ComponentID) set, not slice order")
}

// TestReconstruct_ManifestIDSensitive pins that a different ManifestID
// produces a different reconstruction — i.e., the manifest identity is
// actually mixed into the digest. Silent parallel manifests would be a
// cross-job replay vector.
func TestReconstruct_ManifestIDSensitive(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m1 := sampleManifest()
	m2 := sampleManifest()
	m2.ManifestID = ids.ManifestID("mf-DIFFERENT")

	a, err := r.Reconstruct(context.Background(), m1, sampleComponents())
	require.NoError(t, err)
	b, err := r.Reconstruct(context.Background(), m2, sampleComponents())
	require.NoError(t, err)

	require.False(t, bytes.Equal(a.Bytes, b.Bytes),
		"reconstruction must differ across distinct ManifestIDs")
}

// TestReconstruct_SessionIDSensitive does the same guard for SessionID.
// An adversary that could re-use one session's reconstruction for a
// different session would collapse the doctrinal session boundary.
func TestReconstruct_SessionIDSensitive(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m1 := sampleManifest()
	m2 := sampleManifest()
	m2.SessionID = ids.SessionID("ses-DIFFERENT")

	a, err := r.Reconstruct(context.Background(), m1, sampleComponents())
	require.NoError(t, err)
	b, err := r.Reconstruct(context.Background(), m2, sampleComponents())
	require.NoError(t, err)

	require.False(t, bytes.Equal(a.Bytes, b.Bytes),
		"reconstruction must differ across distinct SessionIDs")
}

// TestReconstruct_ComponentPlaintextSensitive pins that any change to
// any component's plaintext ripples into the output. This is the
// doctrine's one-bit-flip property: a tampered disclosure must produce
// an observable reconstruction difference.
func TestReconstruct_ComponentPlaintextSensitive(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()

	base := sampleComponents()
	tampered := sampleComponents()
	// Flip one bit in the second component's plaintext.
	tampered[1].Plaintext = append([]byte(nil), tampered[1].Plaintext...)
	tampered[1].Plaintext[0] ^= 0x01

	a, err := r.Reconstruct(context.Background(), m, base)
	require.NoError(t, err)
	b, err := r.Reconstruct(context.Background(), m, tampered)
	require.NoError(t, err)

	require.False(t, bytes.Equal(a.Bytes, b.Bytes),
		"one-bit plaintext flip must produce a different reconstruction")
}

// TestReconstruct_HonorsExpectedOutputMaxBytes verifies the output
// length is exactly ExpectedOutputMaxBytes across a spread of sizes,
// including small / prime / large values. Guards against off-by-one
// bugs in the digest-expansion loop at chunk boundaries.
func TestReconstruct_HonorsExpectedOutputMaxBytes(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)

	for _, n := range []uint64{1, 7, 31, 32, 33, 64, 65, 127, 256, 1023} {
		n := n
		t.Run("", func(t *testing.T) {
			t.Parallel()
			m := sampleManifest()
			m.ExpectedOutputMaxBytes = n
			out, err := r.Reconstruct(context.Background(), m, sampleComponents())
			require.NoError(t, err)
			require.Equal(t, int(n), len(out.Bytes))
		})
	}
}

// TestReconstruct_EmptyComponentsRejected pins the Structural refusal
// when the worker is handed a job with no component materials.
func TestReconstruct_EmptyComponentsRejected(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()

	_, err := r.Reconstruct(context.Background(), m, nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// TestReconstruct_DuplicateComponentIDRejected pins the Structural
// refusal when two components share a ComponentID.
func TestReconstruct_DuplicateComponentIDRejected(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()
	dup := sampleComponents()
	dup[1].ComponentID = dup[0].ComponentID // force collision

	_, err := r.Reconstruct(context.Background(), m, dup)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// TestReconstruct_EmptyManifestIDRejected pins Structural refusal for
// a manifest whose ManifestID is zero. This can only happen through a
// caller bug — the issuer would refuse to sign it — but the Reconstructor
// stays defensive.
func TestReconstruct_EmptyManifestIDRejected(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()
	m.ManifestID = ""

	_, err := r.Reconstruct(context.Background(), m, sampleComponents())
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// TestReconstruct_ZeroMaxBytesRejected pins Structural refusal for an
// ExpectedOutputMaxBytes of zero. The validator will already refuse to
// issue such a manifest, but the Reconstructor double-checks.
func TestReconstruct_ZeroMaxBytesRejected(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()
	m.ExpectedOutputMaxBytes = 0

	_, err := r.Reconstruct(context.Background(), m, sampleComponents())
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

// TestReconstruct_CancelledContextRejected pins the Operational
// behaviour: an already-cancelled context short-circuits before any
// work runs. This is what lets the worker loop in cmd/acp-compute stop
// cleanly when the manifest deadline fires.
func TestReconstruct_CancelledContextRejected(t *testing.T) {
	t.Parallel()
	r := newReconstructor(t)
	m := sampleManifest()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := r.Reconstruct(ctx, m, sampleComponents())
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
}

// TestReconstruct_ProducedAtComesFromInjectedClock pins the doctrine
// that no code path under /internal/compute calls time.Now() directly —
// ProducedAt must equal the clock the Reconstructor was built with.
func TestReconstruct_ProducedAtComesFromInjectedClock(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC)
	r, err := worker.NewDeterministicReconstructor(
		shared_time.NewFakeClock(fixed))
	require.NoError(t, err)
	m := sampleManifest()

	out, err := r.Reconstruct(context.Background(), m, sampleComponents())
	require.NoError(t, err)
	require.Equal(t, fixed, out.ProducedAt)
}
