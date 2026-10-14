// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package semantic

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
)

// TestRun_ByteExactMatch — the canonical pass case: Candidate and
// Expected are byte-identical. Score=1.0, Verdict=Pass, no Details.
func TestRun_ByteExactMatch(t *testing.T) {
	t.Parallel()
	want := []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd}
	got := make([]byte, len(want))
	copy(got, want)

	v := Run(Inputs{Candidate: got, Expected: want, HaveExpected: true})
	require.Equal(t, validation_result.VerdictPass, v.Verdict, "bytes match must pass")
	require.Equal(t, 1.0, v.Score)
	require.Equal(t, 1.0, v.Threshold, "threshold must be 1.0 per §2.3")
	require.Empty(t, v.Details, "pass verdict must carry no findings")
}

// TestRun_ByteExactMatch_EmptyPayloads — both candidate and expected
// are empty slices. §2.4 lists "empty" as a required edge-case fixture.
func TestRun_ByteExactMatch_EmptyPayloads(t *testing.T) {
	t.Parallel()
	v := Run(Inputs{Candidate: []byte{}, Expected: []byte{}, HaveExpected: true})
	require.Equal(t, validation_result.VerdictPass, v.Verdict,
		"two empty payloads are byte-equal — doctrine §2 has no special case for them")
	require.Equal(t, 1.0, v.Score)
	require.Empty(t, v.Details)
}

// TestRun_OffByOneBytes — the first §8 negative case ("Candidate differs
// by one byte"). Verdict=Fail, Score=0.0, finding cites the exact offset.
func TestRun_OffByOneBytes(t *testing.T) {
	t.Parallel()
	want := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	got := make([]byte, len(want))
	copy(got, want)
	got[3] = 0xff // single-byte divergence at offset 3

	v := Run(Inputs{Candidate: got, Expected: want, HaveExpected: true})
	require.Equal(t, validation_result.VerdictFail, v.Verdict,
		"one-byte divergence fails the dimension per §2.3 (MVP is binary)")
	require.Equal(t, 0.0, v.Score, "no partial credit in MVP")
	require.Equal(t, 1.0, v.Threshold)

	// Expect exactly one finding — equal length so no length mismatch.
	require.Len(t, v.Details, 1)
	require.Equal(t, CodeByteEquality, v.Details[0].Code)
	require.Equal(t, validation_result.SeverityError, v.Details[0].Severity)
	require.Contains(t, v.Details[0].Message, "offset 3",
		"message must pinpoint the divergence for auditors")
}

// TestRun_LengthMismatch_CandidateShorter — candidate is a prefix of
// expected. Emits both CodeByteLengthMismatch and CodeByteEquality so
// auditors see the proximate cause.
func TestRun_LengthMismatch_CandidateShorter(t *testing.T) {
	t.Parallel()
	want := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	got := []byte{0x10, 0x20, 0x30}

	v := Run(Inputs{Candidate: got, Expected: want, HaveExpected: true})
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Equal(t, 0.0, v.Score)

	codes := map[string]string{}
	for _, d := range v.Details {
		codes[d.Code] = d.Message
	}
	require.Contains(t, codes, CodeByteLengthMismatch,
		"length-mismatch must surface its own finding code")
	require.Contains(t, codes, CodeByteEquality,
		"byte-equality finding must also be present — it is the top-level verdict code")
	require.Contains(t, codes[CodeByteLengthMismatch], "3")
	require.Contains(t, codes[CodeByteLengthMismatch], "5",
		"length finding must cite both observed lengths")
}

// TestRun_LengthMismatch_CandidateLonger — candidate extends beyond the
// expected payload. Symmetric case to the above.
func TestRun_LengthMismatch_CandidateLonger(t *testing.T) {
	t.Parallel()
	want := []byte{0xaa, 0xbb}
	got := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	v := Run(Inputs{Candidate: got, Expected: want, HaveExpected: true})
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Len(t, v.Details, 2)
}

// TestRun_CandidateEmptyButExpectedPopulated — a specific §2.4 edge
// case (empty candidate, non-empty fixture) is still fail.
func TestRun_CandidateEmptyButExpectedPopulated(t *testing.T) {
	t.Parallel()
	v := Run(Inputs{
		Candidate:    []byte{},
		Expected:     []byte{0x01, 0x02},
		HaveExpected: true,
	})
	require.Equal(t, validation_result.VerdictFail, v.Verdict,
		"empty candidate against non-empty fixture must fail")
	require.GreaterOrEqual(t, len(v.Details), 1)
}

// TestRun_MissingExpected_FailsClosed — caller violated the Inputs
// contract (HaveExpected=false). Must fail with CodeMissingExpected and
// NOT with CodeByteEquality — auditors must be able to distinguish a
// service-layer bug from a candidate-level mismatch.
func TestRun_MissingExpected_FailsClosed(t *testing.T) {
	t.Parallel()
	v := Run(Inputs{Candidate: []byte{0x01}, HaveExpected: false})
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Equal(t, 0.0, v.Score)
	require.Len(t, v.Details, 1)
	require.Equal(t, CodeMissingExpected, v.Details[0].Code,
		"missing-fixture failure mode must not be conflated with byte-equality failure")
}

// TestRun_MissingExpected_NilSliceAlsoFails — an explicit nil Expected
// with HaveExpected=true is still a contract violation (the caller
// misreported fixture state).
func TestRun_MissingExpected_NilSliceAlsoFails(t *testing.T) {
	t.Parallel()
	v := Run(Inputs{Candidate: []byte{0x01}, Expected: nil, HaveExpected: true})
	require.Equal(t, validation_result.VerdictFail, v.Verdict)
	require.Equal(t, CodeMissingExpected, v.Details[0].Code)
}

// TestRun_DeterministicOutput — the same inputs produce byte-identical
// DimensionVerdict across calls. Pinned as a doctrine commitment for the
// CI fixture-regeneration test (§2.6).
func TestRun_DeterministicOutput(t *testing.T) {
	t.Parallel()
	in := Inputs{
		Candidate:    []byte{0x01, 0x02, 0x03},
		Expected:     []byte{0x01, 0x02, 0xff},
		HaveExpected: true,
	}
	a := Run(in)
	b := Run(in)
	require.Equal(t, a.Verdict, b.Verdict)
	require.Equal(t, a.Score, b.Score)
	require.Equal(t, a.Threshold, b.Threshold)
	require.Equal(t, len(a.Details), len(b.Details))
	for i := range a.Details {
		require.Equal(t, a.Details[i].Code, b.Details[i].Code)
		require.Equal(t, a.Details[i].Message, b.Details[i].Message,
			"messages must be deterministic — no clocks, no random IDs")
	}
}

// TestFirstDiffMessage_PrefixEquivalence — if candidate is a proper
// prefix of expected, the diagnostic cites the common-prefix length.
func TestFirstDiffMessage_PrefixEquivalence(t *testing.T) {
	t.Parallel()
	msg := firstDiffMessage([]byte{0x01, 0x02}, []byte{0x01, 0x02, 0x03})
	require.Contains(t, msg, "first 2 bytes")
	require.Contains(t, msg, "differ in length")
}
