// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_message

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func TestBuildRecipientAAD_Determinism(t *testing.T) {
	t.Parallel()
	a, err := BuildRecipientAAD(
		ids.SessionID("sess-aad-1"),
		ids.ComponentID("comp-core"),
		42,
		ids.PolicyVersion("v1"),
		ids.KeyID("recv-1"),
	)
	require.NoError(t, err)
	b, err := BuildRecipientAAD(
		ids.SessionID("sess-aad-1"),
		ids.ComponentID("comp-core"),
		42,
		ids.PolicyVersion("v1"),
		ids.KeyID("recv-1"),
	)
	require.NoError(t, err)
	require.True(t, bytes.Equal(a, b),
		"BuildRecipientAAD must be byte-stable across calls with identical inputs")
}

func TestBuildRecipientAAD_EveryFieldChangesOutput(t *testing.T) {
	t.Parallel()
	base, err := BuildRecipientAAD(
		ids.SessionID("s1"),
		ids.ComponentID("c1"),
		0,
		ids.PolicyVersion("p1"),
		ids.KeyID("r1"),
	)
	require.NoError(t, err)

	cases := []struct {
		name    string
		mutated func() []byte
	}{
		{
			name: "session",
			mutated: func() []byte {
				out, err := BuildRecipientAAD(
					ids.SessionID("s2"), ids.ComponentID("c1"), 0,
					ids.PolicyVersion("p1"), ids.KeyID("r1"),
				)
				require.NoError(t, err)
				return out
			},
		},
		{
			name: "component",
			mutated: func() []byte {
				out, err := BuildRecipientAAD(
					ids.SessionID("s1"), ids.ComponentID("c2"), 0,
					ids.PolicyVersion("p1"), ids.KeyID("r1"),
				)
				require.NoError(t, err)
				return out
			},
		},
		{
			name: "seq",
			mutated: func() []byte {
				out, err := BuildRecipientAAD(
					ids.SessionID("s1"), ids.ComponentID("c1"), 1,
					ids.PolicyVersion("p1"), ids.KeyID("r1"),
				)
				require.NoError(t, err)
				return out
			},
		},
		{
			name: "policy",
			mutated: func() []byte {
				out, err := BuildRecipientAAD(
					ids.SessionID("s1"), ids.ComponentID("c1"), 0,
					ids.PolicyVersion("p2"), ids.KeyID("r1"),
				)
				require.NoError(t, err)
				return out
			},
		},
		{
			name: "recipient",
			mutated: func() []byte {
				out, err := BuildRecipientAAD(
					ids.SessionID("s1"), ids.ComponentID("c1"), 0,
					ids.PolicyVersion("p1"), ids.KeyID("r2"),
				)
				require.NoError(t, err)
				return out
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, bytes.Equal(base, tc.mutated()),
				"mutating %s must change AAD bytes", tc.name)
		})
	}
}

func TestBuildRecipientAAD_ContainsAllFiveFields(t *testing.T) {
	t.Parallel()
	b, err := BuildRecipientAAD(
		ids.SessionID("s-aad"),
		ids.ComponentID("c-aad"),
		7,
		ids.PolicyVersion("p-aad"),
		ids.KeyID("r-aad"),
	)
	require.NoError(t, err)

	var shaped map[string]any
	require.NoError(t, json.Unmarshal(b, &shaped))
	// All five fields must be present and populated.
	require.Equal(t, "s-aad", shaped["session_id"])
	require.Equal(t, "c-aad", shaped["component_id"])
	// numeric JSON comes back as float64 for uint32 values.
	require.EqualValues(t, 7, shaped["sequence_index"])
	require.Equal(t, "p-aad", shaped["policy_version"])
	require.Equal(t, "r-aad", shaped["recipient_key_id"])
	require.Len(t, shaped, 5, "AAD must carry exactly 5 fields; drift is a doctrinal bump")
}

func TestBuildRecipientAADForMessage_MatchesManual(t *testing.T) {
	t.Parallel()
	msg := validFixture()
	auto, err := BuildRecipientAADForMessage(&msg)
	require.NoError(t, err)
	manual, err := BuildRecipientAAD(
		msg.SessionID, msg.ComponentID, msg.SequenceIndex,
		msg.PolicyVersion, msg.RecipientKeyID,
	)
	require.NoError(t, err)
	require.True(t, bytes.Equal(auto, manual),
		"BuildRecipientAADForMessage must reconstruct the same bytes as a manual 5-arg call")
}

func TestBuildRecipientAADForMessage_NilReceiverRejected(t *testing.T) {
	t.Parallel()
	_, err := BuildRecipientAADForMessage(nil)
	require.Error(t, err)
}
