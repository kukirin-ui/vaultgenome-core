// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reassembly

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// leaf is a well-formed committed component for the given path.
func leaf(path string) componenttree.Component {
	return componenttree.Component{Path: path, Kind: componenttree.KindConfig, ByteSize: 4, Hash: bytes.Repeat([]byte{0x5A}, 32)}
}

// TestFinalize_DefensiveChecksZeroizeAndRefuse proves the two guards
// that only a corrupted reassembler could trip: an admitted set of the
// right size but the wrong keys, and committed components that no
// longer form a tree. Each is refused with its code, every admitted
// plaintext is zeroized, and no plaintext stays reachable.
func TestFinalize_DefensiveChecksZeroizeAndRefuse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		build func() *AGDReassembler
		code  string
		cat   shared_errors.Category
		want  string
	}{
		{
			name: "admitted keys disagree with committed keys",
			build: func() *AGDReassembler {
				return &AGDReassembler{
					components: ComponentMap{"c-a": leaf("a"), "c-b": leaf("b")},
					admitted:   map[ids.ComponentID][]byte{"c-a": []byte("aaaa"), "c-x": []byte("xxxx")},
				}
			},
			code: CodeCoverageIncomplete, cat: shared_errors.CategoryStructural, want: "missing admitted entry",
		},
		{
			name: "committed components no longer form a tree",
			build: func() *AGDReassembler {
				broken := leaf("b")
				broken.Kind = componenttree.Kind("not-a-kind")
				return &AGDReassembler{
					components: ComponentMap{"c-a": leaf("a"), "c-b": broken},
					admitted:   map[ids.ComponentID][]byte{"c-a": []byte("aaaa"), "c-b": []byte("bbbb")},
				}
			},
			code: CodeMerkleRootMismatch, cat: shared_errors.CategoryIntegrity, want: "tree rebuild failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := tc.build()
			var buffers [][]byte
			for _, p := range r.admitted {
				buffers = append(buffers, p)
			}
			res, err := r.Finalize()
			require.Nil(t, res)
			require.Error(t, err)
			require.Equal(t, tc.code, shared_errors.CodeOf(err))
			require.Equal(t, tc.cat, shared_errors.CategoryOf(err))
			require.Contains(t, err.Error(), tc.want)
			require.True(t, r.IsFinalized())
			require.Nil(t, r.admitted, "no plaintext handle survives a refused Finalize")
			for _, b := range buffers {
				require.Equal(t, make([]byte, len(b)), b, "admitted plaintext is zeroized")
			}
			again, err2 := r.Finalize()
			require.Nil(t, again)
			require.Same(t, err, err2)
		})
	}
}

// TestZeroBytes proves the helper clears what it is given and tolerates
// nothing to clear.
func TestZeroBytes(t *testing.T) {
	t.Parallel()
	b := []byte{1, 2, 3}
	zeroBytes(b)
	require.Equal(t, []byte{0, 0, 0}, b)
	zeroBytes(nil)
	zeroBytes([]byte{})
}
