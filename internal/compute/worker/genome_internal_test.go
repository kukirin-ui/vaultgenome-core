// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoundedBuffer_KeepsAtMostMaxAndRemembersOverflow(t *testing.T) {
	t.Parallel()
	b := &boundedBuffer{max: 5}
	n, err := b.Write([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.False(t, b.overflowed)
	n, err = b.Write([]byte("defgh"))
	require.NoError(t, err, "a full buffer keeps accepting so the process is not broken by a closed pipe")
	require.Equal(t, 5, n)
	require.True(t, b.overflowed)
	require.Equal(t, "abcde", b.buf.String())
	require.Equal(t, "abcde", b.tail())

	long := &boundedBuffer{max: 1 << 20}
	_, _ = long.Write(make([]byte, 1000))
	require.Len(t, []rune(long.tail()), 401, "tail keeps the last 400 bytes behind an ellipsis")
}
