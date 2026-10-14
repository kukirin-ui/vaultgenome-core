// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package behavioral

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPad2_ClampsToTwoDigits pins the two-digit renderer used for the
// fractional part of audit percentages: values outside 0..99 are clamped
// rather than producing a third digit or a non-digit byte.
func TestPad2_ClampsToTwoDigits(t *testing.T) {
	t.Parallel()
	cases := map[int]string{
		-5:  "00",
		0:   "00",
		7:   "07",
		10:  "10",
		99:  "99",
		100: "99",
		250: "99",
	}
	for n, want := range cases {
		require.Equal(t, want, pad2(n), "pad2(%d)", n)
	}
}

// TestItoa_HandlesSignAndZero pins the integer renderer on zero, positive
// and negative inputs, so a message built from it never drops a sign.
func TestItoa_HandlesSignAndZero(t *testing.T) {
	t.Parallel()
	cases := map[int]string{
		0:      "0",
		1:      "1",
		-1:     "-1",
		42:     "42",
		-42:    "-42",
		100:    "100",
		-1000:  "-1000",
		987654: "987654",
	}
	for n, want := range cases {
		require.Equal(t, want, itoa(n), "itoa(%d)", n)
	}
}

// TestFmtPct_ClampsOutOfRange proves a score outside [0,1] — a bug
// elsewhere — still renders as a readable, bounded percentage.
func TestFmtPct_ClampsOutOfRange(t *testing.T) {
	t.Parallel()
	require.Equal(t, "0.00%", fmtPct(-7))
	require.Equal(t, "100.00%", fmtPct(42))
	require.Equal(t, "50.00%", fmtPct(0.5))
	require.Equal(t, "33.33%", fmtPct(1.0/3))
}
