// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package time_test

import (
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/require"

	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

func TestSystemClockFollowsTheWallClock(t *testing.T) {
	t.Parallel()
	c := shared_time.NewSystemClock()
	before := stdtime.Now()
	now := c.Now()
	require.False(t, now.Before(before))
	require.GreaterOrEqual(t, c.Since(before), stdtime.Duration(0))
}

// A fake clock moves only when told to, never backwards.
func TestFakeClockMovesOnlyWhenTold(t *testing.T) {
	t.Parallel()
	start := stdtime.Date(2026, 10, 14, 12, 0, 0, 0, stdtime.UTC)
	c := shared_time.NewFakeClock(start)
	require.Equal(t, start, c.Now())
	require.Equal(t, stdtime.Duration(0), c.Since(start))
	c.Step(90 * stdtime.Second)
	require.Equal(t, start.Add(90*stdtime.Second), c.Now())
	require.Equal(t, 90*stdtime.Second, c.Since(start))
	later := start.Add(stdtime.Hour)
	c.SetNow(later)
	require.Equal(t, later, c.Now())
	require.PanicsWithValue(t, "time.FakeClock.Step: negative step not permitted", func() { c.Step(-stdtime.Second) })
	require.Equal(t, later, c.Now(), "a refused step leaves the clock where it was")
}
